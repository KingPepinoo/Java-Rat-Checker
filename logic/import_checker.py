# import_checker.py
import os
import sys
import subprocess
import re
import zipfile
import json

def load_excluded_patterns(config_path):
    """Load exclusion patterns from the cfg.json file."""
    if not os.path.exists(config_path):
        return []
    with open(config_path, 'r') as config_file:
        config = json.load(config_file)
    return [re.compile(pattern, re.IGNORECASE) for pattern in config.get("import_checker_exclusions", [])]

def decompile_class_files(jar_path, decompiler_path, output_dir):
    """Decompile .class files from the .jar using CFR."""
    # Extract .class files to the output directory
    with zipfile.ZipFile(jar_path, 'r') as jar:
        jar.extractall(output_dir)
    
    class_files = []
    for root, dirs, files in os.walk(output_dir):
        for file in files:
            if file.endswith('.class'):
                class_file = os.path.join(root, file)
                class_files.append(class_file)

    # Decompile all class files at once for efficiency
    if class_files:
        subprocess.run([
            'java', '-jar', decompiler_path,
            '--outputdir', output_dir,
            '--silent',
            *class_files
        ], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    else:
        print("No .class files found to decompile.")
    
    # Collect all .java files
    java_files = []
    for root, dirs, files in os.walk(output_dir):
        for file in files:
            if file.endswith('.java'):
                java_files.append(os.path.join(root, file))
    return java_files

def scan_java_files(java_files, suspicious_items_to_scan, excluded_patterns):
    """Scan decompiled .java files for specific suspicious imports or class usages."""
    suspicious_findings = {}
    import_pattern = re.compile(r'^\s*import\s+(?:static\s+)?([^\s;]+);', re.MULTILINE)
    class_usage_pattern = re.compile(r'\b([a-zA-Z_][a-zA-Z0-9_.]*)\b')

    for java_file in java_files:
        try:
            with open(java_file, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()

                # Combine imports and class usages
                imports = import_pattern.findall(content)
                usages = class_usage_pattern.findall(content)

                for item in imports + usages:
                    # Check if the item matches any exclusion pattern
                    exclude = False
                    for ex_pattern in excluded_patterns:
                        if ex_pattern.match(item):
                            exclude = True
                            break
                    if exclude:
                        continue  # Skip this item as it's excluded

                    # Check if the item is in the list of suspicious items
                    if item in suspicious_items_to_scan:
                        if java_file not in suspicious_findings:
                            suspicious_findings[java_file] = []
                        if item in imports:
                            finding = f"Import: {item}"
                        else:
                            finding = f"Usage: {item}"
                        if finding not in suspicious_findings[java_file]:
                            suspicious_findings[java_file].append(finding)
        except Exception as e:
            print(f"Error reading {java_file}: {e}")
            continue
    return suspicious_findings

def main():
    if len(sys.argv) < 3:
        print("Usage: python import_checker.py <path_to_jar> <path_to_cfr_jar> [<config_path>]")
        return

    jar_path = sys.argv[1]
    decompiler_path = sys.argv[2]
    config_path = sys.argv[3] if len(sys.argv) > 3 else 'cfg.json'

    if not os.path.exists(jar_path):
        print(f"File at {jar_path} does not exist.")
        return

    if not os.path.exists(decompiler_path):
        print(f"CFR decompiler at {decompiler_path} does not exist.")
        return

    # List of specific imports and classes to scan for
    suspicious_items_to_scan = [
        'java.io.BufferedReader',
        'java.io.InputStreamReader',
        'java.io.Reader',
        'java.net.URL',
        'java.net.URLConnection',
        'java.security.cert.X509Certificate',
        'javax.net.ssl.HostnameVerifier',
        'javax.net.ssl.HttpsURLConnection',
        'javax.net.ssl.SSLContext',
        'javax.net.ssl.SSLSession',
        'javax.net.ssl.TrustManager',
        'javax.net.ssl.X509TrustManager',
        'java.lang.reflect.Method',
        'java.lang.reflect.Constructor',
        # Add any additional classes or imports to scan for
    ]

    # Create a temporary directory for decompilation
    temp_dir = 'decompiled_code_temp'
    if not os.path.exists(temp_dir):
        os.makedirs(temp_dir)

    print("Decompiling class files...")
    java_files = decompile_class_files(jar_path, decompiler_path, temp_dir)
        
    # Load exclusion patterns
    excluded_patterns = load_excluded_patterns(config_path)
        
    print("Scanning for specified imports and class usages...")
    suspicious_findings = scan_java_files(java_files, suspicious_items_to_scan, excluded_patterns)

    if suspicious_findings:
        print("Specified imports or class usages detected:")
        for java_file, findings in suspicious_findings.items():
            print(f"\nFile: {java_file}")
            for finding in findings:
                print(f" - {finding}")
    else:
        print("No specified imports or class usages detected.")

    # Cleanup: Remove the temporary directory
    try:
        for root, dirs, files in os.walk(temp_dir, topdown=False):
            for name in files:
                os.remove(os.path.join(root, name))
            for name in dirs:
                os.rmdir(os.path.join(root, name))
        os.rmdir(temp_dir)
    except Exception as e:
        print(f"Error cleaning up temporary files: {e}")

if __name__ == '__main__':
    main()
