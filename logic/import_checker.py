# import_checker.py
import os
import sys
import subprocess
import tempfile
import re
import zipfile
import json

def load_excluded_patterns(config_path):
    """Load exclusion patterns from the cfg.json file."""
    if not os.path.exists(config_path):
        print(f"Configuration file {config_path} does not exist.")
        return []
    with open(config_path, 'r') as config_file:
        config = json.load(config_file)
    return [re.compile(pattern, re.IGNORECASE) for pattern in config.get("import_checker_exclusions", [])]

def decompile_class_files(jar_path, decompiler_path, output_dir):
    """Decompile .class files from the .jar using CFR."""
    # Extract .class files to a temporary directory
    with zipfile.ZipFile(jar_path, 'r') as jar:
        jar.extractall(output_dir)
    
    java_files = []
    for root, dirs, files in os.walk(output_dir):
        for file in files:
            if file.endswith('.class'):
                class_file = os.path.join(root, file)
                # Decompile the .class file to .java
                java_file_path = os.path.splitext(class_file)[0] + '.java'
                java_files.append(java_file_path)
                
                # Run CFR decompiler
                subprocess.run([
                    'java', '-jar', decompiler_path,
                    '--outputdir', os.path.dirname(class_file),
                    class_file
                ], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    return java_files

def scan_java_files(java_files, suspicious_imports_to_scan, excluded_patterns):
    """Scan decompiled .java files for specific suspicious imports."""
    suspicious_imports = {}
    import_pattern = re.compile(r'^\s*import\s+([a-zA-Z0-9_.]+);', re.MULTILINE)

    for java_file in java_files:
        try:
            with open(java_file, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
                imports = import_pattern.findall(content)
                for imp in imports:
                    # Check if the import matches any exclusion pattern
                    exclude = False
                    for ex_pattern in excluded_patterns:
                        if ex_pattern.match(imp):
                            exclude = True
                            break
                    if exclude:
                        continue  # Skip this import as it's excluded

                    # Check if the import is in the list of suspicious imports
                    if imp in suspicious_imports_to_scan:
                        if java_file not in suspicious_imports:
                            suspicious_imports[java_file] = []
                        suspicious_imports[java_file].append(imp)
        except Exception as e:
            pass  # Handle exceptions if necessary
    return suspicious_imports

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

    # List of specific imports to scan for
    suspicious_imports_to_scan = [
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
    ]

    with tempfile.TemporaryDirectory() as temp_dir:
        print("Decompiling class files...")
        java_files = decompile_class_files(jar_path, decompiler_path, temp_dir)
        
        # Load exclusion patterns
        excluded_patterns = load_excluded_patterns(config_path)
        
        print("Scanning for specified imports...")
        suspicious_imports = scan_java_files(java_files, suspicious_imports_to_scan, excluded_patterns)

        if suspicious_imports:
            print("Specified imports detected:")
            for java_file, imports in suspicious_imports.items():
                print(f"\nFile: {java_file}")
                for imp in imports:
                    print(f" - Import: {imp}")
        else:
            print("No specified imports detected.")

if __name__ == '__main__':
    main()
