import os
import sys
import subprocess
import tempfile
import re
import zipfile

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
                relative_path = os.path.relpath(class_file, output_dir)
                java_file_path = os.path.splitext(class_file)[0] + '.java'
                java_files.append(java_file_path)
                
                # Run CFR decompiler
                subprocess.run([
                    'java', '-jar', decompiler_path,
                    '--outputdir', os.path.dirname(class_file),
                    class_file
                ], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    return java_files

def scan_java_files(java_files):
    """Scan decompiled .java files for suspicious imports."""
    suspicious_imports = {}
    import_pattern = re.compile(r'^\s*import\s+([a-zA-Z0-9_.]+);', re.MULTILINE)
    suspicious_patterns = [
        re.compile(r'^java\.net\.', re.IGNORECASE),
        re.compile(r'^java\.nio\.channels\.', re.IGNORECASE),
        re.compile(r'^javax\.net\.', re.IGNORECASE),
        re.compile(r'^org\.apache\.http\.', re.IGNORECASE),
        # Add more patterns as needed
    ]
    
    for java_file in java_files:
        try:
            with open(java_file, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
                imports = import_pattern.findall(content)
                for imp in imports:
                    for pattern in suspicious_patterns:
                        if pattern.match(imp):
                            if java_file not in suspicious_imports:
                                suspicious_imports[java_file] = []
                            suspicious_imports[java_file].append(imp)
        except Exception as e:
            pass  # Handle exceptions if necessary
    return suspicious_imports

def main():
    if len(sys.argv) < 3:
        print("Usage: python import_checker.py <path_to_jar> <path_to_cfr_jar>")
        return

    jar_path = sys.argv[1]
    decompiler_path = sys.argv[2]

    if not os.path.exists(jar_path):
        print(f"File at {jar_path} does not exist.")
        return

    if not os.path.exists(decompiler_path):
        print(f"CFR decompiler at {decompiler_path} does not exist.")
        return

    with tempfile.TemporaryDirectory() as temp_dir:
        print("Decompiling class files...")
        java_files = decompile_class_files(jar_path, decompiler_path, temp_dir)
        print("Scanning for suspicious imports...")
        suspicious_imports = scan_java_files(java_files)

        if suspicious_imports:
            print("Suspicious imports detected:")
            for java_file, imports in suspicious_imports.items():
                print(f"\nFile: {java_file}")
                for imp in imports:
                    print(f" - Import: {imp}")
        else:
            print("No suspicious imports detected.")

if __name__ == '__main__':
    main()
