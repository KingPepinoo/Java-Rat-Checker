import os
import zipfile
import sys

def extract_classes_from_jar(jar_path, temp_dir):
    """Extract .class files from a .jar file to a temporary directory."""
    with zipfile.ZipFile(jar_path, 'r') as jar:
        jar.extractall(temp_dir)

def check_for_obfuscation(class_dir):
    """Check extracted .class files for obfuscated code."""
    obfuscated_files = []
    
    # Define a simple heuristic for obfuscation detection
    for root, _, files in os.walk(class_dir):
        for file in files:
            if file.endswith('.class'):
                file_path = os.path.join(root, file)
                with open(file_path, 'rb') as f:
                    content = f.read()

                    # Check for certain byte patterns that are common in obfuscated files
                    if b'\x00' in content or len(set(content)) < 50:  # Example heuristic
                        obfuscated_files.append(file_path)

    return obfuscated_files

def main():
    # Check if the jar path is provided as an argument
    if len(sys.argv) < 2:
        print("Usage: python obfuscation_checker.py <path_to_jar>")
        return

    jar_path = sys.argv[1]
    temp_dir = os.path.join(os.path.dirname(jar_path), 'temp_classes')

    print("Extracting classes from jar file...")
    extract_classes_from_jar(jar_path, temp_dir)

    obfuscated_files = check_for_obfuscation(temp_dir)

    if obfuscated_files:
        print("Obfuscated code detected in the following files:")
        for obfuscated_file in obfuscated_files:
            print(f" - {obfuscated_file}")
    else:
        print("No obfuscated code detected.")

    # Cleanup: Remove temporary directory and files
    for root, dirs, files in os.walk(temp_dir, topdown=False):
        for name in files:
            os.remove(os.path.join(root, name))
        for name in dirs:
            os.rmdir(os.path.join(root, name))
    os.rmdir(temp_dir)

if __name__ == "__main__":
    main()
