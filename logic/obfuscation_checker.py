import os
import zipfile
import sys

def extract_classes_from_jar(jar_path, temp_dir):
    """Extract .class files from a .jar file to a temporary directory."""
    with zipfile.ZipFile(jar_path, 'r') as jar:
        jar.extractall(temp_dir)

def is_obfuscated(content):
    """Determine if a file is obfuscated based on several heuristic checks."""
    non_ascii_count = sum(1 for char in content if ord(char) > 127)
    unique_bytes = len(set(content))
    
    # Heuristic for highly obfuscated code
    # 1. If there are a large number of non-ASCII characters
    # 2. If the number of unique bytes is low
    if non_ascii_count > 50 or unique_bytes < 30:
        return "Highly Obfuscated"
    
    # Heuristic for partially obfuscated code
    # Detect variables/methods with long or random-looking names
    if len(content) < 100 and non_ascii_count > 10:
        return "Partially Obfuscated"
    
    # Default: no significant obfuscation detected
    return None

def check_for_obfuscation(class_dir):
    """Check extracted .class files for obfuscated code."""
    obfuscated_files = []
    
    for root, _, files in os.walk(class_dir):
        for file in files:
            if file.endswith('.class'):
                file_path = os.path.join(root, file)
                with open(file_path, 'rb') as f:
                    content = f.read().decode('utf-8', errors='ignore')
                    
                    # Check if this file is obfuscated based on the content
                    obfuscation_level = is_obfuscated(content)
                    if obfuscation_level:
                        obfuscated_files.append((file_path, obfuscation_level))
                        
    return obfuscated_files

def main():
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
        for obfuscated_file, obfuscation_level in obfuscated_files:
            print(f" - {obfuscated_file} ({obfuscation_level})")
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
