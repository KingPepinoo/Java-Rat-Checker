# obfuscation_checker.py
import os
import zipfile
import sys
import json
import re

def load_whitelisted_libs(config_path):
    """Load whitelisted libraries from the cfg.json file."""
    if not os.path.exists(config_path):
        return []
    with open(config_path, 'r') as config_file:
        config = json.load(config_file)
    return [re.compile(pattern, re.IGNORECASE) for pattern in config.get("obfuscation_checker_whitelist", [])]

def contains_whitelisted_lib(file_path, whitelisted_patterns):
    """Check if the file path matches any whitelisted library patterns."""
    for pattern in whitelisted_patterns:
        if pattern.search(file_path):
            return True
    return False

def is_obfuscated(content, high_entropy_threshold=6.5):
    """Determine if a file is obfuscated based on heuristic checks."""
    from math import log2
    byte_counts = {}
    for byte in content:
        byte_counts[byte] = byte_counts.get(byte, 0) + 1
    entropy = 0.0
    length = len(content)
    for count in byte_counts.values():
        p_x = count / length
        entropy -= p_x * log2(p_x)
    
    if entropy > high_entropy_threshold:
        return "Highly Obfuscated"
    
    # Additional heuristics can be added here
    
    return None

def has_suspicious_class_names(content):
    """Check for class names that are too short or appear random."""
    # Example: Look for class names with 1-2 characters
    class_name_pattern = re.compile(rb'Lcom/example/([A-Za-z]{1,2})\.class')
    matches = class_name_pattern.findall(content)
    for match in matches:
        name = match.decode('utf-8', errors='ignore')
        if len(name) <= 2:
            return True
    return False

def check_for_obfuscation(jar_path, config_path='cfg.json'):
    """Check extracted .class files for obfuscated code."""
    obfuscated_files = []
    whitelisted_patterns = load_whitelisted_libs(config_path)
    temp_dir = os.path.join(os.path.dirname(jar_path), 'temp_classes_obf')

    try:
        with zipfile.ZipFile(jar_path, 'r') as jar_file:
            jar_file.extractall(temp_dir)
    except zipfile.BadZipFile:
        print(f"The file {jar_path} is not a valid zip file.")
        return obfuscated_files

    for root, _, files in os.walk(temp_dir):
        for file in files:
            if file.endswith('.class'):
                file_path = os.path.join(root, file)
                relative_file_path = os.path.relpath(file_path, temp_dir)
                
                if contains_whitelisted_lib(relative_file_path, whitelisted_patterns):
                    continue  # Skip whitelisted libraries
                
                try:
                    with open(file_path, 'rb') as f:
                        content = f.read()
                        obfuscation_level = is_obfuscated(content)
                        if not obfuscation_level:
                            # Optionally check for suspicious class names
                            if has_suspicious_class_names(content):
                                obfuscation_level = "Highly Obfuscated"
                        if obfuscation_level:
                            obfuscated_files.append((file_path, obfuscation_level))
                except Exception as e:
                    print(f"Error processing file {file_path}: {e}")
                    continue

    # Cleanup: Remove temporary directory and files
    try:
        for root, dirs, files in os.walk(temp_dir, topdown=False):
            for name in files:
                os.remove(os.path.join(root, name))
            for name in dirs:
                os.rmdir(os.path.join(root, name))
        os.rmdir(temp_dir)
    except Exception as e:
        print(f"Error cleaning up temporary files: {e}")

    return obfuscated_files

def main():
    if len(sys.argv) < 2:
        print("Usage: python obfuscation_checker.py <path_to_jar> [<config_path>]")
        return

    jar_path = sys.argv[1]
    config_path = sys.argv[2] if len(sys.argv) > 2 else 'cfg.json'

    if not os.path.exists(jar_path):
        print(f"File at {jar_path} does not exist.")
        return

    print("Extracting classes from jar file...")
    obfuscated_files = check_for_obfuscation(jar_path, config_path)

    if obfuscated_files:
        print("Obfuscated code detected in the following files:")
        for obfuscated_file, obfuscation_level in obfuscated_files:
            print(f" - {obfuscated_file} ({obfuscation_level})")
    else:
        print("No obfuscated code detected.")

if __name__ == "__main__":
    main()
