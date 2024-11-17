# obfuscation_checker.py
import os
import zipfile
import sys
import json
import re
import math
from collections import defaultdict

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

def calculate_entropy(data):
    """Calculate the Shannon entropy of a byte string."""
    if not data:
        return 0
    entropy = 0
    length = len(data)
    byte_counts = defaultdict(int)
    for byte in data:
        byte_counts[byte] += 1
    for count in byte_counts.values():
        p_x = count / length
        entropy -= p_x * math.log2(p_x)
    return entropy

def is_suspicious_name(name):
    """Determine if a name is suspicious based on length and character patterns."""
    # Check for very short names
    if len(name) <= 2:
        return True
    # Check for names with unusual character patterns (e.g., random sequences)
    if re.match(r'^[a-z]+$', name) and not re.match(r'^[aeiou]+$', name):
        # Check for lack of vowels, which is common in obfuscated names
        vowels = set('aeiou')
        if not any(char in vowels for char in name):
            return True
    return False

def extract_webhooks(content):
    """Attempt to extract Discord webhook URLs from the content."""
    webhook_pattern = re.compile(
        rb'https://(discord(app)?\.com/api/webhooks/|canary\.discord\.com/api/webhooks/)[^\s"\']+',
        re.IGNORECASE
    )
    webhooks = webhook_pattern.findall(content)
    decoded_webhooks = [wh.decode('utf-8', errors='ignore') for wh in webhooks]
    return decoded_webhooks

def analyze_class_file(content):
    """Analyze a .class file content for obfuscation."""
    findings = {}

    # Extract class, method, and field names
    names = re.findall(rb'\b([a-zA-Z_][a-zA-Z0-9_]*)\b', content)
    decoded_names = [name.decode('utf-8', errors='ignore') for name in names]
    suspicious_names = [name for name in decoded_names if is_suspicious_name(name)]
    if suspicious_names:
        # Limit to 10 names to avoid flooding
        max_names = 10
        displayed_names = suspicious_names[:max_names]
        findings['suspicious_names'] = displayed_names
        if len(suspicious_names) > max_names:
            findings['additional_names_count'] = len(suspicious_names) - max_names

    # Check for use of reflection
    uses_reflection = b'java/lang/reflect' in content
    if uses_reflection:
        findings['uses_reflection'] = True

    # Check for high entropy strings (possible obfuscated constants)
    strings = re.findall(rb'[\x07-\x0D\x20-\x7E]{4,}', content)
    high_entropy_strings = []
    for s in strings:
        entropy = calculate_entropy(s)
        if entropy > 4.0:  # Adjust threshold as needed
            high_entropy_strings.append(s.decode('utf-8', errors='ignore'))
    if high_entropy_strings:
        findings['high_entropy_strings'] = True  # We won't display the strings to avoid sensitive data leakage

    # Check for complex control flow patterns (e.g., excessive switch statements)
    switch_count = len(re.findall(rb'\blookupswitch\b|\btableswitch\b', content))
    if switch_count > 5:  # Arbitrary threshold
        findings['excessive_switch_statements'] = switch_count

    # Attempt to extract webhooks
    webhooks = extract_webhooks(content)
    if webhooks:
        findings['webhooks'] = webhooks

    return findings

def check_for_obfuscation(jar_path, config_path='cfg.json'):
    """Check extracted .class files for obfuscated code."""
    obfuscated_files = {}
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
                        findings = analyze_class_file(content)
                        if findings:
                            obfuscated_files[file_path] = findings
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
        for obfuscated_file, findings in obfuscated_files.items():
            print(f"\nFile: {obfuscated_file}")
            if 'suspicious_names' in findings:
                print(" - Suspicious Names Detected:")
                for name in findings['suspicious_names']:
                    print(f"   - {name}")
                if 'additional_names_count' in findings:
                    print(f"   ... and {findings['additional_names_count']} more")
            if 'uses_reflection' in findings:
                print(" - Uses Reflection APIs")
            if 'high_entropy_strings' in findings:
                print(" - High Entropy Strings Detected")
            if 'excessive_switch_statements' in findings:
                print(f" - Excessive Switch Statements: {findings['excessive_switch_statements']}")
            if 'webhooks' in findings:
                print(" - Potential Discord Webhooks Found:")
                for webhook in findings['webhooks']:
                    print(f"   - {webhook}")
    else:
        print("No obfuscated code detected.")

if __name__ == "__main__":
    main()
