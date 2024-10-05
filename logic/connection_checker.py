# connection_checker.py
import zipfile
import os
import re
import sys
import tempfile
import json

def load_excluded_patterns(config_path):
    """Load exclusion patterns from the cfg.json file."""
    if not os.path.exists(config_path):
        print(f"Configuration file {config_path} does not exist.")
        return []
    with open(config_path, 'r') as config_file:
        config = json.load(config_file)
    return [re.compile(pattern, re.IGNORECASE) for pattern in config.get("connection_checker_exclusions", [])]

def scan_jar_for_connections(jar_path, config_path='cfg.json'):
    # Patterns for various types of suspicious connections
    https_pattern = re.compile(r'https?://[^\s]+', re.IGNORECASE)
    discord_pattern = re.compile(r'(discord(app)?\.com|discord\.gg)', re.IGNORECASE)
    webhook_pattern = re.compile(r'discord(app)?\.com/api/webhooks', re.IGNORECASE)
    bot_token_pattern = re.compile(r'Bot\s+[A-Za-z0-9\-_]+')
    api_url_pattern = re.compile(r'https?://api\.[^\s]+', re.IGNORECASE)
    
    # Load exclusion patterns from config
    excluded_patterns = load_excluded_patterns(config_path)
    
    suspicious_files = {}
    
    with zipfile.ZipFile(jar_path, 'r') as jar_file:
        with tempfile.TemporaryDirectory() as temp_dir:
            jar_file.extractall(temp_dir)

            for root, dirs, files in os.walk(temp_dir):
                for file in files:
                    file_path = os.path.join(root, file)
                    if file.endswith('.class'):
                        with open(file_path, 'rb') as f:
                            file_content = f.read()
                            # Analyze at byte level to avoid false positives
                            # Look for byte patterns corresponding to strings
                            # Instead of decoding as text
                            suspicious_lines = []
                            for pattern, connection_type in [
                                (https_pattern, "HTTPS"),
                                (discord_pattern, "Discord"),
                                (webhook_pattern, "Discord Webhook"),
                                (bot_token_pattern, "Bot Token"),
                                (api_url_pattern, "API URL")
                            ]:
                                for match in pattern.finditer(file_content.decode('utf-8', errors='ignore')):
                                    line_no = file_content[:match.start()].count(b'\n') + 1
                                    suspicious_lines.append((line_no, match.group(), connection_type))
                            
                            if suspicious_lines:
                                # Further exclude based on line content
                                filtered_lines = []
                                for line_no, line, connection_type in suspicious_lines:
                                    # Extract the actual line text
                                    try:
                                        lines = file_content.decode('utf-8', errors='ignore').splitlines()
                                        line_text = lines[line_no - 1].strip()
                                    except IndexError:
                                        line_text = ""
                                    
                                    exclude = False
                                    for ex_pattern in excluded_patterns:
                                        if ex_pattern.match(line_text):
                                            exclude = True
                                            break
                                    if not exclude:
                                        filtered_lines.append((line_no, line, connection_type))
                                
                                if filtered_lines:
                                    suspicious_files[file_path] = filtered_lines

    return suspicious_files

def main():
    if len(sys.argv) < 2:
        print("Usage: python connection_checker.py <jar_path> [<config_path>]")
        return
    
    jar_path = sys.argv[1]
    config_path = sys.argv[2] if len(sys.argv) > 2 else 'cfg.json'
    
    if os.path.exists(jar_path):
        result = scan_jar_for_connections(jar_path, config_path)
        if result:
            print(f"Suspicious connections found in the following files:")
            for file, lines in result.items():
                print(f"\nFile: {file}")
                for line_no, line, connection_type in lines:
                    print(f"  Line {line_no} ({connection_type}): {line}")
        else:
            print("No suspicious connections or Discord-related content found.")
    else:
        print(f"File at {jar_path} does not exist.")

if __name__ == "__main__":
    main()
