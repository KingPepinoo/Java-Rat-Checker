import zipfile
import os
import re
import sys
import tempfile

def scan_jar_for_connections(jar_path):
    # Patterns for various types of suspicious connections
    https_pattern = re.compile(r'https://[^ \n]+')
    discord_pattern = re.compile(r'(discord(app)?\.com|discord\.gg)')
    webhook_pattern = re.compile(r'discord(app)?\.com/api/webhooks')
    bot_token_pattern = re.compile(r'Bot\s+[A-Za-z0-9\-_]+')
    api_pattern = re.compile(r'\bapi\b', re.IGNORECASE)

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
                            try:
                                decoded_content = file_content.decode('utf-8', errors='ignore')
                                suspicious_lines = []
                                for i, line in enumerate(decoded_content.splitlines()):
                                    connection_type = None
                                    connection_info = None

                                    # Check for suspicious connections
                                    if https_pattern.search(line):
                                        connection_info = https_pattern.findall(line)
                                        connection_type = "HTTPS"
                                    elif discord_pattern.search(line):
                                        connection_info = discord_pattern.findall(line)
                                        connection_type = "Discord"
                                    elif webhook_pattern.search(line):
                                        connection_info = webhook_pattern.findall(line)
                                        connection_type = "Discord Webhook"
                                    elif bot_token_pattern.search(line):
                                        connection_info = bot_token_pattern.findall(line)
                                        connection_type = "Bot Token"
                                    elif api_pattern.search(line):
                                        connection_info = api_pattern.findall(line)
                                        connection_type = "API"

                                    if connection_type and connection_info:
                                        for conn in connection_info:
                                            suspicious_lines.append((i + 1, conn, connection_type))

                                if suspicious_lines:
                                    suspicious_files[file_path] = suspicious_lines
                            except UnicodeDecodeError:
                                pass

    return suspicious_files

def main():
    if len(sys.argv) < 2:
        print("Usage: python connection_checker.py <jar_path>")
        return

    jar_path = sys.argv[1]

    if os.path.exists(jar_path):
        result = scan_jar_for_connections(jar_path)
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

if __name__ == '__main__':
    main()
