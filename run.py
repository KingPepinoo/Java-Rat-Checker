import os
import subprocess
from datetime import datetime
import time
import re

def run_script(script_name, jar_path):
    current_dir = os.path.dirname(os.path.abspath(__file__))
    logic_folder = os.path.join(current_dir, 'logic')
    script_path = os.path.join(logic_folder, script_name)

    if os.path.exists(script_path):
        print(f"Running {script_path}...")
        result = subprocess.run(['python', script_path, jar_path], capture_output=True, text=True)
        return result.stdout
    else:
        print(f"{script_path} does not exist.")
        return ""

def sanitize_filename(filename):
    return "".join(char if char.isalnum() or char in (' ', '-') else '_' for char in filename)

def check_for_suspicious_connections(connection_output):
    minecraft_pattern = re.compile(r'https://[^ ]*minecraft', re.IGNORECASE)
    network_pattern = re.compile(r'https://[^ ]*network', re.IGNORECASE)
    api_pattern = re.compile(r'https://[^ ]+|api\.[^ ]+', re.IGNORECASE)  # More general pattern for URLs or APIs

    suspicious_urls = []
    
    for line in connection_output.splitlines():
        if api_pattern.search(line):
            # Find and store the exact URL or API
            connection = api_pattern.search(line)
            if connection:
                suspicious_urls.append(connection.group())
    
    return suspicious_urls

def main():
    jar_path = input("Please enter the path to the .jar file: ").strip('"')

    if not os.path.exists(jar_path):
        print(f"The file at {jar_path} does not exist. Please check the path and try again.")
        return

    try:
        jar_filename = os.path.splitext(os.path.basename(jar_path))[0]
        jar_filename = sanitize_filename(jar_filename)
        now = datetime.now()
        timestamp = now.strftime("%Y%m%d-%H%M%S")

        results_file_name = f"results-{jar_filename}-{timestamp}.txt"
        results_file_path = os.path.join(os.path.dirname(__file__), results_file_name)

        print(f"Results file will be created at: {results_file_path}")

        connection_output = run_script('connection_checker.py', jar_path)
        obfuscation_output = run_script('obfuscation_checker.py', jar_path)
        dll_output = run_script('dll_scanner.py', jar_path)

        print("\nConnection Checker Output:")
        print(connection_output)
        
        print("\nObfuscation Checker Output:")
        print(obfuscation_output)

        print("\nDLL Scanner Output:")
        print(dll_output)

        results = []
        suspicious_connections = check_for_suspicious_connections(connection_output)

        if "Suspicious connections found" in connection_output:
            results.append("This file is a rat due to suspicious connections.")
            
            for connection in suspicious_connections:
                results.append(f" - Detected suspicious connection: {connection}")
        else:
            results.append("Connection check passed.")

        if "Obfuscated code detected" in obfuscation_output:
            results.append("It is likely this mod is a rat due to obfuscation.")
        else:
            results.append("Obfuscation check passed.")

        if "DLL files detected" in dll_output:
            results.append("Suspicious .dll files found.")
        else:
            results.append("No .dll files detected.")

        with open(results_file_path, "w") as f:
            f.write("Connection Checker Output:\n")
            f.write(connection_output + "\n")
            f.write("Obfuscation Checker Output:\n")
            f.write(obfuscation_output + "\n")
            f.write("DLL Scanner Output:\n")
            f.write(dll_output + "\n")
            f.write("\nFinal Results:\n")
            for result in results:
                f.write(result + "\n")

        print(f"\nResults Summary:")
        for result in results:
            print(result)

        print(f"\nResults have been written to {results_file_path}.")
        print("The program will close in 3 seconds...")
        time.sleep(3)
    
    except Exception as e:
        print(f"An error occurred: {e}")
        time.sleep(3)

if __name__ == '__main__':
    main()
