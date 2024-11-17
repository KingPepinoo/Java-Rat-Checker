# main.py
import os
import subprocess
from datetime import datetime
import time
import re

def run_script(script_name, jar_path, extra_args=None):
    current_dir = os.path.dirname(os.path.abspath(__file__))
    logic_folder = os.path.join(current_dir, 'logic')
    script_path = os.path.join(logic_folder, script_name)

    if os.path.exists(script_path):
        command = ['python', script_path, jar_path]
        if extra_args:
            command.extend(extra_args)
        result = subprocess.run(command, capture_output=True, text=True)
        return result.stdout
    else:
        print(f"{script_path} does not exist.")
        return ""

def sanitize_filename(filename):
    return "".join(char if char.isalnum() or char in (' ', '-') else '_' for char in filename)

def run_import_checker(jar_path):
    cfr_jar_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'cfr.jar')
    logic_folder = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'logic')
    script_path = os.path.join(logic_folder, 'import_checker.py')

    if os.path.exists(script_path):
        result = subprocess.run(['python', script_path, jar_path, cfr_jar_path, 'cfg.json'], capture_output=True, text=True)
        return result.stdout
    else:
        print(f"{script_path} does not exist.")
        return ""

def extract_suspicious_imports(import_output):
    """Extract the suspicious imports and usages from the import checker output."""
    suspicious_items = []
    pattern = re.compile(r' - (Import|Usage): (.+)$', re.MULTILINE)
    matches = pattern.findall(import_output)
    if matches:
        for _, item in matches:
            suspicious_items.append(item)
    return suspicious_items

def run_blacklisted_mods_checker(jar_path):
    logic_folder = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'logic')
    script_path = os.path.join(logic_folder, 'blacklisted_mods.py')

    if os.path.exists(script_path):
        result = subprocess.run(['python', script_path, jar_path], capture_output=True, text=True)
        return result.stdout
    else:
        print(f"{script_path} does not exist.")
        return ""

def print_section(title, content):
    print("\n" + "=" * 60)
    print(f"{title}")
    print("=" * 60)
    print(content)

def extract_obfuscation_findings(obfuscation_output):
    """Extract detailed findings from the obfuscation checker output."""
    obfuscated_files = {}
    file_pattern = re.compile(r'^File: (.+)$', re.MULTILINE)
    findings_pattern = re.compile(r'^ - (.+)$', re.MULTILINE)
    subfinding_pattern = re.compile(r'^   - (.+)$', re.MULTILINE)
    lines = obfuscation_output.split('\n')
    current_file = None
    current_finding = None
    for line in lines:
        file_match = file_pattern.match(line)
        findings_match = findings_pattern.match(line)
        subfinding_match = subfinding_pattern.match(line)
        if file_match:
            current_file = file_match.group(1)
            obfuscated_files[current_file] = []
            current_finding = None
        elif findings_match:
            current_finding = findings_match.group(1)
            obfuscated_files[current_file].append({'finding': current_finding, 'details': []})
        elif subfinding_match and current_finding:
            detail = subfinding_match.group(1)
            obfuscated_files[current_file][-1]['details'].append(detail)
    return obfuscated_files

def main():
    try:
        jar_path = input("Please enter the path to the .jar file: ").strip('"')

        if not os.path.exists(jar_path):
            print(f"The file at {jar_path} does not exist. Please check the path and try again.")
            return

        jar_filename = os.path.splitext(os.path.basename(jar_path))[0]
        jar_filename = sanitize_filename(jar_filename)
        now = datetime.now()
        timestamp = now.strftime("%Y%m%d-%H%M%S")

        results_file_name = f"results-{jar_filename}-{timestamp}.txt"
        results_file_path = os.path.join(os.path.dirname(__file__), results_file_name)

        print(f"Results file will be created at: {results_file_path}")

        connection_output = run_script('connection_checker.py', jar_path, extra_args=['cfg.json'])
        obfuscation_output = run_script('obfuscation_checker.py', jar_path, extra_args=['cfg.json'])
        dll_output = run_script('dll_scanner.py', jar_path, extra_args=['cfg.json'])
        import_output = run_import_checker(jar_path)
        blacklisted_mods_output = run_blacklisted_mods_checker(jar_path)

        # Print outputs with improved formatting
        print_section("Connection Checker Output", connection_output)
        print_section("Obfuscation Checker Output", obfuscation_output)
        print_section("DLL Scanner Output", dll_output)
        print_section("Import Checker Output", import_output)
        print_section("Blacklisted Mods Checker Output", blacklisted_mods_output)

        # Mapping of imports/classes to explanations
        import_explanations = {
            'java.io.BufferedReader': 'Used to read text from an input stream; can read files or network streams, potentially leading to data exfiltration.',
            'java.io.InputStreamReader': 'Reads bytes and decodes them into characters; can be used to read input streams, possibly from malicious sources.',
            'java.io.Reader': 'Abstract class for reading character streams; may be used to read sensitive data.',
            'java.net.URL': 'Represents a URL; can be used to connect to external servers, potentially leaking data or downloading malicious content.',
            'java.net.URLConnection': 'Represents a communication link to a URL; can be used to send or receive data over the network.',
            'java.security.cert.X509Certificate': 'Represents an X.509 certificate; may be used in custom SSL contexts to intercept secure communications.',
            'javax.net.ssl.HostnameVerifier': 'Verifies hostnames during SSL/TLS handshake; overriding this can allow man-in-the-middle attacks.',
            'javax.net.ssl.HttpsURLConnection': 'Provides secure HTTPS connections; may be used to communicate with malicious servers over encrypted channels.',
            'javax.net.ssl.SSLContext': 'Represents an SSL/TLS protocol implementation; can be manipulated to trust malicious certificates.',
            'javax.net.ssl.SSLSession': 'Represents an SSL/TLS session; may be used to access session-specific data.',
            'javax.net.ssl.TrustManager': 'Manages trust material for making trust decisions; custom implementations may bypass certificate validation.',
            'javax.net.ssl.X509TrustManager': 'Manages X.509 certificates; can be used to accept all certificates, including invalid ones.',
            'java.lang.reflect.Method': 'Allows operations on methods via reflection; can be used to invoke methods dynamically, possibly executing malicious code.',
            'java.lang.reflect.Constructor': 'Allows creation of class instances via reflection; can instantiate arbitrary classes, potentially leading to code execution.',
            # Add more explanations as needed
        }

        # Analyze results
        results_passed = []
        results_failed = []
        is_malicious = False

        # Analyze Connection Checker Output
        if "Suspicious connections found" in connection_output:
            results_failed.append("Suspicious connections detected.")
            is_malicious = True
        else:
            results_passed.append("Connection check passed.")

        # Analyze Obfuscation Checker Output
        if "Obfuscated code detected" in obfuscation_output:
            results_failed.append("Obfuscated code detected.")
            # Extract detailed findings
            obfuscated_files = extract_obfuscation_findings(obfuscation_output)
            for file, findings in obfuscated_files.items():
                results_failed.append(f" - File: {file}")
                for finding in findings:
                    results_failed.append(f"   - {finding['finding']}")
                    for detail in finding['details']:
                        results_failed.append(f"     - {detail}")
            is_malicious = True
        else:
            results_passed.append("Obfuscation check passed.")

        # Analyze DLL Scanner Output
        if "DLL files detected" in dll_output:
            results_failed.append("Suspicious .dll files found.")
            is_malicious = True
        else:
            results_passed.append("No .dll files detected.")

        # Analyze Import Checker Output
        suspicious_items = extract_suspicious_imports(import_output)
        if suspicious_items:
            results_failed.append("Suspicious imports or class usages found in the code:")
            for imp in suspicious_items:
                explanation = import_explanations.get(imp, "No explanation available.")
                results_failed.append(f" - {imp}: {explanation}")
            is_malicious = True
        else:
            results_passed.append("Import check passed.")

        # Analyze Blacklisted Mods Output
        if "Blacklisted mods detected:" in blacklisted_mods_output:
            results_failed.append("This mod is identified as a known malicious mod. Remove it from your PC immediately.")
            is_malicious = True
        else:
            results_passed.append("Blacklisted mods check passed.")

        # Print Final Results Summary
        print_section("Final Results Summary", "")

        if results_failed:
            print("Failed Checks:")
            for result in results_failed:
                print(f" - {result}")
            print("\nWARNING: The mod may be malicious. Proceed with caution!")
        else:
            print("All checks passed. No issues detected.")

        print("\nPassed Checks:")
        for result in results_passed:
            print(f" - {result}")

        # Write results to file
        with open(results_file_path, "w") as f:
            f.write("=" * 60 + "\n")
            f.write("Connection Checker Output:\n")
            f.write("=" * 60 + "\n")
            f.write(connection_output + "\n")
            f.write("=" * 60 + "\n")
            f.write("Obfuscation Checker Output:\n")
            f.write("=" * 60 + "\n")
            f.write(obfuscation_output + "\n")
            f.write("=" * 60 + "\n")
            f.write("DLL Scanner Output:\n")
            f.write("=" * 60 + "\n")
            f.write(dll_output + "\n")
            f.write("=" * 60 + "\n")
            f.write("Import Checker Output:\n")
            f.write("=" * 60 + "\n")
            f.write(import_output + "\n")
            f.write("=" * 60 + "\n")
            f.write("Blacklisted Mods Checker Output:\n")
            f.write("=" * 60 + "\n")
            f.write(blacklisted_mods_output + "\n")
            f.write("\n")
            f.write("=" * 60 + "\n")
            f.write("Final Results Summary:\n")
            f.write("=" * 60 + "\n")

            if results_failed:
                f.write("Failed Checks:\n")
                for result in results_failed:
                    f.write(f" - {result}\n")
                f.write("\nWARNING: The mod may be malicious. Proceed with caution!\n")
            else:
                f.write("All checks passed. No issues detected.\n")

            f.write("\nPassed Checks:\n")
            for result in results_passed:
                f.write(f" - {result}\n")

        print(f"\nResults have been written to {results_file_path}.")
        print("The program will close in 3 seconds...")
        time.sleep(3)
    
    except Exception as e:
        print(f"An error occurred: {e}")
        time.sleep(3)

if __name__ == '__main__':
    main()
