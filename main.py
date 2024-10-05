# main.py
import os
import subprocess
from datetime import datetime
import time

def run_script(script_name, jar_path, extra_args=None):
    current_dir = os.path.dirname(os.path.abspath(__file__))
    logic_folder = os.path.join(current_dir, 'logic')
    script_path = os.path.join(logic_folder, script_name)

    if os.path.exists(script_path):
        print(f"Running {script_path}...")
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
        print(f"Running {script_path}...")
        result = subprocess.run(['python', script_path, jar_path, cfr_jar_path, 'cfg.json'], capture_output=True, text=True)
        return result.stdout
    else:
        print(f"{script_path} does not exist.")
        return ""

def run_blacklisted_mods_checker(jar_path):
    logic_folder = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'logic')
    script_path = os.path.join(logic_folder, 'blacklisted_mods.py')

    if os.path.exists(script_path):
        print(f"Running {script_path}...")
        result = subprocess.run(['python', script_path, jar_path], capture_output=True, text=True)
        return result.stdout
    else:
        print(f"{script_path} does not exist.")
        return ""

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

        print("\nConnection Checker Output:")
        print(connection_output)
        
        print("\nObfuscation Checker Output:")
        print(obfuscation_output)

        print("\nDLL Scanner Output:")
        print(dll_output)

        print("\nImport Checker Output:")
        print(import_output)
        
        print("\nBlacklisted Mods Checker Output:")
        print(blacklisted_mods_output)

        results = []
        # Analyze Connection Checker Output
        if "Suspicious connections found" in connection_output:
            results.append("This file is a rat due to suspicious connections.")
        else:
            results.append("Connection check passed.")

        # Analyze Obfuscation Checker Output
        if "Obfuscated code detected" in obfuscation_output:
            results.append("It is likely this mod is a rat due to obfuscation.")
        else:
            results.append("Obfuscation check passed.")

        # Analyze DLL Scanner Output
        if "DLL files detected" in dll_output:
            results.append("Suspicious .dll files found.")
        else:
            results.append("No .dll files detected.")

        # Analyze Import Checker Output
        if "Suspicious imports detected" in import_output:
            results.append("Suspicious imports found in the code.")
        else:
            results.append("Import check passed.")

        # Analyze Blacklisted Mods Output
        if "Blacklisted mods detected:" in blacklisted_mods_output:
            results.append("This mod is guaranteed a rat, this mod has been verified as the TGOSG rat, more commonly known as the seymeow rat. Remove this off your PC ASAP.")
        else:
            results.append("Blacklisted mods check passed.")

        with open(results_file_path, "w") as f:
            f.write("Connection Checker Output:\n")
            f.write(connection_output + "\n")
            f.write("Obfuscation Checker Output:\n")
            f.write(obfuscation_output + "\n")
            f.write("DLL Scanner Output:\n")
            f.write(dll_output + "\n")
            f.write("Import Checker Output:\n")
            f.write(import_output + "\n")
            f.write("Blacklisted Mods Checker Output:\n")
            f.write(blacklisted_mods_output + "\n")
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
