import os
import subprocess
from datetime import datetime
import time

def run_script(script_name, jar_path):
    # Get the current directory
    current_dir = os.path.dirname(os.path.abspath(__file__))
    
    # Path to the logic folder
    logic_folder = os.path.join(current_dir, 'logic')
    
    # Path to the script in the logic folder
    script_path = os.path.join(logic_folder, script_name)

    if os.path.exists(script_path):
        print(f"Running {script_path}...")
        # Run the script using subprocess and capture the output
        result = subprocess.run(['python', script_path, jar_path], capture_output=True, text=True)
        return result.stdout  # Return the output of the script
    else:
        print(f"{script_path} does not exist.")
        return ""

def sanitize_filename(filename):
    # Replace or remove characters that are not allowed in filenames
    return "".join(char if char.isalnum() or char in (' ', '-') else '_' for char in filename)

def main():
    # Get the JAR file path
    jar_path = input("Please enter the path to the .jar file: ").strip('"')

    # Check if the file exists
    if not os.path.exists(jar_path):
        print(f"The file at {jar_path} does not exist. Please check the path and try again.")
        return

    try:
        # Get the file name without extension
        jar_filename = os.path.splitext(os.path.basename(jar_path))[0]

        # Sanitize the jar_filename to avoid issues with special characters
        jar_filename = sanitize_filename(jar_filename)

        # Get the current date and time for the results file name
        now = datetime.now()
        timestamp = now.strftime("%Y%m%d-%H%M%S")

        # Create the results file name
        results_file_name = f"results-{jar_filename}-{timestamp}.txt"
        results_file_path = os.path.join(os.path.dirname(__file__), results_file_name)

        # Debugging: Print the results file path
        print(f"Results file will be created at: {results_file_path}")

        connection_output = run_script('connection_checker.py', jar_path)
        obfuscation_output = run_script('obfuscation_checker.py', jar_path)

        # Print the output for debugging
        print("\nConnection Checker Output:")
        print(connection_output)
        
        print("\nObfuscation Checker Output:")
        print(obfuscation_output)

        # Results and explanations for the report
        results = []
        if "Suspicious connections found" in connection_output:
            results.append("This file is a rat due to suspicious connections.")
            
            # Parse connection type details
            for line in connection_output.splitlines():
                if "HTTPS" in line:
                    results.append(" - Detected an HTTPS connection.")
                elif "Discord Webhook" in line:
                    results.append(" - Detected a Discord webhook connection.")
                elif "Bot Token" in line:
                    results.append(" - Detected a bot token.")
                elif "API" in line:
                    results.append(" - Detected an API connection.")
        elif "No suspicious connections or Discord-related content found." in connection_output:
            results.append("Connection check passed.")

        # Check for flags in obfuscation_checker output
        if "Obfuscated code detected" in obfuscation_output:
            results.append("It is likely this mod is a rat due to obfuscation.")
            
            # Parse obfuscation level details
            for line in obfuscation_output.splitlines():
                if "Highly Obfuscated" in line:
                    results.append(" - Detected highly obfuscated code.")
                elif "Partially Obfuscated" in line:
                    results.append(" - Detected partially obfuscated code.")
        elif "No obfuscated code detected." in obfuscation_output:
            results.append("Obfuscation check passed.")
        
        # Write all outputs to the results file
        with open(results_file_path, "w") as f:
            f.write("Connection Checker Output:\n")
            f.write(connection_output + "\n")
            f.write("Obfuscation Checker Output:\n")
            f.write(obfuscation_output + "\n")
            f.write("\nFinal Results:\n")
            for result in results:
                f.write(result + "\n")

        # Also output the results in the terminal
        print(f"\nResults Summary:")
        for result in results:
            print(result)

        print(f"\nResults have been written to {results_file_path}.")

        # Wait for 3 seconds before closing
        print("The program will close in 3 seconds...")
        time.sleep(3)
    
    except Exception as e:
        print(f"An error occurred: {e}")
        time.sleep(3)  # Wait for 3 seconds before closing on error

if __name__ == '__main__':
    main()

