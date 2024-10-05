# blacklisted_mods.py
import zipfile
import os
import sys
import re

# List of blacklisted mod identifiers and specific file names
BLACKLISTED_IDENTIFIERS = [
    "LISCENCE_TGSOG_RECODE",
    "LISCENCE TGSOG RECODE",
    "TGSOG",
    "recode",
    "Fabric Recode",
    "recode.mixins.json"  # Specific file
]

# List of specific file paths to monitor
BLACKLISTED_FILES = [
    "assets/recode/config.txt",
    "CREDITS.txt"
]

def scan_for_blacklisted_mods(jar_path):
    """
    Scans the .jar file for blacklisted mod identifiers in both file names and file contents,
    as well as the presence of specific blacklisted files.

    Args:
        jar_path (str): Path to the .jar file.

    Returns:
        dict: Dictionary containing detected blacklisted mods with their locations.
    """
    detected_blacklisted_mods = {}

    try:
        with zipfile.ZipFile(jar_path, 'r') as jar_file:
            # Iterate through all files in the .jar
            for file_info in jar_file.infolist():
                file_name = file_info.filename

                # Normalize the file path to use forward slashes
                normalized_file_name = file_name.replace("\\", "/")

                # Check for specific blacklisted files
                if normalized_file_name in BLACKLISTED_FILES:
                    if file_name not in detected_blacklisted_mods:
                        detected_blacklisted_mods[file_name] = []
                    detection_message = f"Presence of blacklisted file '{normalized_file_name}'"
                    detected_blacklisted_mods[file_name].append(detection_message)

                # Check if file name contains any blacklisted mod identifier (case-insensitive)
                for identifier in BLACKLISTED_IDENTIFIERS:
                    if re.search(re.escape(identifier), file_name, re.IGNORECASE):
                        if file_name not in detected_blacklisted_mods:
                            detected_blacklisted_mods[file_name] = []
                        detection_message = f"File name contains blacklisted identifier '{identifier}'"
                        detected_blacklisted_mods[file_name].append(detection_message)

                # Read file content for blacklisted identifiers
                with jar_file.open(file_info) as file:
                    try:
                        # Decode content as UTF-8; ignore errors for binary files
                        content = file.read().decode('utf-8', errors='ignore')
                        for identifier in BLACKLISTED_IDENTIFIERS:
                            if re.search(re.escape(identifier), content, re.IGNORECASE):
                                if file_name not in detected_blacklisted_mods:
                                    detected_blacklisted_mods[file_name] = []
                                detection_message = f"Content contains blacklisted identifier '{identifier}'"
                                detected_blacklisted_mods[file_name].append(detection_message)
                    except Exception as e:
                        # If the file is binary or cannot be decoded, skip content scanning
                        continue
    except zipfile.BadZipFile:
        print(f"The file {jar_path} is not a valid zip file.")
        return {}

    return detected_blacklisted_mods

def main():
    if len(sys.argv) < 2:
        print("Usage: python blacklisted_mods.py <jar_path>")
        return

    jar_path = sys.argv[1]

    if not os.path.exists(jar_path):
        print(f"The file at {jar_path} does not exist.")
        return

    detected = scan_for_blacklisted_mods(jar_path)

    if detected:
        print("Blacklisted mods detected:")
        for file, detections in detected.items():
            print(f"\nFile: {file}")
            for detection in detections:
                print(f" - {detection}")
        print("\nThis mod is guaranteed a rat, this mod has been verified as the TGOSG rat, more commonly known as the seymeow rat. Remove this off your PC ASAP.")
    else:
        print("No blacklisted mods detected.")

if __name__ == "__main__":
    main()
