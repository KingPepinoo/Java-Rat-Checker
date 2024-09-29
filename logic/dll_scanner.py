import zipfile
import os
import sys

def scan_jar_for_dll(jar_path):
    """
    Scans the .jar file for any files with a .dll extension, except for .class files.
    """
    dll_files = []

    # Open the .jar file
    with zipfile.ZipFile(jar_path, 'r') as jar_file:
        # Iterate through all the files in the .jar
        for file_info in jar_file.infolist():
            file_name = file_info.filename
            
            # Skip .class files, and only look for .dll files
            if not file_name.endswith('.class') and file_name.endswith('.dll'):
                dll_files.append(file_name)

    return dll_files

def main():
    if len(sys.argv) < 2:
        print("Usage: python dll_scanner.py <path_to_jar>")
        return

    jar_path = sys.argv[1]

    if os.path.exists(jar_path):
        dll_files = scan_jar_for_dll(jar_path)
        
        if dll_files:
            print("DLL files detected in the following paths:")
            for dll_file in dll_files:
                print(f" - {dll_file}")
        else:
            print("No .dll files detected.")
    else:
        print(f"File at {jar_path} does not exist.")

if __name__ == "__main__":
    main()
