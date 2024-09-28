# Minecraft Mod Scanner
# Overview
This is an open source tool. This tool is designed to scan Minecraft mods for high obfuscation and suspicious connections, such as HTTPS and API calls. It is currently in Beta and may contain bugs or impurities. Users are encouraged to report any issues or suggestions for improvements.

# Requirements
- Python: Version 3.12 or higher is required. You can download Python from the Microsoft Store.

# Running the Tool
- You can run the scanner by right-clicking the script and selecting Open with Python. The script will prompt you to enter the path to the .jar file you want to scan.


# Issues and Support
If you encounter any issues or have requests, please join our community on Discord at https://discord.gg/weezers and report your findings.

# How it works
**Connection Checker** (connection_checker.py)
- Extracts the .class files from the provided .jar.
- Scans through the file contents to detect:
  - URLs with the pattern https://
  - Discord-related connections (e.g., discordapp.com, discord.gg, webhooks)
  - Suspicious API calls or bot tokens
- Flags any lines of code that contain these patterns.
**Obfuscation Checker** (obfuscation_checker.py)
- Extracts .class files from the .jar.
- Analyzes the bytecode for:
  - Non-ASCII characters in class, method, or variable names (a common sign of obfuscation).
  - Randomized byte patterns that are typical of obfuscated code.
  - Low diversity of unique bytes, which is often used in compression or encryption-based obfuscation.
- Classifies files as "Highly Obfuscated" or "Partially Obfuscated."
# 
# Keep in mind
- **No suspicious connections or obfuscation detected:** Not all mods that use obfuscation are malicious. If nothing is flagged, the mod might be safe, but it’s always good to double-check the source of your mods.
- **Invalid characters in results file:** The scanner skips over non-UTF-8 encoded files to avoid crashes, but certain files may still contain unrecognized characters.
# 
# Example Output in Results File
Connection Checker Output:
Suspicious connections found in the following files:

File: C:\path\to\temp\com\example\ExampleMod.class
  Line 259 (API): net/fabricmc/api/ModInitializer

Obfuscation Checker Output:
Obfuscated code detected in the following files:
 - C:\path\to\temp\com\example\ExampleMod.class (Highly Obfuscated)

Final Results:
This file is a rat due to suspicious connections.
 - Detected an API connection.
It is likely this mod is a rat due to obfuscation.
 - Detected highly obfuscated code.
