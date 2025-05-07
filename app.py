import argparse
# import socket # Removed unused import
import sys
import shutil # Add shutil import
import subprocess # Add subprocess import
import os # Add os import
import tempfile # Add tempfile import
import datetime # Add datetime import

### --- ### --- ### --- ### --- ### --- ### --- ### --- ### --- ### --- ### --- ### --- ###

# --- SSH Configuration ---
DB_FILE = "003.bin" # This is the obfuscated 7zip file
REMOTE_USER = "root"
REMOTE_HOST = os.environ.get("REMOTE_HOST")
REMOTE_PING_PATH = "/usr/sbin/traceroute" # Assuming ping is at /sbin/ping on the remote host
# --- Deobfuscation and Extraction Config ---
XOR_STR = os.environ.get("XOR_STR") # Read as string first
ZIP_P = os.environ.get("ZIP_P")
KEY_FILENAME_IN_ARCHIVE = "001.bin" # The expected name of the key file inside the 7z archive

# --- End Configuration ---

def deobfuscate_data(data, key):
    """Deobfuscates byte data using XOR."""
    return bytes([b ^ key for b in data])

def main():
    parser = argparse.ArgumentParser(description=f"Ping an IP Address via SSH to {REMOTE_HOST} using the system 'ping' command.") # Updated description
    # Use a positional argument for the IP address
    parser.add_argument('ip_address', help='IP Address to Ping') # Updated help text
    # Add a verbose flag
    parser.add_argument(
        '-v', '--verbose',
        action='store_true',
        help='Enable verbose output (show [*] informational messages)'
    )
    args = parser.parse_args()

    ip_address = args.ip_address

    # Basic IP format validation (optional but recommended)
    # Add more robust validation if needed (e.g., using ipaddress module)
    if '.' not in ip_address and ':' not in ip_address:
         print(f"[!] Error: '{ip_address}' does not look like a valid IPv4 or IPv6 address.", file=sys.stderr)
         return 1

    # Check if the 'ssh' and '7z' commands are available
    ssh_path = shutil.which("ssh")
    seven_zip_path = shutil.which("7z") # Check for 7z

    if not ssh_path:
        print("[!] Error: 'ssh' command not found in system PATH.", file=sys.stderr)
        return 1
    if not seven_zip_path:
        print("[!] Error: '7z' command not found in system PATH.", file=sys.stderr)
        return 1

    if args.verbose:
        print(f"[*] Found 'ssh' executable at: {ssh_path}")
        print(f"[*] Found '7z' executable at: {seven_zip_path}")

    # --- Validate Environment Variables ---
    if not XOR_STR:
        print("[!] Error: Environment variable 'DATADB' (XOR key) is not set.", file=sys.stderr)
        return 1
    if not ZIP_P:
        print("[!] Error: Environment variable 'DATABIN' (ZIP p) is not set.", file=sys.stderr)
        return 1

    try:
        XOR_KEY = int(XOR_STR, 16) # Convert hex string to int
    except (ValueError, TypeError):
        print(f"[!] Error: Invalid hexadecimal value '{XOR_STR}' for DATADB environment variable.", file=sys.stderr)
        return 1
    # --- End Validate Environment Variables ---

    temp_dir = None # Initialize temp_dir to None
    extracted_key_path = None

    try:
        # --- Deobfuscate and Extract Key ---
        if args.verbose:
            print(f"[*] Reading obfuscated file: {DB_FILE}")
        try:
            with open(DB_FILE, 'rb') as f:
                obfuscated_data = f.read()
        except FileNotFoundError:
            print(f"[!] Error: Obfuscated file '{DB_FILE}' not found.", file=sys.stderr)
            return 1
        except Exception as e:
            print(f"[!] Error reading obfuscated file '{DB_FILE}': {e}", file=sys.stderr)
            return 1

        if args.verbose:
            print(f"[*] Deobfuscating data using XOR key 0x{XOR_KEY:X}") # Now XOR_KEY is an int, :X works
        deobfuscated_data = deobfuscate_data(obfuscated_data, XOR_KEY)

        # Create a secure temporary directory
        temp_dir = tempfile.mkdtemp(prefix="keyextract_")
        if args.verbose:
            print(f"[*] Created temporary directory: {temp_dir}")

        # Write the deobfuscated 7zip file to the temporary directory
        deobfuscated_db_path = os.path.join(temp_dir, "data.db")
        if args.verbose:
            print(f"[*] Writing deobfuscated 7zip archive to: {deobfuscated_db_path}")
        with open(deobfuscated_db_path, 'wb') as f:
            f.write(deobfuscated_data)

        # Extract the 7zip file
        if args.verbose:
            print(f"[*] Extracting '{deobfuscated_db_path}' using p...")
        extract_command = [
            seven_zip_path,
            "x", # Extract command
            f"-p{ZIP_P}", # Set p
            f"-o{temp_dir}", # Set output directory
            deobfuscated_db_path, # Input archive
            "-y" # Assume Yes on all queries (overwrite, etc.)
        ]
        extract_process = subprocess.run(
            extract_command,
            capture_output=True,
            text=True,
            check=False,
            timeout=30
        )

        if extract_process.returncode != 0:
            print(f"[!] Error extracting 7zip file:", file=sys.stderr)
            if extract_process.stdout: print(f"  [7z Stdout]:\\n{extract_process.stdout.strip()}", file=sys.stderr)
            if extract_process.stderr:
                # Filter out the known "Warning: Permanently added ..." message for cleaner output
                stderr_lines = [line for line in extract_process.stderr.strip().splitlines()
                                if "Warning: Permanently added" not in line]
                if stderr_lines:
                    print("[Stderr]")
                    print("\\n".join(stderr_lines))
            if extract_process.returncode != 0:
                print(f"[!] SSH command exited with code: {extract_process.returncode}") # Updated message
            print("-" * 48) # Reformatted separator line
            # Return the exit code of the SSH command itself
            return extract_process.returncode

        if args.verbose:
            print(f"[*] Successfully extracted archive.")
        # print(f"  [7z Stdout]:\\n{extract_process.stdout.strip()}") # Optional: show 7z stdout on success


        extracted_key_path = os.path.join(temp_dir, KEY_FILENAME_IN_ARCHIVE)
        if not os.path.exists(extracted_key_path):
             print(f"[!] Error: Expected key file '{KEY_FILENAME_IN_ARCHIVE}' not found in extracted archive at '{temp_dir}'.", file=sys.stderr)
             # Optional: List files in temp_dir for debugging
             try:
                 files_in_temp = os.listdir(temp_dir)
                 print(f"[*] Files found in temp dir: {files_in_temp}")
             except Exception as list_e:
                 print(f"[!] Could not list files in temp dir: {list_e}")
             return 1

        if args.verbose:
            print(f"[*] Found extracted key file: {extracted_key_path}")

        # Set permissions for the extracted key file
        try:
            if args.verbose:
                print(f"[*] Setting permissions for extracted key file: {extracted_key_path}")
            os.chmod(extracted_key_path, 0o400) # Set permissions to 400
        except Exception as e:
            print(f"[!] Error setting permissions for extracted key file '{extracted_key_path}': {e}", file=sys.stderr)
            return 1
        # --- End Deobfuscate and Extract Key ---

        # --- Execute the remote 'ping' command via SSH ---
        if args.verbose:
            print(f"[*] Running remote 'ping' command for {ip_address} via SSH to {REMOTE_USER}@{REMOTE_HOST} using extracted key...")
        try:
            # Construct the SSH command using the extracted key
            ssh_command = [
                ssh_path,
                "-i", extracted_key_path, # Use the extracted key file path
                # Add SSH options to avoid host key checking and use batch mode
                "-o", "StrictHostKeyChecking=no",
                "-o", "UserKnownHostsFile=/dev/null",
                "-o", "BatchMode=yes",
                f"{REMOTE_USER}@{REMOTE_HOST}",
                REMOTE_PING_PATH, # Use the configured remote ping path
                "-n", 
                "-q", "5",
                "-I",
                ip_address
            ]
            if args.verbose:
                print(f"[*] Executing: {' '.join(ssh_command)}") # Show the command being run
            process = subprocess.run(
                ssh_command, # Use the constructed SSH command
                capture_output=True,
                text=True,
                check=False, # Don't raise exception on non-zero exit code
                timeout=60 # Increase timeout for SSH connection + ping (e.g., 60 seconds)
            )
            print(f"--- Remote PING Output via SSH ({REMOTE_HOST}) ---") # Updated output marker
            if process.stdout:
                print("[Stdout]")
                print(process.stdout.strip())
            if process.stderr:
                # Filter out the known "Warning: Permanently added ..." message for cleaner output
                stderr_lines = [line for line in process.stderr.strip().splitlines()
                                if "Warning: Permanently added" not in line]
                if stderr_lines:
                    print("[Stderr]")
                    print("\\n".join(stderr_lines))
            if process.returncode != 0:
                print(f"[!] SSH command exited with code: {process.returncode}") # Updated message
            print("-" * 48) # Reformatted separator line
            # Return the exit code of the SSH command itself
            return process.returncode

        except subprocess.TimeoutExpired:
             print(f"[!] Error: SSH command timed out trying to ping {ip_address} on {REMOTE_HOST}", file=sys.stderr) # Updated message
             return 1 # Indicate failure
        except Exception as e:
             print(f"[!] Error running SSH command: {e}", file=sys.stderr) # Updated message
             return 1 # Indicate failure
        # --- End Execute the remote 'ping' command via SSH ---

    finally:
        # --- Cleanup ---
        if temp_dir and os.path.exists(temp_dir):
            if args.verbose:
                print(f"[*] Cleaning up temporary directory: {temp_dir}")
            try:
                shutil.rmtree(temp_dir)
                if args.verbose:
                    print("[*] Temporary directory removed.")
            except Exception as e:
                print(f"[!] Warning: Failed to remove temporary directory '{temp_dir}': {e}", file=sys.stderr)
        # --- End Cleanup ---


### --- ### --- ### --- ### --- ### --- ### --- ### --- ### --- ### --- ### --- ### --- ###

if __name__ == "__main__":
    # Use sys.exit() to ensure the exit code is propagated correctly
    sys.exit(main())