# runner_ip2traceroute

This script remotely executes the `traceroute` command on a target host via SSH after deobfuscating and extracting an SSH key.

## Prerequisites

1.  **SSH Client:** The `ssh` command must be available in your system's PATH.
2.  **7zip:** The `7z` command must be available in your system's PATH.
3.  **Obfuscated Archive:** An obfuscated file named `003.bin` must exist in the script's directory. This file contains the password-protected 7zip archive.
4.  **SSH Key File:** The `003.bin` file, when deobfuscated and extracted, must contain an SSH private key file named `001.bin`.
5.  **Environment Variables:**
    *   `REMOTE_HOST`: The hostname or IP address of the remote server to SSH into.
    *   `XOR_STR`: The hexadecimal XOR key (e.g., `a1`) used to deobfuscate `003.bin`.
    *   `ZIP_P`: The password required to extract the 7zip archive contained within the deobfuscated `003.bin`.

## Usage

```bash
python app.py [-v] <ip_address>
```

*   `<ip_address>`: The target IP address to `traceroute` *from* the `REMOTE_HOST`.
*   `-v` or `--verbose`: (Optional) Enable verbose output, showing informational messages about the process.

## Workflow

1.  **Initialization:** The script checks for `ssh` and `7z` executables and validates required environment variables.
2.  **Deobfuscation:** Reads `003.bin`, deobfuscates its content using the `XOR_STR` key.
3.  **Extraction:**
    *   Creates a temporary directory.
    *   Writes the deobfuscated data (assumed to be a 7zip archive) to the temporary directory.
    *   Extracts the archive using the `ZIP_P` password.
    *   Verifies the presence of the SSH key file (`001.bin`) in the extracted contents and sets its permissions to `400`.
4.  **Remote Execution:**
    *   Constructs an `ssh` command to connect to `REMOTE_USER@REMOTE_HOST` (default `REMOTE_USER` is `root`) using the extracted `001.bin` key.
    *   Disables strict host key checking (`StrictHostKeyChecking=no`) and uses `/dev/null` for known hosts (`UserKnownHostsFile=/dev/null`).
    *   Remotely executes `traceroute -n -q 5 <ip_address>` on the `REMOTE_HOST` (using the path `/usr/sbin/traceroute`).
5.  **Output:** Prints the standard output and standard error from the remote `traceroute` command executed via SSH. It filters out common SSH connection messages from stderr for clarity.
6.  **Cleanup:** Removes the temporary directory and its contents.
7.  **Exit Code:** Exits with the return code of the remote `ssh` command (which reflects the success/failure of the remote `traceroute`).

## Error Handling

The script includes error handling for:
*   Missing `ssh` or `7z` commands.
*   Missing or invalid environment variables.
*   Missing `003.bin` file or errors during reading/deobfuscation.
*   Errors during 7zip extraction (e.g., wrong password).
*   Missing `001.bin` key file after extraction.
*   Errors setting permissions on the key file.
*   SSH command failures or timeouts.