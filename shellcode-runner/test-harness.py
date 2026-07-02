import os
import sys
import time
import json
import subprocess
import argparse
from datetime import datetime

def log_telemetry(log_file, dst_dir, dst_filename, parameters, exit_code, file_deleted):
    """Records test execution metrics to a log file."""
    log_entry = {
        "timestamp": datetime.now().isoformat(),
        "dstDir": dst_dir,
        "dstFilename": dst_filename,
        "parameters": parameters,
        "exit_code": exit_code,
        "file_still_present_after_run": file_deleted
    }
    try:
        with open(log_file, "a") as f:
            f.write(json.dumps(log_entry) + "\n")
    except Exception as e:
        print(f"[-] Error writing to log file: {e}", file=sys.stderr)

def process_test_case(test_case, log_file):
    """Executes the life cycle of a single test case scenario."""
    src_filename = test_case.get("src_filename")
    src_dir = test_case.get("src_dir")
    dst_filename = test_case.get("dst_filename")
    dst_dir = test_case.get("dst_dir")
    parameters = test_case.get("parameters", "")

    if not all([src_filename, src_dir, dst_filename, dst_dir]):
        print(f"[-] Skipping invalid test case configuration: {test_case}", file=sys.stderr)
        return

    src_path = os.path.join(src_dir, src_filename)
    dst_path = os.path.join(dst_dir, dst_filename)

    # 1. File Copy Phase (with overwrite prompt)
    if not os.path.exists(src_path):
        print(f"[-] Source file does not exist: {src_path}")
        return

    if os.path.exists(dst_path):
        response = input(f"[?] Target file '{dst_path}' already exists. Overwrite? (y/n): ").strip().lower()
        if response != 'y':
            print(f"[*] Skipping test case for {dst_filename} due to user skip.")
            return

    try:
        os.makedirs(dst_dir, exist_ok=True)
        # Reading/writing binary to handle any executable file type cleanly without external dependencies
        with open(src_path, 'rb') as src_f, open(dst_path, 'wb') as dst_f:
            dst_f.write(src_f.read())
        print(f"[+] Successfully copied {src_filename} to {dst_path}")
    except Exception as e:
        print(f"[-] Failed to copy file: {e}", file=sys.stderr)
        return

    # 2 & 3. Execution & Monitoring Phase
    exit_code = None
    print(f"[*] Executing: {dst_path} with arguments: {parameters}")
    
    # Split parameters string safely for subprocess window execution compatibility
    cmd = [dst_path] + (parameters.split() if parameters else [])
    
    try:
        # Launching the process asynchronously
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        
        # Monitor for up to 5 minutes (300 seconds)
        timeout = 300 
        start_time = time.time()
        
        while time.time() - start_time < timeout:
            exit_code = proc.poll()
            if exit_code is not None:
                print(f"[+] Process terminated early with exit code: {exit_code}")
                break
            time.sleep(1) # Poll every second
        
        # If still running after 5 minutes, kill it
        if exit_code is None:
            print(f"[!] Process exceeded timeout window. Terminating process...")
            proc.kill()
            proc.wait() # Ensure process cleanup is complete
            exit_code = "KILLED_TIMEOUT"

    except Exception as e:
        print(f"[-] Execution error: {e}", file=sys.stderr)
        exit_code = f"ERROR: {str(e)}"

    # 4. Cleanup Phase
    file_still_present = os.path.exists(dst_path)
    if file_still_present:
        try:
            os.remove(dst_path)
            print(f"[+] Successfully deleted destination file: {dst_path}")            
        except Exception as e:
            print(f"[!] Failed to delete destination file {dst_path}: {e}", file=sys.stderr)

    # 5. Telemetry Phase
    log_telemetry(log_file, dst_dir, dst_filename, parameters, exit_code, file_still_present)
    print(f"[+] Telemetry captured for {dst_filename}.\n" + "-"*50)

def main():
    parser = argparse.ArgumentParser(description="QA Automation Test Harness")
    parser.add_argument("-i", "--input", required=True, help="Path to the JSON configuration file containing test data.")
    parser.add_argument("-l", "--log", default="qa_test_harness.log", help="Path to output telemetry log file.")
    args = parser.parse_args()

    if not os.path.exists(args.input):
        print(f"[-] Input file '{args.input}' not found.", file=sys.stderr)
        sys.exit(1)

    try:
        with open(args.input, 'r') as f:
            data = json.load(f)
    except json.JSONDecodeError as e:
        print(f"[-] Invalid JSON format in input file: {e}", file=sys.stderr)
        sys.exit(1)

    # Accept both a single JSON object or a list of JSON objects
    test_cases = data if isinstance(data, list) else [data]

    print(f"[*] Starting test suite processing. Total cases found: {len(test_cases)}\n" + "="*50)
    for test_case in test_cases:
        process_test_case(test_case, args.log)
    print("[*] Test suite execution complete.")

if __name__ == "__main__":
    main()