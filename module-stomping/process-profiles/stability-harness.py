import json
import subprocess
import time
import os

def is_module_loaded(pid, module_name):
    """Checks if a specific DLL is loaded by the target PID via tasklist."""
    try:
        cmd = ["tasklist", "/FI", f"PID eq {pid}", "/M", module_name]
        result = subprocess.run(cmd, capture_output=True, text=True, creationflags=subprocess.CREATE_NO_WINDOW)
        return module_name.lower() in result.stdout.lower()
    except Exception:
        return False

def run_configured_test(config_path):
    if not os.path.exists(config_path):
        print(f"[-] Configuration file not found: {config_path}")
        return

    # 1. Parse configuration parameters safely
    try:
        with open(config_path, "r", encoding="utf-8") as f:
            config = json.load(f)
            
        target = config["target_executable"]
        trigger_dll = config["trigger_dll"]
        tool = config["secondary_tool"]
        tool_args = config.get("tool_arguments", [])
        timeout_sec = config.get("timeout_seconds", 60)
    except Exception as e:
        print(f"[-] Failed to parse JSON configuration: {e}")
        return

    print(f"[*] Loaded profile for: {os.path.basename(target)}")
    
    # 2. Start the primary process
    process = subprocess.Popen([target])
    pid = process.pid
    print(f"[+] Started primary process {pid} normally.")

    # 3. Poll until the dependency module settles
    print(f"[*] Waiting for {trigger_dll} to stabilize in memory...")
    start_time = time.time()
    module_found = False
    
    while time.time() - start_time < 10:  # 10s initialization boundary
        if is_module_loaded(pid, trigger_dll):
            module_found = True
            print(f"[+] Verified {trigger_dll} mapping established.")
            break
        time.sleep(0.2)
        
        if process.poll() is not None:
            print("[-] Primary process terminated during initialization.")
            return

    if not module_found:
        print(f"[-] Warning: {trigger_dll} not explicitly verified. Proceeding...")

    # 4. Resolve arguments and launch secondary tool
    cmd_line = [tool] + [arg.replace("{pid}", str(pid)) if isinstance(arg, str) else str(arg) for arg in tool_args]
    print(f"[+] Launching companion process: {' '.join(cmd_line)}")
    secondary_process = subprocess.Popen(cmd_line)

    # 5. Monitor execution life cycle up to the timeout threshold
    print(f"[*] Monitoring execution stability window ({timeout_sec}s)...")
    try:
        exit_code = process.wait(timeout=timeout_sec)
        
        # Interpret termination exit codes
        STATUS_ACCESS_VIOLATION = -1073741819      # 0xC0000005
        STATUS_INVALID_CRUNTIME = -1073740777      # 0xC0000417
        STATUS_INVALID_CRUNTIME_ALT = 3221225622
        
        if exit_code in [STATUS_ACCESS_VIOLATION, 0xC0000005]:
            print("[!] Stability Fault: Process crashed due to an Access Violation (0xC0000005).")
        elif exit_code in [STATUS_INVALID_CRUNTIME, STATUS_INVALID_CRUNTIME_ALT]:
            print("[!] Stability Fault: Process forced closure via Invalid CRT Parameter (0xC0000417).")
        elif exit_code != 0:
            print(f"[!] Process stopped prematurely with exit code: {exit_code}")
        else:
            print(f"[+] Process completed run cleanly with exit code: {exit_code}")

    except subprocess.TimeoutExpired:
        print(f"[+] Stability Window Met: Process handled workload successfully for {timeout_sec}s.")
    except KeyboardInterrupt:
        print("[-] Execution stopped by user.")
    finally:
        print("[+] Performing environmental cleanup...")
        if process.poll() is None:
            process.kill()
            process.wait()
        if secondary_process.poll() is None:
            try:
                secondary_process.kill()
                secondary_process.wait()
            except OSError:
                pass

if __name__ == "__main__":
    CONFIG_FILE = "stability-harness-config.json"
    run_configured_test(CONFIG_FILE)