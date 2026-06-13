import os
import sys
import time
import json
import subprocess
import argparse

def is_module_loaded(pid, module_name):
    """Verifies if the designated DLL dependency has settled in target space."""
    try:
        cmd = ["tasklist", "/FI", f"PID eq {pid}", "/M", module_name]
        result = subprocess.run(cmd, capture_output=True, text=True, creationflags=subprocess.CREATE_NO_WINDOW)
        return module_name.lower() in result.stdout.lower()
    except Exception:
        return False

def log_test_metric(log_manifest_path, iteration, target, module, status, exit_code, duration):
    """Commits test-case analytical records to a raw JSONL log manifest."""
    entry = {
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "iteration": iteration,
        "target_binary": os.path.basename(target),
        "evaluated_module": module,
        "status": status,
        "kernel_exit_code": hex(exit_code) if isinstance(exit_code, int) else exit_code,
        "execution_duration_sec": round(duration, 2)
    }
    with open(log_manifest_path, "a", encoding="utf-8") as f:
        f.write(json.dumps(entry) + "\n")
        f.flush()

def run_parametric_campaign(config_path, log_manifest_path):
    if not os.path.exists(config_path):
        print(f"[-] Error: Configuration file not found at {config_path}")
        return

    try:
        with open(config_path, "r", encoding="utf-8") as f:
            profiles = json.load(f)
            
        # If the JSON file is just a single object configuration instead of a list, wrap it in a list
        if isinstance(profiles, dict):
            profiles = [profiles]
            
    except Exception as e:
        print(f"[-] Failed to read JSON configuration: {e}")
        return

    print(f"[*] Initializing Process Stability Campaign with {len(profiles)} profiles.")
    print("=" * 80)

    for idx, profile in enumerate(profiles, start=1):
        # Defensive Check: Ensure the item is actually a dictionary structure
        if not isinstance(profile, dict):
            print(f"[-] Skipping entry #{idx}: Expected a JSON object/dictionary but got {type(profile).__name__}.")
            continue

        target = profile.get("target_executable")
        trigger_dll = profile.get("trigger_dll")
        tool = profile.get("secondary_tool")
        tool_args = profile.get("tool_arguments", [])
        timeout_sec = profile.get("timeout_seconds", 60)

        # Ensure required configuration parameters are present before spinning up processes
        if not target or not trigger_dll:
            print(f"[-] Skipping entry #{idx}: Missing 'target_executable' or 'trigger_dll'.")
            continue

        print(f"[-] Executing Profile {idx}/{len(profiles)}: {os.path.basename(target)}")
        
        # Environmental Sanity Check: Ensure no hanging instances remain
        binary_name = os.path.basename(target)
        subprocess.run(f"taskkill /f /im {binary_name} >nul 2>&1", shell=True)
        time.sleep(0.5)

        # If the target is Word, remove the Resiliency key so it forgets past crashes
        if "winword.exe" == binary_name.lower():
            # Force delete the key (and all subkeys) quietly
            subprocess.run(r'reg delete "HKCU\Software\Microsoft\Office\16.0\Word\Resiliency" /f >nul 2>&1', shell=True)
            # Pre-emptively enforce the bypass switch just in case
            subprocess.run(r'reg add "HKCU\Software\Microsoft\Office\16.0\Word\Resiliency" /v "DoNotShowSafeModeLauncher" /t REG_DWORD /d 1 /f >nul 2>&1', shell=True)

            # Note: The path 16.0 in the registry string covers Office 2016, 2019, 2021, and Microsoft 365. 
            # If you happen to be testing older legacy environments, you'll just need to adjust that number (15.0 for Office 2013, 14.0 for Office 2010).

        time.sleep(0.5)

        start_time = time.time()
        process = None

        start_time = time.time()
        process = None
        secondary_process = None

        try:
            # 1. Spawn main application process
            process = subprocess.Popen([target])
            pid = process.pid
            print(f"    [+] Spawned target process host with PID: {pid}")

            # 2. Wait for dependency structure validation
            module_found = False
            init_timeout = 10
            init_start = time.time()
            
            while time.time() - init_start < init_timeout:
                if is_module_loaded(pid, trigger_dll):
                    module_found = True
                    break
                time.sleep(0.2)
                if process.poll() is not None:
                    break

            if not module_found:
                print(f"    [!] Warning: Dependency {trigger_dll} not verified in memory context.")

            # give the process a little time to initialize
            time.sleep(10)

            # 3. Resolve arguments and link secondary utility tool
            if tool:
                cmd_line = [tool] + [arg.replace("{pid}", str(pid)) if isinstance(arg, str) else str(arg) for arg in tool_args]
                print(f"    [+] Executing companion tool: {' '.join(cmd_line)}")
                secondary_process = subprocess.Popen(cmd_line)
            else:
                print("    [*] No secondary companion tool specified for this profile.")

            # 4. Monitor performance across the defined timeout boundary
            print(f"    [*] Monitoring stability layout for {timeout_sec}s maximum...")
            exit_code = process.wait(timeout=timeout_sec)
            
            # Process terminated early; interpret exit code
            duration = time.time() - start_time
            
            # Map standard exception codes
            STATUS_ACCESS_VIOLATION = -1073741819      # 0xC0000005
            STATUS_INVALID_CRUNTIME = -1073740777      # 0xC0000417
            STATUS_INVALID_CRUNTIME_ALT = 3221225622
            
            if exit_code in [STATUS_ACCESS_VIOLATION, 0xC0000005]:
                status_str = "TERMINATED_ACCESS_VIOLATION"
                print("    [!] Result: Access Violation Fault Detected.")
            elif exit_code in [STATUS_INVALID_CRUNTIME, STATUS_INVALID_CRUNTIME_ALT]:
                status_str = "TERMINATED_CRT_FAILURE"
                print("    [!] Result: Invalid Parameter Runtime Closure Detected.")
            elif exit_code != 0:
                status_str = f"TERMINATED_UNEXPECTED_CODE"
                print(f"    [!] Result: Finished with abnormal return code: {exit_code}")
            else:
                status_str = "TERMINATED_CLEAN"
                print("    [+] Result: Process finished cleanly prior to timeout.")

            log_test_metric(log_manifest_path, idx, target, trigger_dll, status_str, exit_code, duration)

        except subprocess.TimeoutExpired:
            # Application successfully survived the duration requirements
            duration = time.time() - start_time
            print(f"    [+] Result: Process maintained stability for full {timeout_sec}s.")
            log_test_metric(log_manifest_path, idx, target, trigger_dll, "STABLE_TIMEOUT_REACHED", "STABLE", duration)

        finally:
            # Thorough teardown processing per iteration loop
            if process and process.poll() is None:
                process.kill()
                process.wait()
            if secondary_process and secondary_process.poll() is None:
                try:
                    secondary_process.kill()
                    secondary_process.wait()
                except OSError:
                    pass

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Process Stability Testing Campaign Runner")
    
    # Required Stability Plan Argument
    parser.add_argument(
        "-p", "--plan", 
        required=True, 
        help="Absolute path to the target stability plan JSON configuration file."
    )
    
    # Optional Log Manifest Argument
    parser.add_argument(
        "-l", "--log",
        default="execution_telemetry_results.jsonl",
        help="Path where the analytical JSONL log manifest should be saved (default: execution_telemetry_results.jsonl)."
    )
    
    args = parser.parse_args()
    run_parametric_campaign(args.plan, args.log)