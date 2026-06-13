import json

# Paths to your data files
MASTER_EXPORTS_FILE = "c:\\payloads\\uxtheme-modules.txt"
ACTIVE_TELEMETRY_FILE = "active_telemetry.jsonl"
OUTPUT_DORMANT_FILE = "uxtheme_dormant_targets.txt"

def isolate_dormant_code():
    # 1. Load the comprehensive master export list
    with open(MASTER_EXPORTS_FILE, "r", encoding="utf-8") as f:
        master_exports = set(line.strip() for line in f if line.strip())
    
    print(f"[*] Loaded {len(master_exports)} total exports from master list.")

    # 2. Parse the active telemetry log to find what actually fired
    active_functions = set()
    try:
        # Inside your post-testing analysis script:
        active_functions = set()
        TARGET_DLL = "uxtheme.dll" # Filter for your specific analysis target

        with open(ACTIVE_TELEMETRY_FILE, "r", encoding="utf-8") as f:
            for line in f:
                if line.strip():
                    entry = json.loads(line)
                    # Only match active functions that belong to the current target DLL
                    if entry["module"].lower() == TARGET_DLL.lower():
                        active_functions.add(entry["function"])
    except FileNotFoundError:
        print(f"[-] Telemetry file {ACTIVE_TELEMETRY_FILE} not found.")
        return

    print(f"[*] Identified {len(active_functions)} unique functions called during profiling.")

    # 3. Perform the set subtraction (Master Set - Active Set = Dormant Set)
    dormant_targets = master_exports - active_functions
    print(f"[+] Successfully isolated {len(dormant_targets)} completely dormant functions!")

    # 4. Save the clean targets to a file for blast-radius calculation
    with open(OUTPUT_DORMANT_FILE, "w", encoding="utf-8") as f:
        for func in sorted(dormant_targets):
            f.write(func + "\n")
            
    print(f"[+] Dormant targets written to: {OUTPUT_DORMANT_FILE}")

if __name__ == "__main__":
    isolate_dormant_code()                