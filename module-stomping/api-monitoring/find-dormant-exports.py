import argparse
import json
import sys


def isolate_dormant_code(
    master_file, telemetry_file, output_file, target_dll
):
    # 1. Load the comprehensive master export list
    try:
        with open(master_file, "r", encoding="utf-8") as f:
            master_exports = set(line.strip() for line in f if line.strip())
    except FileNotFoundError:
        print(f"[-] Master exports file '{master_file}' not found.")
        sys.exit(1)

    print(f"[*] Loaded {len(master_exports)} total exports from master list.")

    # 2. Parse the active telemetry log to find what actually fired
    active_functions = set()
    try:
        with open(telemetry_file, "r", encoding="utf-8") as f:
            for line in f:
                if line.strip():
                    entry = json.loads(line)
                    # Only match active functions that belong to the current target DLL
                    if entry.get("module", "").lower() == target_dll.lower():
                        active_functions.add(entry.get("function"))
    except FileNotFoundError:
        print(f"[-] Telemetry file '{telemetry_file}' not found.")
        sys.exit(1)

    print(
        f"[*] Identified {len(active_functions)} unique functions called during profiling."
    )

    # 3. Perform the set subtraction (Master Set - Active Set = Dormant Set)
    dormant_targets = master_exports - active_functions
    print(
        f"[+] Successfully isolated {len(dormant_targets)} completely dormant functions!"
    )

    # 4. Save the clean targets to a file for blast-radius calculation
    try:
        with open(output_file, "w", encoding="utf-8") as f:
            for func in sorted(dormant_targets):
                f.write(func + "\n")
    except Exception as e:
        print(f"[-] Failed to write output file: {e}")
        sys.exit(1)

    print(f"[+] Dormant targets written to: {output_file}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Isolate dormant exported functions by comparing a master list against active telemetry."
    )

    parser.add_argument(
        "-m",
        "--master",
        required=True,
        help="Path to the master exports text file (e.g., uxtheme-modules.txt).",
    )
    parser.add_argument(
        "-t",
        "--telemetry",
        required=True,
        help="Path to the active telemetry log JSONL file.",
    )
    parser.add_argument(
        "-o",
        "--output",
        required=True,
        help="Path where the output dormant functions file should be saved.",
    )
    parser.add_argument(
        "-d",
        "--dll",
        required=True,
        help="Target DLL name to filter within telemetry (e.g., uxtheme.dll).",
    )

    args = parser.parse_args()

    # Run the isolation logic with the required parameters
    isolate_dormant_code(args.master, args.telemetry, args.output, args.dll)