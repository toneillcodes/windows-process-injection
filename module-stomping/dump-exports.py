import os
import csv
import argparse
import pefile

def dump_module_exports(dll_path, log_file=None, console_output=True, names_only=False, process_name=None):
    """
    Parses a local PE file, extracts the Export Address Table (EAT), 
    calculates precise function sizes via .pdata exception entries, 
    and displays or logs a structured manifest sorted by layout.
    """
    if not os.path.exists(dll_path):
        print(f"[-] Error: Target file not found at '{dll_path}'")
        return

    dll_name = os.path.basename(dll_path)
    target_process = process_name if process_name else "target_process.exe"

    try:
        # Load the PE file and explicitly force parsing of the directories
        pe = pefile.PE(dll_path, fast_load=False)
        
        if not hasattr(pe, 'DIRECTORY_ENTRY_EXPORT'):
            print(f"[-] Error: '{dll_name}' has no Export Address Table (EAT).")
            return

        # 1. Harvest exact runtime function sizes via SEH Exception Directory (.pdata)
        pdata_sizes = {}
        exception_dir_idx = pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_EXCEPTION']
        if len(pe.OPTIONAL_HEADER.DATA_DIRECTORY) > exception_dir_idx:
            exception_dir = pe.OPTIONAL_HEADER.DATA_DIRECTORY[exception_dir_idx]
            if exception_dir.VirtualAddress != 0 and exception_dir.Size != 0:
                pe.parse_data_directories(directories=[exception_dir_idx])
                if hasattr(pe, 'DIRECTORY_ENTRY_EXCEPTION'):
                    for entry in pe.DIRECTORY_ENTRY_EXCEPTION:
                        begin_rva = entry.struct.BeginAddress
                        end_rva = entry.struct.EndAddress
                        pdata_sizes[begin_rva] = end_rva - begin_rva

        # 2. Extract exports, filter forwarders, and calculate sizing configurations
        exported_functions = []
        for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
            # Derive name or fallback to the new ordinal matching convention
            if exp.name:
                func_name = exp.name.decode('utf-8', errors='ignore')
            else:
                func_name = f"ordinal_{exp.ordinal}"

            # Detect forwarded exports
            is_forwarded = False
            forwarder_str = ""
            if exp.forwarder:
                is_forwarded = True
                forwarder_str = exp.forwarder.decode('utf-8', errors='ignore')

            rva = exp.address if exp.address else 0
            
            # Look up size from unwind data; fallback to minimum block if missing or forwarded
            calculated_size = pdata_sizes.get(rva, 64) if not is_forwarded else 0

            exported_functions.append({
                'name': func_name,
                'ordinal': exp.ordinal,
                'rva': rva,
                'is_forwarded': is_forwarded,
                'forwarder_target': forwarder_str,
                'size': calculated_size
            })

        # Sort functions sequentially by RVA so it maps linearly to memory layout
        exported_functions_sorted = sorted(exported_functions, key=lambda x: x['rva'])

        # --- CONDITION 1: DIRECT CONSOLE OUTPUT (DEFAULTS TO TRUE) ---
        if console_output or names_only:
            lines = []
            if names_only:
                # Generate a raw list of names only (filtering out anonymous tokens or forwarders)
                for func in exported_functions_sorted:
                    if not func['name'].startswith("ordinal_") and not func['is_forwarded']:
                        lines.append(func['name'])
            else:
                # Generate full structured diagnostic manifest table
                lines.append("\n" + "="*130)
                lines.append(f"📦 EXPORT ADDRESS TABLE & CAPACITY MANIFEST: {dll_name}")
                lines.append("="*130)
                lines.append(f"{'Exported Symbol / Function Name':<45} | {'Ordinal':<8} | {'RVA Layout':<12} | {'Size':<10} | {'Forwarding Target / Details'}")
                lines.append("-"*130)

                for func in exported_functions_sorted:
                    if func['is_forwarded']:
                        rva_str = "[!] FORWARDED"
                        size_str = "0 bytes"
                        details = f"Points to -> {func['forwarder_target']}"
                    else:
                        rva_str = hex(func['rva']) if func['rva'] != 0 else "N/A"
                        size_str = f"{func['size']} bytes"
                        details = "Native Code Body"

                    lines.append(f"{func['name']:<45} | {func['ordinal']:<8} | {rva_str:<12} | {size_str:<10} | {details}")

                lines.append("-"*130)
                lines.append(f"[+] Successfully extracted {len(exported_functions_sorted)} entries from the structural layout.")
                lines.append("="*130 + "\n")

            for line in lines:
                print(line)

        # --- CONDITION 2: PIPELINE AUTOMATION CSV LOGGING ---
        if log_file:
            fieldnames = ['ModuleName', 'FullTextSectionSize', 'FunctionName', 'Offset', 'FuncSize']
            
            with open(log_file, mode='w', newline='', encoding='utf-8') as f:
                writer = csv.DictWriter(f, fieldnames=fieldnames)
                writer.writeheader()
                
                for func in exported_functions_sorted:
                    # Skip forwarded assets in automated plans to prevent uncatchable stomp faults
                    if func['is_forwarded']:
                        continue
                        
                    writer.writerow({
                        'ModuleName': dll_name,
                        'FullTextSectionSize': 0,
                        'FunctionName': func['name'],
                        'Offset': hex(func['rva']),
                        'FuncSize': func['size']
                    })
            print(f"[+] Operational blueprint successfully committed to: '{log_file}'")

    except pefile.PEFormatError:
        print(f"[-] Error: '{dll_path}' is not a valid Portable Executable file.")
    except Exception as e:
        print(f"[-] An unexpected processing error occurred: {e}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Extract and map export table capacities with structural unwind parsing.")
    parser.add_argument("-f", "--file", type=str, required=True, help="Path to the target DLL on disk.")    
    # Execution Flow Control Switches
    parser.add_argument("-l", "--log", nargs='?', const="stability_blueprint.csv", default=None,
                        help="Enable pipeline CSV generation. Optionally specify a file path destination.")
    parser.add_argument("--names-only", action="store_true", help="Output a clean list of string function names only.")
    
    # Control console formatting behavior (Defaulting to True, switchable via --no-console)
    parser.add_argument("-c", "--console", dest="console", action="store_true", default=True, help="Print structured table matrix straight to terminal (Default).")
    parser.add_argument("--no-console", dest="console", action="store_false", help="Disable text table generation entirely for background runs.")
    
    args = parser.parse_args()
    dump_module_exports(
        dll_path=args.file, 
        log_file=args.log, 
        console_output=args.console, 
        names_only=args.names_only
    )