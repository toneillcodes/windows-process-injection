import os
import csv
import argparse
import pefile

def dump_module_exports(dll_path, log_file=None, console_output=True, names_only=False, process_name=None, linear_step_size=None, linear_block_size=None):
    """
    Parses a local PE file, extracts the Export Address Table (EAT) or maps
    the .text section linearly starting from the first export RVA by a step size constraint, 
    and logs a structured manifest sorted by layout.
    """
    if not os.path.exists(dll_path):
        print(f"[-] Error: Target file not found at '{dll_path}'")
        return

    dll_name = os.path.basename(dll_path)

    try:
        pe = pefile.PE(dll_path, fast_load=False)
        
        # Extract .text boundaries for total canvas bounds
        text_size = 0
        text_start = 0
        for section in pe.sections:
            if section.Name.decode('utf-8', errors='ignore').strip('\x00') == '.text':
                text_start = section.VirtualAddress
                text_size = section.Misc_VirtualSize if section.Misc_VirtualSize else section.SizeOfRawData
                break
        
        if text_size == 0:
            print("[-] Error: Could not locate a valid '.text' section boundary.")
            return

        # Core Parsing Phase: Gather exports to determine layout bounds
        pdata_sizes = {}
        exception_dir_idx = pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_EXCEPTION']
        if len(pe.OPTIONAL_HEADER.DATA_DIRECTORY) > exception_dir_idx:
            exception_dir = pe.OPTIONAL_HEADER.DATA_DIRECTORY[exception_dir_idx]
            if exception_dir.VirtualAddress != 0 and exception_dir.Size != 0:
                pe.parse_data_directories(directories=[exception_dir_idx])
                if hasattr(pe, 'DIRECTORY_ENTRY_EXCEPTION'):
                    for entry in pe.DIRECTORY_ENTRY_EXCEPTION:
                        pdata_sizes[entry.struct.BeginAddress] = entry.struct.EndAddress - entry.struct.BeginAddress

        has_exports = hasattr(pe, 'DIRECTORY_ENTRY_EXPORT')
        exported_functions = []
        
        if has_exports:
            for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
                func_name = exp.name.decode('utf-8', errors='ignore') if exp.name else f"ordinal_{exp.ordinal}"
                is_forwarded = bool(exp.forwarder)
                rva = exp.address if exp.address else 0
                calculated_size = pdata_sizes.get(rva, 64) if not is_forwarded else 0

                exported_functions.append({
                    'name': func_name,
                    'ordinal': exp.ordinal,
                    'rva': rva,
                    'is_forwarded': is_forwarded,
                    'size': calculated_size
                })

        exported_functions_sorted = sorted(exported_functions, key=lambda x: x['rva'])

        # =========================================================
        # EXECUTION PATH A: LINEAR STEPPING MODE (MATCHING RVAs)
        # =========================================================
        if linear_step_size is not None:
            if linear_step_size <= 0:
                print("[-] Error: Step size must be a positive integer.")
                return
            
            # Default block size to match step size if not explicitly specified
            if linear_block_size is None:
                linear_block_size = linear_step_size
            elif linear_block_size <= 0:
                print("[-] Error: Block size must be a positive integer.")
                return

            # Determine baseline starting target: Use first export RVA if available, fallback to text_start
            if exported_functions_sorted:
                starting_rva = exported_functions_sorted[0]['rva']
            else:
                print("[*] Notice: No exports detected. Falling back to start of .text section.")
                starting_rva = text_start

            # Calculate remaining space available from our starting cursor to the end of the text section
            text_end = text_start + text_size
            effective_size = text_end - starting_rva

            if effective_size <= 0:
                print("[-] Error: First export RVA sits outside detected .text boundaries.")
                return

            linear_blocks = []
            # Walk sequentially through the effective span using the configured step increment
            for slice_offset in range(0, effective_size, linear_step_size):
                # The actual window chunk evaluates up to the separate block size limit
                current_block_size = min(linear_block_size, effective_size - slice_offset)
                
                # Calculate the literal RVA relative to the module base
                actual_rva = starting_rva + slice_offset

                linear_blocks.append({
                    'Offset': hex(actual_rva),
                    'BlockSize': current_block_size
                })

            if console_output:
                print("\n" + "="*95)
                print(f"[*] LINEAR STEPPING MODE ACTIVE (Step Size: {linear_step_size} bytes, Block Size: {linear_block_size} bytes)")
                print(f"    Target Starting RVA (First Export): {hex(starting_rva)}")
                print(f"    Effective testing space remaining: {effective_size} bytes")
                print("    [Offsets calculated relative to Module Base (RVA)]")
                print("="*95)
                print(f"{'Block Sequence ID':<25} | {'Module RVA Offset':<18} | {'Block Size (Bytes)'}")
                print("-"*95)
                display_limit = 50
                for idx, block in enumerate(linear_blocks, start=1):
                    if idx >= display_limit:
                        print(f"... and {len(linear_blocks) - display_limit} more blocks ...")
                        break
                    print(f"Block #{idx:<18} | {block['Offset']:<18} | {block['BlockSize']} bytes")
                print("="*95)

            if log_file:
                fieldnames = ['ModuleName', 'FullTextSectionSize', 'FunctionName', 'Offset', 'FuncSize']
                with open(log_file, mode='w', newline='', encoding='utf-8') as f:
                    writer = csv.DictWriter(f, fieldnames=fieldnames)
                    writer.writeheader()
                    for block in linear_blocks:
                        writer.writerow({
                            'ModuleName': dll_name,
                            'FullTextSectionSize': text_size,
                            'FunctionName': '', 
                            'Offset': block['Offset'],
                            'FuncSize': block['BlockSize']
                        })
                print(f"[+] Operational linear stepping blueprint committed to: '{log_file}'")
            return

        # =========================================================
        # EXECUTION PATH B: ORIGINAL MANIFEST MODE
        # =========================================================
        if not has_exports:
            print(f"[-] Error: '{dll_name}' has no Export Address Table (EAT).")
            return

        if console_output: # Only enter if console output isn't silenced
            lines = []
            if names_only:
                for func in exported_functions_sorted:
                    if not func['name'].startswith("ordinal_") and not func['is_forwarded']:
                        lines.append(func['name'])
            else:
                lines.append("\n" + "="*130)
                lines.append(f"📦 EXPORT ADDRESS TABLE & CAPACITY MANIFEST: {dll_name}")
                lines.append("="*130)
                lines.append(f"{'Exported Symbol / Function Name':<45} | {'Ordinal':<8} | {'RVA Layout':<12} | {'Size':<10} | {'Details'}")
                lines.append("-"*130)
                for func in exported_functions_sorted:
                    rva_str = "[!] FORWARDED" if func['is_forwarded'] else hex(func['rva'])
                    size_str = f"{func['size']} bytes"
                    lines.append(f"{func['name']:<45} | {func['ordinal']:<8} | {rva_str:<12} | {size_str:<10} | {'Native' if not func['is_forwarded'] else 'Forwarded'}")
                lines.append("-"*130)
            for line in lines:
                print(line)

        if log_file:
            fieldnames = ['ModuleName', 'FullTextSectionSize', 'FunctionName', 'Offset', 'FuncSize']
            with open(log_file, mode='w', newline='', encoding='utf-8') as f:
                writer = csv.DictWriter(f, fieldnames=fieldnames)
                writer.writeheader()
                for func in exported_functions_sorted:
                    if func['is_forwarded']:
                        continue
                    writer.writerow({
                        'ModuleName': dll_name,
                        'FullTextSectionSize': text_size,
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
    parser = argparse.ArgumentParser(description="Extract and map export table capacities or step through code linearly.")
    parser.add_argument("-f", "--file", type=str, required=True, help="Path to the target DLL on disk.")    
    # Output controls
    parser.add_argument("-o", "--output", nargs='?', const="stability_blueprint.csv", default=None, help="Enable pipeline CSV generation.")
    parser.add_argument("-n", "--names-only", action="store_true", help="Output a clean list of string function names only.")
    # Linear stepping execution switches
    parser.add_argument("--linear-step", type=int, default=None, metavar="BYTES", help="Enable sequential step mode through the .text section with the specified stride distance.")
    parser.add_argument("--linear-block", type=int, default=None, metavar="BYTES", help="The continuous test size chunk extracted at every offset step. (Defaults to match step size if omitted).")
    # Console output controls
    parser.add_argument("-c", "--console", dest="console", action="store_true", default=True, help="Print results to terminal (Default).")
    parser.add_argument("-q", "--quiet", dest="console", action="store_false", help="Disable text display entirely.")
    
    args = parser.parse_args()
    dump_module_exports(
        dll_path=args.file,    
        log_file=args.output, # Passed the updated argument here
        console_output=args.console, 
        names_only=args.names_only,
        linear_step_size=args.linear_step,
        linear_block_size=args.linear_block
    )