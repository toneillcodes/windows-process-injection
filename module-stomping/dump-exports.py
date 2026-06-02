import os
import argparse
import pefile

def dump_module_exports(dll_path, output_file=None, names_only=False):
    """
    Parses a local PE file, extracts the Export Address Table (EAT),
    and displays a structured list of names, ordinals, and RVAs sorted by layout.
    Optionally outputs a raw list of function names only and saves to a file.
    """
    if not os.path.exists(dll_path):
        print(f"[-] Error: Target file not found at '{dll_path}'")
        return

    try:
        # Load the PE file and explicitly force parsing of the export directory
        pe = pefile.PE(dll_path, fast_load=False)
        
        if not hasattr(pe, 'DIRECTORY_ENTRY_EXPORT'):
            print(f"[-] Error: '{os.path.basename(dll_path)}' has no Export Address Table (EAT).")
            return

        exported_functions = []

        # Iterate over the parsed symbols in the export directory
        for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
            # Derive name or fallback to ordinal string representation if un-exported by name
            if exp.name:
                func_name = exp.name.decode('utf-8', errors='ignore')
            else:
                func_name = f"[No Symbol] Ordinal_{exp.ordinal}"

            exported_functions.append({
                'name': func_name,
                'ordinal': exp.ordinal,
                'rva': exp.address if exp.address else 0
            })

        # Sort functions sequentially by RVA so it maps linearly to memory layout
        exported_functions_sorted = sorted(exported_functions, key=lambda x: x['rva'])

        lines = []
        
        if names_only:
            # Generate a raw list of names only (filtering out un-named functions if desired)
            for func in exported_functions_sorted:
                # Omit default placeholder strings if you want clean include/exclude lists
                if not func['name'].startswith("[No Symbol]"):
                    lines.append(func['name'])
        else:
            # Generate full structured diagnostic manifest
            lines.append("\n" + "="*95)
            lines.append(f"📦 EXPORT ADDRESS TABLE MANIFEST: {os.path.basename(dll_path)}")
            lines.append("="*95)
            lines.append(f"{'Exported Symbol / Function Name':<55} | {'Ordinal':<10} | {'Relative Virtual Address (RVA)':<15}")
            lines.append("-"*95)

            for func in exported_functions_sorted:
                rva_str = hex(func['rva']) if func['rva'] != 0 else "Forwarded / N/A"
                lines.append(f"{func['name']:<55} | {func['ordinal']:<10} | {rva_str:<15}")

            lines.append("-"*95)
            lines.append(f"[+] Successfully extracted {len(exported_functions_sorted)} exports from the EAT.")
            lines.append("="*95 + "\n")

        # Output to screen
        for line in lines:
            print(line)

        # Write to file if specified
        if output_file:
            try:
                with open(output_file, 'w', encoding='utf-8') as f:
                    for line in lines:
                        f.write(line + '\n')
                print(f"[+] Successfully saved output to: '{output_file}'\n")
            except Exception as file_err:
                print(f"[-] Warning: Failed to write output to file: {file_err}")

    except pefile.PEFormatError:
        print(f"[-] Error: '{dll_path}' is not a valid Portable Executable file.")
    except Exception as e:
        print(f"[-] An unexpected processing error occurred: {e}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Extract and map the complete Export Address Table layout from a target PE module.")
    parser.add_argument("-f", "--file", type=str, required=True, help="Path to the target DLL on disk.")
    parser.add_argument("-o", "--output", type=str, default=None, help="Optional path to a text file to write the output to.")
    parser.add_argument("--names-only", action="store_true", help="Output a clean list of function names only, omitting headers, RVAs, and ordinals.")
    
    args = parser.parse_args()
    dump_module_exports(args.file, args.output, args.names_only)