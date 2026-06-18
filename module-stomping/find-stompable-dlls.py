import os
import csv
import argparse
import pefile

def auto_int(x):
    """Helper to accept both decimal integers and hex strings (0x...) from CLI."""
    return int(x, 0)

def parse_flat_file(file_path, list_type_label):
    """
    Parses a flat text file containing only clean DLL filenames (one per line).
    Normalizes them to lowercase for robust, case-insensitive comparison.
    """
    names_set = set()
    if not file_path:
        return names_set

    print(f"[*] Loading {list_type_label} from: '{file_path}'")
    try:
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            for line in f:
                dll_name = line.strip().lower()
                
                # Ignore blank lines or markdown-style separator lines
                if not dll_name or dll_name.startswith('---') or dll_name.startswith('[+]'):
                    continue
                
                names_set.add(dll_name)
                    
        print(f"[+] Loaded {len(names_set)} modules into {list_type_label} filter.")
    except Exception as e:
        print(f"[-] Warning: Failed to read {list_type_label} file: {e}")
        
    return names_set

def find_phantom_dll_candidates(target_dir, min_file_size_mb, min_text_section_size, excluded_dlls, included_dlls, log_file=None, console_output=True):
    """
    Scans a directory for DLLs matching structural criteria.
    Supports exclusion filters, targeted scope filters, and conditional pipeline logging.
    """
    min_file_size_bytes = min_file_size_mb * 1024 * 1024
    candidates = []

    if console_output:
        print(f"[*] Scanning Target Directory: '{target_dir}'")
        print(f"[*] Filtering for Files      : > {min_file_size_mb}MB")
        print(f"[*] Required .text Space     : {hex(min_text_section_size)} bytes")
        
        if included_dlls:
            print(f"[*] Targeted Include Filter  : Active ({len(included_dlls)} specific targets allowed)")
        if excluded_dlls:
            print(f"[*] Exclusion Filter         : Active ({len(excluded_dlls)} modules blacklisted)")
            
        print("-" * 140)
        print(f"{'Full File Path':<85} | {'File Size (MB)':<15} | {'Size of .text':<15} | {'Virtual Address':<15}")
        print("-" * 140)

    for root, _, files in os.walk(target_dir):
        for file in files:
            file_lower = file.lower()
            if not file_lower.endswith('.dll'):
                continue
                
            # Gate 1: Include lookup list filter bounds
            if included_dlls and (file_lower not in included_dlls):
                continue

            # Gate 2: Exclude lookup blacklist filter bounds
            if excluded_dlls and (file_lower in excluded_dlls):
                continue
                
            file_path = os.path.join(root, file)
            
            try:
                file_size = os.path.getsize(file_path)
                if file_size < min_file_size_bytes:
                    continue
                
                pe = pefile.PE(file_path, fast_load=True)
                
                for section in pe.sections:
                    section_name = section.Name.decode('utf-8', errors='ignore').strip('\x00')
                    
                    if section_name == '.text':
                        v_size = section.Misc_VirtualSize
                        
                        if v_size >= min_text_section_size:
                            file_size_mb = file_size / (1024 * 1024)
                            if console_output:
                                print(f"{file_path:<85} | {file_size_mb:<15.2f} | {hex(v_size):<15} | {hex(section.VirtualAddress):<15}")
                            
                            candidates.append({
                                'Name': file, # Base filename matches list-process-dlls paradigm expect layouts
                                'TextSectionSize': v_size
                            })
                        break 
                        
            except (pefile.PEFormatError, PermissionError, FileNotFoundError):
                continue

    if console_output:
        print("-" * 140)
        print(f"[*] Found {len(candidates)} potential candidates matching the criteria.")

    # --- PIPELINE SEAMLESS AUTOMATION EXPORT ---
    if log_file and candidates:
        # Field structure exactly matching list-process-dlls layout configuration needs
        fieldnames = ['Name', 'TextSectionSize']
        try:
            with open(log_file, mode='w', newline='', encoding='utf-8') as f:
                writer = csv.DictWriter(f, fieldnames=fieldnames)
                writer.writeheader()
                for cand in candidates:
                    writer.writerow({
                        'Name': cand['Name'],
                        'TextSectionSize': cand['TextSectionSize']
                    })
            print(f"[+] Operational structural blueprint saved to: '{log_file}'")
        except Exception as file_err:
            print(f"[-] Error: Failed to write pipeline target spreadsheet: {file_err}")

    return candidates

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Find DLL candidates with targeted tracking and exclusion parameters.")
    
    # Positionals & core targets
    parser.add_argument("size", type=auto_int, help="The total required size of the .text section (e.g., 0x80000)")
    parser.add_argument("-d", "--dir", type=str, default=r"C:\Windows\System32", help="Target directory to scan (default: C:\\Windows\\System32)")
    parser.add_argument("-m", "--min-size", type=float, default=1.0, help="Minimum file size on disk in MB (default: 1.0)")
    
    # Flat configurations files switches
    parser.add_argument("-x", "--exclude", type=str, default=None, help="Path to a text file containing specific DLLs to EXCLUDE")
    parser.add_argument("-i", "--include", type=str, default=None, help="Path to a text file containing specific DLLs to INCLUDE")

    # Pipeline output and terminal display switches
    parser.add_argument("-l", "--log", type=str, default=None, help="Destination pipeline tracking file path to export CSV output parameters.")
    parser.add_argument("-c", "--console", dest="console", action="store_true", default=True, help="Print structured layout results table directly to screen terminal (Default).")
    parser.add_argument("--no-console", dest="console", action="store_false", help="Suppress terminal visual representation during backend background tasks loops.")

    args = parser.parse_args()

    if not os.path.isdir(args.dir):
        print(f"[-] Error: '{args.dir}' is not a valid directory.")
        exit(1)

    # Parse flat filters definitions
    excluded_modules = parse_flat_file(args.exclude, "EXCLUDE_MODULES")
    included_modules = parse_flat_file(args.include, "INCLUDE_MODULES")

    find_phantom_dll_candidates(
        target_dir=args.dir, 
        min_file_size_mb=args.min_size, 
        min_text_section_size=args.size,
        excluded_dlls=excluded_modules,
        included_dlls=included_modules,
        log_file=args.log,
        console_output=args.console
    )