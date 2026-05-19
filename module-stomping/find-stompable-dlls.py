import os
import argparse
import pefile

def auto_int(x):
    """Helper to accept both decimal integers and hex strings (0x...) from CLI."""
    return int(x, 0)

def find_phantom_dll_candidates(target_dir, min_file_size_mb, min_text_section_size):
    """
    Scans a directory for DLLs larger than a minimum file size, then parses their 
    PE headers to find candidates where the .text section is large enough to hold 
    the mapped payload.
    """
    min_file_size_bytes = min_file_size_mb * 1024 * 1024
    candidates = []

    print(f"[*] Scanning Target Directory: '{target_dir}'")
    print(f"[*] Filtering for Files      : > {min_file_size_mb}MB")
    print(f"[*] Required .text Space     : {hex(min_text_section_size)} bytes")
    print("-" * 90)
    print(f"{'DLL Name':<40} | {'File Size (MB)':<15} | {'Size of .text':<15} | {'Virtual Address':<15}")
    print("-" * 90)

    for root, _, files in os.walk(target_dir):
        for file in files:
            if not file.lower().endswith('.dll'):
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
                            print(f"{file:<40} | {file_size_mb:<15.2f} | {hex(v_size):<15} | {hex(section.VirtualAddress):<15}")
                            candidates.append({
                                'path': file_path,
                                'file_size': file_size,
                                'text_virtual_size': v_size
                            })
                        break 
                        
            except (pefile.PEFormatError, PermissionError, FileNotFoundError):
                continue

    print("-" * 90)
    print(f"[*] Found {len(candidates)} potential candidates.")
    return candidates

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Find DLL candidates with a specific minimum .text section size.")
    
    # Required size argument - parses both normal ints and hex strings
    parser.add_argument(
        "size", 
        type=auto_int, 
        help="The total required size of the .text section (e.g., 524288 or 0x80000)"
    )
    
    # Optional directory argument - defaults to System32
    parser.add_argument(
        "-d", "--dir", 
        type=str, 
        default=r"C:\Windows\System32", 
        help="Target directory to scan (default: C:\\Windows\\System32)"
    )
    
    # Optional file size filter - defaults to 1MB
    parser.add_argument(
        "-m", "--min-size", 
        type=float, 
        default=1.0, 
        help="Minimum file size on disk in MB (default: 1.0)"
    )

    args = parser.parse_args()

    # Validate target directory
    if not os.path.isdir(args.dir):
        print(f"[-] Error: '{args.dir}' is not a valid directory.")
        exit(1)

    find_phantom_dll_candidates(
        target_dir=args.dir, 
        min_file_size_mb=args.min_size, 
        min_text_section_size=args.size
    )
