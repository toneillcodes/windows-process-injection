import os
import argparse
import pefile

def auto_int(x):
    """Helper to accept both decimal integers and hex strings (0x...) from CLI."""
    return int(x, 0)

def analyze_stomp_blast_radius(dll_path, target_function, payload_size):
    """
    Calculates the contiguous window available for a target function and maps
    out exactly how many downstream exports will be overwritten by a given payload size.
    """
    target_function_lower = target_function.lower()
    
    if not os.path.exists(dll_path):
        print(f"[-] Error: File not found at '{dll_path}'")
        return

    try:
        pe = pefile.PE(dll_path)
        
        if not hasattr(pe, 'DIRECTORY_ENTRY_EXPORT'):
            print(f"[-] Error: '{os.path.basename(dll_path)}' has no Export Address Table.")
            return

        # Gather and map all exports
        exports = []
        target_rva = None
        
        for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
            if exp.address is None:
                continue
            name = exp.name.decode('utf-8', errors='ignore') if exp.name else f"Ordinal_{exp.ordinal}"
            exports.append({'name': name, 'rva': exp.address})
            
            if name.lower() == target_function_lower:
                target_rva = exp.address

        if target_rva is None:
            print(f"[-] Error: Function '{target_function}' not found in {os.path.basename(dll_path)}.")
            return

        # Sort the exports sequentially by their memory layout
        exports_sorted = sorted(exports, key=lambda x: x['rva'])
        
        # Calculate the payload's absolute ceiling in memory
        stomp_ceiling_rva = target_rva + payload_size

        # Find our target's position index
        target_index = next(i for i, exp in enumerate(exports_sorted) if exp['rva'] == target_rva)
        
        # Calculate single function maximum continuous space
        available_isolated_space = 0
        if target_index + 1 < len(exports_sorted):
            available_isolated_space = exports_sorted[target_index + 1]['rva'] - target_rva
        else:
            # Fallback to section boundary if it's the final export
            for section in pe.sections:
                if section.VirtualAddress <= target_rva < (section.VirtualAddress + section.Misc_VirtualSize):
                    available_isolated_space = (section.VirtualAddress + section.Misc_VirtualSize) - target_rva
                    break

        # Analyze the blast radius (how many functions we intersect with)
        overwritten_functions = []
        for i in range(target_index + 1, len(exports_sorted)):
            next_exp = exports_sorted[i]
            
            # If the next function starts before our payload ends, it's caught in the blast radius
            if next_exp['rva'] < stomp_ceiling_rva:
                overwritten_functions.append(next_exp)
            else:
                break # We outgrew the payload boundary

        # Format Reporting Output
        print("\n" + "="*90)
        print(f"💥 MODULE STOMP BLAST RADIUS ANALYSIS: {os.path.basename(dll_path)}")
        print("="*90)
        print(f"Target Function       : {target_function}")
        print(f"Target Function RVA   : {hex(target_rva)}")
        print(f"Your Payload Size     : {payload_size} bytes ({hex(payload_size)})")
        print(f"Isolated Exec Space   : {available_isolated_space} bytes ({hex(available_isolated_space)})")
        print("-"*90)

        if payload_size <= available_isolated_space:
            print("🟢 STATUS: [SAFE FIT]")
            print(f"Your payload fits entirely within the isolated boundary of {target_function}.")
            print("Zero adjacent exported functions will be modified.")
        else:
            print("🔴 STATUS: [OVERFLOW RISK / COLLATERAL DAMAGE]")
            print(f"Your payload overflows the isolated function boundary by {payload_size - available_isolated_space} bytes.")
            print(f"Total adjacent exports completely or partially overwritten: {len(overwritten_functions)}")
            print("\n🚨 Overwritten Functions List:")
            print(f"  {'Offset From Target':<22} | {'Function Name':<45} | {'Start RVA':<15}")
            print("  " + "-"*85)
            for exp in overwritten_functions:
                offset = exp['rva'] - target_rva
                print(f"  +{offset:<20} | {exp['name']:<45} | {hex(exp['rva'])}")
                
        print("="*90 + "\n")

    except Exception as e:
        print(f"[-] An error occurred: {e}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Analyze the collateral damage/blast radius of a specific stomp payload.")
    parser.add_argument("-f", "--file", type=str, required = True, help="Path to the target DLL.")
    parser.add_argument("-fnc", "--function", type=str, required=True, help="The export function to start stomping from.")
    parser.add_argument("-s", "--size", type=auto_int, required=True, help="Size of your payload in bytes (can be int or hex string like 0x200).")
    
    args = parser.parse_args()
    analyze_stomp_blast_radius(args.file, args.function, args.size)