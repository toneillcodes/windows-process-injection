import os
import argparse
import pefile

def auto_int(x):
    return int(x, 0)

def parse_pdata_functions(pe):
    """
    Parses the IMAGE_DIRECTORY_ENTRY_EXCEPTION directory to find the real 
    runtime boundaries and reconstruct chained/fragmented functions.
    """
    functions = {}
    UNW_FLAG_CHAININFO = 0x04

    if not hasattr(pe, 'DIRECTORY_ENTRY_EXCEPTION'):
        return functions

    for entry in pe.DIRECTORY_ENTRY_EXCEPTION:
        try:
            if hasattr(entry, 'struct'):
                begin_rva = getattr(entry.struct, 'BeginAddress', None) or getattr(entry, 'BeginAddress', 0)
                end_rva = getattr(entry.struct, 'EndAddress', None) or getattr(entry, 'EndAddress', 0)
                unwind_rva = getattr(entry.struct, 'UnwindInfoAddress', None) or getattr(entry, 'UnwindInfoAddress', 0)
            else:
                begin_rva = getattr(entry, 'BeginAddress', 0)
                end_rva = getattr(entry, 'EndAddress', 0)
                unwind_rva = getattr(entry, 'UnwindInfoAddress', 0)
            
            if not begin_rva or not end_rva or not unwind_rva:
                continue
                
            chunk_size = end_rva - begin_rva

            unwind_bytes = pe.get_data(unwind_rva, 4)
            if not unwind_bytes or len(unwind_bytes) < 4:
                continue
                
            version_and_flags = unwind_bytes[0]
            flags = version_and_flags >> 3
            count_of_codes = unwind_bytes[2]

            if (flags & UNW_FLAG_CHAININFO) == UNW_FLAG_CHAININFO:
                count_of_codes_aligned = (count_of_codes + 1) & ~1
                chained_entry_rva = unwind_rva + 4 + (count_of_codes_aligned * 2)
                
                parent_bytes = pe.get_data(chained_entry_rva, 4)
                if parent_bytes and len(parent_bytes) == 4:
                    parent_begin_rva = int.from_bytes(parent_bytes, byteorder='little')
                    
                    if parent_begin_rva in functions:
                        functions[parent_begin_rva]['total_size'] += chunk_size
                        functions[parent_begin_rva]['chunks'].append((begin_rva, end_rva))
            else:
                if begin_rva not in functions:
                    functions[begin_rva] = {
                        'primary_begin': begin_rva,
                        'end_boundary': end_rva,
                        'total_size': chunk_size,
                        'chunks': [(begin_rva, end_rva)]
                    }
        except Exception:
            continue

    return functions

def analyze_stomp_blast_radius(dll_path, target_function, payload_size):
    target_function_lower = target_function.lower()
    
    if not os.path.exists(dll_path):
        print(f"[-] Error: File not found at '{dll_path}'")
        return

    try:
        pe = pefile.PE(dll_path)
        
        if not hasattr(pe, 'DIRECTORY_ENTRY_EXPORT'):
            print(f"[-] Error: '{os.path.basename(dll_path)}' has no Export Address Table.")
            return

        # 1. Gather all exports and sort them by memory layout
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
            print(f"[-] Error: Function '{target_function}' not found in Export Table.")
            return

        exports_sorted = sorted(exports, key=lambda x: x['rva'])
        pdata_map = parse_pdata_functions(pe)
        
        # 2. Determine isolated execution room using BOTH structural data sources
        isolated_space = 0
        is_tracked_in_pdata = False
        target_parent_rva = None

        # Check if target RVA falls inside an explicit .pdata chunk
        for base_rva, info in pdata_map.items():
            for chunk_start, chunk_end in info['chunks']:
                if chunk_start <= target_rva < chunk_end:
                    is_tracked_in_pdata = True
                    target_parent_rva = base_rva
                    isolated_space = chunk_end - target_rva
                    break
            if is_tracked_in_pdata:
                break

        # Hardened Hybrid Fallback Logic
        # Calculate the absolute closest next constraint (the next export or the next .pdata entry)
        next_constraints = []

        # Constraint A: Next adjacent Export RVA
        for exp in exports_sorted:
            if exp['rva'] > target_rva:
                next_constraints.append(exp['rva'])
                break

        # Constraint B: Next adjacent .pdata entry start
        for base_rva in pdata_map.keys():
            if base_rva > target_rva:
                next_constraints.append(base_rva)
                break

        # If we were tracked in .pdata, our current chunk end is also a valid boundary constraint
        if is_tracked_in_pdata and target_parent_rva:
            for chunk_start, chunk_end in pdata_map[target_parent_rva]['chunks']:
                if chunk_start <= target_rva < chunk_end:
                    next_constraints.append(chunk_end)

        if next_constraints:
            # The closest upcoming wall determines our real isolated safe space
            closest_next_wall = min(next_constraints)
            isolated_space = closest_next_wall - target_rva
        else:
            # Ultimate fallback to the section boundary limit
            for section in pe.sections:
                if section.VirtualAddress <= target_rva < (section.VirtualAddress + section.Misc_VirtualSize):
                    isolated_space = (section.VirtualAddress + section.Misc_VirtualSize) - target_rva
                    break

        # 3. Analyze the true collateral damage path
        stomp_ceiling_rva = target_rva + payload_size
        overwritten_functions = []

        # Trace adjacent exports that are stepped on
        for exp in exports_sorted:
            if target_rva < exp['rva'] < stomp_ceiling_rva:
                overwritten_functions.append({'name': exp['name'], 'rva': exp['rva'], 'type': 'Exported Func'})

        # Trace internal .pdata functions that are stepped on (excluding exports we already flagged)
        flagged_rvas = {x['rva'] for x in overwritten_functions}
        for base_rva in sorted(pdata_map.keys()):
            if base_rva == target_parent_rva:
                continue
            if target_rva < base_rva < stomp_ceiling_rva:
                if base_rva not in flagged_rvas:
                    overwritten_functions.append({
                        'name': f"InternalFunc_{hex(base_rva)}", 
                        'rva': base_rva, 
                        'type': 'Internal (SEH Tracked)'
                    })

        # Sort the destruction list linearly by proximity
        overwritten_functions.sort(key=lambda x: x['rva'])

        # 4. Format Reporting Output
        print("\n" + "="*90)
        print(f"💥 HYBRID MODULE STOMP ANALYSIS: {os.path.basename(dll_path)}")
        print("="*90)
        print(f"Target Function       : {target_function}")
        print(f"Target Function RVA   : {hex(target_rva)}")
        print(f"Tracked via SEH Tables: {'Yes' if is_tracked_in_pdata else 'No (Leaf/Stub/Untracked)'}")
        print(f"Your Payload Size     : {payload_size} bytes ({hex(payload_size)})")
        print(f"Isolated Safe Space   : {isolated_space} bytes ({hex(isolated_space)})")
        print("-"*90)

        if payload_size <= isolated_space:
            print("🟢 STATUS: [SAFE FIT]")
            print(f"Your payload fits perfectly within the physical boundary of this function block.")
            print("Zero adjacent logic structures or exports will be modified.")
        else:
            print("🔴 STATUS: [OVERFLOW RISK / COLLATERAL DAMAGE]")
            print(f"Your payload overflows the isolated space boundary by {payload_size - isolated_space} bytes.")
            print(f"Total adjacent/internal functions completely or partially overwritten: {len(overwritten_functions)}")
            if overwritten_functions:
                print("\n🚨 Overwritten Functions & Logic Boundaries:")
                print(f"  {'Offset From Target':<22} | {'Function Symbol / Name':<40} | {'Type':<20}")
                print("  " + "-"*88)
                for exp in overwritten_functions:
                    offset = exp['rva'] - target_rva
                    print(f"  +{offset:<20} | {exp['name']:<40} | {exp['type']:<20}")
        print("="*90 + "\n")

    except Exception as e:
        print(f"[-] An error occurred: {e}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Analyze the collateral damage/blast radius of a specific stomp payload.")
    parser.add_argument("-f", "--file", type=str, required=True, help="Path to the target DLL.")
    parser.add_argument("-fnc", "--function", type=str, required=True, help="The export function to start stomping from.")
    parser.add_argument("-s", "--size", type=auto_int, required=True, help="Size of your payload in bytes.")
    
    args = parser.parse_args()
    analyze_stomp_blast_radius(args.file, args.function, args.size)