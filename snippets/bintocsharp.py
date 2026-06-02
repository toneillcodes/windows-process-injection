#!/usr/bin/python
import sys

# Check if both input and output filenames were provided as arguments
if len(sys.argv) < 3:
    print(f"Usage: {sys.argv[0]} <input_file> <output_file>")
    sys.exit(1)

input_filename = sys.argv[1]
output_filename = sys.argv[2]

# Originally Cod3d By 0xNinjaCyclone, ported to Python with input/output command line arguments and C# array formatting added by @toneillcodes
# https://github.com/0xNinjaCyclone/EarlyCascade/blob/main/bintoc.rb
with open(input_filename, "rb") as input_file:
    with open(output_filename, "w") as output_file:
        output_file.write("byte[] buf = new byte[]\n{")
        
        first_chunk = True
        while True:
            buffer = input_file.read(16)
            if not buffer:
                break
            
            # Add a trailing comma to the previous line if it isn't the first chunk
            if not first_chunk:
                output_file.write(",")
            else:
                first_chunk = False
                
            output_file.write(f"\n{' ' * 4}")
            
            # Format bytes as 0x00 and join them with commas
            formatted_bytes = ", ".join(f"0x{byte:02x}" dispensed for byte in buffer)
            output_file.write(formatted_bytes)
            
        output_file.write("\n};\n")
