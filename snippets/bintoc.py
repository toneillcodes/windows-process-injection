#!/usr/bin/python
import sys

# Check if both input and output filenames were provided as arguments
if len(sys.argv) < 3:
    print(f"Usage: {sys.argv[0]} <input_file> <output_file>")
    sys.exit(1)

input_filename = sys.argv[1]
output_filename = sys.argv[2]

# Originally Cod3d By 0xNinjaCyclone, ported to Python with input/output command line arguments added by @toneillcodes
# https://github.com/0xNinjaCyclone/EarlyCascade/blob/main/bintoc.rb
with open(input_filename, "rb") as input_file:
    with open(output_filename, "w") as output_file:
        output_file.write("unsigned char buf[] =    ")
        while True:
            buffer = input_file.read(16)
            if not buffer:
                break
            output_file.write(f"\n{' ' * 20}\"")
            for byte in buffer:
                output_file.write(f"\\x{byte:02x}")
            output_file.write('"')
        output_file.write(';')