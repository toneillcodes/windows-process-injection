#!/usr/bin/python
import sys

# Check if both input and output filenames were provided as arguments
if len(sys.argv) < 3:
    print(f"Usage: {sys.argv[0]} <input_file> <output_file>")
    sys.exit(1)

input_filename = sys.argv[1]
output_filename = sys.argv[2]

# Read the entire large payload into memory
with open(input_filename, "rb") as input_file:
    payload = input_file.read()

# Convert the binary data into a C-compatible integer array format
# This completely avoids C1091 by eliminating string literals entirely ("")
lines = []
for i in range(0, len(payload), 12):  # 12 bytes per line keeps it clean
    chunk = payload[i:i+12]
    hex_line = ", ".join(f"0x{byte:02x}" for byte in chunk)
    lines.append(f"    {hex_line}")

# Join all lines together with commas and newlines
array_content = ",\n".join(lines)

# Write the final array to the output file
with open(output_filename, "w") as output_file:
    output_file.write(f"// Payload size: {len(payload)} bytes\n")
    output_file.write("unsigned char buf[] = {\n")
    output_file.write(array_content)
    output_file.write("\n};\n")