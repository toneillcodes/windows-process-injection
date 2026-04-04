import sys

def bin_to_csharp(input_filename, output_filename=None):
    """
    Reads a binary file and prints/saves it as a C# byte array.
    """
    try:
        with open(input_filename, 'rb') as f:
            data = f.read()
    except FileNotFoundError:
        print(f"Error: File '{input_filename}' not found.")
        return

    # Format the bytes into "0x00, "
    formatted_data = ", ".join([f"0x{b:02x}" for b in data])

    # Add line breaks for readability (approx 14 bytes per line)
    bytes_per_line = 14
    words = formatted_data.split(", ")
    lines = []
    for i in range(0, len(words), bytes_per_line):
        lines.append(", ".join(words[i:i + bytes_per_line]))
    
    final_output = "byte[] shellcode = {\n    " + ",\n    ".join(lines) + "\n};"

    # Print to console
    print(final_output)

    # Optionally save to file
    if output_filename:
        with open(output_filename, 'w') as f:
            f.write(final_output)
        print(f"\nSuccessfully saved to {output_filename}")

# --- Usage ---
bin_to_csharp("http_x86.xthread.bin")
