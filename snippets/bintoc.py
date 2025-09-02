#!/usr/bin/python
# Originally Cod3d By 0xNinjaCyclone, file output added by @toneillcodes
# https://github.com/0xNinjaCyclone/EarlyCascade/blob/main/bintoc.rb
with open("demon.x64.bin", "rb") as input_file:
    with open("shellcode.txt", "w") as output_file:
        output_file.write("BYTE x64_stub[] =    ")
        while True:
            buffer = input_file.read(16)
            if not buffer:
                break
            output_file.write(f"\n{' ' * 20}\"")
            for byte in buffer:
                output_file.write(f"\\x{byte:02x}")
            output_file.write('"')
        output_file.write(';')
