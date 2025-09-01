#!/usr/bin/ruby
# Originally Cod3d By 0xNinjaCyclone, file output added by @toneillcodes
# https://github.com/0xNinjaCyclone/EarlyCascade/blob/main/bintoc.rb
File.open("demon.x64.bin", "rb") do |input_file|
  File.open("shellcode.txt", "w") do |output_file|
    output_file.print "BYTE x64_stub[] =    "
    while buffer = input_file.read(16)
      output_file.print "\n#{' ' * 4 * 5}\""
      buffer.bytes.each do |byte|
        output_file.print "\\x%0.2x" % byte
      end
      output_file.print '"'
    end
    output_file.puts ';'
  end
end
