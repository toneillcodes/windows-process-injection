#!/usr/bin/ruby

# Check if both input and output filenames were provided as arguments
if ARGV.length < 2
  puts "Usage: #{$0} <input_file> <output_file>"
  exit 1
end

input_filename  = ARGV[0]
output_filename = ARGV[1]

# Originally Cod3d By 0xNinjaCyclone, command line arguments and file output added by @toneillcodes
# https://github.com/0xNinjaCyclone/EarlyCascade/blob/main/bintoc.rb
File.open(input_filename, "rb") do |input_file|
  File.open(output_filename, "w") do |output_file|
    output_file.print "unsigned char buf[] =    "
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