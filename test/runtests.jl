using DWARF
using Base.Test

# Line Table Tests

x = IOBuffer()
# stub (0x2a = 42 bytes after header field, adjust that number if changing the header)
write(x,[0x47,0x00,0x00,0x00,0x02,0x00,0x2a,0x00,0x00,0x00,0x01,0x01,0xfb,0x0e,0x0d]) # 8 bytes after header length
# opcode lengths
standard_opcode_lengths = [0x00,0x01,0x01,0x01,0x01,0x00,0x00,0x00,0x01,0x00,0x00,0x01]
write(x,standard_opcode_lengths) # 12 bytes
# include directories (11 bytes)
write(x,"/julia/test")
write(x,"\0")       # null terminate
write(x,'\0')       # end of list
# Write file entries (12 bytes)
write(x,"test.jl")
write(x,'\0')       # null terminate
write(x,ULEB128(1)) # directory index
write(x,ULEB128(0)) # timestamp
write(x,ULEB128(0)) # file size
write(x,'\0')       # end of list

# The actual line number program
write(x,[0x05,0x01,0x00,0x09,0x02,0x0e,0x30,0xec,0x2c,0x01,0x00,0x00,0x00,0x03,0x14,0x01,0x02,0xac,0x01,0x00,0x01,0x01])

seekstart(x)
header = DWARF.LineTableSupport.read_header(x)
@test header.stub == DWARF.LineTableSupport.HeaderStub{UInt32}(
    0x47, # Total Length
    0x02, # Version
    0x2a, # Header Length (bytes after this point)
    0x01, # minimum_instruction_length
    0x01, # maximum_operations_per_instruction (implicit it DWARF version 2)
    0x01, # default_is_stmt
    reinterpret(Int8, 0xfb), # line_base
    0x0e, # line_range
    0x0d) # opcode_base

@test header.standard_opcode_lengths == standard_opcode_lengths
@test header.include_directories == ["/julia/test"]
@test length(header.file_names) == 1
@test header.file_names[1] == DWARF.LineTableSupport.FileEntry("test.jl",1,0,0)
@test position(x) == header.stub.header_length+10

seekstart(x)
t = LineTable(x)
s = start(t)
r,s = next(t,s)
@test r == DWARF.LineTableSupport.RegisterState(5048643598,0,1,21,1,true,false,false,false,false,0,0)
r,s = next(t,s)
@test r == DWARF.LineTableSupport.RegisterState(5048643770,0,1,21,1,true,false,true,false,false,0,0)
@test done(t,s)
