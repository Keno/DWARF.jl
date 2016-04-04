module CallFrameInfo

using DWARF
using DWARF: DIETreeRef, SLEB128, ULEB128
import DWARF.tag, DWARF.children, DWARF.attributes
using ELF
using ObjFileBase: DebugSections, ObjectHandle
import Base.read
function read_cstring(io)
    a = Array(UInt8, 0)
    while (x = read(io, UInt8)) != 0
        push!(a, x)
    end
    a
end

immutable Undef
end
immutable Same
end
immutable Offset
    n :: Int
    is_val :: Bool
end
immutable Expr
    opcodes :: Vector{UInt8}
    is_val :: Bool
end
immutable Reg
    n :: Int
end
typealias RegState Union{Undef,Same,Offset,Expr,Reg}
type RegStates
    values :: Dict{Int,RegState}
    cfa :: Union{Tuple{Int,Int},Expr,Undef} # either (reg,offset) or a DWARF expr
    delta :: Int
end
RegStates() = RegStates(Dict{Int,RegState}(), Undef(), 0)
Base.getindex(s :: RegStates, n) = get(s.values, n, Undef())
Base.setindex!(s :: RegStates, val::RegState, n :: Int) = isa(val,Undef) ? delete!(s.values, n) : s.values[n] = val
Base.convert(::Type{Int}, x::Union{SLEB128,ULEB128}) = convert(Int,convert(BigInt,x))
function Base.show(io::IO, s :: RegStates)
    print(io, "RegStates [", s.delta, "] cfa: ")
    if isa(s.cfa, Tuple{Int,Int})
        @printf(io, "r%d + %#x", s.cfa[1], s.cfa[2])
    else
        println(io, s.cfa)
    end
    for (k,v) in s.values
        println(io, "\tr", k, " = ", v)
    end
end
Base.show(io::IO, o::Offset) = @printf(io, "%s(cfa+ %#x)", o.is_val ? "" : "*", o.n)
immutable AddrFormat
    base :: UInt8
    mod :: UInt8
end
AddrFormat(x::UInt8) = AddrFormat(x & 0x0f, x & 0xf0)
function readtype(fmt::AddrFormat)
    if fmt.base == DWARF.DW_EH_PE_absptr
        UInt
    elseif fmt.base == DWARF.DW_EH_PE_sdata4
        Int32
    else
        error("Unknown read type $fmt")
    end
end
abstract Entry
immutable CIE <: Entry
    fr
    offset :: UInt
    code_align :: Int
    data_align :: Int
    addr_format :: AddrFormat
    return_reg :: UInt8
    initial_code :: Vector{UInt8}
end
immutable FDE{LocType} <: Entry
    offset :: UInt
    cie :: CIE
    initial_loc :: LocType
    range :: LocType
    code :: Vector{UInt8}
end
immutable FrameRecord
    offset :: UInt
    cies :: Vector{CIE}
    fdes :: Vector{FDE}
end
function Base.show(io::IO, fr :: FrameRecord)
    println(io, "call frame info :")
    for e in fr.cies
        println(io, e)
    end
    for e in fr.fdes
        println(io, e)
    end
end
Base.show(io::IO, fmt::AddrFormat) = print(io, "(", DWARF.DW_EH_PE[fmt.base], " : ", DWARF.DW_EH_PE[fmt.mod], ")")
function Base.show(io::IO, cie::CIE)
    @printf(io, "CIE[%#x] align (code:%#x data:%#x) (addr format %s) %d bytes of instructions", cie.offset, cie.code_align, cie.data_align, cie.addr_format, length(cie.initial_code))
end
function Base.show(io::IO, fde::FDE)
    @printf(io, "FDE[%#x] cie:%#x (addr:%#x sz:%#x) %d bytes of instructions", fde.offset, fde.cie.offset, fde.initial_loc, fde.range, length(fde.code))
end

function absolute_initial_loc(fde::FDE)
    if fde.cie.addr_format.mod == DWARF.DW_EH_PE_pcrel
        Int(fde.cie.fr.offset + 8 + fde.offset) + Int(fde.initial_loc) # TODO why the WORD_SIZE offset ?
    else
        warn("not supported pointer encoding $(fde.cie.addr_format.mod)")
    end
end

function interpret_op(s :: RegStates, ops, cie :: CIE)
    op = read(ops, UInt8)
    #    @show op
    # Section 6.4.2 of DWARF 4
    if op == DWARF.DW_CFA_set_loc                 # 6.4.2.1 Row creation
        error()
    elseif (op & 0xc0) == DWARF.DW_CFA_advance_loc
        delta = Int(op & ~0xc0)
        s.delta += delta * cie.code_align
    elseif op == DWARF.DW_CFA_advance_loc1
        s.delta += read(ops, UInt8) * cie.code_align
    elseif op == DWARF.DW_CFA_advance_loc2
        s.delta += read(ops, UInt16) * cie.code_align
    elseif op == DWARF.DW_CFA_advance_loc4
        s.delta += read(ops, UInt32) * cie.code_align
    elseif op == DWARF.DW_CFA_def_cfa             # 6.4.2.2 CFA definitions        
        reg = convert(Int,read(ops, ULEB128))
        off = convert(Int,read(ops, ULEB128))
        s.cfa = (reg, off)
    elseif op == DWARF.DW_CFA_def_cfa_sf
        reg = convert(Int,read(ops, ULEB128))
        off = convert(Int,read(ops, SLEB128))
        s.cfa = (reg, off*cie.data_align)
    elseif op == DWARF.DW_CFA_def_cfa_register
        @assert(isa(s.cfa,Tuple{Int,Int}))
        reg = convert(Int,read(ops,ULEB128))
        s.cfa = (reg, s.cfa[2])
    elseif op == DWARF.DW_CFA_def_cfa_offset
        @assert(isa(s.cfa, Tuple{Int,Int}))
        s.cfa = (s.cfa[1], convert(Int, read(ops, ULEB128)))
    elseif op == DWARF.DW_CFA_def_cfa_offset_sf
        @assert(isa(s.cfa, Tuple{Int,Int}))
        s.cfa = (s.cfa[1], convert(Int, read(ops, SLEB128))*cie.data_align)
    elseif op == DWARF.DW_CFA_def_cfa_expression
        len = convert(Int,read(ops,ULEB128))
        s.cfa = Expr(read(ops,UInt8,len), true)
    elseif op == DWARF.DW_CFA_undefined           # 6.4.2.3 Register rules
        reg = convert(Int, read(ops, ULEB128))
        s[reg] = Undef()
    elseif op == DWARF.DW_CFA_same_value
        reg = convert(Int, read(ops, ULEB128))
        s[reg] = Same()
    elseif (op & 0xc0) == DWARF.DW_CFA_offset
        reg = Int(op & ~0xc0)
        off = convert(Int, read(ops, ULEB128))*cie.data_align
        s[reg] = Offset(off, false)
    elseif op == DWARF.DW_CFA_offset_extended
        reg = convert(Int, read(ops, ULEB128))
        off = convert(Int, read(ops, ULEB128))*cie.data_align
        s[reg] = Offset(off, false)
    elseif op == DWARF.DW_CFA_offset_extended_sf
        reg = convert(Int, read(ops, ULEB128))
        off = convert(Int, read(ops, SLEB128))*cie.data_align
        s[reg] = Offset(off, false)
    elseif op == DWARF.DW_CFA_val_offset
        reg = convert(Int, read(ops, ULEB128))
        off = convert(Int, read(ops, ULEB128))*cie.data_align
        s[reg] = Offset(off, true)
    elseif op == DWARF.DW_CFA_val_offset_sf
        reg = convert(Int, read(ops, ULEB128))
        off = convert(Int, read(ops, SLEB128))*cie.data_align
        s[reg] = Offset(off, true)
    elseif op == DWARF.DW_CFA_register
        reg_dst = convert(Int, read(ops, ULEB128))
        reg_stc = convert(Int, read(ops, ULEB128))
        s[reg_dst] = Reg(reg_src)
    elseif op == DWARF.DW_CFA_expression ||
           op == DWARF.DW_CFA_val_expression
        error()
    elseif op == DWARF.DW_CFA_restore ||
           op == DWARF.DW_CFA_restore_extended
        error()
    elseif op == DWARF.DW_CFA_remember_state ||   # 6.4.2.4 Row state
           op == DWARF.DW_CFA_restore_state
        error()
    elseif op == DWARF.DW_CFA_nop                 # 6.4.2.5 Padding
    else
        error("unknown CFA opcode $op")
    end
#    @show s
end

function read(oh::ObjectHandle, ::Type{Entry}, fr :: FrameRecord, sect_offset :: Int)
    len = read(oh, UInt32)
    len > 0 || return nothing
    beg_pos = position(oh)
    offset = UInt(beg_pos - sect_offset - 4)
    if len == 0xffffffff
        error("unsupported extended length")
    end
    id = read(oh, UInt32)
    if id == 0 # CIE
        version = read(oh, UInt8)
        if version != 1
            error("unsupported frame record version : $version")
        end
        augment = read_cstring(oh)
        has_augment_data = false
        has_eh_data = false
        addr_format = DWARF.DW_EH_PE_absptr
        if length(augment) > 0
            if augment[1] == 'z'
                has_augment_data = true
            else
                error("can't parse augment data '$(bytestring(augment))'")
            end
        end
        code_align = read(oh, ULEB128)
        data_align = read(oh, SLEB128)
        return_reg = read(oh, UInt8)
        if has_augment_data
            augment_length = convert(Int, read(oh, ULEB128))
            a_pos = position(oh)
            seek(oh, a_pos)
            for i = 2:length(augment)
                if augment[i] == 'R'
                    addr_format = read(oh, UInt8)
                elseif augment[i] == 'L'
                    read(oh, UInt8) # TODO use that maybe
                elseif augment[i] == 'P'
                    read(oh, readtype(AddrFormat(read(oh, UInt8)))) # TODO ditto
                else
                    warn("unknown augment data '$(Char(augment[i]))' in '$(bytestring(augment))'")
                end
            end
            seek(oh, augment_length + a_pos)
        end
        code = read(oh, UInt8, len - (position(oh) - beg_pos))
        CIE(fr, offset, code_align, data_align, AddrFormat(addr_format), return_reg, code)
    else # FDE
        cie_offset = UInt(beg_pos - id - sect_offset)
        cie = fr.cies[findfirst(cie -> cie.offset == cie_offset, fr.cies)]
        loc_type = readtype(cie.addr_format)
        initial_loc = read(oh, loc_type)
        range = read(oh, loc_type)
        code = read(oh, UInt8, len - (position(oh) - beg_pos))
        FDE(offset, cie, initial_loc, range, code)
    end
end

function read(x :: DebugSections, ::Type{FrameRecord})
    oh = x.oh
    seek(x.eh_frame)
    sect_offset = position(oh)
    cies = Array(CIE, 0)
    fdes = Array(FDE, 0)
    fr = FrameRecord(ELF.sectionaddress(x.eh_frame), cies, fdes)
    while true
        entry = read(oh, Entry, fr, sect_offset)
        if isa(entry, CIE)
            push!(cies, entry)
        elseif isa(entry, FDE)
            push!(fdes, entry)
        else
            break
        end
    end
    fr
end

function interpret!(rs, code, cie, target)
    ops = IOBuffer(code)
    while !eof(ops) && rs.delta < target
        interpret_op(rs, ops, cie)
    end
end
function interpret!(fde, target)
    rs = RegStates()
    interpret!(rs, fde.cie.initial_code, fde.cie, target)
    interpret!(rs, fde.code, fde.cie, target)
    rs
end
function interp_all(fr)
    for fde in fr.fdes
        rs = RegStates()
        interpret!(rs, fde.cie.initial_code, fde.cie)
        println(" ==== ")
        interpret!(rs, fde.code, fde.cie)
        println(" ================= ")
    end
end

tag(d::DIETreeRef) = tag(d.tree)
children(d::DIETreeRef) = map(c->DIETreeRef(d.dbgs, d.strtab, c), children(d.tree))
attributes(d::DIETreeRef) = attributes(d.tree)


end
