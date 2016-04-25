module CallFrameInfo

using DWARF
using DWARF: SLEB128, ULEB128
import DWARF.tag, DWARF.children, DWARF.attributes
using ObjFileBase
using ObjFileBase: DebugSections, ObjectHandle, handle
import Base.read
function read_cstring(io)
    a = Array(UInt8, 0)
    while (x = read(io, UInt8)) != 0
        push!(a, x)
    end
    a
end

export realize_cie, initial_loc, FDEIterator, fde_range

# Reference type

immutable FDERef
    eh_frame::SectionRef
    offset::UInt
    # Distinguish between FDEs in eh_frame (true) or debug_frame
    is_eh_not_debug::Bool
end

immutable CIERef
    eh_frame::SectionRef
    offset::UInt
end


# Dwarf encoding
immutable DataRel; ptr; end
immutable PcRel; ptr; end
immutable Indirect; ptr; end

function encoding_type(encoding)
    data_enc = (encoding & 0xf)
    if data_enc == DWARF.DW_EH_PE_uleb128
        return ULEB128
    elseif data_enc == DWARF.DW_EH_PE_absptr
        return Ptr{Void}
    elseif data_enc == DWARF.DW_EH_PE_omit
        return Void
    elseif data_enc == DWARF.DW_EH_PE_udata2
        return UInt16
    elseif data_enc == DWARF.DW_EH_PE_udata4
        return UInt32
    elseif data_enc == DWARF.DW_EH_PE_udata8
        return UInt64
    elseif data_enc == DWARF.DW_EH_PE_sleb128
        return SLEB128
    elseif data_enc == DWARF.DW_EH_PE_sdata2
        return Int16
    elseif data_enc == DWARF.DW_EH_PE_sdata4
        return Int32
    elseif data_enc == DWARF.DW_EH_PE_sdata8
        return Int64
    else
        @show data_enc
        error("Unknown encoding type")
    end
end


function read_encoded(io, encoding)
    (encoding == DWARF.DW_EH_PE_omit) && return nothing
    res = read(io, encoding_type(encoding))
    base_enc = encoding & 0x70
    res = (base_enc == DWARF.DW_EH_PE_datarel) ? DataRel(res) :
        (base_enc == DWARF.DW_EH_PE_pcrel) ? PcRel(res) :
        (@assert base_enc == DWARF.DW_EH_PE_absptr; res)
    (base_enc & 0x80 != 0) && (res = Indirect(res))
    res
end

typealias Encoded Union{Integer, DataRel, PcRel}

# eh_frame_hdr parsing
immutable eh_frame_hdr
    eh_frame_ptr::Encoded
    fde_count::UInt
    table_offset::UInt
    table_enc::UInt8
end

function read(io::SectionRef, ::Type{eh_frame_hdr})
    seekstart(io)
    version = read(io, UInt8)
    @assert version == 1
    eh_frame_ptr_enc = read(io, UInt8)
    fde_count_enc = read(io, UInt8)
    table_enc = read(io, UInt8)
    eh_frame_ptr = read_encoded(io, eh_frame_ptr_enc)
    fde_count = UInt(read_encoded(io, fde_count_enc))
    eh_frame_hdr(eh_frame_ptr, fde_count, position(io), table_enc)
end

immutable EhFrameRef <: Base.AbstractArray{Tuple,1}
    header::eh_frame_hdr
    hdr_sec::SectionRef
    frame_sec::SectionRef
end
EhFrameRef(hdr_sec::SectionRef, frame_sec::SectionRef) =
    EhFrameRef(read(hdr_sec, eh_frame_hdr), hdr_sec, frame_sec)
Base.length(ehfr::EhFrameRef) = Int(ehfr.header.fde_count)
Base.size(ehfr::EhFrameRef) = (length(ehfr),)

function compute_entry_type(ehfr)
    enc = ehfr.header.table_enc
    # First check that the encoding is indeed datarel
    @assert (enc & 0xf0) == DWARF.DW_EH_PE_datarel
    entry_field_T = encoding_type(enc)
    # We also require fixed-size entries, otherwise we can't really binary search
    @assert !isa(entry_field_T, DWARF.LEB128)
    entry_field_T
end

seekentry(ehfr, idx, entry_size=2sizeof(compute_entry_type(ehfr))) =
    seek(ehfr.hdr_sec, ehfr.header.table_offset + (idx-1)*entry_size)
function Base.getindex(ehdr::EhFrameRef, idx, entry_type=compute_entry_type(ehdr))
    seekentry(ehdr, idx, 2sizeof(entry_type))
    ip = read(ehdr.hdr_sec, entry_type)
    offset = read(ehdr.hdr_sec, entry_type)
    (ip, offset)
end

"""
Searches for an FDE covering an ip, represented as an offset from the start
of the eh_frame_hdr section
"""
function search_fde_offset(frame_sec, tab, offset, offs_slide = 0)
    found_idx = searchsortedlast(tab, (offset, 0),by = x->x[1])
    (found_idx == 0) && error("Not found")
    (tab[found_idx][1], FDERef(frame_sec, offs_slide + tab[found_idx][2], true))
end

# eh_frame parsing
immutable RegNum
    num::UInt64
end
function Base.print(io::IO, r::RegNum)
    print(io, "%", (isa(io,IOContext) && haskey(io,:reg_map)) ?
        get(io,:reg_map,:unknown)[r.num] : r.num)
end
Base.convert(::Type{Int}, r::RegNum) = Int(r.num)

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
typealias CFAState Union{Tuple{RegNum,Int},Expr,Undef}
type RegStates
    values :: Dict{Int,RegState}
    stack :: Vector{Tuple{CFAState, Dict{Int,RegState}}}
    cfa :: CFAState # either (reg,offset) or a DWARF expr
    delta :: Int
end
RegStates() = RegStates(Dict{Int,RegState}(), Vector{Dict{Int,RegState}}(), Undef(), 0)
Base.copy(s::RegStates) = RegStates(copy(s.values),copy(s.stack),s.cfa,s.delta)

Base.getindex(s :: RegStates, n) = get(s.values, n, Undef())
Base.setindex!(s :: RegStates, val::RegState, n :: Union{Int, RegNum}) =
    isa(val,Undef) ? delete!(s.values, Int(n)) : s.values[Int(n)] = val
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
immutable CIE
    code_align :: Int
    data_align :: Int
    addr_format :: UInt8
    return_reg :: UInt8
    initial_code :: Vector{UInt8}
end
function Base.show(io::IO, cie::CIE)
    @printf(io, "CIE align (code:%#x data:%#x) (addr format %s) %d bytes of instructions", cie.code_align, cie.data_align, cie.addr_format, length(cie.initial_code))
end

function operands(ops, opcode, addrT)
    if opcode == DWARF.DW_CFA_nop || opcode == DWARF.DW_CFA_remember_state ||
            opcode == DWARF.DW_CFA_restore_state
        return ()
    elseif (opcode & 0xc0) == DWARF.DW_CFA_advance_loc
        return (opcode & ~0xc0,)
    elseif (opcode & 0xc0) == DWARF.DW_CFA_restore
        return (RegNum(opcode & ~0xc0),)
    elseif (opcode & 0xc0) == DWARF.DW_CFA_offset
        return (RegNum(opcode & ~0xc0), UInt(read(ops, ULEB128)))
    elseif opcode == DWARF.DW_CFA_set_loc
        return (read(ops, addrT),)
    elseif opcode == DWARF.DW_CFA_advance_loc1
        return (read(ops, UInt8),)
    elseif opcode == DWARF.DW_CFA_advance_loc2
        return (read(ops, UInt16),)
    elseif opcode == DWARF.DW_CFA_advance_loc4
        return (read(ops, UInt32),)
    elseif opcode == DWARF.DW_CFA_offset_extended || opcode == DWARF.DW_CFA_def_cfa
        reg = RegNum(read(ops, ULEB128))
        offset = UInt(read(ops, ULEB128))
        return (reg, offset)
    elseif opcode == DWARF.DW_CFA_offset_extended_sf || opcode == DWARF.DW_CFA_def_cfa_sf
        reg = RegNum(read(ops, ULEB128))
        offset = Int(read(ops, SLEB128))
        return (reg, offset)
    elseif opcode == DWARF.DW_CFA_register
        reg1 = RegNum(read(ops, ULEB128))
        reg2 = RegNum(read(ops, ULEB128))
        return (reg1, reg2)
    elseif opcode == DWARF.DW_CFA_restore_extended || opcode == DWARF.DW_CFA_undefined ||
            opcode == DWARF.DW_CFA_same_value || opcode == DWARF.DW_CFA_def_cfa_register
        return (RegNum(read(ops, ULEB128)),)
    elseif opcode == DWARF.DW_CFA_def_cfa_offset
        return (UInt(read(ops, ULEB128)),)
    elseif opcode == DWARF.DW_CFA_def_cfa_expression
        length = UInt(read(ops, ULEB128))
        return (read(ops, UInt8, length),)
    elseif opcode == DWARF.DW_CFA_expression
        reg =  RegNum(read(ops, ULEB128))
        length = UInt(read(ops, ULEB128))
        return (reg, read(ops, UInt8, length))
    elseif opcode == DWARF.DW_CFA_val_expression
        val = UInt(read(ops, ULEB128))
        length = UInt(read(ops, ULEB128))
        return (val, read(ops, UInt8, length))
    elseif opcode == DWARF.DW_CFA_def_cfa_offset_sf
        return (Int(read(ops, SLEB128)), )
    elseif opcode == DWARF.DW_CFA_val_offset
        val = UInt(read(ops, ULEB128))
        offset = UInt(read(ops, ULEB128))
        return (val, offset)
    elseif opcode == DWARF.DW_CFA_val_offset_sf
        val = UInt(read(ops, ULEB128))
        offset = Int(read(ops, SLEB128))
        return (val, offset)
    else
        error("Unknown opcode")
    end
end

function evaluage_op(s :: RegStates, ops, cie :: CIE; initial_rs = RegStates())
    op = read(ops, UInt8)
    # Section 6.4.2 of DWARF 4
    opops = operands(ops, op, UInt64)
    if op == DWARF.DW_CFA_set_loc                 # 6.4.2.1 Row creation
        error()
    elseif (op & 0xc0) == DWARF.DW_CFA_advance_loc || op == DWARF.DW_CFA_advance_loc1 ||
            op == DWARF.DW_CFA_advance_loc2 || op == DWARF.DW_CFA_advance_loc4
        s.delta += opops[1] * cie.code_align
    elseif op == DWARF.DW_CFA_def_cfa             # 6.4.2.2 CFA definitions
        s.cfa = (opops[1], Int(opops[2]))
    elseif op == DWARF.DW_CFA_def_cfa_sf
        s.cfa = (opops[1], Int(opops[2]*cie.data_align))
    elseif op == DWARF.DW_CFA_def_cfa_register
        s.cfa = (opops[1], s.cfa[2])
    elseif op == DWARF.DW_CFA_def_cfa_offset
        s.cfa = (s.cfa[1], Int(opops[1]))
    elseif op == DWARF.DW_CFA_def_cfa_offset_sf
        s.cfa = (s.cfa[1], Int(opops[1]*cie.data_align))
    elseif op == DWARF.DW_CFA_def_cfa_expression
        s.cfa = Expr(opops[1], false)
    elseif op == DWARF.DW_CFA_undefined           # 6.4.2.3 Register rules
        s[opops[1]] = Undef()
    elseif op == DWARF.DW_CFA_same_value
        s[opops[1]] = Same()
    elseif (op & 0xc0) == DWARF.DW_CFA_offset
        s[opops[1]] = Offset(Int(opops[2])*cie.data_align, false)
    elseif op == DWARF.DW_CFA_offset_extended || op == DWARF.DW_CFA_offset_extended_sf
    # Note, we assume here that DW_CFA_offset_extended uses a factored offset
    # even though the DWARF specification does not clearly state this.
        s[opops[1]] = Offset(Int(opops[2])*cie.data_align, false)
    elseif op == DWARF.DW_CFA_val_offset || op == op == DWARF.DW_CFA_val_offset_sf
        s[opops[1]] = Offset(opops[2]*cie.data_align, true)
    elseif op == DWARF.DW_CFA_register
        s[opops[1]] = Reg(opops[2])
    elseif op == DWARF.DW_CFA_expression ||
           op == DWARF.DW_CFA_val_expression
        error()
    elseif (op & 0xc0) == DWARF.DW_CFA_restore ||
           op == DWARF.DW_CFA_restore_extended
        s[opops[1]] = initial_rs[opops[1]]
    elseif op == DWARF.DW_CFA_remember_state    # 6.4.2.4 Row state
        push!(s.stack, (copy(s.cfa), copy(s.values)))
    elseif op == DWARF.DW_CFA_restore_state
        s.cfa, s.values = pop!(s.stack)
    elseif op == DWARF.DW_CFA_nop                 # 6.4.2.5 Padding
    else
        error("unknown CFA opcode $op")
    end
end

function read_lenid(io)
    len = read(io, UInt32)
    len > 0 || return error()
    if len == 0xffffffff
        len = read(io, UInt64)
    end
    begpos = position(io)
    id = read(io, UInt32)
    len, begpos, id
end

function realize(ref::CIERef)
    seek(ref.eh_frame, ref.offset)
    len, begpos, id = read_lenid(ref.eh_frame)
    @assert id == 0
    read_cie(ref.eh_frame, len)
end

function _dump_program(out, bytes, eh_frame, endpos, cie, target=0, rs = RegStates())
    bytes && (return read(eh_frame, UInt8, endpos - position(eh_frame)))
    while position(eh_frame) < endpos
        oppos = position(eh_frame)
        op = read(eh_frame, UInt8)
        opcode = (op & 0xc0) != 0 ? (op & 0xc0) : op
        print_with_color(:blue, out, DWARF.DW_CFA[opcode])
        for operand in operands(eh_frame, op, encoding_type(cie.addr_format))
            print(out, ' ')
            if isa(operand, Array)
                DWARF.Expressions.print_expression(out,
                    encoding_type(cie.addr_format), operand, :NativeEndian)
            else
                print(out, operand)
            end
        end
        
        seek(eh_frame, oppos)
        evaluage_op(rs, eh_frame, cie)
        if (op & 0xc0) == DWARF.DW_CFA_advance_loc || op == DWARF.DW_CFA_advance_loc1 ||
                op == DWARF.DW_CFA_advance_loc2 || op == DWARF.DW_CFA_advance_loc4
            print(out," (=> $(rs.delta))")
        end
        println(out)
        if target != 0 && rs.delta > target
            print_with_color(:red, out, "--------------\n")
            target = 0
        end
    end
    (target != 0 && print_with_color(:red, out, "--------------\n"))
end

function _prepare_program(f, fde::FDERef, cie = nothing)
    eh_frame = fde.eh_frame
    seek(eh_frame, fde.offset)
    length = read(eh_frame, UInt32)
    (length == ~UInt32(0)) && (length = read(eh_frame, UInt64))
    startpos = position(eh_frame)
    if cie == nothing
        # Obtain CIERef
        CIE_pointer = read(eh_frame, typeof(length))
        cie = CIERef(eh_frame, fde.is_eh_not_debug ?
            startpos - CIE_pointer : CIE_pointer)
        cie = realize(cie)
    end
    seek(eh_frame, startpos + sizeof(length) + 2sizeof(encoding_type(cie.addr_format)))
    augment_length = UInt(read(eh_frame, ULEB128))
    seek(eh_frame, position(eh_frame) + augment_length)
    f(eh_frame, startpos + length, cie, augment_length)
end
realize_cie(fde) = _prepare_program((a,b,cie,augment_length)->cie, fde)

"""
Returns the inital ip as a module-relative offset.
"""
initial_loc(fde, cie = nothing) = _prepare_program(fde, cie) do eh_frame, _, cie, augment_length
    pos = position(eh_frame)-2sizeof(encoding_type(cie.addr_format))-augment_length-1
    seek(eh_frame, pos)
    pos = position(handle(eh_frame))
    enc = read_encoded(eh_frame, cie.addr_format)
    if isa(enc, PcRel)
        enc = pos + Int64(enc.ptr)
    end
    enc
end

"""
Returns the final ip as a module-relative offset.
"""
fde_range(fde, cie = nothing) = _prepare_program(fde, cie) do eh_frame, _, cie, augment_length
    pos = position(eh_frame)-2sizeof(encoding_type(cie.addr_format))-augment_length-1
    seek(eh_frame, pos)
    read_encoded(eh_frame, cie.addr_format)
    enc = read_encoded(eh_frame, cie.addr_format)
    if isa(enc, PcRel) # The modifier does not apply to the range
        enc = enc.ptr
    end
    enc
end

dump_program(out::IO, fde::FDERef; cie = nothing, bytes = false, target = 0, rs = RegStates()) =
    _prepare_program((a,b,c,_)->_dump_program(out, bytes, a,b,c, target, rs), fde, cie)

dump_program(out, cie::CIE; bytes = false, target = 0, rs = RegStates()) =
    _dump_program(out,  bytes, IOBuffer(cie.initial_code),
        length(cie.initial_code), cie, target, rs)

function evaluate_program(code::Union{IO, SectionRef}, target,
        cie, rs = RegStates(), maxpos = (-1 % UInt); initial_rs = RegStates())
    while !eof(code) && position(code) < maxpos && rs.delta <= target
        evaluage_op(rs, code, cie; initial_rs=initial_rs)
    end
    rs
end

function evaluate_program(fde::FDERef, target; cie = nothing)
    _prepare_program(fde, cie) do eh_frame, endpos, cie, augment_length
        rs = RegStates()
        evaluate_program(IOBuffer(cie.initial_code), target, cie, rs)
        evaluate_program(eh_frame, target, cie, rs, endpos; initial_rs = copy(rs))
        rs
    end
end

immutable FDEIterator
    eh_frame::SectionRef
end
Base.iteratorsize(::Type{FDEIterator}) = Base.SizeUnknown()
Base.done(x::FDEIterator, offset) = offset >= sectionsize(x.eh_frame)

function forward_to_fde(eh_frame, offset, skipfirst = true)
    while true
        seek(eh_frame, offset)
        eof(eh_frame) && break
        len, begpos, id = read_lenid(eh_frame)
        # Check if we found an fde
        !skipfirst && (id != 0) && return offset
        skipfirst = false
        offset = begpos + len
    end
    return offset
end

Base.start(x::FDEIterator) = forward_to_fde(x.eh_frame, 0, false)
function Base.next(x::FDEIterator, offset)
    return (FDERef(x.eh_frame, offset, true), forward_to_fde(x.eh_frame, offset))
end

function read_cie(io, len)
    beg_pos = position(io) - sizeof(len)
    version = read(io, UInt8)
    augment = read_cstring(io)
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
    code_align = read(io, ULEB128)
    data_align = read(io, SLEB128)
    return_reg = read(io, UInt8)
    if has_augment_data
        augment_length = convert(Int, read(io, ULEB128))
        a_pos = position(io)
        seek(io, a_pos)
        for i = 2:length(augment)
            if augment[i] == 'R'
                addr_format = read(io, UInt8)
            elseif augment[i] == 'L'
                read(io, UInt8) # TODO use that maybe
            elseif augment[i] == 'P'
                read_encoded(io, read(io, UInt8)) # TODO ditto
            elseif augment[i] == 'S'
                # TODO: ditto (represents a signal frame)
            else
                warn("unknown augment data '$(Char(augment[i]))' in '$(bytestring(augment))'")
            end
        end
        seek(io, augment_length + a_pos)
    end
    code = read(io, UInt8, len - (position(io) - beg_pos))
    CIE(code_align, data_align, addr_format, return_reg, code)
end
function Base.read(io::IO, ::Type{CIE})
    len, begpos, id = read_lenid(io)
    read_cie(io, len)
end

end
