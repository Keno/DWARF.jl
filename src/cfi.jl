module CallFrameInfo

using DWARF
using DWARF: SLEB128, ULEB128
import DWARF.tag, DWARF.children, DWARF.attributes
using ObjFileBase
using ObjFileBase: DebugSections, ObjectHandle, handle
import Base: read, setindex!
using Base: @pure
function read_cstring(io)
    a = Array{UInt8}(0)
    while (x = read(io, UInt8)) != 0
        push!(a, x)
    end
    a
end

export realize_cie, initial_loc, FDEIterator, fde_range, realize_cieoff

# Reference type

immutable FDERef{SR<:SectionRef}
    eh_frame::SR
    offset::UInt
    # Distinguish between FDEs in eh_frame (true) or debug_frame
    is_eh_not_debug::Bool
    ptrT::Type{T} where T<:Union{UInt32, UInt64}
end

immutable CIERef{SR<:SectionRef}
    eh_frame::SR
    offset::UInt
    ptrT::Type{T} where T<:Union{UInt32, UInt64}
end


# Dwarf encoding
immutable DataRel; ptr; end
immutable PcRel; ptr; end
immutable Indirect; ptr; end

@pure function encoding_type(encoding, ptrT)
    data_enc = (encoding & 0xf)
    if data_enc == DWARF.DW_EH_PE_uleb128
        return ULEB128
    elseif data_enc == DWARF.DW_EH_PE_absptr
        return ptrT
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
        error("Unknown encoding type ($data_enc)")
    end
end
const sizeof_map = UInt8[try; sizeof(encoding_type(i,UInt64)); catch; 0; end for i=0:0xc]
sizeof_encoding_type(enc, ptrT) = ((enc&0xf) == DWARF.DW_EH_PE_absptr) ? sizeof(ptrT) : sizeof_map[(enc&0xf)+1]



function read_encoded(io, encoding, ptrT)
    (encoding == DWARF.DW_EH_PE_omit) && return nothing
    res = read(io, encoding_type(encoding, ptrT))
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

function read{T<:ObjFileBase.ObjectHandle}(io::SectionRef{T}, ::Type{eh_frame_hdr})
    seekstart(io)
    version = read(io, UInt8)
    @assert version == 1
    eh_frame_ptr_enc = read(io, UInt8)
    fde_count_enc = read(io, UInt8)
    table_enc = read(io, UInt8)
    ptrT = ObjFileBase.intptr(ObjFileBase.handle(io))
    eh_frame_ptr = read_encoded(io, eh_frame_ptr_enc, ptrT)
    fde_count = UInt(read_encoded(io, fde_count_enc, ptrT))
    eh_frame_hdr(eh_frame_ptr, fde_count, position(io), table_enc)
end

immutable EhFrameRef{SR <: SectionRef} <: Base.AbstractArray{Tuple,1}
    header::eh_frame_hdr
    hdr_sec::SR
    frame_sec::SR
end
EhFrameRef(hdr_sec::SectionRef, frame_sec::SectionRef) =
    EhFrameRef(read(hdr_sec, eh_frame_hdr), hdr_sec, frame_sec)
Base.length(ehfr::EhFrameRef) = Int(ehfr.header.fde_count)
Base.size(ehfr::EhFrameRef) = (length(ehfr),)

@pure function compute_entry_type(enc::Integer, ptrT)
    # First check that the encoding is indeed datarel
    @assert (enc & 0xf0) == DWARF.DW_EH_PE_datarel
    entry_field_T = encoding_type(enc, ptrT)
    # We also require fixed-size entries, otherwise we can't really binary search
    @assert !isa(entry_field_T, DWARF.LEB128)
    entry_field_T
end
compute_entry_type(ehfr::EhFrameRef,
    ptrT=ObjFileBase.intptr(ObjFileBase.handle(ehfr.hdr_sec))) =
        compute_entry_type(ehfr.header.table_enc, ptrT)

seekentry(ehfr, idx, entry_size=2sizeof(compute_entry_type(ehfr))) =
    seek(ehfr.hdr_sec, ehfr.header.table_offset + (idx-1)*entry_size)
function Base.getindex{T}(ehdr::EhFrameRef, idx, entry_type::Type{T})
    seekentry(ehdr, idx, 2sizeof(entry_type))
    ip = read(ehdr.hdr_sec, entry_type)::entry_type
    offset = read(ehdr.hdr_sec, entry_type)::entry_type
    (Int(ip), Int(offset))
end
function Base.getindex(ehfr::EhFrameRef, idx)
    # Fast-path the standard case
    enc = ehfr.header.table_enc
    if enc == 0x3b
        # ptrT is irrelevant
        Base.getindex(ehfr, idx, compute_entry_type(0x3b, UInt64))
    else
        Base.getindex(ehfr, idx, compute_entry_type(ehfr))::Tuple{Int,Int}
    end
end

# This is a huge performance hotspot. Hand optimize it.
function searchsortedlast_fde{T}(ehfr::EhFrameRef, offset, entry_type::Type{T})
    lo = 0
    hi = length(ehfr)
    @inbounds while lo < hi-1
        m = (lo+hi)>>>1
        seekentry(ehfr, m+1, 2sizeof(entry_type))
        if offset < read(ehfr.hdr_sec, entry_type)::entry_type
            hi = m
        else
            lo = m
        end
    end
    return lo+1
end
function searchsortedlast_fde(ehfr::EhFrameRef, offset)
    # Fast-path the standard case
    enc = ehfr.header.table_enc
    enc == 0x3b ? searchsortedlast_fde(ehfr, offset, compute_entry_type(0x3b, UInt64)) :
        searchsortedlast_fde(ehfr, offset, compute_entry_type(ehfr))
end
searchsortedlast_fde(tab, offset) = searchsortedlast(tab, (offset, 0),by = x->x[1])

"""
Searches for an FDE covering an ip, represented as an offset from the start
of the eh_frame_hdr section
"""
function search_fde_offset(frame_sec, tab, offset, offs_slide = 0;
        is_eh_not_debug = true, ptrT = ObjFileBase.intptr(ObjFileBase.handle(frame_sec)))
    found_idx = searchsortedlast_fde(tab, offset)
    (found_idx == 0) && error("Not found")
    res = tab[found_idx]
    (res[1], FDERef(frame_sec, UInt64(offs_slide + res[2]), is_eh_not_debug, ptrT))
end

# eh_frame parsing
immutable RegNum
    num::Int
end
const RegCFA = RegNum(-1)
function Base.print(io::IO, r::RegNum)
    if r == RegCFA
        print(io, "%cfa")
    else
        print(io, "%", (isa(io,IOContext) && haskey(io,:reg_map)) ?
              get(io,:reg_map,:unknown)[r.num] : r.num)
    end
end
Base.convert(::Type{Int}, r::RegNum) = Int(r.num)

immutable Expr
    opcodes :: Vector{UInt8}
    is_val :: Bool
end
const ExprNone = Expr(Array{UInt8}(0), false)
module Flag
const Undef = 0
const Same = 1
const Val = 2
const Deref = 3
# if the RegState is DwarfExpr the actual expression is elsewhere in the RegStates container
const DwarfExpr = 4
end
immutable RegState
    base :: RegNum
    offset :: Int
    flag :: UInt8
end
const ExprRegState = RegState(RegNum(-2),0,Flag.DwarfExpr)
Offset(r::RegNum, n::Int) = RegState(r, n, Flag.Val)
Load(r::RegNum, n::Int) = RegState(r, n, Flag.Deref)
Undef() = RegState(RegNum(-2),0, Flag.Undef)
Same() = RegState(RegNum(-2),0, Flag.Same)
Reg(n::Int) = RegState(RegNum(n),0,Flag.Val)

function Base.show(io::IO, r::RegState)
    if r.flag == Flag.Undef
        print(io, "undef")
    elseif r.flag == Flag.Same
        print(io, "same")
    elseif r.flag == Flag.DwarfExpr
        print(io, "expr")
    elseif r.flag == Flag.Val
        @printf(io, "%s + %#x", r.base, r.offset)
    elseif r.flag == Flag.Deref
        @printf(io, "*(%s + %#x)", r.base, r.offset)
    else
        error()
    end
end
isundef(r::RegState) = r.flag == Flag.Undef
issame(r::RegState) = r.flag == Flag.Same
isdwarfexpr(r::RegState) = r.flag == Flag.DwarfExpr
const StackT = Tuple{Dict{Int,RegState},Dict{Int,Expr},RegState,Expr}
type RegStates
    values :: Dict{Int,RegState}
    values_expr :: Dict{Int,Expr}
    stack :: Vector{StackT}
    cfa :: RegState
    cfa_expr :: Expr
    delta :: Int
end
RegStates() = RegStates(Dict{Int,RegState}(), Dict{Int,Expr}(), Array{StackT}(0), Undef(), ExprNone, 0)
Base.copy(s::RegStates) = RegStates(copy(s.values),copy(s.values_expr),copy(s.stack),s.cfa,s.cfa_expr,s.delta)

Base.getindex(s :: RegStates, n) = get(s.values, n, Undef())
function Base.setindex!(s :: RegStates, val::RegState, n :: Union{Integer, RegNum})
    @assert(!isdwarfexpr(val))
    if isundef(val)
        delete!(s.values, Int(n))
    else
        s.values[Int(n)] = val
    end
    nothing
end
function Base.setindex!(s :: RegStates, val :: Expr, n :: Union{Integer, RegNum})
    s.values[Int(n)] = ExprRegState
    s.values_expr[Int(n)] = val
end
function Base.show(io::IO, s :: RegStates)
    print(io, "RegStates [", s.delta, "] cfa: ")
    println(io, s.cfa)
    for (k,v) in s.values
        println(io, "\t", RegNum(k), " = ", v)
    end
end

immutable CIE
    code_align :: Int
    data_align :: Int
    addr_format :: UInt8
    return_reg :: UInt8
    initial_code :: Vector{UInt8}
    has_augment_data :: Bool
end
function Base.show(io::IO, cie::CIE)
    @printf(io, "CIE align (code:%#x data:%#x) (addr format %s) %d bytes of instructions", cie.code_align, cie.data_align, cie.addr_format, length(cie.initial_code))
end

operands(ops, opcode, ::Union{Val{DWARF.DW_CFA_nop}, Val{DWARF.DW_CFA_remember_state},
                    Val{DWARF.DW_CFA_restore_state}}, addrT)  = ()
operands(ops, opcode, ::Val{DWARF.DW_CFA_advance_loc}, addrT)  = (opcode & ~0xc0,)
operands(ops, opcode, ::Val{DWARF.DW_CFA_restore}, addrT)      = (RegNum(opcode & ~0xc0),)
operands(ops, opcode, ::Val{DWARF.DW_CFA_offset}, addrT)       = (RegNum(opcode & ~0xc0), UInt(read(ops, ULEB128)))
operands(ops, opcode, ::Val{DWARF.DW_CFA_set_loc}, addrT)      = (read(ops, addrT),)
operands(ops, opcode, ::Val{DWARF.DW_CFA_advance_loc1}, addrT) = (read(ops, UInt8),)
operands(ops, opcode, ::Val{DWARF.DW_CFA_advance_loc2}, addrT) = (read(ops, UInt16),)
operands(ops, opcode, ::Val{DWARF.DW_CFA_advance_loc4}, addrT) = (read(ops, UInt32),)
operands(ops, opcode, ::Val{DWARF.DW_CFA_def_cfa_offset}, addrT) = (UInt(read(ops, ULEB128)),)
function operands(ops, opcode, ::Union{Val{DWARF.DW_CFA_offset_extended},
        Val{DWARF.DW_CFA_def_cfa}}, addrT)
    reg = RegNum(read(ops, ULEB128))
    offset = UInt(read(ops, ULEB128))
    return (reg, offset)
end
function operands(ops, opcode, ::Union{Val{DWARF.DW_CFA_offset_extended_sf},
        Val{DWARF.DW_CFA_def_cfa_sf}}, addrT)
    reg = RegNum(read(ops, ULEB128))
    offset = Int(read(ops, SLEB128))
    return (reg, offset)
end
function operands(ops, opcode, ::Val{DWARF.DW_CFA_register}, addrT)
    reg1 = RegNum(read(ops, ULEB128))
    reg2 = RegNum(read(ops, ULEB128))
    return (reg1, reg2)
end
function operands(ops, opcode, ::Union{Val{DWARF.DW_CFA_restore_extended},
        Val{DWARF.DW_CFA_undefined}, Val{DWARF.DW_CFA_same_value},
        Val{DWARF.DW_CFA_def_cfa_register}}, addrT)
    return (RegNum(read(ops, ULEB128)),)
end
function operands(ops, opcode, ::Val{DWARF.DW_CFA_def_cfa_expression}, addrT)
    length = UInt(read(ops, ULEB128))
    return (read(ops, UInt8, length),)
end
function operands(ops, opcode, ::Val{DWARF.DW_CFA_expression}, addrT)
    reg =  RegNum(read(ops, ULEB128))
    length = UInt(read(ops, ULEB128))
    return (reg, read(ops, UInt8, length))
end
function operands(ops, opcode, ::Val{DWARF.DW_CFA_val_expression}, addrT)
    val = UInt(read(ops, ULEB128))
    length = UInt(read(ops, ULEB128))
    return (val, read(ops, UInt8, length))
end
function operands(ops, opcode, ::Val{DWARF.DW_CFA_def_cfa_offset_sf}, addrT)
    return (Int(read(ops, SLEB128)), )
end
function operands(ops, opcode, ::Val{DWARF.DW_CFA_val_offset}, addrT)
    val = UInt(read(ops, ULEB128))
    offset = UInt(read(ops, ULEB128))
    return (val, offset)
end
function operands(ops, opcode, ::Val{DWARF.DW_CFA_val_offset_sf}, addrT)
    val = UInt(read(ops, ULEB128))
    offset = Int(read(ops, SLEB128))
    return (val, offset)
end
operands{u}(ops, opcode::Val{u}, addrT) = error("Unknown opcode $u")
function operands(ops, opcode::Integer, addrT)
    op = (opcode & 0xc0)
    (op == 0) && (op = opcode)
    operands(ops, opcode, Val{op}(), addrT)
end

# This rewrites an ifnest
# if a == 4
# end
# into
# if a == 4
# a = 4
# end
# which is currently required for type inference to do its job. Once type
# inference improves, this should be removed.
using Base.Meta
function rewrite_condition(assgn, expr)
    if isexpr(expr, :if)
        condition = expr.args[1]
        if isexpr(condition, :(||))
            or = condition
            condition = condition.args[1]
            expr.args[1] = condition
            oldargs3 = expr.args[3]
            expr.args[3] = quote
                if $(or.args[2])
                    $(copy(expr.args[2]))
                else
                    $oldargs3
                end
            end
        end
        @assert isexpr(condition, :call) && condition.args[1] == :(==)
        eq = Base.Expr(:(=), condition.args[2], condition.args[3])
        expr.args[2] = quote
            $eq
            let $assgn
                $(expr.args[2])
            end
        end
        for i = 1:length(expr.args[3].args)
            expr.args[3].args[i] = rewrite_condition(assgn, expr.args[3].args[i])
        end
    elseif isexpr(expr, :block)
        for i = 1:length(expr.args)
            expr.args[i] = rewrite_condition(assgn, expr.args[i])
        end
    end
    expr
end

macro rewrite_if(assgn, ifnest)
    expr = rewrite_condition(assgn, ifnest)
    esc(expr)
end

# This function is a bit of a hotspot. The slightly odd structure is the result
# of wanting to be able to use the same code to inspect (print) and evaluate the
# operands. Naively, one could evaluate the operands first. However, since
# typeinference is not path-sensitive that would be slow. Instead, we call the
# operands() function only once op is known, which should allow type inference
# to fully inline the function.
function evaluate_op(s :: RegStates, opio, cie :: CIE, initial_rs = RegStates())
    opcode = read(opio, UInt8)
    op = (opcode & 0xc0)
    (op == 0) && (op = opcode)
    # Section 6.4.2 of DWARF 4
    # The macro is for performance, you may pretend it isn't there when reading
    # this code.
    @rewrite_if (opops = operands(opio, opcode, Val{op}(), UInt64)) if (
        op == DWARF.DW_CFA_set_loc)                # 6.4.2.1 Row creation
        error()
    elseif op == DWARF.DW_CFA_advance_loc || op == DWARF.DW_CFA_advance_loc1 ||
            op == DWARF.DW_CFA_advance_loc2 || op == DWARF.DW_CFA_advance_loc4
        s.delta += opops[1] * cie.code_align
    elseif op == DWARF.DW_CFA_def_cfa             # 6.4.2.2 CFA definitions
        s.cfa = Offset(opops[1], Int(opops[2]))
    elseif op == DWARF.DW_CFA_def_cfa_sf
        s.cfa = Offset(opops[1], Int(opops[2]*cie.data_align))
    elseif op == DWARF.DW_CFA_def_cfa_register
        s.cfa = Offset(opops[1], s.cfa.offset)
    elseif op == DWARF.DW_CFA_def_cfa_offset
        s.cfa = Offset(s.cfa.base, Int(opops[1]))
    elseif op == DWARF.DW_CFA_def_cfa_offset_sf
        s.cfa = Offset(s.cfa.base, Int(opops[1]*cie.data_align))
    elseif op == DWARF.DW_CFA_def_cfa_expression
        s.cfa = ExprRegState
        s.cfa_expr = Expr(opops[1], false)
    elseif op == DWARF.DW_CFA_undefined           # 6.4.2.3 Register rules
        s[opops[1]] = Undef()
    elseif op == DWARF.DW_CFA_same_value
        s[opops[1]] = Same()
    elseif op == DWARF.DW_CFA_offset
        s[opops[1]] = Load(RegCFA, Int(opops[2])*cie.data_align)
    elseif op == DWARF.DW_CFA_offset_extended || op == DWARF.DW_CFA_offset_extended_sf
    # Note, we assume here that DW_CFA_offset_extended uses a factored offset
    # even though the DWARF specification does not clearly state this.
        s[opops[1]] = Load(RegCFA, Int(opops[2])*cie.data_align)
    elseif op == DWARF.DW_CFA_val_offset || op == DWARF.DW_CFA_val_offset_sf
        s[opops[1]] = Offset(RegCFA, opops[2]*cie.data_align)
    elseif op == DWARF.DW_CFA_register
        s[opops[1]] = Reg(opops[2])
    elseif op == DWARF.DW_CFA_expression ||
           op == DWARF.DW_CFA_val_expression
        s[opops[1]] = Expr(opops[2], op == DWARF.DW_CFA_val_expression)
    elseif op == DWARF.DW_CFA_restore ||
           op == DWARF.DW_CFA_restore_extended
        s[opops[1]] = initial_rs[opops[1]]
    elseif op == DWARF.DW_CFA_remember_state    # 6.4.2.4 Row state
        push!(s.stack, (copy(s.values), copy(s.values_expr), s.cfa, s.cfa_expr))
    elseif op == DWARF.DW_CFA_restore_state
        s.values, s.values_expr, s.cfa, s.cfa_expr = pop!(s.stack)
    elseif op == DWARF.DW_CFA_nop                 # 6.4.2.5 Padding
    else
        error("unknown CFA opcode $op")
    end
    nothing
end

function read_lenid(io)
    len::UInt64 = read(io, UInt32)
    ls = sizeof(UInt32)
    len > 0 || return ls, 0, 0, 0
    if len == 0xffffffff
        len = read(io, UInt64)
        ls = sizeof(UInt64)
    end
    begpos = position(io)
    id = read(io, UInt32)
    ls, len, begpos, id
end

function realize(ref::CIERef)
    seek(ref.eh_frame, ref.offset)
    ls, len, begpos, id = read_lenid(ref.eh_frame)
    @assert (id == 0 || id == ~(typeof(id)(0)))
    read_cie(ref.eh_frame, len, ls, ref.ptrT)
end

function _dump_program(out, bytes, eh_frame, endpos, cie, ptrT, target=0, rs = RegStates())
    bytes && (return read(eh_frame, UInt8, endpos - position(eh_frame)))
    while position(eh_frame) < endpos
        oppos = position(eh_frame)
        op = read(eh_frame, UInt8)
        opcode = (op & 0xc0) != 0 ? (op & 0xc0) : op
        print_with_color(:blue, out, DWARF.DW_CFA[opcode])
        for operand in operands(eh_frame, op, encoding_type(cie.addr_format, ptrT))
            print(out, ' ')
            if isa(operand, Array)
                DWARF.Expressions.print_expression(out, ptrT, operand, :NativeEndian)
            else
                print(out, operand)
            end
        end
        
        seek(eh_frame, oppos)
        evaluate_op(rs, eh_frame, cie)
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

function _prepare_program{R}(f, fde::FDERef{R}, cie = nothing, ciecache = nothing, ccoff=0)
    eh_frame = fde.eh_frame
    seek(eh_frame, fde.offset)
    length = read(eh_frame, UInt32)
    (length == ~UInt32(0)) && (length = read(eh_frame, UInt64))
    startpos = position(eh_frame)
    # Split to create optimization boundary
    # Manual union splitting
    if typeof(length) == UInt32
        __prepare_program(f, fde, cie, ciecache, length::UInt32, startpos, ccoff)
    else
        __prepare_program(f, fde, cie, ciecache, length::UInt64, startpos, ccoff)
    end
end
function __prepare_program{T,R}(f, fde::FDERef{R}, cie::Void, ciecache, length::T, startpos, ccoff)
    eh_frame = fde.eh_frame
    # Obtain CIERef
    CIE_pointer::UInt64 = read(eh_frame, typeof(length))
    cieoff = fde.is_eh_not_debug ? startpos - CIE_pointer : CIE_pointer
    if ciecache == nothing
        __prepare_program(f, fde, realize(CIERef(eh_frame, cieoff, fde.ptrT)), ciecache, length, startpos, 0)
    else
        ccoff = findfirst(ciecache.offsets, cieoff)
        __prepare_program(f, fde, ciecache.cies[ccoff], ciecache, length, startpos, ccoff)
    end
end
function __prepare_program{T,R}(f, fde::FDERef{R}, cie::CIE, ciecache, length::T, startpos, ccoff)
    eh_frame = fde.eh_frame
    seek(eh_frame, startpos + sizeof(length) + 2sizeof_encoding_type(cie.addr_format, fde.ptrT))
    augment_length = cie.has_augment_data ? UInt(read(eh_frame, ULEB128)) : 0
    seek(eh_frame, position(eh_frame) + augment_length)
    cie.has_augment_data && (augment_length += 1) # For the augment_length itself
    f(eh_frame, startpos + length, cie, augment_length, ccoff)
end

function realize_cie(fde, ciecache = nothing)
    f = (a,b,cie,augment_length,__)->cie
    _prepare_program(f, fde, nothing, ciecache)
end

function realize_cieoff(fde, ciecache = nothing)
    f = (a,b,cie,augment_length,ccoff)->(cie,ccoff)
    _prepare_program(f, fde, nothing, ciecache)
end

"""
Returns the inital ip as a module-relative offset.
"""
initial_loc(fde, cie = nothing) = _prepare_program(fde, cie) do eh_frame, _, cie, augment_length, __
    pos = position(eh_frame)-2sizeof_encoding_type(cie.addr_format, fde.ptrT)-augment_length
    seek(eh_frame, pos)
    pos = position(handle(eh_frame))
    enc = read_encoded(eh_frame, cie.addr_format, fde.ptrT)
    if isa(enc, PcRel)
        enc = pos + (enc.ptr%Int64)
    end
    enc
end

"""
Returns the final ip as a module-relative offset.
"""
fde_range(fde, cie = nothing) = _prepare_program(fde, cie) do eh_frame, _, cie, augment_length, __
    pos = position(eh_frame)-2sizeof_encoding_type(cie.addr_format, fde.ptrT)-augment_length
    seek(eh_frame, pos)
    read_encoded(eh_frame, cie.addr_format, fde.ptrT)
    enc = read_encoded(eh_frame, cie.addr_format, fde.ptrT)
    if isa(enc, PcRel) # The modifier does not apply to the range
        enc = enc.ptr
    end
    enc
end

dump_program(out::IO, fde::FDERef; cie = nothing, bytes = false, target = 0, rs = RegStates()) =
    _prepare_program((a,b,c,_,__)->_dump_program(out, bytes, a,b,c, fde.ptrT, target, rs), fde, cie)

dump_program(out, cie::CIE; ptrT = UInt64, bytes = false, target = 0, rs = RegStates()) =
    _dump_program(out,  bytes, IOBuffer(cie.initial_code),
        length(cie.initial_code), cie, ptrT, target, rs)

function evaluate_program(code::IO, target,
        cie, rs = RegStates(), maxpos = (-1 % UInt); initial_rs = RegStates())
    while !eof(code) && position(code) < maxpos && rs.delta <= target
        evaluate_op(rs, code, cie, initial_rs)
    end
    rs
end
function evaluate_program(sec::SectionRef, target,
        cie, rs = RegStates(), maxpos = (-1 % UInt); initial_rs = RegStates())
    iomaxpos = maxpos == (-1 % UInt) ? (-1 % UInt) :
        position(handle(sec).io) + maxpos - position(sec)
    evaluate_program(handle(sec).io, target, cie, rs, iomaxpos; initial_rs = initial_rs)
end

const _dummy_rs = RegStates() # microoptimization
function evaluate_program(fde::FDERef, target; cie = nothing, ciecache = nothing, ccoff = 0)
    _prepare_program(fde, cie, ciecache, ccoff) do eh_frame, endpos, cie, augment_length, ccoff
        if ccoff != 0
            rs = copy(ciecache.initial_rss[ccoff])
        else
            rs = RegStates()
            evaluate_program(IOBuffer(cie.initial_code), target, cie, rs; initial_rs = _dummy_rs)
        end
        evaluate_program(eh_frame, target, cie, rs, endpos; initial_rs = copy(rs))
        rs
    end::RegStates
end

function forward_to_fde_or_cie(eh_frame, offset, is_eh_not_debug=true, skipfirst = true, tofde = true)
    offset = UInt64(offset)
    while true
        seek(eh_frame, offset)
        eof(eh_frame) && break
        ls, len, begpos, id = read_lenid(eh_frame)
        len == 0 && return sectionsize(eh_frame)
        # Check if we found an fde. In eh_frame sections CIE_id is 0, in
        # debug_frame sections CIE_id is 0xffffffff.
        !skipfirst && (tofde $ (is_eh_not_debug ? id == 0 : id == ~(typeof(id)(0)))) && return offset
        skipfirst = false
        offset = UInt64(begpos + len)
    end
    return offset
end

immutable FDEIterator
    eh_frame::SectionRef
    is_eh_not_debug::Bool
    ptrT::Union{Type{UInt32},Type{UInt64}}
end
FDEIterator(eh_frame::SectionRef, ptrT) = FDEIterator(eh_frame, true, ptrT)
Base.iteratorsize(::Type{FDEIterator}) = Base.SizeUnknown()
Base.done(x::FDEIterator, offset) = offset >= sectionsize(x.eh_frame)
Base.start(x::FDEIterator) = forward_to_fde_or_cie(x.eh_frame, 0, x.is_eh_not_debug, false, true)
function Base.next(x::FDEIterator, offset)
    return (FDERef(x.eh_frame, offset, x.is_eh_not_debug, x.ptrT), forward_to_fde_or_cie(x.eh_frame, offset, x.is_eh_not_debug))
end

immutable CIEIterator
    eh_frame::SectionRef
    is_eh_not_debug::Bool
    ptrT::Union{Type{UInt32},Type{UInt64}}
end
CIEIterator(eh_frame, is_eh_not_debug) = CIEIterator(eh_frame, is_eh_not_debug, ObjFileBase.intptr(ObjFileBase.handle(eh_frame)))
Base.iteratorsize(::Type{CIEIterator}) = Base.SizeUnknown()
Base.done(x::CIEIterator, offset) = offset >= sectionsize(x.eh_frame)
Base.start(x::CIEIterator) = forward_to_fde_or_cie(x.eh_frame, 0, x.is_eh_not_debug, false, false)
function Base.next(x::CIEIterator, offset)
    return (CIERef(x.eh_frame, UInt(offset), x.ptrT), forward_to_fde_or_cie(x.eh_frame, offset, x.is_eh_not_debug, true, false))
end

function read_cie(io, len, ls, ptrT)
    beg_pos = position(io) - ls
    version = read(io, UInt8)
    augment = read_cstring(io)
    has_augment_data = false
    has_eh_data = false
    addr_format = DWARF.DW_EH_PE_absptr
    if length(augment) > 0
        if augment[1] == UInt32('z')
            has_augment_data = true
        else
            error("can't parse augment data '$(String(augment))'")
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
            if augment[i] == UInt32('R')
                addr_format = read(io, UInt8)
            elseif augment[i] == UInt32('L')
                read(io, UInt8) # TODO use that maybe
            elseif augment[i] == UInt32('P')
                read_encoded(io, read(io, UInt8), ptrT) # TODO ditto
            elseif augment[i] == UInt32('S')
                # TODO: ditto (represents a signal frame)
            else
                warn("unknown augment data '$(Char(augment[i]))' in '$(bytestring(augment))'")
            end
        end
        seek(io, augment_length + a_pos)
    end
    code = read(io, UInt8, len - (position(io) - beg_pos))
    CIE(code_align, data_align, addr_format, return_reg, code, has_augment_data)
end
function Base.read(io::IO, ::Type{CIE})
    ls, len, begpos, id = read_lenid(io)
    read_cie(io, len, ls)
end

# Precomputing CIE to pull it out of the hot path
immutable CIECache
    offsets::Vector{UInt}
    cies::Vector{CIE}
    initial_rss::Vector{RegStates}
end
CIECache() = CIECache(Vector{UInt}(), Vector{CIE}(), Vector{RegStates}())

function precompute(eh_frame_sec, is_eh_not_debug=true)
    cache = CIECache()
    for cieref in CIEIterator(eh_frame_sec, is_eh_not_debug)
        push!(cache.offsets, cieref.offset)
        push!(cache.cies, realize(cieref))
        rs = RegStates()
        cie = cache.cies[end]
        evaluate_program(IOBuffer(cie.initial_code), 0, cie, rs; initial_rs = _dummy_rs)
        push!(cache.initial_rss, rs)
    end
    cache
end

end
