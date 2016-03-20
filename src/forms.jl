import DWARF: LEB128, LightDIERef
import Base: print, show, convert

# An attribute, encapsulating the name, form and value
immutable Attribute
    spec::AttributeSpecification
    value
end
convert{T}(::Type{T},at::Attribute) = convert(T, at.value)

function Base.show(io::IO, at::Attribute)
    indent = isa(io, IOContext) ? get(io, :indent, 0) : 0
    print(io," "^indent)
    if !haskey(DW_AT, at.spec.name)
        printfield_with_color(:red, io, string("Unknown ($(at.spec.name))"),18; align=:left)
    else
        printfield_with_color(attr_color, io, DW_AT[at.spec.name],18; align=:left)
    end
    printfield(io,string(" [", DW_FORM[at.spec.form], "] "),25, align = :left)
    if at.spec.form == DWARF.DW_FORM_addr
        print(io,"0x",hex(at.value,2sizeof(at.value)))
    elseif at.spec.form == DWARF.DW_FORM_sec_offset
        target_name = ".debug_unkown"
        if at.spec.name == DWARF.DW_AT_stmt_list
            target_name = ".debug_line"
        elseif at.spec.name == DWARF.DW_AT_location
            target_name = ".debug_loc"
        elseif at.spec.name == DWARF.DW_AT_start_scope || at.spec.name == DWARF.DW_AT_ranges
            target_name = ".debug_ranges"
        elseif at.spec.name == DWARF.DW_AT_macro_info
            target_name = ".debug_macinfo"
        end
        print(io,target_name,"[0x",hex(at.value.offset,
            2*sizeof(at.value.offset > typemax(UInt32) ?
                at.value.offset : UInt32)),"]")
    elseif at.spec.name == DWARF.DW_AT_language && haskey(DWARF.DW_LANG, at.value)
        print(io, at.value, " (", DWARF.DW_LANG[at.value], ")")
    else
        showcompact(io, at.value)
    end
end

function Base.bytestring(at::Attribute, strtab = nothing)
    if at.spec.form == DWARF.DW_FORM_string
        return bytestring(at.value)
    elseif at.spec.form == DWARF.DW_FORM_strp
        @assert strtab !== nothing
        bytestring(at.value, strtab)
    else
        error("Not a string attribute")
    end
end

# Special form types
immutable StrTableReference
    offset::UInt64
end
StrTableReference(::Void) = nothing
Base.bytestring(ref::StrTableReference, strtab) = strtab_lookup(strtab, ref.offset)

function show(io::IO, x::StrTableReference)
    strtab = isa(io, IOContext) ? get(io, :strtab, nothing) : nothing
    if strtab === nothing
        print(io, ".debug_str[0x",
            hex(x.offset,2*sizeof(x.offset > typemax(UInt32) ? 
                x.offset : UInt32)),"]")
    else
        show(io, strtab_lookup(strtab, x.offset))
    end
end

immutable SectionReference
    offset::UInt64
end
convert(::Type{UInt}, x::SectionReference) = convert(UInt, x.offset)
SectionReference(::Void) = nothing

immutable DwarfExpr{T}
    expr::Vector{UInt8}
end
(::Type{DwarfExpr{T}}){T}(::Void) = nothing
function show{T}(io::IO, expr::DwarfExpr{T})
    DWARF.Expressions.print_expression(io,T,expr.expr,:NativeEndian)
end

# Utility function for form processing
readorskip(io::IO, T::Type, endianness, ::Val{:skip}) = (skip(io, sizeof(T)); nothing)
readorskip(io::IO, T::Type, endianness, ::Val{:read}) = unpack(io, T, endianness)
readorskip{T<:LEB128}(io::IO, ::Type{T}, endianness, ::Val{:skip}) =
    while (read(io,UInt8)&0x80)!=0;end
readbytesorskip(io::IO, nbytes, ::Val{:skip}) = (skip(io, nbytes); nothing)
readbytesorskip(io::IO, nbytes, ::Val{:read}) = read(io, nbytes)

readorskipuntil(io::IO, delim::UInt8, ros) =
    (ret = readuntil(io, delim); ros == Val{:skip}() ? nothing : ret)

function make_ref(cu::LightDIERef, cuoffs)
    adjusted_offset = cu.cu.offset + cuoffs
    LightDIERef(cu.io, cu.cu, adjusted_offset)
end
make_ref(cu::LightDIERef, cuoffs::Void) = nothing
    
# Main function encoding how to process a given form
function readorskip(cu::LightDIERef, form, endianness, ros)
    io = cu.io
    cuheader = cu.cu.header
    if form == DWARF.DW_FORM_addr
        ret = readorskip(io, DWARF.size_to_inttype(cuheader.address_size), endianness, ros)
    elseif form == 0x2
        error("Invalid form")
    elseif form == DWARF.DW_FORM_block2
        length = read(io, UInt16)
        ret = readbytesorskip(io, length, ros)
    elseif form == DWARF.DW_FORM_block4
        length = read(io, UInt32)
        ret = readbytesorskip(io, length, ros)
    elseif form == DWARF.DW_FORM_data2
        ret = readorskip(io, UInt16, endianness, ros)
    elseif form == DWARF.DW_FORM_data4
        ret = readorskip(io, UInt32, endianness, ros)
    elseif form == DWARF.DW_FORM_data8
        ret = readorskip(io, UInt64, endianness, ros)
    elseif form == DWARF.DW_FORM_string
        ret = readorskipuntil(io, UInt8(0), ros)
    elseif form == DWARF.DW_FORM_block
        length = read(io, ULEB128)
        ret = readbytesorskip(io, UInt(length), ros)
    elseif form == DWARF.DW_FORM_exprloc
        length = read(io, ULEB128)
        ret = DwarfExpr{DWARF.size_to_inttype(cuheader.address_size)}(readbytesorskip(io, UInt(length), ros))
    elseif form == DWARF.DW_FORM_block1
        length = read(io, UInt8)
        ret = readbytesorskip(io, length, ros)
    elseif form == DWARF.DW_FORM_data1 || form == DWARF.DW_FORM_flag
        ret = readorskip(io, UInt8, endianness, ros)
    elseif form == DWARF.DW_FORM_sdata
        ret = readorskip(io, SLEB128, endianness, ros)
    elseif form == DWARF.DW_FORM_strp
        offs = readorskip(io, typeof(cuheader.unit_length), endianness, ros)
        ret = StrTableReference(offs)
    elseif form == DWARF.DW_FORM_udata
        ret = readorskip(io, ULEB128, endianness, ros)
    elseif form == DWARF.DW_FORM_ref_addr
        ret = readorskip(io, cuheader.version == 2 ?
            size_to_inttype(cuheader.address_size) :
            typeof(cuheader.unit_length), endianness, ros)
    elseif form == DWARF.DW_FORM_ref1
        ret = make_ref(cu, readorskip(io, UInt8, endianness, ros))
    elseif form == DWARF.DW_FORM_ref2
        ret = make_ref(cu, readorskip(io, UInt16, endianness, ros))
    elseif form == DWARF.DW_FORM_ref4
        ret = make_ref(cu, readorskip(io, UInt32, endianness, ros))
    elseif form == DWARF.DW_FORM_ref8
        ret = make_ref(cu, readorskip(io, UInt64, endianness, ros))
    elseif form == DWARF.DW_FORM_ref_udata
        ret = make_ref(cu, UInt(readorskip(io, ULEB128, endianness, ros)))
    elseif form == DWARF.DW_FORM_indirect
        form = read(io, ULEB128)
        return readorskip(io, form, ros, endianness)
    elseif form == DWARF.DW_FORM_sec_offset
        offs = readorskip(io, typeof(cuheader.unit_length), endianness, ros)
        ret = SectionReference(offs)
    elseif form == DWARF.DW_FORM_flag_present
        ret = nothing
    elseif form == DWARF.DW_FORM_ref_sig8
        ret = readorskip(io, UInt64, endianness, ros)
    end
    (form, ret)
end
