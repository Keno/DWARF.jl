using ObjFileBase
import AbstractTrees: children
import Base: start, next, done
import Base: print, show

immutable CU
    offset::UInt
    ats::AbbrevTableSet
    header::DWARFCUHeader
end

immutable LightDIERef
    io::IO
    cu::CU
    offset::UInt
end

# Small helper to seek to the start of a die ref and get the abbrev entry
function seekentry(die::LightDIERef)
    seek(die.io, die.offset)
    abbrev = UInt(read(die.io, ULEB128))
    abbrev == 0 && return zero_entry
    die.cu.ats.entries[abbrev]
end

tag(die::LightDIERef) = seekentry(die).tag

# Iterate over a DIEs attributes
immutable AttributeIterator
    die::LightDIERef
    ate::AbbrevTableEntry
end
function AttributeIterator(die::LightDIERef)
    new(die,seekentry(die))
end
function start(it::AttributeIterator)
    seekentry(it.die)
    (position(it.die.io), 1)
end
function next(it::AttributeIterator, state)
    endianness = :NativeEndian
    seek(it.die.io,state[1])
    idx = state[2]
    form, value = readorskip(it.die, it.ate.attributes[idx].form, endianness, Val{:read}())
    ret = Attribute(AttributeSpecification(it.ate.attributes[idx].name, form), value)
    (ret, (position(it.die.io), state[2]+1))
end
done(it::AttributeIterator, state) = state[2] > length(it.ate.attributes)
attributes(die::LightDIERef) = AttributeIterator(die)

# Show on a LightDIERef shows the contents of the DIE
function show(io::IO, die::LightDIERef)
    ate = seekentry(die)
    print_with_color(tag_color, io, tag_name(ate.tag))
    println(io)
    for attr in AttributeIterator(die, ate)
        print(io, "  "); show(io, attr); println(io)
    end
end
function Base.showcompact(io::IO, die::LightDIERef)
    print(io,"(cu + $(die.offset - die.cu.offset) => {$(hex(die.offset,2sizeof(die.offset)))})")
end

# Iterate over a DIEs children (not including attributes)
immutable ChildIterator
     die::LightDIERef
end
children(die::LightDIERef) = ChildIterator(die)

# State is (next_offset, next_abbrev)
function start(it::ChildIterator)
    ate = seekentry(it.die)
    ate.has_children == 0 && return (UInt(0),UInt(0))
    skip_attributes(it.die, ate)
    next_offset = position(it.die.io)
    next_abbrev = UInt(read(it.die.io, ULEB128))
    (next_offset, next_abbrev)
end
function next(it::ChildIterator, state)
    io = it.die.io
    seek(io, state[1])
    ate = it.die.cu.ats.entries[state[2]]
    ret = LightDIERef(io, it.die.cu, state[1])
    # Could just determine the size from state[2] and have state[1] be after the
    # abbrev, but so be it.
    read(io, ULEB128)
    skip_attributes(ret, ate)
    ate.has_children != 0 && skip_children(io, it.die)
    next_offset = position(io)
    next_abbrev = UInt(read(io, ULEB128))
    (ret, (next_offset, next_abbrev))
end
done(it::ChildIterator, state) = state[2] == 0

function skip_children(io::IO, cu)
    level = 1
    while level >= 1
        abbrev = UInt(read(io, ULEB128))
        if abbrev == 0
            level -= 1
            continue
        end
        ate = cu.cu.ats.entries[abbrev]
        skip_attributes(cu, ate)
        ate.has_children != 0 && (level += 1)
    end
end


# Iterate over units in a section
immutable UnitIterator{T}
    unit_section::SectionRef
    debug_abbrev::SectionRef
end
start(x::UnitIterator) = sectionoffset(x.unit_section)
function next{T}(x::UnitIterator{T}, offset)
    io = ObjFileBase.handle(x.unit_section).io
    seek(io, offset)
    endianness = :NativeEndian
    cuheader = read(io, T, endianness)
    seek(x.debug_abbrev, cuheader.debug_abbrev_offset)
    ats = read(io, AbbrevTableSet, endianness)
    die_offset = offset + sizeof(cuheader) +
      (isa(cuheader.unit_length, UInt64) ? sizeof(UInt32) : 0)
    ret = LightDIERef(io, CU(offset, ats, cuheader), die_offset)
    next_offset = die_offset + cuheader.unit_length - sizeof(cuheader) + sizeof(cuheader.unit_length)
    (ret, next_offset)
end
done(x::UnitIterator, off) = off >= sectionoffset(x.unit_section) + sectionsize(x.unit_section)
Base.iteratorsize{T<:UnitIterator}(::Type{T}) = Base.SizeUnknown()

function realize(ref::LightDIERef)
    seek(ref.io, ref.offset)
    abbrev = UInt(read(ref.io, ULEB128))
    read(ref.io, ref.cu.header, ref.cu.ats.entries[abbrev], DIE, :NativeEndian)
end

function readnthattr(ref, ate, endianness, idx)
    for i = 1:(idx-1)
        readorskip(ref, ate.attributes[i].form, :NativeEndian, Val{:skip}())
    end
    # Form could be indirect, so we need the return value
    readorskip(ref, ate.attributes[idx].form, endianness, Val{:read}())
end

function extract_attribute(ref::LightDIERef, name, endianness = :NativeEndian)
    io = ref.io
    ate = seekentry(ref)
    idx = findfirst(x->x.name==name, ate.attributes)
    if idx == 0
        idx = findfirst(x->x.name==DWARF.DW_AT_abstract_origin, ate.attributes)
        (idx == 0) && return Nullable{Attribute}()
        form, value = readnthattr(ref, ate, endianness, idx)
        return extract_attribute(value, name, endianness)
    end
    form, value = readnthattr(ref, ate, endianness, idx)
    Nullable{Attribute}(Attribute(AttributeSpecification(ate.attributes[idx].name, form), value))
end

function skip_attributes(ref::LightDIERef, ate)
    for at in ate.attributes
        readorskip(ref, at.form, :NativeEndian, Val{:skip}())
    end
end
