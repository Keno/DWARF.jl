import Base: start, next, done
using ObjFileBase: handle

# Iterate over units in a section
immutable UnitIterator{T}
    section::SectionRef
end
start(x::UnitIterator) = sectionoffset(x.section)
function next{T}(x::UnitIterator{T}, offset)
    io = handle(x.section).io
    seek(io, offset)
    ret = read(io, T)
    @show typeof(ret)
    @show offset + sizeof(ret)
    next_offset = offset + ret.unit_length + sizeof(ret) +
        (isa(ret.unit_length, UInt64) ? sizeof(UInt32) : 0)
    @show offset
    @show ret
    @show next_offset
    (ret, next_offset)
end
done(x::UnitIterator, off) = off >= sectionoffset(x.section) + sectionsize(x.section)

# Accelerated access to certain attributes
const AttrSpec = Nullable{Tuple{UInt,UInt}}
immutable AbbrevSpec
    tag::UInt
    children::Bool
    AT_name::AttrSpec
    AT_linkage_name::AttrSpec
    # Class is fixed
    AT_low_pc::Nullable{UInt}
    AT_high_pc::AttrSpec
    die_size::UInt
    entry::AbbrevTableEntry
end

const specs = AbbrevSpec[]
const mapping = Dict{Vector{AttributeSpecification}, Int}()

function process_abbrev(entry::AbbrevTableEntry, cu)
    haskey(mapping, entry.attributes) && mapping[entry.attributes]
    offset = 0
    AT_name::AttrSpec = nothing
    AT_linkage_name::AttrSpec = nothing
    AT_low_pc::Nullable{UInt} = nothing
    AT_high_pc::AttrSpec = nothing
    for attr in entry.attributes
        (name, form) = attr.name, attr.form
        if name in (DW_AT_name, DW_AT_linkage_name, DW_AT_high_pc)
            AT_name = (offset % UInt,UInt(form))
        elseif name == DW_AT_low_pc
            AT_low_pc = offset % UInt
        end
        if offset == -1 || form == DW_FORM_string || form == DW_FORM_exprloc ||
            form == DW_FORM_udata
            offset = -1
        else
            offset += Attributes.sizeof_form(form, cu)
        end
    end
    spec = AbbrevSpec(convert(UInt, entry.tag),entry.has_children != 0, AT_name, AT_linkage_name, AT_low_pc,
        AT_high_pc,reinterpret(UInt,offset),entry)
    push!(specs, spec)
    mapping[entry.attributes] = length(specs)
end

# A simple reference we can use to pick up where we left off
immutable LightDIERef
    io::IO
    cu::DWARFCUHeader
    offset::UInt
end

# A cache of values needed for fast navigation of an object file. Should
# ideally be computed once and saved
immutable ObjFileCache
    io::IO
    ats::AbbrevTableSet
    spec_cache::Vector{Int}
    cu_offsets::Vector{UInt}
end

# Iterate over the immediate children
immutable ChildIterator
    parent_ref::LightDIERef
    cache::ObjFileCache
end
function start(x::ChildIterator)
    off = x.parent_ref.offset + specs[x.parent_ref.spec_idx].die_size
    seek(x.parent_ref.io, off)
    abbrev = read(x, ULEB128)
    (position(x.parent_ref.io), abbrev)
end

function skip_children(io, cache)
    while true
        abbrev = read(io, ULEB128)
        if abbrev == 0
            return
        end
        spec = specs[cache.spec_cache[abbrev]]
        seek(io, position(io)+spec.die_size)
        spec.has_children && skip_children(io, cache)
    end
end

function next(c::ChildIterator, state)
    io = c.parent_ref.io
    spec_idx = c.cache.spec_cache[state[2]]
    ret = LightDIERef(io, c.parent_ref.cu, state[1])
    # To determine the next offset, skip all children
    specs[spec_idx].has_children && skip_children(io, x.cache)
    next_abbrev = read(io, ULEB128)
    (ret, (position(io), next_abbrev))
end
done(x::ChildIterator, state) = state[2] == 0

# Readers for different classes
function read_address(io::IO, form, cu::DWARFCUHeader, endianness)
    @assert form == DW_FORM_addr
    T = DWARF.size_to_inttype(cu.address_size)
    fix_endian(read(io,T),endianness)
end

function read_constant(io::IO, form, cu::DWARFCUHeader, endianness)
    if form == DW_FORM_data1
        fix_endian(read(io,UInt8), endianness)
    elseif form == DW_FORM_data2
        fix_endian(read(io,UInt8), endianness)
    elseif form == DW_FORM_data4
        fix_endian(read(io,UInt32), endianness)
    elseif form == DW_FORM_data8
        fix_endian(read(io,UInt64), endianness)
    elseif form == DW_FORM_udata
        read(io,ULEB128)
    elseif form == DW_form_sdata
        read(io,SLEB128)
    else
        error("Not a form for constant class")
    end
end

function pc_range(r::LightDIERef, cache, endianness = Val{:NativeEndian}())
    @show r
    @show realize(r, cache)
    seek(r.io, r.offset)
    abbrev = read(r.io, ULEB128)
    spec = specs[cache.spec_cache[UInt(abbrev)]]
    @show spec
    seek(r.io, r.offset + get(spec.AT_low_pc))
    low = read_address(r.io, DW_FORM_addr, r.cu, endianness)
    offset, form = get(spec.AT_high_pc)
    seek(r.io, r.offset + offset)
    if form == DW_FORM_addr
        high = read_address(r.io, form, r.cu, endianness)
    else
        high = low + read_constant(r.io, form, r.cu, endianness)
    end
    low:high
end

function searchip(cache, it, fake_cu, ip)
    io = cache.io
    off = start(it)
    while !done(it, off)
        cu, off = next(it, off)
        @show cu
        ref = LightDIERef(io, isa(fake_cu, DWARFCUHeader) ? fake_cu : cu, off - cu.unit_length)
        @show ref
        range = pc_range(ref, cache)
        @show range
        if first(range) <= ip <= last(range)
            return ref
        end
    end
    error("Not found")
end

function searchcu(x::DebugSections, ip, cache = process_for_objfile(x.oh))
    it = UnitIterator{DWARFCUHeader}(x.debug_info)
    searchip(cache, it, nothing, ip)
end

function searchcusp(x::DebugSections, ip, cache = process_for_objfile(x.oh))
    curef = searchcu(x,ip,cache)
    spref = searchip(cache, ChildIterator(curef,cache), curef.cu, ip)
    curef, spref
end

function resolve_ref(cache, offset)
    io = cache.io
    idx = searchsortedfirst(cache.cu_offsets, offset) - 1
    seek(io, cache.cu_offsets[idx])
    cu = read(io, DWARFCUHeader)
    LightDIERef(io, cu, offset)
end

function realize(ref::LightDIERef, cache)
    seek(ref.io, ref.offset)
    abbrev = UInt(read(ref.io, ULEB128))
    read(ref.io, ref.cu, specs[cache.spec_cache[abbrev]].entry, DIE, Val{:NativeEndian}())
end

function process_for_objfile(x::DebugSections, endianness = Val{:NativeEndian}())
    seek(x.debug_abbrev, 0)
    ats = read(handle(x.debug_abbrev).io, AbbrevTableSet, endianness)
    it = UnitIterator{DWARFCUHeader}(x.debug_info)
    cu = first(it)
    spec_cache = map(x->process_abbrev(x, cu), ats.entries)
    offsets = UInt[]
    off = start(it)
    @show ("startoff",off)
    while !done(it, off)
        push!(offsets, off)
        _, off = next(it, off)
    end
    ObjFileCache(x.oh.io, ats, spec_cache, offsets)
end
