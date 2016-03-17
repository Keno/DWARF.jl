import Base: start, next, done

# Iterate over units in a section
immutable UnitIterator{T}
    section::SectionRef
end
start(x::UnitIterator) = 0
function next{T}(x::UnitIterator{T}, offset)
    seek(x.section, offset)
    ret = read(handle(x.section).io, T)
    (ret, position(x.section) + ret.unit_length + (sizeof(ret) - sizeof(ret.unit_length)))
end
done(x::UnitIterator, off) = x >= sectionsize(x.section)

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

function process_abbrev(entry::AbbrevTableEntry)
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
        if offset == -1 || form == DW_form_string
            offset = -1
        else
            offset += Attributes.sizeof_form(form)
        end
    end
    spec = AbbrevSpec(convert(UInt, entry.tag),entry.has_children != 0, entry.AT_name, AT_linkage_name, AT_low_pc,
        AT_high_pc,reinterpret(UInt,offset))
    push!(specs, spec)
    mapping[entry.attributes] = spec
end

# A simple reference we can use to pick up where we left off
immutable LightDIERef
    io::IO
    cu::DWARFCUHeader
    offset::UInt
    spec_idx::Int
end

# A cache of values needed for fast navigation of an object file. Should
# ideally be computed once and saved
immutable ObjFileCache
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
    ret = LightDIERef(io, c.parent_ref.cu, state[1], spec_idx)
    # To determine the next offset, skip all children
    specs[spec_idx].has_children && skip_children(io, x.cache)
    next_abbrev = read(io, ULEB128)
    (ret, (position(io), next_abbrev))
end
done(x::ChildIterator, state) = state[2] == 0

# Readers for different classes
function read_address(io::IO, form, cu::DWARFCUHeader, endianness)
    @assert form == DW_FORM_addr
    T = DWARF.size_to_inttype(header.address_size)
    AddressAttribute{T}(name,fix_endian(read(io,T),endianness))
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

function pc_range(r::LightDIERef, endianness = Val{:NativeEndian}())
    spec = specs[r.spec_idx]
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

function searchip(it, fake_cu, ip)
    off = start(it)
    while !done(it, off)
        this_off = off
        cu, off = next(it, this_off)
        ref = LightDIERef(x.oh.io, isa(fake_cu, DWARFCUHeader) ? fake_cu : cu, this_off)
        range = pc_range(ref)
        if first(range) <= ip <= last(range)
            return ref
        end
    end
    error("Not found")
end

function searchcu(x::DebugSections, ip, cache = process_for_objfile(x.oh))
    it = UnitIterator(x.debug_info)
    searchip(it, cu, ip)
end

function searchcusp(x::DebugSections, ip, cache = process_for_objfile(x.oh))
    curef = searchcu(x,ip,cache)
    spref = searchip(ChildIterator(curef,cache), cu, ip)
end

function resolve_ref(x::DebugSections, offset, cache)
    idx = searchsortedfirst(cache.offsets, offset) - 1
    seek(x.oh.io, cache.offsets[idx])
    cu = read(x.oh.io, DWARFCUHeader)
    seek(x.oh.io, offset)
    spec_idx = read(x.oh.io, ULEB128)
    LightDIERef(x.oh.io, cu, offset, spec_idx % UInt)
end

function realize(ref::LightDIERef)
    seek(ref.io, ref.offset)
    read(ref.io, ref.cu, specs[ref.spec_idx].entry, DIE, Val{:NativeEndian}())
end

function process_for_objfile(x::DebugSections, endianness = Val{:NativeEndian}())
    seek(x.debug_abbrev, 0)
    ats = read(handle(x.debug_abbrev).io, AbbrevTableSet, endianness)
    spec_cache = map(process_abbrev, ats.entries)
    it = UnitIterator{DWARFCUHeader}(x.debug_info)
    offsets = UInt[]
    off = start(it)
    while !done(it, off)
        push!(offsets, off)
        _, off = next(it, off)
    end
    ObjFileCache(ats, spec_cache, offsets)
end
