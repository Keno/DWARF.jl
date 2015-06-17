import ObjFileBase: Section, DebugSections, endianness

immutable DIETreeRef
    oh
    strtab
    tree
end

function show(io::IO, ref::DIETreeRef)
    show(io::IO, ref.tree; strtab = ref.strtab)
end

function dies(oh::ObjectHandle)
    dbgs = debugsections(oh)
    if dbgs.debug_str !== nothing
        return DIETreeRef(oh, load_strtab(dbgs.debug_str), read(oh, DIETree; dbgs = dbgs))
    else
        return read(oh, DIETree; dbgs = dbgs)
    end
end

function read{T<:ObjectHandle}(oh::T,::Type{DWARF.DIETree}; dbgs = debugsections(oh))
    seek(dbgs.oh, ObjFileBase.sectionoffset(dbgs.debug_info))
    s = read(dbgs.oh, DWARF.DWARFCUHeader)
    pos = position(dbgs.oh)
    abbrev = read(dbgs.oh, ObjFileBase.deref(dbgs.debug_abbrev), s, DWARF.AbbrevTableSet)
    seek(dbgs.oh, pos)
    DIETree = read(oh, s, abbrev, zero(DWARF.DIETree), DWARF.DIETreeNode, endianness(oh));
    DIETree
end

function read{T<:ObjectHandle,S}(oh::T,sec::Section{S},::Type{DWARF.ARTable})
    @assert T <: S
    seek(oh, sec)
    ret = DWARF.ARTable(Array(DWARF.ARTableSet,0))
    while position(oh) < sectionoffset(sec) + sectionsize(sec)
        push!(ret.sets, read(oh, DWARF.ARTableSet, endianness(oh)))
    end
    ret
end

function read{T<:ObjectHandle,S}(oh::T,sec::Section{S},::Type{DWARF.PUBTable})
    @assert T <: S
    seek(oh, sec)
    ret = DWARF.PUBTable(Array(DWARF.PUBTableSet,0))
    while position(oh) < sectionoffset(sec) + sectionsize(sec)
        push!(ret.sets,read(oh,DWARF.PUBTableSet, endianness(oh)))
    end
    ret
end

function read{T<:ObjectHandle,S}(oh::T, sec::Section{S},
        ::Type{DWARF.AbbrevTableSet})
    @assert T <: S
    seek(oh, sec)
    read(oh, AbbrevTableSet, endianness(oh))
end

function read{T<:ObjectHandle,S}(oh::T,debug_info::Section{S},
        s::DWARF.PUBTableSet,::Type{DWARF.DWARFCUHeader})
    @assert T <: S
    seek(oh,sectionoffset(debug_info)+s.header.debug_info_offset)
    read(oh,DWARF.DWARFCUHeader, endianness(oh))
end

function read{T<:ObjectHandle,S}(oh::T, debug_info::Section{S}, s::DWARF.DWARFCUHeader,
        ::Type{DWARF.AbbrevTableSet})
    @assert T <: S
    seek(oh,sectionoffset(debug_info)+s.debug_abbrev_offset)
    read(oh,DWARF.AbbrevTableSet, endianness(oh))
end

function read{T<:ObjectHandle,S}(oh::T,
    debug_info::Section{S}, debug_abbrev::Section{S},
    s::DWARF.PUBTableSet, e::DWARF.PUBTableEntry,
    header::DWARF.DWARFCUHeader, ::Type{DWARF.DIETree})

    @assert T <: S
    ats = read(oh,debug_abbrev,header,DWARF.AbbrevTableSet)
    seek(oh,sectionoffset(debug_info)+s.header.debug_info_offset+e.offset)
    ret = DWARF.DIETree(Array(DWARF.DIETreeNode,0))
    read(oh,header,ats,ret,DWARF.DIETreeNode,:LittleEndian)
    ret
end

function findindexbyname(x::DebugSections,name;
        pubtable=read(x.oh, deref(x.debug_pubnames), DWARF.PUBTable))
    symbols = map(y->map(x->x.name,y.entries),pubtable.sets)
    for i = 1:length(symbols)
        ind = findfirst(symbols[i],name)
        if ind != 0
            return (i,ind)
        end
    end
    return (0,0)
end

function findcubyname(x::DebugSections, name;
    pubtable = read(x.oh, deref(x.debug_pubnames), DWARF.PUBTable))
    (si,ei) = findindexbyname(x, name; pubtable = pubtable)
    if si == ei == 0
        error("Not Found")
    end
    read(x.oh,deref(x.debug_info),pubtable.sets[si],DWARF.DWARFCUHeader)
end

function finddietreebyname(x::DebugSections, name;
    pubtable = read(x.oh, deref(x.debug_pubnames), DWARF.PUBTable))
    (si,ei) = findindexbyname(x, name; pubtable = pubtable)
    if si == ei == 0
        error("Not Found")
    end
    pubset = pubtable.sets[si]
    pubentry = pubset.entries[ei]
    cu = read(x.oh,deref(x.debug_info),pubset,DWARF.DWARFCUHeader)
    d = read(x.oh,deref(x.debug_info),deref(x.debug_abbrev),pubset,pubentry,
        cu,DWARF.DIETree)
end

function read(x::DebugSections, ::Type{DWARF.ARTableSet})
    read(x.oh, deref(x.debug_aranges), DWARF.ARTableSet)
end
