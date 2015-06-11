function read{T<:ObjectHandle}(oh::T,::Type{DWARF.DIETree})
    dbgs = debugsections(oh)
    seek(dbgs.oh, ObjFileBase.sectionoffset(dbgs.debug_info))
    s = read(dbgs.oh, DWARF.DWARFCUHeader)
    pos = position(dbgs.oh)
    abbrev = read(dbgs.oh, ObjFileBase.deref(dbgs.debug_abbrev), s, DWARF.AbbrevTableSet)
    seek(dbgs.oh, pos)
    DIETree = read(oh, s, abbrev, zero(DWARF.DIETree), DWARF.DIETreeNode, ObjFileBase.endianness(oh));
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
