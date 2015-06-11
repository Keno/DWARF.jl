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
