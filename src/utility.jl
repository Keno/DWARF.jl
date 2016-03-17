import ObjFileBase: Section, DebugSections, endianness, deref
import Base: start, next, done
export DIETrees

import AbstractTrees: print_tree

immutable DIETreeRef
    oh
    strtab
    tree
end
deref(ref::DIETreeRef) = ref.tree
children(ref::DIETreeRef) = children(ref.tree)
printnode(io::IO, ref::DIETreeRef) = printnode(io, ref.tree)

function show(io::IO, ref::DIETreeRef)
    show(IOContext(io, :strtab => ref.strtab), ref.tree)
end

function dies(oh::ObjectHandle)
    dbgs = debugsections(oh)
    if dbgs.debug_str !== nothing
        return DIETreeRef(oh, load_strtab(dbgs.debug_str), read(oh, DIETree; dbgs = dbgs))
    else
        return read(dbgs, DIETree)
    end
end

function _read_tree(dbgs, s)
    pos = position(dbgs.oh)
    abbrev = read(dbgs.oh, ObjFileBase.deref(dbgs.debug_abbrev), s, DWARF.AbbrevTableSet)
    seek(dbgs.oh, pos)
    DIETree = read(dbgs.oh, s, abbrev, zero(DWARF.DIETree), DWARF.DIETreeNode, endianness(dbgs.oh));
    DIETree
end

read{T<:ObjectHandle}(oh::T,::Type{DWARF.DIETree}; dbgs = debugsections(oh)) = read(dbgs, DIETree)
function read(dbgs::DebugSections,::Type{DWARF.DIETree}, offset = 0)
    seek(dbgs.oh, ObjFileBase.sectionoffset(dbgs.debug_info)+offset)
    s = read(dbgs.oh, DWARF.DWARFCUHeader)
    _read_tree(dbgs, s)
end

immutable DIETrees
    dbgs
end
DIETrees(h::ObjectHandle) = DIETrees(debugsections(h))
show(io::IO, dies::DIETrees) = print(io,"DIETrees(",dies.dbgs.oh,")")
function print_tree(f::Function, io::IO, dies::DIETrees; kwargs...)
    AbstractTrees._print_tree(f, IOContext(io, :strtab, load_strtab(dies.dbgs.debug_str)), dies; kwargs...)
end

start(dt::DIETrees) = 0
function next(dt::DIETrees, off)
    v = read(dt.dbgs, DIETree, off)
    (DIETreeRef(dt.dbgs.oh,load_strtab(dt.dbgs.debug_str),v),position(dt.dbgs.oh)-sectionoffset(dt.dbgs.debug_info))
end
done(dt::DIETrees,off) = off >= ObjFileBase.sectionsize(dt.dbgs.debug_info)

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
    read(oh,header,ats,ret,DWARF.DIETreeNode, endianness(oh))
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

function findcubyname(x::DebugSections, pubtable::DWARF.PUBTable, name)
    (si,ei) = findindexbyname(x, name; pubtable = pubtable)
    if si == ei == 0
        error("Not Found")
    end
    s = read(x.oh,deref(x.debug_info),pubtable.sets[si],DWARF.DWARFCUHeader)
    _read_tree(x, s)
end

function searchcuspbyname(x::DebugSections, name)
    trees = DIETrees(x)
    strtab = load_strtab(x.debug_str)
    for tree in trees
        for child in children(tree)
            if tag(child) == DW_TAG_subprogram
                for at in attributes(child)
                    if tag(at) == DW_AT_name
                        if bytestring(at, strtab) == name
                            return (tree,child)
                        end
                    end
                end
            end
        end
    end
    error("Not found")
end

function searchcuspbyip(x::DebugSections, ip)
    ref(tree) = DIETreeRef(x.oh, ObjFileBase.StrTab(x.debug_str),tree)
    trees = DIETrees(x)
    strtab = load_strtab(x.debug_str)
    for tree in trees
        for child in children(tree)
            if tag(child) == DW_TAG_subprogram
                low = 0
                high = 0
                for at in attributes(child)
                    if tag(at) == DW_AT_low_pc
                        low = convert(UInt,at)
                    elseif tag(at) == DW_AT_high_pc
                        high = isa(at, AddressAttribute) ? convert(UInt, at) :
                            low + convert(UInt, at)
                    end
                end
                (low <= ip < high) && return (ref(tree),ref(child))
            end
        end
    end
    error("Not found")
end

function findcubyname(x::DebugSections, name)
    if x.debug_pubnames != nothing
        findcubyname(x, read(x.oh, deref(x.debug_pubnames), DWARF.PUBTable), name)
    else
        searchcuspbyname(x, name)[1]
    end
end

function finddietreebyname(x::DebugSections, pubtable::DWARF.PUBTable, name)
    (si,ei) = findindexbyname(x, name; pubtable = pubtable)
    (si == ei == 0) && error("Not Found")
    pubset = pubtable.sets[si]
    pubentry = pubset.entries[ei]
    cu = read(x.oh,deref(x.debug_info),pubset,DWARF.DWARFCUHeader)
    DIETreeRef(x.oh, ObjFileBase.StrTab(x.debug_str),
        read(x.oh,deref(x.debug_info),deref(x.debug_abbrev),pubset,pubentry,
        cu,DWARF.DIETree))
end

function findcuspbyname(x::DebugSections, name)
    if x.debug_pubnames != nothing
        pubtable = read(x.oh, deref(x.debug_pubnames), DWARF.PUBTable)
        (si,ei) = findindexbyname(x, name; pubtable = pubtable)
        (si == ei == 0) && error("Not Found")
        pubset = pubtable.sets[si]
        pubentry = pubset.entries[ei]
        cu = read(x.oh,deref(x.debug_info),pubset,DWARF.DWARFCUHeader)
        cutree = _read_tree(x, cu)
        sptree = DIETreeRef(x.oh, ObjFileBase.StrTab(x.debug_str),
            read(x.oh,deref(x.debug_info),deref(x.debug_abbrev),pubset,pubentry,
            cu,DWARF.DIETree))
        return (cutree, sptree)
    else
        searchcuspbyname(x, name)
    end
end

function finddietreebyname(x::DebugSections, name)
    if x.debug_pubnames != nothing
        finddietreebyname(x, read(x.oh, deref(x.debug_pubnames), DWARF.PUBTable), name)
    else
        searchcuspbyname(x, name)[2]
    end
end

function read(x::DebugSections, ::Type{DWARF.ARTableSet})
    read(x.oh, deref(x.debug_aranges), DWARF.ARTableSet)
end
