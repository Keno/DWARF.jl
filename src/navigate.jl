function pc_range(die)
    low = extract_attribute(die, DWARF.DW_AT_low_pc)
    high = extract_attribute(die, DWARF.DW_AT_high_pc)
    (isnull(low) || isnull(high)) && return Nullable{UnitRange{UInt64}}()
    low = get(low).value
    high = get(high)
    if high.spec.form == DW_FORM_addr
        high = high.value
    else
        high = low + high.value
    end
    Nullable{UnitRange{UInt64}}(low:high)
end

function _searchforip(it, ip)
    for x in it
        pcr = pc_range(x)
        isnull(pcr) && continue
        pcr = get(pcr)
        (first(pcr) <= ip < last(pcr)) && return x
    end
    error("Not found")
end

searchcuforip(dbgs, ip) =
  _searchforip(UnitIterator{DWARFCUHeader}(dbgs.debug_info, dbgs.debug_abbrev), ip)
searchspforip(cu, ip) = _searchforip(ChildIterator(cu), ip)
