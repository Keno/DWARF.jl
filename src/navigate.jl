function pc_range(die)
    low = extract_attribute(die, DWARF.DW_AT_low_pc).value
    high = extract_attribute(die, DWARF.DW_AT_high_pc)
    if high.spec.form == DW_FORM_addr
        high = high.value
    else
        high = low + high.value
    end
    low:high
end

function _searchforip(it, ip)
    for x in it
        try
            pcr = pc_range(x)
            (first(pcr) <= ip < last(pcr)) && return x
        catch e
            continue
        end
    end
    error("Not found")
end

searchcuforip(dbgs, ip) =
  _searchforip(UnitIterator{DWARFCUHeader}(dbgs.debug_info, dbgs.debug_abbrev), ip)
searchspforip(cu, ip) = _searchforip(ChildIterator(cu), ip)
