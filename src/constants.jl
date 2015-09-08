using Base.Meta

macro constants(array, stripprefix, expr)
    ret = Expr(:block)
    # Initialize the name lookup array
    push!(ret.args,:(const $array = Dict{Uint32,ASCIIString}()))
    for e in expr.args
        if !isexpr(e,:const)
            continue
        end
        eq = e.args[1]
        @assert isexpr(eq,:(=))
        name = string(eq.args[1])
        name = replace(name,stripprefix,"",1)
        push!(ret.args,e)
        push!(ret.args,:($array[UInt32($(eq.args[1]))] = $name))
    end
    return esc(ret)
end

# # # DWARF TAG constants
@constants DW_TAG "" begin
    const DW_TAG_array_type = 0x01 #
    const DW_TAG_class_type = 0x02 #
    const DW_TAG_entry_point = 0x03 #
    const DW_TAG_enumeration_type = 0x04 #
    const DW_TAG_formal_parameter = 0x05 #
    const DW_TAG_imported_declaration = 0x08 #
    const DW_TAG_label = 0x0a #
    const DW_TAG_lexical_block = 0x0b #
    const DW_TAG_member = 0x0d #
    const DW_TAG_pointer_type = 0x0f #
    const DW_TAG_reference_type = 0x10 #
    const DW_TAG_compile_unit = 0x11 #
    const DW_TAG_string_type = 0x12 #
    const DW_TAG_structure_type = 0x13 #
    const DW_TAG_subroutine_type = 0x15 #
    const DW_TAG_typedef = 0x16 #
    const DW_TAG_union_type = 0x17 #
    const DW_TAG_unspecified_parameters = 0x18 #
    const DW_TAG_variant = 0x19 #
    const DW_TAG_common_block = 0x1a #
    const DW_TAG_common_inclusion = 0x1b #
    const DW_TAG_inheritance = 0x1c #
    const DW_TAG_inlined_subroutine = 0x1d #
    const DW_TAG_module = 0x1e #
    const DW_TAG_ptr_to_member_type = 0x1f #
    const DW_TAG_set_type = 0x20 #
    const DW_TAG_subrange_type = 0x21 #
    const DW_TAG_with_stmt = 0x22 #
    const DW_TAG_access_declaration = 0x23 #
    const DW_TAG_base_type = 0x24 #
    const DW_TAG_catch_block = 0x25 #
    const DW_TAG_const_type = 0x26 #
    const DW_TAG_constant = 0x27 #
    const DW_TAG_enumerator = 0x28 #
    const DW_TAG_file_type = 0x29 #
    const DW_TAG_friend = 0x2a #
    const DW_TAG_namelist = 0x2b #
    const DW_TAG_namelist_item = 0x2c #
    const DW_TAG_packed_type = 0x2d #
    const DW_TAG_subprogram = 0x2e #
    const DW_TAG_template_type_parameter = 0x2f #
    const DW_TAG_template_value_parameter = 0x30 #
    const DW_TAG_thrown_type = 0x31 #
    const DW_TAG_try_block = 0x32 #
    const DW_TAG_variant_part = 0x33 #
    const DW_TAG_variable = 0x34 #
    const DW_TAG_volatile_type = 0x35 #
    const DW_TAG_dwarf_procedure = 0x36 #
    const DW_TAG_restrict_type = 0x37 #
    const DW_TAG_interface_type = 0x38 #
    const DW_TAG_namespace = 0x39 #
    const DW_TAG_imported_module = 0x3a #
    const DW_TAG_unspecified_type = 0x3b #
    const DW_TAG_partial_unit = 0x3c #
    const DW_TAG_imported_unit = 0x3d #
    const DW_TAG_condition = 0x3f #
    const DW_TAG_shared_type = 0x40 #
    const DW_TAG_type_unit = 0x41 #
    const DW_TAG_rvalue_reference_type = 0x42 #
    const DW_TAG_template_alias = 0x43 #
    const DW_TAG_lo_user = 0x4080 #

    # GNU Extensions
    const DW_TAG_GNU_template_parameter_pack = 0x4107

    const DW_TAG_hi_user = 0xffff #
end

# # # DWARF child determination encodings
@constants DW_CHILDREN "" begin
    const DW_CHILDREN_no = 0x00 #
    const DW_CHILDREN_yes = 0x01 #
end

# # # DARF attribute encodings
@constants DW_AT "" begin
    const DW_AT_sibling = 0x01 # reference
    const DW_AT_location = 0x02 # exprloc, loclistptr
    const DW_AT_name = 0x03 # string
    const DW_AT_ordering = 0x09 # constant
    const DW_AT_byte_size = 0x0b # constant, exprloc, reference
    const DW_AT_bit_offset = 0x0c # constant, exprloc, reference
    const DW_AT_bit_size = 0x0d # constant, exprloc, reference
    const DW_AT_stmt_list = 0x10 # lineptr
    const DW_AT_low_pc = 0x11 # address
    const DW_AT_high_pc = 0x12 # address, constant
    const DW_AT_language = 0x13 # constant
    const DW_AT_discr = 0x15 # reference
    const DW_AT_discr_value = 0x16 # constant
    const DW_AT_visibility = 0x17 # constant
    const DW_AT_import = 0x18 # reference
    const DW_AT_string_length = 0x19 # exprloc, loclistptr
    const DW_AT_common_reference = 0x1a # reference
    const DW_AT_comp_dir = 0x1b # string
    const DW_AT_const_value = 0x1c # block, constant, string
    const DW_AT_containing_type = 0x1d # reference
    const DW_AT_default_value = 0x1e # reference
    const DW_AT_inline = 0x20 # constant
    const DW_AT_is_optional = 0x21 # flag
    const DW_AT_lower_bound = 0x22 # constant, exprloc, reference
    const DW_AT_producer = 0x25 # string
    const DW_AT_prototyped = 0x27 # flag
    const DW_AT_return_addr = 0x2a # exprloc, loclistptr
    const DW_AT_start_scope = 0x2c # Constant, rangelistptr
    const DW_AT_bit_stride = 0x2e # constant, exprloc, reference
    const DW_AT_upper_bound = 0x2f # constant, exprloc, reference
    const DW_AT_abstract_origin = 0x31 # reference
    const DW_AT_accessibility = 0x32 # constant
    const DW_AT_address_class = 0x33 # constant
    const DW_AT_artificial = 0x34 # flag
    const DW_AT_base_types = 0x35 # reference
    const DW_AT_calling_convention = 0x36 # constant
    const DW_AT_count = 0x37 # constant, exprloc, reference
    const DW_AT_data_member_location = 0x38 # constant, exprloc, loclistptr
    const DW_AT_decl_column = 0x39 # constant
    const DW_AT_decl_file = 0x3a # constant
    const DW_AT_decl_line = 0x3b # constant
    const DW_AT_declaration = 0x3c # flag
    const DW_AT_discr_list = 0x3d # block
    const DW_AT_encoding = 0x3e # constant
    const DW_AT_external = 0x3f # flag
    const DW_AT_frame_base = 0x40 # exprloc, loclistptr
    const DW_AT_friend = 0x41 # reference
    const DW_AT_identifier_case = 0x42 # constant
    const DW_AT_macro_info = 0x43 # macptr
    const DW_AT_namelist_item = 0x44 # reference
    const DW_AT_priority = 0x45 # reference
    const DW_AT_segment = 0x46 # exprloc, loclistptr
    const DW_AT_specification = 0x47 # reference
    const DW_AT_static_link = 0x48 # exprloc, loclistptr
    const DW_AT_type = 0x49 # reference
    const DW_AT_use_location = 0x4a # exprloc, loclistptr
    const DW_AT_variable_parameter = 0x4b # flag
    const DW_AT_virtuality = 0x4c # constant
    const DW_AT_vtable_elem_location = 0x4d # exprloc, loclistptr
    const DW_AT_allocated = 0x4e # constant, exprloc, reference
    const DW_AT_associated = 0x4f # constant, exprloc, reference
    const DW_AT_data_location = 0x50 # exprloc
    const DW_AT_byte_stride = 0x51 # constant, exprloc, reference
    const DW_AT_entry_pc = 0x52 # address
    const DW_AT_use_UTF8 = 0x53 # flag
    const DW_AT_extension = 0x54 # reference
    const DW_AT_ranges = 0x55 # rangelistptr
    const DW_AT_trampoline = 0x56 # address, flag, reference, string
    const DW_AT_call_column = 0x57 # constant
    const DW_AT_call_file = 0x58 # constant
    const DW_AT_call_line = 0x59 # constant
    const DW_AT_description = 0x5a # string
    const DW_AT_binary_scale = 0x5b # constant
    const DW_AT_decimal_scale = 0x5c # constant
    const DW_AT_small = 0x5d # reference
    const DW_AT_decimal_sign = 0x5e # constant
    const DW_AT_digit_count = 0x5f # constant
    const DW_AT_picture_string = 0x60 # string
    const DW_AT_mutable = 0x61 # flag
    const DW_AT_threads_scaled = 0x62 # flag
    const DW_AT_explicit = 0x63 # flag
    const DW_AT_object_pointer = 0x64 # reference
    const DW_AT_endianity = 0x65 # constant
    const DW_AT_elemental = 0x66 # flag
    const DW_AT_pure = 0x67 # flag
    const DW_AT_recursive = 0x68 # flag
    const DW_AT_signature = 0x69 # reference
    const DW_AT_main_subprogram = 0x6a # flag
    const DW_AT_data_bit_offset = 0x6b # constant
    const DW_AT_const_expr = 0x6c # flag
    const DW_AT_enum_class = 0x6d # flag
    const DW_AT_linkage_name = 0x6e # string
    const DW_AT_lo_user = 0x2000 # ---
    const DW_AT_hi_user = 0x3fff # ---

    const DW_AT_MIPS_loop_begin = 0x2002
    const DW_AT_MIPS_tail_loop_begin = 0x2003
    const DW_AT_MIPS_epilog_begin = 0x2004
    const DW_AT_MIPS_loop_unroll_factor = 0x2005
    const DW_AT_MIPS_software_pipeline_depth = 0x2006
    const DW_AT_MIPS_linkage_name = 0x2007
    const DW_AT_MIPS_stride = 0x2008
    const DW_AT_MIPS_abstract_name = 0x2009
    const DW_AT_MIPS_clone_origin = 0x200a
    const DW_AT_MIPS_has_inlines = 0x200b
    const DW_AT_MIPS_stride_byte = 0x200c
    const DW_AT_MIPS_stride_elem = 0x200d
    const DW_AT_MIPS_ptr_dopetype = 0x200e
    const DW_AT_MIPS_allocatable_dopetype = 0x200f
    const DW_AT_MIPS_assumed_shape_dopetype = 0x2010
end

# # # DW FORM constants
@constants DW_FORM "" begin
    const DW_FORM_addr = 0x01 # address
    const DW_FORM_block2 = 0x03 # block
    const DW_FORM_block4 = 0x04 # block
    const DW_FORM_data2 = 0x05 # constant
    const DW_FORM_data4 = 0x06 # constant
    const DW_FORM_data8 = 0x07 # constant
    const DW_FORM_string = 0x08 # string
    const DW_FORM_block = 0x09 # block
    const DW_FORM_block1 = 0x0a # block
    const DW_FORM_data1 = 0x0b # constant
    const DW_FORM_flag = 0x0c # flag
    const DW_FORM_sdata = 0x0d # constant
    const DW_FORM_strp = 0x0e # string
    const DW_FORM_udata = 0x0f # constant
    const DW_FORM_ref_addr = 0x10 # reference
    const DW_FORM_ref1 = 0x11 # reference
    const DW_FORM_ref2 = 0x12 # reference
    const DW_FORM_ref4 = 0x13 # reference
    const DW_FORM_ref8 = 0x14 # reference
    const DW_FORM_ref_udata = 0x15 # reference
    const DW_FORM_indirect = 0x16 # (see Section 7.5.3)
    const DW_FORM_sec_offset = 0x17 # lineptr, loclistptr, macptr, rangelistptr
    const DW_FORM_exprloc = 0x18 # exprloc
    const DW_FORM_flag_present = 0x19 # flag
    const DW_FORM_ref_sig8 = 0x20 # reference
end

# # # DWARF operation encodings
@constants DW_OP "" begin
    const DW_OP_addr = 0x03 # # 1 constant address
    const DW_OP_deref = 0x06 # # 0
    const DW_OP_const1u = 0x08 # 1 1-byte constant
    const DW_OP_const1s = 0x09 # 1 1-byte constant
    const DW_OP_const2u = 0x0a # 1 2-byte constant
    const DW_OP_const2s = 0x0b # 1 2-byte constant
    const DW_OP_const4u = 0x0c # 1 4-byte constant
    const DW_OP_const4s = 0x0d # 1 4-byte constant
    const DW_OP_const8u = 0x0e # 1 8-byte constant
    const DW_OP_const8s = 0x0f # 1 8-byte constant
    const DW_OP_constu = 0x10 # 1 ULEB128 constant
    const DW_OP_consts = 0x11 # 1 SLEB128 constant
    const DW_OP_dup = 0x12 # 0
    const DW_OP_drop = 0x13 # 0
    const DW_OP_over = 0x14 # 0
    const DW_OP_pick = 0x15 # 1 1-byte stack index
    const DW_OP_swap = 0x16 # 0
    const DW_OP_rot = 0x17 # 0
    const DW_OP_xderef = 0x18 # 0
    const DW_OP_abs = 0x19 # 0
    const DW_OP_and = 0x1a # 0
    const DW_OP_div = 0x1b # 0
    const DW_OP_minus = 0x1c # 0
    const DW_OP_mod = 0x1d # 0
    const DW_OP_mul = 0x1e # 0
    const DW_OP_neg = 0x1f # 0
    const DW_OP_not = 0x20 # 0
    const DW_OP_or = 0x21 # 0
    const DW_OP_plus = 0x22 # 0
    const DW_OP_plus_uconst = 0x23 # 1 ULEB128 addend
    const DW_OP_shl = 0x24 # 0
    const DW_OP_shr = 0x25 # 0
    const DW_OP_shra = 0x26 # 0
    const DW_OP_xor = 0x27 # 0
    const DW_OP_skip = 0x2f # 1 signed 2-byte constant
    const DW_OP_bra = 0x28 # 1 signed 2-byte constant
    const DW_OP_eq = 0x29 # 0
    const DW_OP_ge = 0x2a # 0
    const DW_OP_gt = 0x2b # 0
    const DW_OP_le = 0x2c # 0
    const DW_OP_lt = 0x2d # 0
    const DW_OP_ne = 0x2e # 0
    const DW_OP_lit1 = 0x31 # 0
    const DW_OP_lit31 = 0x4f # 0
    const DW_OP_reg0 = 0x50 # 0
    const DW_OP_reg31 = 0x6f # 0
    const DW_OP_breg0 = 0x70 # 1
    const DW_OP_breg31 = 0x8f # 1
    const DW_OP_regx = 0x90 # 1 ULEB128 register
    const DW_OP_fbreg = 0x91 # 1 SLEB128 offset
    const DW_OP_bregx = 0x92 # 2 ULEB128 register followed by SLEB128 offset
    const DW_OP_piece = 0x93 # 1 ULEB128 size of piece addressed
    const DW_OP_deref_size = 0x94 # 1 1-byte size of data retrieved
    const DW_OP_xderef_size = 0x95 # 1 1-byte size of data retrieved
    const DW_OP_nop = 0x96 # 0
    const DW_OP_push_object_address = 0x97 # 0
    const DW_OP_call2 = 0x98 # 1 2-byte offset of DIE
    const DW_OP_call4 = 0x99 # 1 4-byte offset of DIE
    const DW_OP_call_ref = 0x9a # 1 4- or 8-byte offset of DIE
    const DW_OP_form_tls_address = 0x9b # 0
    const DW_OP_call_frame_cfa = 0x9c # 0
    const DW_OP_bit_piece = 0x9d # 2 ULEB128 size followed by ULEB128 offset
    const DW_OP_implicit_value = 0x9e # 2 ULEB128 size followed by block of that size
    const DW_OP_stack_value = 0x9f # 0
    const DW_OP_lo_user = 0xe0
    const DW_OP_hi_user = 0xff #
end

# # # Base Type Attribute Encodings
@constants DW_ATE "" begin
    const DW_ATE_address = 0x01 #
    const DW_ATE_boolean = 0x02 #
    const DW_ATE_complex_float = 0x03 #
    const DW_ATE_float = 0x04 #
    const DW_ATE_signed = 0x05 #
    const DW_ATE_signed_char = 0x06 #
    const DW_ATE_unsigned = 0x07 #
    const DW_ATE_unsigned_char = 0x08 #
    const DW_ATE_imaginary_float = 0x09 #
    const DW_ATE_packed_decimal = 0x0a #
    const DW_ATE_numeric_string = 0x0b #
    const DW_ATE_edited = 0x0c #
    const DW_ATE_signed_fixed = 0x0d #
    const DW_ATE_unsigned_fixed = 0x0e #
    const DW_ATE_decimal_float = 0x0f #
    const DW_ATE_UTF = 0x10 #
    const DW_ATE_lo_user = 0x80 #
    const DW_ATE_hi_user = 0xff #
end

# # # Decimal sign encodings
@constants DW_DS "" begin
    const DW_DS_unsigned = 0x01 #
    const DW_DS_leading_overpunch = 0x02 #
    const DW_DS_trailing_overpunch = 0x03 #
    const DW_DS_leading_separate = 0x04 #
    const DW_DS_trailing_separate = 0x05 #
end

# # # Endianity Encodings
@constants DW_END "" begin
    const DW_END_default = 0x00 #
    const DW_END_big = 0x01 #
    const DW_END_little = 0x02 #
    const DW_END_lo_user = 0x40 #
    const DW_END_hi_user = 0xff #
end

# # # Accessibility Codes
@constants DW_ACCESS "" begin
    const DW_ACCESS_public = 0x01 #
    const DW_ACCESS_protected = 0x02 #
    const DW_ACCESS_private = 0x03 #
end

# # # Visibility Codes
@constants DW_VIS "" begin
    const DW_VIS_local = 0x01 #
    const DW_VIS_exported = 0x02 #
    const DW_VIS_qualified = 0x03 #
end

# # # Virtuality Codes
@constants DW_VIRTUALITY "" begin
    const DW_VIRTUALITY_none = 0x00 #
    const DW_VIRTUALITY_virtual = 0x01 #
    const DW_VIRTUALITY_pure_virtual = 0x02 #
end

# # # Language Encodings
@constants DW_LANG "" begin
    const DW_LANG_C89 = 0x0001 # 0
    const DW_LANG_C = 0x0002 # 0
    const DW_LANG_Ada83 = 0x0003 # 1
    const DW_LANG_C_plus_plus = 0x0004 # 0
    const DW_LANG_Cobol74 = 0x0005 # 1
    const DW_LANG_Cobol85 = 0x0006 # 1
    const DW_LANG_Fortran77 = 0x0007 # 1
    const DW_LANG_Fortran90 = 0x0008 # 1
    const DW_LANG_Pascal83 = 0x0009 # 1
    const DW_LANG_Modula2 = 0x000a # 1
    const DW_LANG_Java = 0x000b # 0
    const DW_LANG_C99 = 0x000c # 0
    const DW_LANG_Ada95 = 0x000d # 1
    const DW_LANG_Fortran95 = 0x000e # 1
    const DW_LANG_PLI = 0x000f # 1
    const DW_LANG_ObjC = 0x0010 # 0
    const DW_LANG_ObjC_plus_plus = 0x0011 # 0
    const DW_LANG_UPC = 0x0012 # 0
    const DW_LANG_D = 0x0013 # 0
    const DW_LANG_Python = 0x0014 # 0
    const DW_LANG_lo_user = 0x8000 #
    const DW_LANG_hi_user = 0xffff #
end

# # # Address Class Encodings
@constants DW_ADDR "" begin
    const DW_ADDR_NONE = 0
end

# # # Identifier Case Encodings
@constants DW_ID "" begin
    const DW_ID_case_sensitive = 0x00 #
    const DW_ID_up_case = 0x01 #
    const DW_ID_down_case = 0x02 #
    const DW_ID_case_insensitive = 0x03 #
end

# # # Calling convention encodings
@constants DW_CC "" begin
    const DW_CC_normal = 0x01 #
    const DW_CC_program = 0x02 #
    const DW_CC_nocall = 0x03 #
    const DW_CC_lo_user = 0x40 #
    const DW_CC_hi_user = 0xff #
end

# # # Inline encodings
@constants DW_INL "" begin
    const DW_INL_not_inlined = 0x00 #
    const DW_INL_inlined = 0x01 #
    const DW_INL_declared_not_inlined = 0x02 #
    const DW_INL_declared_inlined = 0x03 #
end

# # # Odering encodings
@constants DW_ORD "" begin
    const DW_ORD_row_major = 0x00 #
    const DW_ORD_col_major = 0x01 #
end

# # # Discriminant descriptor encodings
@constants DW_DSC "" begin
    const DW_DSC_label = 0x00 #
    const DW_DSC_range = 0x01 #
end

# # # Line Number Standard Opcode encodings
@constants DW_LNS "" begin
    const DW_LNS_copy = 0x01 #
    const DW_LNS_advance_pc = 0x02 #
    const DW_LNS_advance_line = 0x03 #
    const DW_LNS_set_file = 0x04 #
    const DW_LNS_set_column = 0x05 #
    const DW_LNS_negate_stmt = 0x06 #
    const DW_LNS_set_basic_block = 0x07 #
    const DW_LNS_const_add_pc = 0x08 #
    const DW_LNS_fixed_advance_pc = 0x09 #
    const DW_LNS_set_prologue_end = 0x0a #
    const DW_LNS_set_epilogue_begin = 0x0b #
    const DW_LNS_set_isa = 0x0c #
end


# # # Line Number Extended Opcode encodings
@constants DW_LNE "" begin
    const DW_LNE_end_sequence = 0x01 #
    const DW_LNE_set_address = 0x02 #
    const DW_LNE_define_file = 0x03 #
    const DW_LNE_set_discriminator = 0x04 #
    const DW_LNE_lo_user = 0x80 #
    const DW_LNE_hi_user = 0xff #
end

# # # Macinfo Type Encodings
@constants DW_MACINFO "" begin
    const DW_MACINFO_define = 0x01 #
    const DW_MACINFO_undef = 0x02 #
    const DW_MACINFO_start_file = 0x03 #
    const DW_MACINFO_end_file = 0x04 #
    const DW_MACINFO_vendor_ext = 0xff #
end
