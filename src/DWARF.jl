module DWARF
    using StrPack

    include("constants.jl")

    import Base: read, write, zero, bswap, isequal, show, print, show_indented


    abstract DWARFHeader
    abstract DWARFCUHeader <: DWARFHeader # Compilation Unit Header
    abstract DWARFTUHeader <: DWARFHeader # Type Unit Header
    abstract DWARFARHeader <: DWARFHeader # Address Range Header
    abstract DWARFPUBHeader <: DWARFHeader
    abstract PUBTableEntry
    abstract PUBTableSet

    export AbbrevTableEntry, AbbrevTableSet, ULEB128, SLEB128


    module DWARF32
        using StrPack
        using DWARF

        @struct immutable CUHeader <: DWARF.DWARFCUHeader
            unit_length::Uint32
            version::Uint16
            debug_abbrev_offset::Uint32
            address_size::Uint8
        end align_packed

        @struct immutable TUHeader <: DWARF.DWARFTUHeader
            unit_length::Uint32
            version::Uint16
            debug_abbrev_offset::Uint32
            address_size::Uint8
            type_signature::Uint64
            type_offset::Uint32
        end align_packed

        @struct immutable ARHeader <: DWARF.DWARFARHeader
            unit_length::Uint32
            version::Uint16
            debug_info_offset::Uint32
            address_size::Uint8
            segment_size::Uint8
        end align_packed

        @struct immutable PUBHeader <: DWARF.DWARFPUBHeader
            unit_length::Uint32
            version::Uint16
            debug_info_offset::Uint32
            debug_info_length::Uint32
        end align_packed

        immutable PUBTableEntry <: DWARF.PUBTableEntry
            offset::Uint32
            name::ASCIIString
        end

        immutable PUBTableSet <: DWARF.PUBTableSet
            header::PUBHeader
            entries::Array{PUBTableEntry,1}
        end

    end

    module DWARF64
        using StrPack
        using DWARF

        @struct immutable CUHeader <: DWARF.DWARFCUHeader
            unit_length::Uint64
            version::Uint16
            debug_abbrev_offset::Uint64
            address_size::Uint8
            type_offset::Uint64
        end align_packed

        @struct immutable TUHeader <: DWARF.DWARFTUHeader
            unit_length::Uint32
            version::Uint16
            debug_abbrev_offset::Uint32
            address_size::Uint8
            type_signature::Uint64
            type_offset::Uint64
        end align_packed

        @struct immutable ARHeader <: DWARF.DWARFARHeader
            unit_length::Uint32
            version::Uint16
            debug_info_offset::Uint64
            address_size::Uint8
            segment_size::Uint8
        end align_packed

        @struct immutable PUBHeader <: DWARF.DWARFPUBHeader
            unit_length::Uint32
            version::Uint16
            debug_info_offset::Uint64
            debug_info_length::Uint64
        end align_packed

        immutable PUBTableEntry <: DWARF.PUBTableEntry
            offset::Uint64
            name::ASCIIString
        end

        immutable PUBTableSet <: DWARF.PUBTableSet
            header::PUBHeader
            entries::Array{PUBTableEntry,1}
        end
    end

    ### LEB 128 types
    abstract LEB128

    Base.convert{T<:LEB128}(::Type{T},x::Int64) = T(big(x))
    Base.convert{T<:LEB128}(::Type{BigInt},x::T) = x.val

    immutable ULEB128 <: LEB128
        val::BigInt
    end

    immutable SLEB128 <: LEB128
        val::BigInt
    end

    isequal(a::LEB128,b::LEB128) = (a.val==b.val)
    isequal(a::LEB128,b::Integer) = (a.val==b)
    isequal(a::Integer,b::LEB128) = (b==a.val)

    function read(io::IO, ::Type{ULEB128})
        v = BigInt(0)
        shift = 0
        while true
            c = read(io,Uint8)
            v |= BigInt(c&0x7f)<<shift
            if (c&0x80)==0 #is last bit
                break
            end
            shift+=7
        end
        ULEB128(v)
    end


    function write(io::IO, x::ULEB128)
        x = x.val
        while true
            v = uint8(x) & 0x7f
            x >>= 7
            if x != 0
                v |= 0x80 # = ~0x7f
            end
            write(io,v) 
            x == 0 && break
        end
    end

    function decode(data::Array{Uint8,1}, offset, ::Type{ULEB128})
        v = BigInt(0)
        shift = 0
        i=0
        while(true)
            c = data[offset+i]
            i+=1
            v |= BigInt(c&0x7f)<<shift
            if (c&0x80)==0 #is last bit
                break
            end
            shift+=7
        end
        (offset+i,ULEB128(v))
    end

    function decode(data::Array{Uint8,1}, offset, ::Type{SLEB128})
        v = BigInt(0)
        shift = 0
        c=0
        i=0
        while(true)
            c = data[offset+i]
            i+=1
            v |= BigInt(c&0x7f)<<shift
            if (c&0x80)==0 #is last bit
                break
            end
            shift+=7
        end
        if (c & 0x40) != 0
            v |= -(BigInt(1)<<shift)
        end

        (offset+i,SLEB128(v))
    end

    function read(io::IO, ::Type{SLEB128})
        v = BigInt(0)
        shift = 0
        c=0
        while(true)
            c = read(io,Uint8)
            v |= BigInt(c&0x7f)<<shift
            if (c&0x80)==0 #is last bit
                break
            end
            shift+=7
        end
        if (c & 0x40) != 0
            v |= -(BigInt(1)<<shift)
        end

        SLEB128(v)
    end

    function write(io::IO, x::SLEB128)
        x = x.val
        more = true
        while more
            v = uint8(x) & 0x7f
            x >>= 7
            if ((x == 0 && ((v & 0x40) == 0)) || (x == -1 && ((v & 0x40) > 0)))
                more = false
            else
                v |= 0x80
            end
            write(io,v)
        end
    end

    fix_endian(x,endianness) = StrPack.endianness_converters[endianness][2](x)

    # Attributes
    module Attributes
        import DWARF
        import DWARF.ULEB128
        import DWARF.SLEB128
        import DWARF.fix_endian

        import Base.isequal, Base.read
        export AttributeSpecification, Attribute, GenericStringAttribute,
            Constant1, Constant2, Constant4, Constant8, SConstant, 
            UConstant, GenericStringAttribute, StrTableReference

        ###
        # Generic Attributes
        #
        # DWARF is designed in such a way that even consumers who may not understand 
        # all the possible arguments can still parse any DAWRF file. To do so, they 
        # have a fixed number of storage formats that need to be supported. In this
        # implementation attributes which have no specialized form are left as generic
        # attributes in the tree. 
        ##

        abstract Attribute
        abstract GenericAttribute <: Attribute

        using StrPack

        immutable AddressAttribute{T} <: GenericAttribute
            name::ULEB128
            content::T
        end

        immutable BlockAttribute <: GenericAttribute
            name::ULEB128
            content::Array{Uint8,1}
        end

        abstract GenericConstantAttribute <: GenericAttribute

        macro gattr(attr_name,supertype,ctype)
            quote
                immutable $attr_name <: $supertype
                    name::ULEB128
                    content::$ctype
                    ($(esc(attr_name)))(name::ULEB128) = new(name)
                    ($(esc(attr_name)))(name::ULEB128,content::$ctype) = new(name,content)
                end
            end
        end
        
        @gattr ExplicitFlag GenericAttribute Uint8
        @gattr Constant1 GenericConstantAttribute Uint8
        @gattr Constant2 GenericConstantAttribute Uint16
        @gattr Constant4 GenericConstantAttribute Uint32
        @gattr Constant8 GenericConstantAttribute Uint64
        @gattr SConstant GenericConstantAttribute SLEB128
        @gattr UConstant GenericConstantAttribute ULEB128

        abstract GenericReferenceAttribute <: GenericAttribute

        @gattr Reference1 GenericReferenceAttribute Uint8
        @gattr Reference2 GenericReferenceAttribute Uint16
        @gattr Reference4 GenericReferenceAttribute Uint32
        @gattr Reference8 GenericReferenceAttribute Uint64
        @gattr UReference GenericReferenceAttribute ULEB128

        abstract GenericStringAttribute <: GenericAttribute

        # # # 32/64-bit dependent types
        abstract StrTableReference
        module DWARF32
            import DWARF.ULEB128
            using ..Attributes
            immutable StrTableReference <: GenericStringAttribute
                name::ULEB128
                content::Uint32
            end
        end

        module DWARF64
            import DWARF.ULEB128
            using ..Attributes
            immutable StrTableReference <: GenericStringAttribute
                name::ULEB128
                content::Uint64
            end
        end

        immutable StringAttribute <: GenericStringAttribute
            name::ULEB128
            content::ASCIIString
        end

        immutable UnimplementedAttribute
        end

        const form_mapping = [
            AddressAttribute,       # DW_FORM_addr
            UnimplementedAttribute, # -- Invalid
            BlockAttribute,         # DW_FORM_block2
            BlockAttribute,         # DW_FORM_block4
            Constant2,              # DW_FORM_data2
            Constant4,              # DW_FORM_data4
            Constant8,              # DW_FORM_data8
            StringAttribute,        # DW_FORM_string
            BlockAttribute,         # DW_FORM_block
            BlockAttribute,         # DW_FORM_block1
            Constant1,              # DW_FORM_data1
            ExplicitFlag,           # DW_FORM_flag
            SConstant,              # DW_FORM_sdata
            StrTableReference,      # DW_FORM_strp
            UConstant,              # DW_FORM_udata
            UnimplementedAttribute, # DW_FORM_ref_addr
            Reference1,             # DW_FORM_ref1
            Reference2,             # DW_FORM_ref2
            Reference4,             # DW_FORM_ref4
            Reference8,             # DW_FORM_ref8
            UReference,             # DW_FORM_ref_udata
            UnimplementedAttribute, # DW_FORM_indirect
            UnimplementedAttribute, # DW_FORM_sec_offset
            UnimplementedAttribute, # DW_FORM_exprloc
            UnimplementedAttribute, # DW_FORM_flag_present
            UnimplementedAttribute  # DW_FORM_ref_sig8
        ]

        function form2gattrT(form::ULEB128)
            mapping = form_mapping[form.val]
            if mapping == UnimplementedAttribute
                error("Unimplemented Attribute Form $form")
            end
            mapping
        end

        ## Specialized Attrbutes

        abstract SpecializedAttribute <: Attribute

        immutable NameAttribute <: SpecializedAttribute
            ASCIIString
            NameAttribute(gattr::StringAttribute) = new(gattr.content)
        end

        immutable ExternalFlag <: SpecializedAttribute
            ExternalFlag(args...) = new()
        end

        const at_mapping = [
            UnimplementedAttribute, #DW_AT_sibling = 0x01 # reference 
            UnimplementedAttribute, #DW_AT_location = 0x02 # exprloc, loclistptr 
            NameAttribute,          #DW_AT_name = 0x03 # string 
            UnimplementedAttribute, # --INVALID 0x04
            UnimplementedAttribute, # --INVALID 0x05
            UnimplementedAttribute, # --INVALID 0x06
            UnimplementedAttribute, # --INVALID 0x07
            UnimplementedAttribute, # --INVALID 0x08
            UnimplementedAttribute, #DW_AT_ordering = 0x09 # constant 
            UnimplementedAttribute, # --INVALID 0x0a
            UnimplementedAttribute, #DW_AT_byte_size = 0x0b # constant, exprloc, reference 
            UnimplementedAttribute, #DW_AT_bit_offset = 0x0c # constant, exprloc, reference 
            UnimplementedAttribute, #DW_AT_bit_size = 0x0d # constant, exprloc, reference 
            UnimplementedAttribute, # --INVALID 0x0e
            UnimplementedAttribute, # --INVALID 0x0f        
            UnimplementedAttribute, #DW_AT_stmt_list = 0x10 # lineptr 
            UnimplementedAttribute, #DW_AT_low_pc = 0x11 # address 
            UnimplementedAttribute, #DW_AT_high_pc = 0x12 # address, constant 
            UnimplementedAttribute, #DW_AT_language = 0x13 # constant 
            UnimplementedAttribute, # --INVALID 0x14
            UnimplementedAttribute, #DW_AT_discr = 0x15 # reference 
            UnimplementedAttribute, #DW_AT_discr_value = 0x16 # constant 
            UnimplementedAttribute, #DW_AT_visibility = 0x17 # constant 
            UnimplementedAttribute, #DW_AT_import = 0x18 # reference 
            UnimplementedAttribute, #DW_AT_string_length = 0x19 # exprloc, loclistptr 
            UnimplementedAttribute, #DW_AT_common_reference = 0x1a # reference 
            UnimplementedAttribute, #DW_AT_comp_dir = 0x1b # string 
            UnimplementedAttribute, #DW_AT_const_value = 0x1c # block, constant, string
            UnimplementedAttribute, #DW_AT_containing_type = 0x1d # reference 
            UnimplementedAttribute, #DW_AT_default_value = 0x1e # reference 
            UnimplementedAttribute, # --INVALID 0x1f
            UnimplementedAttribute, #DW_AT_inline = 0x20 # constant 
            UnimplementedAttribute, #DW_AT_is_optional = 0x21 # flag 
            UnimplementedAttribute, #DW_AT_lower_bound = 0x22 # constant, exprloc, reference 
            UnimplementedAttribute, # --INVALID 0x23
            UnimplementedAttribute, # --INVALID 0x24
            UnimplementedAttribute, #DW_AT_producer = 0x25 # string 
            UnimplementedAttribute, # --INVALID 0x26
            UnimplementedAttribute, #DW_AT_prototyped = 0x27 # flag 
            UnimplementedAttribute, # --INVALID 0x28
            UnimplementedAttribute, # --INVALID 0x29
            UnimplementedAttribute, #DW_AT_return_addr = 0x2a # exprloc, loclistptr 
            UnimplementedAttribute, # --INVALID 0x2b
            UnimplementedAttribute, #DW_AT_start_scope = 0x2c # Constant, rangelistptr 
            UnimplementedAttribute, # --INVALID 0x2d
            UnimplementedAttribute, #DW_AT_bit_stride = 0x2e # constant, exprloc, reference 
            UnimplementedAttribute, #DW_AT_upper_bound = 0x2f # constant, exprloc, reference 
            UnimplementedAttribute, # --INVALID 0x30
            UnimplementedAttribute, #DW_AT_abstract_origin = 0x31 # reference 
            UnimplementedAttribute, #DW_AT_accessibility = 0x32 # constant 
            UnimplementedAttribute, #DW_AT_address_class = 0x33 # constant 
            UnimplementedAttribute, #DW_AT_artificial = 0x34 # flag 
            UnimplementedAttribute, #DW_AT_base_types = 0x35 # reference 
            UnimplementedAttribute, #DW_AT_calling_convention = 0x36 # constant 
            UnimplementedAttribute, #DW_AT_count = 0x37 # constant, exprloc, reference 
            UnimplementedAttribute, #DW_AT_data_member_location = 0x38 # constant, exprloc, loclistptr 
            UnimplementedAttribute, #DW_AT_decl_column = 0x39 # constant 
            UnimplementedAttribute, #DW_AT_decl_file = 0x3a # constant 
            UnimplementedAttribute, #DW_AT_decl_line = 0x3b # constant 
            UnimplementedAttribute, #DW_AT_declaration = 0x3c # flag 
            UnimplementedAttribute, #DW_AT_discr_list = 0x3d # block 
            UnimplementedAttribute, #DW_AT_encoding = 0x3e # constant 
            ExternalFlag,           #DW_AT_external = 0x3f # flag 
            UnimplementedAttribute, #DW_AT_frame_base = 0x40 # exprloc, loclistptr 
            UnimplementedAttribute, #DW_AT_friend = 0x41 # reference 
            UnimplementedAttribute, #DW_AT_identifier_case = 0x42 # constant 
            UnimplementedAttribute, #DW_AT_macro_info = 0x43 # macptr 
            UnimplementedAttribute, #DW_AT_namelist_item = 0x44 # reference 
            UnimplementedAttribute, #DW_AT_priority = 0x45 # reference 
            UnimplementedAttribute, #DW_AT_segment = 0x46 # exprloc, loclistptr 
            UnimplementedAttribute, #DW_AT_specification = 0x47 # reference 
            UnimplementedAttribute, #DW_AT_static_link = 0x48 # exprloc, loclistptr 
            UnimplementedAttribute, #DW_AT_type = 0x49 # reference 
            UnimplementedAttribute, #DW_AT_use_location = 0x4a # exprloc, loclistptr 
            UnimplementedAttribute, #DW_AT_variable_parameter = 0x4b # flag 
            UnimplementedAttribute, #DW_AT_virtuality = 0x4c # constant 
            UnimplementedAttribute, #DW_AT_vtable_elem_location = 0x4d # exprloc, loclistptr
            UnimplementedAttribute, #DW_AT_allocated = 0x4e # constant, exprloc, reference 
            UnimplementedAttribute, #DW_AT_associated = 0x4f # constant, exprloc, reference 
            UnimplementedAttribute, #DW_AT_data_location = 0x50 # exprloc 
            UnimplementedAttribute, #DW_AT_byte_stride = 0x51 # constant, exprloc, reference 
            UnimplementedAttribute, #DW_AT_entry_pc = 0x52 # address 
            UnimplementedAttribute, #DW_AT_use_UTF8 = 0x53 # flag 
            UnimplementedAttribute, #DW_AT_extension = 0x54 # reference 
            UnimplementedAttribute, #DW_AT_ranges = 0x55 # rangelistptr 
            UnimplementedAttribute, #DW_AT_trampoline = 0x56 # address, flag, reference, string 
            UnimplementedAttribute, #DW_AT_call_column = 0x57 # constant 
            UnimplementedAttribute, #DW_AT_call_file = 0x58 # constant 
            UnimplementedAttribute, #DW_AT_call_line = 0x59 # constant 
            UnimplementedAttribute, #DW_AT_description = 0x5a # string 
            UnimplementedAttribute, #DW_AT_binary_scale = 0x5b # constant 
            UnimplementedAttribute, #DW_AT_decimal_scale = 0x5c # constant 
            UnimplementedAttribute, #DW_AT_small = 0x5d # reference 
            UnimplementedAttribute, #DW_AT_decimal_sign = 0x5e # constant 
            UnimplementedAttribute, #DW_AT_digit_count = 0x5f # constant 
            UnimplementedAttribute, #DW_AT_picture_string = 0x60 # string 
            UnimplementedAttribute, #DW_AT_mutable = 0x61 # flag 
            UnimplementedAttribute, #DW_AT_threads_scaled = 0x62 # flag 
            UnimplementedAttribute, #DW_AT_explicit = 0x63 # flag 
            UnimplementedAttribute, #DW_AT_object_pointer = 0x64 # reference 
            UnimplementedAttribute, #DW_AT_endianity = 0x65 # constant 
            UnimplementedAttribute, #DW_AT_elemental = 0x66 # flag 
            UnimplementedAttribute, #DW_AT_pure = 0x67 # flag 
            UnimplementedAttribute, #DW_AT_recursive = 0x68 # flag 
            UnimplementedAttribute, #DW_AT_signature = 0x69 # reference 
            UnimplementedAttribute, #DW_AT_main_subprogram = 0x6a # flag 
            UnimplementedAttribute, #DW_AT_data_bit_offset = 0x6b # constant 
            UnimplementedAttribute, #DW_AT_const_expr = 0x6c # flag 
            UnimplementedAttribute, #DW_AT_enum_class = 0x6d # flag 
            UnimplementedAttribute  #DW_AT_linkage_name = 0x6e # string 
        ]

        function specialize(gattr)
            #try 
                T = at_mapping[gattr.name.val]
                if T == UnimplementedAttribute
                    return gattr
                end
                return T(gattr)
            #catch
            #    return gattr
            #end
        end

        read(io::IO,name,::Type{UConstant}) = UConstant(name,read(io,ULEB128))
        read(io::IO,name,::Type{SConstant}) = SConstant(name,read(io,SLEB128))
        read(io::IO,name,::Type{UReference}) = UReference(name,read(io,ULEB128))
        read(io::IO,name,::Type{ExplicitFlag}) = ExplicitFlag(name,read(io,Uint8))
        function read{T<:Union(GenericConstantAttribute,GenericReferenceAttribute)}(io::IO,::Type{T},
                                            header::DWARF.DWARFCUHeader,name,form,endianness::Symbol) 
            t = T(name)
            t = T(name,fix_endian(read(io,typeof(t.content)),endianness))
            t
        end
        read(io::IO,name,T::Type{StringAttribute}) = StringAttribute(name,strip(readuntil(io,'\0'),'\0'))
        read{T<:GenericAttribute}(io::IO,::Type{T},header::DWARF.DWARFCUHeader,name,form,endianness::Symbol) = read(io,name,T)
        function read(io::IO,::Type{BlockAttribute},header::DWARF.DWARFCUHeader,name,form,endianness::Symbol)
            if form == DWARF.DW_FORM_block1
                length = read(io,Uint8)
            elseif form == DWARF.DW_FORM_block2
                length = fix_endian(read(io,Uint16),endianness)
            elseif form == DWARF.DW_FORM_block4
                length = fix_endian(read(io,Uint32),endianness)
            elseif form == DWARF.DW_FORM_block
                length = fix_endian(read(io,ULEB128),endianness)
            else
                error("Unkown Block Form $form")
            end
            content = Array(Uint8,length)
            read(io,content)
            BlockAttribute(name,content)
        end
        function read(io::IO,::Type{AddressAttribute},header::DWARF.DWARFCUHeader,form,endianness::Symbol)
            T = DWARF.size_to_inttype(header.address_size)
            AddressAttribute{T}(name,fix_endian(read(io,T),endianness))
        end
        function read(io::IO,::Type{StrTableReference},header::DWARF.DWARFCUHeader,form,endianness::Symbol)
            if typeof(header.debug_abbrev_offset) == Uint32
                DWARF32.StrTableReference(name,fix_endian(read(io,Uint32),endianness))
            elseif typeof(header.debug_abbrev_offset) == Uint64
                DWARF64.StrTableReference(name,fix_endian(read(io,Uint64),endianness))
            end
        end

        immutable AttributeSpecification
            name::ULEB128
            form::ULEB128
        end
        isequal(a::AttributeSpecification,b::AttributeSpecification) = (a.name == b.name)&&(a.form == b.form)

        function read(io::IO,::Type{AttributeSpecification},endianness::Symbol)
            name = read(io,ULEB128)
            form = read(io,ULEB128)
            AttributeSpecification(name,form)
        end

        function read(io::IO,header::DWARF.DWARFCUHeader,a::AttributeSpecification,endianness::Symbol)
            generic = specialize(read(io,form2gattrT(a.form),header,a.name,a.form,endianness))
            # TODO: Return Actual Attributes
            generic
        end
    end
    using .Attributes

    module Expressions
        # TODO
        using DWARF
        import DWARF.fix_endian

        type StateMachine{T}
            stack::Array{T,1}
        end

        function evaluate_generic_instruction{T}(s::StateMachine{T},opcodes,i,getreg_func::Function,getword_func,endianness::Symbol)
            opcode = opcodes[i]
            i+=1
            if opcode == DWARF.DW_OP_deref
                push!(s.stack,getword_func(pop!(s.stack)))
            elseif opcode == DWARF.DW_OP_addr
                push!(s.stack,fix_endian(reinterpret(T,opcodes[i:(i+sizeof(T)-1)])[1],endianness))
                i+=sizeof(T)-1
            elseif opcode == DWARF.DW_OP_const1u
                i+=1
                push!(s.stack,convert(T,opcodes[i]))
            elseif opcode == DWARF.DW_OP_const1s
                i+=1 
                # Yes, this is actually different from the above, since we need to sign extend properly
                push!(s.stack,convert(T,fix_endian(reinterpret(Int8,opcodes[i]),endianness)))
            elseif opcode == DWARF.DW_OP_const2u # 1 2-byte constant 
                push!(s.stack,convert(T,fix_endian(reinterpret(Uint16,opcodes[i:i+1])[1],endianness)))
                i+=2
            elseif opcode == DWARF.DW_OP_const2s # 1 2-byte constant 
                push!(s.stack,convert(T,fix_endian(reinterpret(Int16,opcodes[i:i+1])[1],endianness)))
                i+=2
            elseif opcode == DWARF.DW_OP_const4u # 1 4-byte constant 
                push!(s.stack,convert(T,fix_endian(reinterpret(Uint32,opcodes[i:i+3])[1],endianness)))
                i+=4
            elseif opcode == DWARF.DW_OP_const4u # 1 4-byte constant 
                push!(s.stack,convert(T,fix_endian(reinterpret(Int32,opcodes[i:i+3])[1],endianness)))
                i+=4
            elseif opcode == DWARF.DW_OP_const8u # 1 8-byte constant 
                push(!s.stack,convert(T,fix_endian(reinterpret(Uint64,opcodes[i:i+7])[1],endianness)))
                i+=8  
            elseif opcode == DWARF.DW_OP_const8s # 1 8-byte constant 
                push!(s.stack,convert(T,fix_endian(reinterpret(Int64,opcodes[i:i+7])[1],endianness)))
                i+=8   
            elseif opcode == DWARF.DW_OP_constu 
                (i,val) = decode(opcodes,i,ULEB128)
                push!(s.stack,convert(T,val))
            elseif opcode == DWARF.DW_OP_consts
                (i,val) = decode(opcodes,i,SLEB128)  
                push!(s.stack,convert(T,val))
            elseif opcode == DWARF.DW_OP_dup 
                push!(s.stack,s.stack[length(s.stack)-1])
            elseif opcode == DWARF.DW_OP_pick
                push!(s.stack,s.stack[opcode[i+=1]])
            elseif opcode == DWARF.DW_OP_swap
                top = length(s.stack)
                val = s.stack[top]
                s.stack[top] = s.stack[top-1]
                s.stack[top-1] = val
            elseif opcode == DWARF.DW_OP_rot
                top = length(s.stack)
                val = s.stack[top]
                s.stack[top] = s.stack[top-1]
                s.stack[top-1] = s.stack[top-2]
                s.stack[top-2] = val
            elseif opcode == DWARF.DW_OP_xderef
                error("Unimplemented")
            elseif opcode == DWARF.DW_OP_abs
                push!(s.stack,abs(signed(pop!(s.stack))))
            elseif opcode == DWARF.DW_OP_and
                push!(s.stack,pop!(s.stack)&pop!(s.stack))
            elseif opcode == DWARF.DW_OP_div
                top = pop!(s.stack)
                push!(s.stack,pop!(s.stack)/top)
            elseif opcode == DWARF.DW_OP_minus
                top = pop!(s.stack)
                push!(s.stack,pop!(s.stack)-top)
            elseif opcode == DWARF.DW_OP_minus
                top = pop!(s.stack)
                push!(s.stack,pop!(s.stack)%top)
            elseif opcode == DWARF.DW_OP_mul
                push!(s.stack,pop!(s.stack)*pop!(s.stack))
            elseif opcode == DWARF.DW_OP_neg
                push!(s.stack,-(signed(pop!(s.stack))))
            elseif opcode == DWARF.DW_OP_not
                push!(s.stack,~(pop!(s.stack)))
            elseif opcode == DWARF.DW_OP_plus_uconst
                (i,val) = decode(opcodes,i,ULEB128)
                push!(s.stack,pop!(s.stack)+val)
            elseif opcode == DWARF.DW_OP_shl
                top = pop!(s.stack)
                push!(s.stack,pop!(s.stack)<<top)  
            elseif opcode == DWARF.DW_OP_shr
                top = pop!(s.stack)
                push!(s.stack,pop!(s.stack)>>top)  
            elseif opcode == DWARF.DW_OP_shra
                top = pop!(s.stack)
                push!(s.stack,convert(T,signed(pop!(s.stack))>>top))   
            elseif opcode == DWARF.DW_OP_xor
                top = pop!(s.stack)
                push!(s.stack,pop!(s.stack)$top)  
            elseif opcode == DWARF.DW_OP_le
                top = pop!(s.stack)
                push!(s.stack,convert(T,pop!(s.stack)<=top))
            elseif opcode == DWARF.DW_OP_ge
                top = pop!(s.stack)
                push!(s.stack,convert(T,pop!(s.stack)>=top))
            elseif opcode == DWARF.DW_OP_eq
                top = pop!(s.stack)
                push!(s.stack,convert(T,pop!(s.stack)==top))
            elseif opcode == DWARF.DW_OP_lt
                top = pop!(s.stack)
                push!(s.stack,convert(T,pop!(s.stack)<top))
            elseif opcode == DWARF.DW_OP_gt
                top = pop!(s.stack)
                push!(s.stack,convert(T,pop!(s.stack)>top))
            elseif opcode == DWARF.DW_OP_ne
                top = pop!(s.stack)
                push!(s.stack,convert(T,pop!(s.stack)!=top))
            elseif opcode == DWARF.DW_OP_skip
                i += fix_endian(reinterrept(Int16,opcodes[i:i+1])[1],endianness)
            elseif opcode == DWARF.DW_OP_bra
                if(pop!(s.stack) != 0)
                    i += fix_endian(reinterrept(Int16,opcodes[i:i+1])[1],endianness)
                end
            elseif opcode == DWARF.DW_OP_call2 || opcode == DWARF.DW_OP_call4 || opcode == DWARF.DW_OP_call_ref
                error("Unimplemented")
            elseif opcode >= DWARF.DW_OP_lit1 && opcode <= DWARF.DW_OP_lit31
                push!(s.stack,opcode-DW_OP_lit1+1)
            elseif opcode >= DWARF.DW_OP_breg0 && opcode <= DWARF.DW_OP_breg31
                push!(s.stack,getreg_func(opcode-DWARF.DW_OP_breg0))
            elseif opcode == DWARF.DW_OP_bregx
                (i,val) = decode(opcodes,i,ULEB128)
                push!(s.stack,getreg_func(val))
            elseif opcode == DWARF.DW_OP_nop
                #NOP
            else 
                return (i-1,false)
            end
            (i,true)
        end

        function evaluate_generic{T}(s::StateMachine{T},opcodes::Array{Uint8,1},getreg_func::Function,getword_func,endianness::Symbol)
            i=1
            while true
                i,res = evaluate_generic_instruction(s,opcodes,i,getreg_func,getword_func,endianness)
                if !res
                    error("Unrecognized Opcode ",opcodes[i])
                end
                if i==length(opcodes)
                    break
                end
            end
        end

        immutable RegisterLocation
            i::Int32
        end

        immutable MemoryLocation{T}
            i::T
        end

        function evaluate_simple_location{T}(s::StateMachine{T},opcodes::Array{Uint8,1},getreg_func::Function,getword_func,endianness::Symbol)
            i=1
            opcode = opcodes[i]
            if opcode >= DWARF.DW_OP_reg0 && opcode <= DWARF.DW_OP_reg31
                return RegisterLocation(opcode-DWARF.DW_OP_reg0)
            elseif opcode == DWARF.DW_OP_regx
                (i,val) = decode(opcodes,i,ULEB128)
                return RegisterLocation(val)
            else
                evaluate_generic(s,opcodes,getreg_func,getword_func,endianness)
                return MemoryLocation{T}(last(s.stack))
            end
        end
    end

    # The line table is encoded as a state machine program 
    # operating on a register machine, whose register represent the
    # values the debugger needs to know about the current source location
    module LineTableSupport
        using StrPack

        import ..ULEB128, ..SLEB128, ..DWARF

        immutable HeaderStub{T}
            length::T
            version::Uint16
            header_length::T
            minimum_instruction_length::Uint8
            maximum_operations_per_instruction::Uint8
            default_is_stmt::Uint8
            line_base::Int8
            line_range::Int8
            opcode_base::Uint8
        end

        immutable FileEntry
            name::UTF8String
            dir_idx::BigInt
            timestamp::BigInt
            filelength::BigInt
        end

        Base.isequal(x::FileEntry,y::FileEntry) = 
            (x.name == y.name && x.dir_idx == y.dir_idx && x.timestamp == y.timestamp && x.filelength == y.filelength)

        function Base.read(io::IO,::Type{FileEntry})
            s = readstring(io)
            if endof(s) == 0
                return FileEntry(s,0,0,0)
            end
            return FileEntry(s,read(io,ULEB128),read(io,ULEB128),read(io,ULEB128))
        end

        function unpack(io,::Type{HeaderStub}) 
            T = Uint32
            length = read(io,T)
            if length == 0xffffffff
                T = Uint64
                length = read(io,T)
            end
            version = read(io,Uint16)
            header_length = read(io,T)
            minimum_instruction_length = read(io,Uint8)
            maximum_operations_per_instruction = version >= 4 ? read(io,Uint8) : 1
            HeaderStub{T}(length,version,header_length,minimum_instruction_length,maximum_operations_per_instruction,
                read(io,Uint8),read(io,Int8),read(io,Int8),read(io,Uint8))
        end

        immutable Header{T}
            stub::HeaderStub{T}
            standard_opcode_lengths::Vector{Uint8}
            include_directories::Vector{UTF8String}
            file_names::Vector{FileEntry}
        end

        function readstring(io)
            ret = Array(Uint8,0)
            while true
                c = read(io,Uint8)
                c == 0 && break
                push!(ret,c)
            end
            UTF8String(ret)
        end

        function read_header(io)
            stub = unpack(io,HeaderStub)
            standard_opcode_lengths = Array(Uint8,stub.opcode_base-1)
            read(io,standard_opcode_lengths)
            include_directories = UTF8String[]
            while true
                s = readstring(io)
                endof(s) == 0 && break
                push!(include_directories,s)
            end
            file_names = FileEntry[]
            while true
                f = read(io,FileEntry)
                endof(f.name) == 0 && break
                push!(file_names,f)
            end
            Header{header_type(stub)}(stub,standard_opcode_lengths,include_directories,file_names)
        end

        header_type{T}(h::Header{T}) = T
        header_type{T}(h::HeaderStub{T}) = T

        immutable RegisterState
            address::BigInt
            op_index::BigInt
            file::BigInt
            line::BigInt
            column::BigInt
            is_stmt::Bool
            basic_block::Bool
            end_sequence::Bool
            prologue_end::Bool
            epilogue_begin::Bool
            isa::BigInt
            discriminator::BigInt

            # Initial Register state as defined by DWARF standard
            function RegisterState(default_is_stmt::Bool)
                new(BigInt(0),BigInt(0),BigInt(1),BigInt(1),BigInt(0),default_is_stmt,
                    false,false,false,false,BigInt(0),BigInt(0))
            end

            function RegisterState(x::RegisterState;
                    address = x.address, op_index = x.op_index, file = x.file, line = x.line,
                    column = x.column, is_stmt = x.is_stmt, basic_block = x.basic_block,
                    end_sequence = x.end_sequence, prologue_end = x.prologue_end, 
                    epilogue_begin = x.epilogue_begin, isa = x.isa, discriminator = x.discriminator)
                new(address,op_index,file,line,column,is_stmt,basic_block,end_sequence,prologue_end,
                    epilogue_begin,isa,discriminator)
            end

            RegisterState(address,op_index,file,line,column,is_stmt,basic_block,end_sequence,
                    prologue_end,epilogue_begin,isa,discriminator) =
                new(address,op_index,file,line,column,is_stmt,basic_block,end_sequence,
                    prologue_end,epilogue_begin,isa,discriminator)
        end

        Base.isequal(x::RegisterState,y::RegisterState) = (
            x.address == y.address &&
            x.op_index == y.op_index &&
            x.file == y.file &&
            x.line == y.line &&
            x.column == y.column &&
            x.is_stmt == y.is_stmt &&
            x.basic_block == y.basic_block &&
            x.end_sequence == y.end_sequence &&
            x.prologue_end == y.prologue_end &&
            x.epilogue_begin == y.epilogue_begin &&
            x.isa == y.isa &&
            x.discriminator == y.discriminator)

        type StateMachine
            header::Header
            state::RegisterState
        end

        function pc_adv!(m::StateMachine,op_adv)
            m.state = RegisterState(m.state,
                address = m.state.address + m.header.stub.minimum_instruction_length *
                    div(m.state.op_index + op_adv,m.header.stub.maximum_operations_per_instruction),
                op_index = m.state.op_index + 
                    mod(m.state.op_index + op_adv,m.header.stub.maximum_operations_per_instruction))
        end

        function pcl_adv!(m::StateMachine,op)
            adj_opc = op - m.header.stub.opcode_base
            pc_adv!(m,div(adj_opc,m.header.stub.line_range))
            m.state = RegisterState(m.state,
                line = m.state.line + m.header.stub.line_base + mod(adj_opc,m.header.stub.line_range))
        end

        function step(io,m::StateMachine)
            op = read(io,Uint8)
            if op == 0
                # Extended opcode
                pos = position(io)
                size::BigInt = read(io,ULEB128)
                ex_op = read(io,Uint8)
                if ex_op == DWARF.DW_LNE_end_sequence
                    m.state = RegisterState(m.state,end_sequence = true)
                    ret = (true,m.state) 
                    m.state = RegisterState(m.header.stub.default_is_stmt > 0)
                    position(io) > pos+size+1 && error("Malformed extended instruction")
                    return ret
                elseif ex_op == DWARF.DW_LNE_set_address
                    addrsize = pos+size - position(io) + 1
                    if addrsize == 4
                        m.state = RegisterState(m.state,address = read(io,Uint32))
                    elseif addrsize == 8
                        m.state = RegisterState(m.state,address = read(io,Uint64))
                    else
                        error("Unsupported target address size $addrsize")
                    end
                elseif ex_op == DWARF.DW_LNE_define_file
                    push!(m.file_names,read(io,FileEntry))
                elseif ex_op == DWARF.DW_LNE_set_discriminator
                    m.state = RegisterState(m.state,discriminator = read(io,ULEB128))
                else 
                    error("Unrecognized extended opcode $ex_op")
                end
                position(io) > pos+size+1 && error("Malformed extended instruction (op=$ex_op, pos=$pos, size=$size, iopos=$(position(io)))")
            elseif op < m.header.stub.opcode_base
                # standard opcode
                if op == DWARF.DW_LNS_copy
                    if m.header.standard_opcode_lengths[DWARF.DW_LNS_copy] != 0
                        error("Malformed Instruction")
                    end
                    ret = (true,m.state)
                    m.state = RegisterState(m.state,
                        discriminator = 0,
                        basic_block = false,
                        prologue_end = false,
                        epilogue_begin = false)
                    return ret
                elseif op == DWARF.DW_LNS_advance_pc
                    if m.header.standard_opcode_lengths[DWARF.DW_LNS_advance_pc] != 1
                        error("Malformed Instruction")
                    end
                    pc_adv!(m,read(io,ULEB128).val)
                elseif op == DWARF.DW_LNS_advance_line
                    if m.header.standard_opcode_lengths[DWARF.DW_LNS_advance_line] != 1
                        error("Malformed Instruction")
                    end
                    m.state = RegisterState(m.state,line = m.state.line + read(io,SLEB128).val)
                elseif op == DWARF.DW_LNS_set_file
                    if m.header.standard_opcode_lengths[DWARF.DW_LNS_set_file] != 1
                        error("Malformed Instruction")
                    end
                    m.state = RegisterState(m.state,line = read(io,ULEB128))
                elseif op == DWARF.DW_LNS_set_column
                    if m.header.standard_opcode_lengths[DWARF.DW_LNS_set_column] != 1
                        error("Malformed Instruction")
                    end
                    m.state = RegisterState(m.state,column = read(io,ULEB128))
                elseif op == DWARF.DW_LNS_negate_stmt
                    if m.header.standard_opcode_lengths[DWARF.DW_LNS_negate_stmt] != 0
                        error("Malformed Instruction")             
                    end
                    m.state = RegisterState(m.state,is_stmt = !m.state.is_stmt)
                elseif op == DWARF.DW_LNS_set_basic_block
                    if m.header.standard_opcode_lengths[DWARF.DW_LNS_set_basic_block] != 0
                        error("Malformed Instruction")             
                    end
                    m.state = RegisterState(m.state,basic_block = true)
                elseif op == DWARF.DW_LNS_const_add_pc
                    if m.header.standard_opcode_lengths[DWARF.DW_LNS_const_add_pc] != 0
                        error("Malformed Instruction")             
                    end
                    pc_adv!(m,255)
                elseif op == DWARF.DW_LNS_fixed_advance_pc
                    if m.header.standard_opcode_lengths[DWARF.DW_LNS_fixed_advance_pc] != 1
                        error("Malformed Instruction")             
                    end   
                    m.state = RegisterState(m.state,
                        address = m.state.address + read(io,Uint16),
                        op_index = 0)
                elseif op == DWARF.DW_LNS_set_prologue_end
                    if m.header.standard_opcode_lengths[DWARF.DW_LNS_set_prologue_end] != 0
                        error("Malformed Instruction")             
                    end 
                    m.state = RegisterState(m.state, prologue_end = false)
                elseif op == DWARF.DW_LNS_set_epilogue_begin
                    if m.header.standard_opcode_lengths[DWARF.DW_LNS_set_epilogue_begin] != 0
                        error("Malformed Instruction")             
                    end 
                    m.state = RegisterState(m.state, epilogue_begin = false)
                elseif op == DWARF.DW_LNS_set_epilogue_begin
                    if m.header.standard_opcode_lengths[DWARF.DW_LNS_set_epilogue_begin] != 0
                        error("Malformed Instruction")             
                    end 
                    m.state = RegisterState(m.state, isa = read(io,ULEB128))
                end
            else 
                # special opcode
                # standard actions
                m.state = RegisterState(m.state,
                    basic_block = false,
                    prologue_end = false,
                    epilogue_begin = false,
                    discriminator = 0)
                # decode the opcode
                pc_adv!(m,op)
            end
            return (false,m.state)
        end

        function state_step(io,m::StateMachine)
            stop = false
            state = m.state
            while !stop
                (stop, state) = step(io,m)
            end
            return state
        end

        # Iterate over the line table
        immutable LineTable
            io::IO
            header::Header
            start::Int
            LineTable(io,header,start) = new(io,header,start)
            LineTable(io) = (pos=position(io);new(io,read_header(io),pos))
        end

        import Base: start, next, done

        function start(x::LineTable) 
            # The header length is the number of bytes after the header length
            # The fields from the start are length (header_type), version (Uint16) and header_length(header_type)
            # plus an additional Uint32 if the header_type is Uint64
            seek(x.io,x.start + x.header.stub.header_length + 2*sizeof(header_type(x.header)) + sizeof(Uint16) +
                (header_type(x.header) == Uint64 ? sizeof(Uint32) : 0))
            StateMachine(x.header,RegisterState(x.header.stub.default_is_stmt > 0))
        end
        next(x::LineTable,m::StateMachine) = (state_step(x.io,m),m)
        done(x::LineTable,m::StateMachine) = position(x.io) > (x.start + x.header.stub.length)
    end

    import .LineTableSupport.LineTable
    export LineTable

    zero(::Type{AttributeSpecification}) = AttributeSpecification(ULEB128(BigInt(0)),ULEB128(BigInt(0)))

    immutable DIE
        tag::ULEB128
        attributes::Array{Attribute,1}
    end

    show(io::IO,d::DIE) = print(io,"DIE(type ",d.tag,", ",length(d.attributes)," Attributes)")

    immutable ARTableEntry{S,T}
        segment::S
        address::T
        length::T
    end

    isequal{S,T}(a::ARTableEntry{S,T},b::ARTableEntry{S,T}) = (a.segment==b.segment)&&(a.address==b.address)&&(a.length==b.length)

    zero{S,T}(::Type{ARTableEntry{S,T}}) = ARTableEntry{S,T}(zero(S),zero(T),zero(T))

    const DEBUG_SECTIONS = [
        "debug_abbrev",
        "debug_aranges",
        "debug_frame",
        "debug_info",
        "debug_line",
        "debug_loc",
        "debug_macinfo",
        "debug_pubnames",
        "debug_ranges",
        "debug_str",
        "debug_types"]

    @struct immutable InitialLength
        val::Uint32
    end

    for (t,t32,t64) in ((:(DWARF.DWARFCUHeader),:(DWARF32.CUHeader),:(DWARF32.CUHeader)),
                      (:(DWARF.DWARFTUHeader),:(DWARF32.TUHeader),:(DWARF32.TUHeader)),
                      (:(DWARF.DWARFARHeader),:(DWARF32.ARHeader),:(DWARF32.ARHeader)),
                      (:(DWARF.DWARFPUBHeader),:(DWARF32.PUBHeader),:(DWARF32.PUBHeader)))
        @eval function read(io::IO,::Type{($t)},endianness::Symbol)
                # XXX: Is there a better way to do this?
                l = unpack(io,InitialLength,endianness)
                if l.val<0xfffffff0 #Is a 32bit DWARF record
                    skip(io,-sizeof(InitialLength)) #Try to rewind
                    return unpack(io,($t32),endianness)
                elseif l.val == 0xffffffff
                    return unpack(io,($t64),endianness)
                else 
                    error("Unkown Compilation Unit Header Type")
                end 
            end
        @eval read(io::IO,::Type{$t}) = read(io,$t,:NativeEndian)
    end

    immutable Zero
    end
    
    bswap(::Zero) = Zero()
    read(io::IO,::Type{Zero}) = Zero()
    zero(::Type{Zero}) = Zero()

    function size_to_inttype(size)
        if size == 0
            return Zero
        elseif size == 1
            return Uint8
        elseif size == 2
            return Uint16
        elseif size == 4
            return Uint32
        elseif size == 8
            return Uint64
        elseif size == 16
            return Uint128
        else
            error("Unsupported size unit $size")
        end
    end

    immutable ARTableSet{S,T}
        header::DWARFARHeader
        entries::Array{ARTableEntry{S,T},1}
    end

    type ARTable
        sets::Array{ARTableSet,1}
    end

    const dummy_dict = Dict{None,Array{Integer,1}}() #Since we don't have StrPack support for Parametric types

    # aranges tables
    function read(io::IO,::Type{ARTableSet},endianness::Symbol)
        header = read(io,DWARFARHeader,endianness)
        t = ARTableEntry{size_to_inttype(header.segment_size),size_to_inttype(header.address_size)}
        table = ARTableSet(header,Array(t,0))
        entry_size = StrPack.calcsize(t,dummy_dict,align_packed)
        while true
            skip(io,position(io)%entry_size) # Align to a boundary that is a multiple of the entry size
            r = unpack(io,t,dummy_dict,align_packed,endianness)
            if r==zero(t)
                break
            end
            push!(table.entries,r)
        end
        table
    end
    read(io::IO,::Type{ARTableSet}) = read(io,ARTableSet,:NativeEndian)

    # pubnames/pubtypes
    type PUBTable
        sets::Array{PUBTableSet,1}
    end

    function read{T<:PUBTableEntry}(io::IO,::Type{T},endianness::Symbol)
        offset = StrPack.endianness_converters[endianness][2](read(io,T.types[1]))
        if offset != 0
            name = strip(readuntil(io,'\0'),'\0')
        else
            name = ""
        end
        T(offset,name)
    end

    function read(io::IO,::Type{PUBTableSet},endianness::Symbol)
        header = read(io,DWARFPUBHeader,endianness)
        if typeof(header) == DWARF32.PUBHeader
            t=DWARF32.PUBTableSet(header,Array(DWARF32.PUBTableEntry,0))
        elseif typeof(header) == DWARF64.PUBHeader
            t=DWARF64.PUBTableSet(header,Array(DWARF64.PUBTableEntry,0))
        end
        while true
            entry = read(io,eltype(t.entries),endianness)
            if entry.offset == 0
                break
            end
            push!(t.entries,entry)
        end
        t
    end
    read(io::IO,::Type{PUBTableSet}) = read(io,PUBTableSet,:NativeEndian)

    immutable AbbrevTableEntry
        code::ULEB128
        tag::ULEB128
        has_children::Uint8
        attributes::Array{AttributeSpecification,1}
    end

    immutable AbbrevTableSet 
        entries::Array{AbbrevTableEntry,1}
    end
    zero(::Type{AbbrevTableEntry}) = AbbrevTableEntry(ULEB128(BigInt(0)),ULEB128(BigInt(0)),uint8(0),Array(AttributeSpecification,0))

    function read(io::IO,::Type{AbbrevTableEntry},endianness::Symbol)
        code = read(io,ULEB128)
        if code != 0
            tag = read(io,ULEB128)
            has_children = read(io,Uint8)
            ret = AbbrevTableEntry(code,tag,has_children,Array(AttributeSpecification,0))
            while true
                e = read(io,AttributeSpecification,endianness)
                if(e == zero(AttributeSpecification))
                    break
                end
                push!(ret.attributes,e)
            end
            return ret
        else
            return zero(AbbrevTableEntry)
        end
    end

    function read(io::IO,::Type{AbbrevTableSet},endianness::Symbol)
        ret = AbbrevTableSet(Array(AbbrevTableEntry,0))
        while true
            e = read(io,AbbrevTableEntry,endianness)
            if e.code == 0
                break
            end
            push!(ret.entries,e)
        end
        ret
    end

    # Assume position is right after number
    function read(io::IO,num::ULEB128,header::DWARFCUHeader,ate::AbbrevTableEntry,::Type{DIE},endianness::Symbol)
        ret = DIE(num,Array(Attribute,0))
        for a in ate.attributes
            push!(ret.attributes,read(io,header,a,endianness))
        end
        ret
    end
    function read(io::IO,header::DWARFCUHeader,ats::AbbrevTableSet,::Type{DIE})
        num = read(io,ULEB128)
        ae = ats.entries[num.val]
        read(io,num,header,ae,DIE)
    end


    function read(io::IO,::Type{DIE},endianness::Symbol)
        tag = read(io,ULEB128)
        DIE(tag,Array(AttributeSpecification,0))
    end

    ## Tree Interface
    const zero_die = DIE(ULEB128(BigInt(0)),Array(Attribute,0))
    zero(::Type{DIE}) = zero_die

    abstract DIENode

    immutable DIETreeNode <: DIENode
        self::DIE
        children::Array{DIETreeNode,1}
        parent::DIENode
    end

    type DIETree <: DIENode
        children::Array{DIETreeNode,1}
    end

    show(io::IO,node::DIETreeNode) = (print(io,"DIETreeNode(");show(io,node.self);print(io,", ",length(node.children)," children)"))
    show(io::IO,node::DIETree) = print(io,"DIETree(",length(node.children)," children)")


    const zero_node = DIETreeNode(zero(DIE),Array(DIETreeNode,0),DIETree(Array(DIETreeNode,0)))

    zero(::Type{DIETreeNode}) = zero_node

    function read(io::IO,header::DWARFCUHeader,ats::AbbrevTableSet,parent::Union(DIETree,DIETreeNode),::Type{DIETreeNode},endianness::Symbol)
        num = read(io,ULEB128)
        if num != 0
            ae = ats.entries[num.val]
            ret = DIETreeNode(read(io,num,header,ae,DIE,endianness),Array(DIETreeNode,0),parent)
            push!(parent.children,ret)
            if(ae.has_children == DW_CHILDREN_yes)
                read(io,header,ats,ret,DIETreeNode,endianness)
            else
                read(io,header,ats,parent,DIETreeNode,endianness)
            end
            return ret
        end
        zero(DIETreeNode)
    end
end #module