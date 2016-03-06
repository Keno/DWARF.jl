VERSION >= v"0.4.0-dev+6641" && __precompile__()
module DWARF
    using ObjFileBase
    using StrPack
    using AbstractTrees

    include("constants.jl")

    import Base: read, write, zero, bswap, isequal, show, print, hash, ==
    import Base: start, next, done

    import AbstractTrees: children, printnode

    abstract DWARFHeader
    abstract DWARFCUHeader <: DWARFHeader # Compilation Unit Header
    abstract DWARFTUHeader <: DWARFHeader # Type Unit Header
    abstract DWARFARHeader <: DWARFHeader # Address Range Header
    abstract DWARFPUBHeader <: DWARFHeader
    abstract PUBTableEntry
    abstract PUBTableSet

    export AbbrevTableEntry, AbbrevTableSet, ULEB128, SLEB128,
        DIETree, attributes, dies


    module DWARF32
        using DWARF
        using StrPack

        @struct immutable CUHeader <: DWARF.DWARFCUHeader
            unit_length::UInt32
            version::UInt16
            debug_abbrev_offset::UInt32
            address_size::UInt8
        end align_packed

        @struct immutable TUHeader <: DWARF.DWARFTUHeader
            unit_length::UInt32
            version::UInt16
            debug_abbrev_offset::UInt32
            address_size::UInt8
            type_signature::UInt64
            type_offset::UInt32
        end align_packed

        @struct immutable ARHeader <: DWARF.DWARFARHeader
            unit_length::UInt32
            version::UInt16
            debug_info_offset::UInt32
            address_size::UInt8
            segment_size::UInt8
        end align_packed

        @struct immutable PUBHeader <: DWARF.DWARFPUBHeader
            unit_length::UInt32
            version::UInt16
            debug_info_offset::UInt32
            debug_info_length::UInt32
        end align_packed

        immutable PUBTableEntry <: DWARF.PUBTableEntry
            offset::UInt32
            name::ASCIIString
        end

        immutable PUBTableSet <: DWARF.PUBTableSet
            header::PUBHeader
            entries::Array{PUBTableEntry,1}
        end

    end

    module DWARF64
        using DWARF
        using StrPack

        @struct immutable CUHeader <: DWARF.DWARFCUHeader
            unit_length::UInt64
            version::UInt16
            debug_abbrev_offset::UInt64
            address_size::UInt8
            type_offset::UInt64
        end align_packed

        @struct immutable TUHeader <: DWARF.DWARFTUHeader
            unit_length::UInt32
            version::UInt16
            debug_abbrev_offset::UInt32
            address_size::UInt8
            type_signature::UInt64
            type_offset::UInt64
        end align_packed

        @struct immutable ARHeader <: DWARF.DWARFARHeader
            unit_length::UInt32
            version::UInt16
            debug_info_offset::UInt64
            address_size::UInt8
            segment_size::UInt8
        end align_packed

        @struct immutable PUBHeader <: DWARF.DWARFPUBHeader
            unit_length::UInt32
            version::UInt16
            debug_info_offset::UInt64
            debug_info_length::UInt64
        end align_packed

        immutable PUBTableEntry <: DWARF.PUBTableEntry
            offset::UInt64
            name::ASCIIString
        end

        immutable PUBTableSet <: DWARF.PUBTableSet
            header::PUBHeader
            entries::Array{PUBTableEntry,1}
        end
    end

    ### Display
    function show(io::IO, header::DWARFCUHeader)
        is64 = isa(header,DWARF64.CUHeader)
        printentry(io,"Length","0x",hex(header.unit_length))
        printentry(io,"Version",dec(header.version))
        printentry(io,"Abbrev Offset","0x",hex(header.debug_abbrev_offset))
        printentry(io,"Address Size","0x",hex(header.address_size))
        is64 && printentry(io,"Type Offset","0x",hex(header.type_offset))
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

    show(io::IO,s::SLEB128) = show(io,s.val)
    hash(x::LEB128, h::UInt64) = hash(x.val, h)
    isequal(a::LEB128,b::LEB128) = (a.val==b.val)
    isequal(a::LEB128,b::Integer) = (a.val==b)
    isequal(a::Integer,b::LEB128) = (b==a.val)
    ==(a::LEB128,b::LEB128) = isequal(a,b)
    ==(a::LEB128,b::Integer) = isequal(a.val, b)
    ==(a::Integer,b::LEB128) = isequal(b, a.val)
    Base.zero{T<:LEB128}(::Type{T}) = convert(T,0)


    function read(io::IO, ::Type{ULEB128})
        v = BigInt(0)
        shift = 0
        while true
            c = read(io,UInt8)
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
            v = (x % UInt8) & 0x7f
            x >>= 7
            if x != 0
                v |= 0x80 # = ~0x7f
            end
            write(io,v)
            x == 0 && break
        end
    end

    function decode(data::Array{UInt8,1}, offset, ::Type{ULEB128})
        v = BigInt(0)
        shift = 0
        i=0
        while true
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

    function decode(data::Array{UInt8,1}, offset, ::Type{SLEB128})
        v = BigInt(0)
        shift = 0
        c=0
        i=0
        while true
            c = data[offset+i]
            i+=1
            v |= BigInt(c&0x7f)<<shift
            shift+=7
            if (c&0x80)==0 #is last bit
                break
            end
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
            c = read(io,UInt8)
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
            v = (x % UInt8) & 0x7f
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

    const attr_color = :cyan

    # Attributes
    module Attributes
        import DWARF
        import DWARF: ULEB128, SLEB128, attr_color, fix_endian, DW_AT
        using ObjFileBase
        using AbstractTrees
        import ObjFileBase: strtab_lookup
        import AbstractTrees: printnode

        import Base: isequal, read, show, bytestring, ==
        export AttributeSpecification, Attribute, GenericStringAttribute,
            Constant1, Constant2, Constant4, Constant8, SConstant,
            UConstant, GenericStringAttribute, StrTableReference


        # Printing

        function print_name(io, x, kind; indent = 0, kwargs...)
            print(io," "^indent)
            if !haskey(DW_AT,x.name.val)
                printfield_with_color(:red, io, string("Unknown ($(x.name.val))"),17; align=:left)
            else
                printfield_with_color(attr_color, io, DW_AT[x.name.val],17; align=:left)
            end
            printfield(io,string(" [", kind, "] "),25, align = :left)
        end

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

        immutable AddressAttribute{T<:Union{Int64,UInt64,Int32,UInt32,Ptr{Void}}} <: GenericAttribute
            name::ULEB128
            content::T
        end
        for T in (Int64,UInt64,Int32,UInt32,Ptr{Void})
            Base.convert(::Type{T},x::AddressAttribute{T}) = x.content
        end

        immutable BlockAttribute <: GenericAttribute
            name::ULEB128
            content::Array{UInt8,1}
        end

        immutable ExprLocAttribute{T} <: GenericAttribute
            name::ULEB128
            content::Array{UInt8,1}
        end

        printnode(io::IO, x::BlockAttribute; kwargs...) =
            print_name(io, x, :BlockAttribute)
        function printnode(io::IO, x::AddressAttribute; kwargs...)
            print_name(io, x, :AddressAttribute)
            print(io, "0x",hex(x.content,2*sizeof(x.content)))
        end

        function printnode{T}(io::IO, x::ExprLocAttribute{T}; kwargs...)
            print_name(io, x, :ExprLocAttribute; kwargs...)
            DWARF.Expressions.print_expression(io,T,x.content,:NativeEndian)
        end

        function show(io::IO, x::GenericAttribute; indent = 0, kwargs...)
            printnode(io, x; indent = indent, kwargs...)
            println(io)
        end


        abstract GenericConstantAttribute <: GenericAttribute

        macro gattr(attr_name,supertype,ctype)
            esc(quote
                immutable $attr_name <: $supertype
                    name::ULEB128
                    content::$ctype
                    ($(attr_name))(name::ULEB128) = new(name,zero($ctype))
                    ($(attr_name))(name::ULEB128,content::$ctype) = new(name,content)
                end
                function printnode(io::IO,x::$attr_name; kwargs...)
                    Attributes.print_name(io, x, $(string(attr_name)); kwargs...)
                    print(io, x.content)
                end
                function Base.convert{T<:Integer}(::Type{T},x::$attr_name)
                    convert(T,x.content)
                end
            end)
        end

        @gattr ExplicitFlag GenericAttribute UInt8
        @gattr ImplicitFlag GenericAttribute Void
        @gattr Constant1 GenericConstantAttribute UInt8
        @gattr Constant2 GenericConstantAttribute UInt16
        @gattr Constant4 GenericConstantAttribute UInt32
        @gattr Constant8 GenericConstantAttribute UInt64
        @gattr SConstant GenericConstantAttribute SLEB128
        @gattr UConstant GenericConstantAttribute ULEB128

        abstract GenericReferenceAttribute <: GenericAttribute
        abstract DebugInfoReference <: GenericReferenceAttribute

        @gattr Reference1 GenericReferenceAttribute UInt8
        @gattr Reference2 GenericReferenceAttribute UInt16
        @gattr Reference4 GenericReferenceAttribute UInt32
        @gattr Reference8 GenericReferenceAttribute UInt64
        @gattr UReference GenericReferenceAttribute ULEB128

        abstract GenericStringAttribute <: GenericAttribute

        # # # 32/64-bit dependent types
        abstract StrTableReference <: GenericStringAttribute
        abstract SectionOffset <: GenericAttribute
        module DWARF32
            import DWARF.ULEB128
            using ..Attributes
            using AbstractTrees
            import AbstractTrees: printnode
            immutable StrTableReference <: Attributes.StrTableReference
                name::ULEB128
                content::UInt32
            end
            @Attributes.gattr DebugInfoReference Attributes.DebugInfoReference UInt32
            @Attributes.gattr SectionOffset Attributes.GenericAttribute UInt32
        end

        module DWARF64
            import DWARF.ULEB128
            using ..Attributes
            using AbstractTrees
            import AbstractTrees: printnode
            immutable StrTableReference <: Attributes.StrTableReference
                name::ULEB128
                content::UInt64
            end
            @Attributes.gattr DebugInfoReference Attributes.DebugInfoReference UInt64
            @Attributes.gattr SectionOffset Attributes.GenericAttribute UInt64
        end
        function bytestring(x::StrTableReference, strtab = nothing)
            strtab_lookup(strtab, x.content)
        end

        function printnode(io::IO, x::StrTableReference; kwargs...)
            strtab = isa(io, IOContext) ? get(io, :strtab, nothing) : nothing
            print_name(io, x, :StrTableReference; kwargs...)
            if strtab === nothing
                print(io, ".debug_str[0x",hex(x.content,2*sizeof(x.content))"]")
            else
                show(io, strtab_lookup(strtab, x.content))
            end
        end

        immutable StringAttribute <: GenericStringAttribute
            name::ULEB128
            content::ASCIIString
        end
        function printnode(io::IO, x::StringAttribute; kwargs...)
            print_name(io, x, :StringAttribute; kwargs...)
            show(io, x.content)
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
            DebugInfoReference,     # DW_FORM_ref_addr
            Reference1,             # DW_FORM_ref1
            Reference2,             # DW_FORM_ref2
            Reference4,             # DW_FORM_ref4
            Reference8,             # DW_FORM_ref8
            UReference,             # DW_FORM_ref_udata
            UnimplementedAttribute, # DW_FORM_indirect
            SectionOffset,          # DW_FORM_sec_offset
            ExprLocAttribute,       # DW_FORM_exprloc
            ImplicitFlag,           # DW_FORM_flag_present
            UnimplementedAttribute  # DW_FORM_ref_sig8
        ]

        function form2gattrT(form::ULEB128)
            mapping = form_mapping[form.val]
            if mapping == UnimplementedAttribute
                error("Unimplemented Attribute Form $form")
            end
            mapping
        end

        read(io::IO,name::ULEB128,::Type{UConstant}) = UConstant(name,read(io,ULEB128))
        read(io::IO,name::ULEB128,::Type{SConstant}) = SConstant(name,read(io,SLEB128))
        read(io::IO,name::ULEB128,::Type{UReference}) = UReference(name,read(io,ULEB128))
        read(io::IO,name::ULEB128,::Type{ExplicitFlag}) = ExplicitFlag(name,read(io,UInt8))
        read(io::IO,name::ULEB128,::Type{ImplicitFlag}) = ImplicitFlag(name,nothing)
        function read{T<:Union{GenericConstantAttribute,GenericReferenceAttribute}}(io::IO,::Type{T},
                                            header::DWARF.DWARFCUHeader,name,form,endianness::Symbol)
            t = T(name)
            t = T(name,fix_endian(read(io,typeof(t.content)),endianness))
            t
        end
        read(io::IO,name::ULEB128,T::Type{StringAttribute}) = StringAttribute(name,strip(readuntil(io,'\0'),'\0'))
        read{T<:GenericAttribute}(io::IO,::Type{T},header::DWARF.DWARFCUHeader,name,form,endianness::Symbol) = read(io,name,T)
        function read(io::IO,::Type{BlockAttribute},header::DWARF.DWARFCUHeader,name,form,endianness::Symbol)
            if form == DWARF.DW_FORM_block1
                length = read(io,UInt8)
            elseif form == DWARF.DW_FORM_block2
                length = fix_endian(read(io,UInt16),endianness)
            elseif form == DWARF.DW_FORM_block4
                length = fix_endian(read(io,UInt32),endianness)
            elseif form == DWARF.DW_FORM_block
                length = fix_endian(read(io,ULEB128),endianness)
            else
                error("Unkown Block Form $form")
            end
            content = Array(UInt8,length)
            read!(io,content)
            BlockAttribute(name,content)
        end
        function read(io::IO,::Type{ExprLocAttribute},header::DWARF.DWARFCUHeader,name,form,endianness::Symbol)
            length = read(io,ULEB128).val
            content = Array(UInt8,length)
            read!(io,content)
            T = DWARF.size_to_inttype(header.address_size)
            ExprLocAttribute{T}(name, content)
        end
        function read(io::IO,::Type{AddressAttribute},header::DWARF.DWARFCUHeader,name,form,endianness::Symbol)
            T = DWARF.size_to_inttype(header.address_size)
            AddressAttribute{T}(name,fix_endian(read(io,T),endianness))
        end
        function read(io::IO,::Type{StrTableReference},header::DWARF.DWARFCUHeader,name,form,endianness::Symbol)
            if typeof(header.debug_abbrev_offset) == UInt32
                DWARF32.StrTableReference(name,fix_endian(read(io,UInt32),endianness))
            elseif typeof(header.debug_abbrev_offset) == UInt64
                DWARF64.StrTableReference(name,fix_endian(read(io,UInt64),endianness))
            end
        end
        function read(io::IO,::Type{DebugInfoReference},header::DWARF.DWARFCUHeader,name,form,endianness::Symbol)
            if typeof(header.debug_abbrev_offset) == UInt32 && header.version > 2
                DWARF32.DebugInfoReference(name,fix_endian(read(io,UInt32),endianness))
            else
                DWARF64.DebugInfoReference(name,fix_endian(read(io,UInt64),endianness))
            end
        end
        function read(io::IO,::Type{SectionOffset},header::DWARF.DWARFCUHeader,name,form,endianness::Symbol)
            if typeof(header.debug_abbrev_offset) == UInt32
                DWARF32.SectionOffset(name,fix_endian(read(io,UInt32),endianness))
            elseif typeof(header.debug_abbrev_offset) == UInt64
                DWARF64.SectionOffset(name,fix_endian(read(io,UInt64),endianness))
            end
        end

        immutable AttributeSpecification
            name::ULEB128
            form::ULEB128
        end
        isequal(a::AttributeSpecification,b::AttributeSpecification) = (a.name == b.name)&&(a.form == b.form)
        ==(a::AttributeSpecification,b::AttributeSpecification) = isequal(a,b)

        function read(io::IO,::Type{AttributeSpecification},endianness::Symbol)
            name = read(io,ULEB128)
            form = read(io,ULEB128)
            AttributeSpecification(name,form)
        end

        function read(io::IO,header::DWARF.DWARFCUHeader,a::AttributeSpecification,endianness::Symbol)
            generic = read(io,form2gattrT(a.form),header,a.name,a.form,endianness)
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

        function operands(addr_type,opcode,opcodes,i,endianness)
            if opcode == DWARF.DW_OP_addr
                operand = fix_endian(reinterpret(addr_type,opcodes[i:(i+sizeof(addr_type)-1)])[1],endianness)
                i += sizeof(addr_type)
            elseif opcode == DWARF.DW_OP_const1u || opcode == DWARF.DW_OP_pick
                operand = convert(addr_type,opcodes[i])
                i += 1
            elseif opcode == DWARF.DW_OP_const1s
                operand = convert(addr_type,opcodes[i])
                # Yes, this is actually different from the above, since we need to sign extend properly
                push!(s.stack,convert(addr_type,fix_endian(reinterpret(Int8,opcodes[i]),endianness)))
                i += 1
            elseif opcode == DWARF.DW_OP_const2u # 1 2-byte constant
                operand = convert(addr_type,fix_endian(reinterpret(UInt16,opcodes[i:i+1])[1],endianness))
                i+=2
            elseif opcode == DWARF.DW_OP_const2s  || opcode == DWARF.DW_OP_bra || opcode == DWARF.DW_OP_skip # 1 2-byte constant
                operand = convert(addr_type,fix_endian(reinterpret(Int16,opcodes[i:i+1])[1],endianness))
                i+=2
            elseif opcode == DWARF.DW_OP_const4u # 1 4-byte constant
                operand = convert(addr_type,fix_endian(reinterpret(UInt32,opcodes[i:i+3])[1],endianness))
                i+=4
            elseif opcode == DWARF.DW_OP_const4u # 1 4-byte constant
                operand = convert(addr_type,fix_endian(reinterpret(Int32,opcodes[i:i+3])[1],endianness))
                i+=4
            elseif opcode == DWARF.DW_OP_const8u # 1 8-byte constant
                operand = convert(addr_type,fix_endian(reinterpret(UInt64,opcodes[i:i+7])[1],endianness))
                i+=8
            elseif opcode == DWARF.DW_OP_const8s # 1 8-byte constant
                operand = convert(addr_type,fix_endian(reinterpret(Int64,opcodes[i:i+7])[1],endianness))
                i+=8
            elseif opcode == DWARF.DW_OP_constu || opcode == DWARF.DW_OP_plus_uconst ||
                    opcode == DWARF.DW_OP_regx || opcode == DWARF.DW_OP_piece
                (i,operand) = DWARF.decode(opcodes,i,ULEB128)
            elseif opcode == DWARF.DW_OP_consts || opcode == DWARF.DW_OP_fbreg ||
                opcode >= DWARF.DW_OP_breg0 && opcode <= DWARF.DW_OP_breg31
                (i,operand) = DWARF.decode(opcodes,i,SLEB128)
            elseif opcode == DWARF.DW_OP_bregx
                (i,reg) = DWARF.decode(opcodes,i,ULEB128)
                (i,offset) = DWARF.decode(opcodes,i,SLEB128)
                operand = (reg,offset)
            elseif opcode == DWARF.DW_OP_bit_piece
                (i,reg) = DWARF.decode(opcodes,i,ULEB128)
                (i,offset) = DWARF.decode(opcodes,i,ULEB128)
                operand = (reg,offset)
            else
                return (i,)
            end
            return (i,operand)
        end

        function evaluate_generic_instruction{T}(s::StateMachine{T},opcodes,i,getreg_func::Function,getword_func,endianness::Symbol)
            opcode = opcodes[i]
            i+=1
            if opcode == DWARF.DW_OP_deref
                push!(s.stack,getword_func(pop!(s.stack)))
            elseif in(opcode,(DWARF.DW_OP_addr,DWARF.DW_OP_const1u,DWARF.DW_OP_const1s,DWARF.DW_OP_const2u,
                              DWARF.DW_OP_const2s,DWARF.DW_OP_const4u,DWARF.DW_OP_const4s,DWARF.DW_OP_const8u,
                              DWARF.DW_OP_const8s,DWARF.DW_OP_constu,DWARF.DW_OP_consts))
                (i,val) = operands(T,opcode,opcodes,i,endianness)
                push!(s.stack,convert(T,val))
            elseif opcode == DWARF.DW_OP_dup
                push!(s.stack,s.stack[length(s.stack)-1])
            elseif opcode == DWARF.DW_OP_pick
                (i,val) = operands(T,opcode,opcodes,i,endianness)
                push!(s.stack,s.stack[val])
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
                (i,val) = DWARF.decode(opcodes,i,ULEB128)
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
                (i,skip) = operands(T,opcode,opcodes,i,endianness)
                if(pop!(s.stack) != 0)
                    i += skip
                end
            elseif opcode == DWARF.DW_OP_call2 || opcode == DWARF.DW_OP_call4 || opcode == DWARF.DW_OP_call_ref
                error("Unimplemented")
            elseif opcode >= DWARF.DW_OP_lit1 && opcode <= DWARF.DW_OP_lit31
                push!(s.stack,opcode-DW_OP_lit1+1)
            elseif opcode >= DWARF.DW_OP_breg0 && opcode <= DWARF.DW_OP_breg31
                (i,offset) = operands(T,opcode,opcodes,i,endianness)
                push!(s.stack,getreg_func(opcode-DWARF.DW_OP_breg0) + offset)
            elseif opcode == DWARF.DW_OP_bregx
                (i,(val,offset)) = operands(T,opcode,opcodes,i,endianness)
                push!(s.stack,getreg_func(val) + offset)
            elseif opcode == DWARF.DW_OP_nop
                #NOP
            else
                return (i-1,false)
            end
            (i,true)
        end

        function evaluate_generic{T}(s::StateMachine{T},opcodes::Array{UInt8,1},getreg_func::Function,getword_func,endianness::Symbol)
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

        function op_name(opcode)
            if DWARF.DW_OP_lit1 <= opcode <= DWARF.DW_OP_lit31
                return string("DW_OP_lit",1+opcode-DWARF.DW_OP_lit1)
            elseif DWARF.DW_OP_reg0 <= opcode <= DWARF.DW_OP_reg31
                return string("DW_OP_reg",opcode-DWARF.DW_OP_reg0)
            elseif DWARF.DW_OP_breg0 <= opcode <= DWARF.DW_OP_breg31
                return string("DW_OP_breg",opcode-DWARF.DW_OP_breg0)
            else
                return DWARF.DW_OP[opcode]
            end
        end

        function print_expression(io::IO, addr_type, opcodes::Array{UInt8,1},endianness::Symbol)
            i = 1
            while i <= length(opcodes)
                opcode = opcodes[i]
                i += 1
                ops = operands(addr_type, opcode, opcodes, i, endianness)
                i = ops[1]
                print_with_color(:blue, io, op_name(opcode))
                print(io," ")
                if length(ops) > 1
                    operand = ops[2]
                    if !isa(operand,Tuple)
                        operand = (operand,)
                    end
                    print(io,join(map(repr,operand)," ")," ")
                end
            end
        end

        immutable RegisterLocation
            i::Int32
        end

        immutable MemoryLocation{T}
            i::T
        end

        function evaluate_simple_location{T}(s::StateMachine{T},opcodes::Array{UInt8,1},getreg_func::Function,getword_func,endianness::Symbol)
            i=1
            opcode = opcodes[i]
            if opcode >= DWARF.DW_OP_reg0 && opcode <= DWARF.DW_OP_reg31
                return RegisterLocation(opcode-DWARF.DW_OP_reg0)
            elseif opcode == DWARF.DW_OP_regx
                (i,val) = DWARF.decode(opcodes,i,ULEB128)
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
        import Base: ==

        immutable HeaderStub{T}
            length::T
            version::UInt16
            header_length::T
            minimum_instruction_length::UInt8
            maximum_operations_per_instruction::UInt8
            default_is_stmt::UInt8
            line_base::Int8
            line_range::Int8
            opcode_base::UInt8
        end

        immutable FileEntry
            name::UTF8String
            dir_idx::BigInt
            timestamp::BigInt
            filelength::BigInt
        end

        Base.isequal(x::FileEntry,y::FileEntry) =
            (x.name == y.name && x.dir_idx == y.dir_idx && x.timestamp == y.timestamp && x.filelength == y.filelength)
        ==(x::FileEntry, y::FileEntry) = isequal(x,y)

        function Base.read(io::IO,::Type{FileEntry})
            s = readstring(io)
            if endof(s) == 0
                return FileEntry(s,0,0,0)
            end
            return FileEntry(s,read(io,ULEB128),read(io,ULEB128),read(io,ULEB128))
        end

        function unpack(io,::Type{HeaderStub})
            T = UInt32
            length = read(io,T)
            if length == 0xffffffff
                T = UInt64
                length = read(io,T)
            end
            version = read(io,UInt16)
            header_length = read(io,T)
            minimum_instruction_length = read(io,UInt8)
            maximum_operations_per_instruction = version >= 4 ? read(io,UInt8) : 1
            HeaderStub{T}(length,version,header_length,minimum_instruction_length,maximum_operations_per_instruction,
                read(io,UInt8),read(io,Int8),read(io,Int8),read(io,UInt8))
        end

        immutable Header{T}
            stub::HeaderStub{T}
            standard_opcode_lengths::Vector{UInt8}
            include_directories::Vector{UTF8String}
            file_names::Vector{FileEntry}
        end

        function readstring(io)
            ret = Array(UInt8,0)
            while true
                c = read(io,UInt8)
                c == 0 && break
                push!(ret,c)
            end
            UTF8String(ret)
        end

        function read_header(io)
            stub = unpack(io,HeaderStub)
            standard_opcode_lengths = Array(UInt8,stub.opcode_base-1)
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
        ==(x::RegisterState, y::RegisterState) = isequal(x,y)

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
            op = read(io,UInt8)
            if op == 0
                # Extended opcode
                pos = position(io)
                size::BigInt = read(io,ULEB128)
                ex_op = read(io,UInt8)
                if ex_op == DWARF.DW_LNE_end_sequence
                    m.state = RegisterState(m.state,end_sequence = true)
                    ret = (true,m.state)
                    m.state = RegisterState(m.header.stub.default_is_stmt > 0)
                    position(io) > pos+size+1 && error("Malformed extended instruction")
                    return ret
                elseif ex_op == DWARF.DW_LNE_set_address
                    addrsize = pos+size - position(io) + 1
                    if addrsize == 4
                        m.state = RegisterState(m.state,address = read(io,UInt32))
                    elseif addrsize == 8
                        m.state = RegisterState(m.state,address = read(io,UInt64))
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
                        address = m.state.address + read(io,UInt16),
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
            # The fields from the start are length (header_type), version (UInt16) and header_length(header_type)
            # plus an additional UInt32 if the header_type is UInt64
            seek(x.io,x.start + x.header.stub.header_length + 2*sizeof(header_type(x.header)) + sizeof(UInt16) +
                (header_type(x.header) == UInt64 ? sizeof(UInt32) : 0))
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

    tag(x::DIE) = x.tag
    tag{T<:Attributes.GenericAttribute}(x::T) = x.name
    attributes(x::DIE) = x.attributes

    const tag_color = :blue

    tag_name(tag) = DW_TAG[tag]

    showcompact(io::IO,d::DIE) = print(io,"DIE(type ",d.tag.val,", ",length(d.attributes)," Attributes)")
    printnode(io::IO, d::DIE) = print_with_color(tag_color, io, tag_name(d.tag))
    function show(io::IO, d::DIE; indent = 0, strtab = nothing)
        printnode(io, d)
        println(io)
        for attr in d.attributes
            show(io, attr; indent = indent + 2, strtab = strtab)
        end
    end


    immutable ARTableEntry{S,T}
        segment::S
        address::T
        length::T
    end

    immutable LocationListEntry{T}
        first::T
        last::T
        data::Array{UInt8,1}
    end

    immutable LocationList{T}
        entries::Vector{LocationListEntry{T}}
    end

    function show{T}(io::IO, x::LocationListEntry{T})
        print(io,repr(x.first)," - ", repr(x.last), ": ")
        Expressions.print_expression(io, T, x.data,:NativeEndian)
        println(io)
    end

    function show(io::IO, x::LocationList)
        println(io,"Location List:")
        for e in x.entries
            show(io, e)
        end
    end

    isequal{S,T}(a::ARTableEntry{S,T},b::ARTableEntry{S,T}) = (a.segment==b.segment)&&(a.address==b.address)&&(a.length==b.length)
    =={S,T}(a::ARTableEntry{S,T},b::ARTableEntry{S,T}) = isequal(a,b)


    zero{S,T}(::Type{ARTableEntry{S,T}}) = ARTableEntry{S,T}(zero(S),zero(T),zero(T))

    const DEBUG_SECTIONS = ObjFileBase.DEBUG_SECTIONS

    @struct immutable InitialLength
        val::UInt32
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
            return UInt8
        elseif size == 2
            return UInt16
        elseif size == 4
            return UInt32
        elseif size == 8
            return UInt64
        elseif size == 16
            return UInt128
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

    const dummy_dict = Dict{Union{},Array{Integer,1}}() #Since we don't have StrPack support for Parametric types

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
        has_children::UInt8
        attributes::Array{AttributeSpecification,1}
    end

    immutable AbbrevTableSet
        entries::Array{AbbrevTableEntry,1}
    end
    zero(::Type{AbbrevTableEntry}) = AbbrevTableEntry(ULEB128(BigInt(0)),ULEB128(BigInt(0)),UInt8(0),Array(AttributeSpecification,0))

    function read(io::IO,::Type{AbbrevTableEntry},endianness::Symbol)
        code = read(io,ULEB128)
        if code != 0
            tag = read(io,ULEB128)
            has_children = read(io,UInt8)
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
    function read(io::IO,header::DWARFCUHeader,ate::AbbrevTableEntry,::Type{DIE},endianness::Symbol)
        ret = DIE(ate.tag,Array(Attribute,0))
        for a in ate.attributes
            push!(ret.attributes,read(io,header,a,endianness))
        end
        ret
    end
    function read(io::IO,header::DWARFCUHeader,ats::AbbrevTableSet,::Type{DIE},endianness::Symbol)
        num = read(io,ULEB128)
        ae = ats.entries[num.val]
        read(io,header,ae,DIE,endianness)
    end


    function read(io::IO,::Type{DIE},endianness::Symbol)
        tag = read(io,ULEB128)
        DIE(tag,Array(AttributeSpecification,0))
    end

    function read{T}(io::IO,::Type{LocationList{T}})
        ret = LocationListEntry{T}[]
        while true
            pos = position(io)
            start = read(io, T)
            last = read(io, T)
            if start == typemax(T)
                error("Base address seclection not implemented")
            elseif start == 0 && last == 0
                break
            else
                length = read(io, UInt16)
                push!(ret,LocationListEntry{T}(start,last,readbytes(io,length)))
            end
        end
        LocationList{T}(ret)
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
    printnode(io::IO, node::DIETreeNode) = printnode(io, node.self)

    # Iterating over a DIETreeNode yields attributes, then children
    start(x::DIETreeNode) = 1
    function next(x::DIETreeNode,it)
        val = (it <= length(attributes(x))) ?
            attributes(x)[it] : x.children[it-length(attributes(x))]
        (val, it+1)
    end
    done(x::DIETreeNode, it) = it > length(attributes(x)) + length(x.children)

    tag(x::DIETreeNode) = tag(x.self)
    attributes(x::DIETreeNode) = attributes(x.self)

    type DIETree <: DIENode
        children::Array{DIETreeNode,1}
    end
    children(x::DIETree) = x.children

    showcompact(io::IO,node::DIETreeNode) = (print(io,"DIETreeNode(");showcompact(io,node.self);print(io,", ",length(node.children)," children)"))
    showcompact(io::IO,node::DIETree) = print(io,"DIETree(",length(node.children)," children)")

    function show(io::IO, node::DIETreeNode; indent = 0, strtab = nothing)
        show(io, node.self; indent = indent, strtab = strtab)
        for child in node.children
            show(io, child; indent = indent + 2, strtab = strtab)
        end
    end
    function show(io::IO, tree::DIETree; strtab = nothing)
        for child in tree.children
            show(io, child; strtab = strtab)
        end
    end

    const zero_node = DIETreeNode(zero(DIE),Array(DIETreeNode,0),DIETree(Array(DIETreeNode,0)))

    zero(::Type{DIETreeNode}) = zero_node
    zero(::Type{DIETree}) = DIETree(DIETreeNode[])

    function read(io::IO,header::DWARFCUHeader,ats::AbbrevTableSet,parent::Union{DIETree,DIETreeNode},::Type{DIETreeNode},endianness::Symbol)
        num = read(io,ULEB128)
        if num != 0
            ae = ats.entries[num.val]
            ret = DIETreeNode(read(io,header,ae,DIE,endianness),Array(DIETreeNode,0),parent)
            push!(parent.children,ret)
            if(ae.has_children == DW_CHILDREN_yes)
                read(io,header,ats,ret,DIETreeNode,endianness)
            end
            isa(parent,DIETreeNode) && read(io,header,ats,parent,DIETreeNode,endianness)
            return ret
        end
        zero(DIETreeNode)
    end

    include("utility.jl")
end #module
