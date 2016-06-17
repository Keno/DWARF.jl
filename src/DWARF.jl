__precompile__()
module DWARF
    using ObjFileBase
    using StructIO
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
        attributes, dies


    module DWARF32
        using DWARF
        using StructIO

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
            name::String
        end

        immutable PUBTableSet <: DWARF.PUBTableSet
            header::PUBHeader
            entries::Array{PUBTableEntry,1}
        end

    end

    module DWARF64
        using DWARF
        using StructIO

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
            name::String
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
    abstract LEB128{T}

    Base.convert{T<:LEB128}(::Type{T},x::Int64) = T(big(x))
    Base.convert{T<:Integer, S<:LEB128}(::Type{T}, x::S) = convert(T,x.val)

    immutable ULEB128{T} <: LEB128{T}
        val::T
    end

    immutable SLEB128{T} <: LEB128{T}
        val::T
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
    Base.hex(x::LEB128) = hex(x.val)

    function read{T}(io::IO, ::Type{ULEB128{T}})
        v = T(0)
        shift = 0
        while true
            c = read(io,UInt8)
            ((8*sizeof(T))-2 < shift) && throw(InexactError())
            v |= T(c&0x7f)<<shift
            if (c&0x80)==0 #is last bit
                break
            end
            shift+=7
        end
        ULEB128{T}(v)
    end
    read(io::IO, ::Type{ULEB128}) = read(io,ULEB128{UInt})

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

    function decode{T}(data::Array{UInt8,1}, offset, ::Type{ULEB128{T}})
        v = T(0)
        shift = 0
        i=0
        while true
            c = data[offset+i]
            i+=1
            ((8*sizeof(T))-2 < shift) && throw(InexactError())
            v |= T(c&0x7f)<<shift
            if (c&0x80)==0 #is last bit
                break
            end
            shift+=7
        end
        (offset+i,T(v))
    end

    function decode{T}(data::Array{UInt8,1}, offset, ::Type{SLEB128{T}})
        v = T(0)
        shift = 0
        c=0
        i=0
        while true
            c = data[offset+i]
            i+=1
            ((8*sizeof(T))-2 < shift) && throw(InexactError())
            v |= T(c&0x7f)<<shift
            shift+=7
            if (c&0x80)==0 #is last bit
                break
            end
        end
        if (c & 0x40) != 0
            v |= -(T(1)<<shift)
        end

        (offset+i,T(v))
    end

    function read{T}(io::IO, ::Type{SLEB128{T}})
        v = T(0)
        shift = 0
        c=0
        while(true)
            c = read(io,UInt8)
            ((8*sizeof(T))-2 < shift) && throw(InexactError())
            v |= T(c&0x7f)<<shift
            shift+=7
            if (c&0x80)==0 #is last bit
                break
            end
        end
        if (c & 0x40) != 0
            v |= -(T(1)<<shift)
        end

        SLEB128{T}(v)
    end
    read(io::IO, ::Type{SLEB128}) = read(io, SLEB128{Int})

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

    const attr_color = :cyan

    immutable AttributeSpecification
        # These are both ULEB128s on disk, but we keep them as
        # integers in memory to avoid having to deal with BigInt
        name::UInt64
        form::UInt8
    end
    isequal(a::AttributeSpecification,b::AttributeSpecification) = (a.name == b.name)&&(a.form == b.form)
    ==(a::AttributeSpecification,b::AttributeSpecification) = isequal(a,b)

    function read(io::IO,::Type{AttributeSpecification},endianness::Symbol)
        name = read(io,ULEB128)
        form = read(io,ULEB128)
        AttributeSpecification(name,form)
    end

    function read(io::IO,header::DWARF.DWARFCUHeader,a::AttributeSpecification,endianness::Symbol)
        generic = read(io,Attributes.form2gattrT(a.form),header,a.name,a.form,endianness)
        # TODO: Return Actual Attributes
        generic
    end

    immutable AbbrevTableEntry
        # These are technically ULEB128 in the on disk format, but we keep them
        # as UInt64 in memory which should be large enough for anything ever
        # encoutered in reality
        code::UInt64
        tag::UInt64
        has_children::UInt8
        attributes::Array{AttributeSpecification,1}
    end

    immutable AbbrevTableSet
        entries::Array{AbbrevTableEntry,1}
    end
    zero(::Type{AbbrevTableEntry}) = AbbrevTableEntry(0,0,UInt8(0),Array(AttributeSpecification,0))
    const zero_entry = zero(AbbrevTableEntry)

    function readorskip
    end
    include("dies.jl")
    # Attributes
    module Attributes
        include("forms.jl")
    end
    using .Attributes

    module Expressions
        # TODO
        using DWARF
        using StructIO
        import StructIO: fix_endian

        type StateMachine{T}
            stack::Array{T,1}
            StateMachine(stack::Array{T,1}) = new(stack)
            StateMachine() = new(T[])
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
                (i,operand) = DWARF.decode(opcodes,i,ULEB128{addr_type})
            elseif opcode == DWARF.DW_OP_consts || opcode == DWARF.DW_OP_fbreg ||
                opcode >= DWARF.DW_OP_breg0 && opcode <= DWARF.DW_OP_breg31
                (i,operand) = DWARF.decode(opcodes,i,SLEB128{typeof(signed(addr_type(0)))})
            elseif opcode == DWARF.DW_OP_bregx
                (i,reg) = DWARF.decode(opcodes,i,ULEB128{UInt})
                (i,offset) = DWARF.decode(opcodes,i,SLEB128{addr_type})
                operand = (reg,offset)
            elseif opcode == DWARF.DW_OP_bit_piece
                (i,reg) = DWARF.decode(opcodes,i,ULEB128{UInt})
                (i,offset) = DWARF.decode(opcodes,i,ULEB128{addr_type})
                operand = (reg,offset)
            else
                return (i,)
            end
            return (i,operand)
        end

        function evaluate_generic_instruction{T}(s::StateMachine{T},opcodes,i,
                getreg_func::Function,getword_func,addr_func,endianness::Symbol)
            opcode = opcodes[i]
            i+=1
            if opcode == DWARF.DW_OP_deref
                addr = pop!(s.stack)
                push!(s.stack,getword_func(addr))
            elseif in(opcode,(DWARF.DW_OP_const1u,DWARF.DW_OP_const1s,DWARF.DW_OP_const2u,
                              DWARF.DW_OP_const2s,DWARF.DW_OP_const4u,DWARF.DW_OP_const4s,DWARF.DW_OP_const8u,
                              DWARF.DW_OP_const8s,DWARF.DW_OP_constu,DWARF.DW_OP_consts))
                (i,val) = operands(T,opcode,opcodes,i,endianness)
                push!(s.stack,convert(T,val))
            elseif opcode == DWARF.DW_OP_addr
                (i,val) = operands(T,opcode,opcodes,i,endianness)
                push!(s.stack,addr_func(convert(T,val)))
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
            elseif opcode == DWARF.DW_OP_plus
                push!(s.stack,pop!(s.stack)+pop!(s.stack))
            elseif opcode == DWARF.DW_OP_mul
                push!(s.stack,pop!(s.stack)*pop!(s.stack))
            elseif opcode == DWARF.DW_OP_neg
                push!(s.stack,-(signed(pop!(s.stack))))
            elseif opcode == DWARF.DW_OP_not
                push!(s.stack,~(pop!(s.stack)))
            elseif opcode == DWARF.DW_OP_plus_uconst
                (i,val) = DWARF.decode(opcodes,i,ULEB128{UInt})
                push!(s.stack,pop!(s.stack)+UInt(val))
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
                push!(s.stack,opcode-DWARF.DW_OP_lit1+1)
            elseif opcode >= DWARF.DW_OP_breg0 && opcode <= DWARF.DW_OP_breg31
                (i,offset) = operands(T,opcode,opcodes,i,endianness)
                push!(s.stack,Int(getreg_func(opcode-DWARF.DW_OP_breg0)) + offset)
            elseif opcode == DWARF.DW_OP_fbreg
                (i,offset) = operands(T,opcode,opcodes,i,endianness)
                val = getreg_func(opcode)
                push!(s.stack,val + offset%UInt64)
            elseif opcode == DWARF.DW_OP_bregx
                (i,(val,offset)) = operands(T,opcode,opcodes,i,endianness)
                push!(s.stack,getreg_func(val) + offset)
            elseif opcode == DWARF.DW_OP_call_frame_cfa
                push!(s.stack,getreg_func(DWARF.DW_OP_call_frame_cfa))
                i -= 1
            elseif opcode == DWARF.DW_OP_nop
                #NOP
            elseif opcode == DWARF.DW_OP_stack_value
                # Handled explicitly elsewhere
            else
                return (i-1,false)
            end
            (i,true)
        end

        function evaluate_generic{T}(s::StateMachine{T},opcodes::Array{UInt8,1},getreg_func::Function,getword_func,addr_func,endianness::Symbol)
            i=1
            while i <= length(opcodes)
                (opcodes[i] == DWARF.DW_OP_stack_value) &&
                    return true
                i,res = evaluate_generic_instruction(s,opcodes,i,getreg_func,getword_func,addr_func,endianness)
                if !res
                    error("Unrecognized Opcode ",opcodes[i])
                end
            end
            return false
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

        function evaluate_simple_location{T}(s::StateMachine{T},opcodes::Array{UInt8,1},
                getreg_func::Function,getword_func,addr_func,endianness::Symbol)
            i=1
            opcode = opcodes[i]
            if opcode >= DWARF.DW_OP_reg0 && opcode <= DWARF.DW_OP_reg31
                return RegisterLocation(opcode-DWARF.DW_OP_reg0)
            elseif opcode == DWARF.DW_OP_regx
                (i,val) = DWARF.decode(opcodes,i+1,ULEB128{UInt})
                return RegisterLocation(val)
            else
                if evaluate_generic(s,opcodes,getreg_func,getword_func,addr_func,endianness)
                    return last(s.stack)
                else
                    return MemoryLocation{T}(last(s.stack))
                end
            end
        end
    end

    # The line table is encoded as a state machine program
    # operating on a register machine, whose register represent the
    # values the debugger needs to know about the current source location
    module LineTableSupport
        using StructIO

        import ..ULEB128, ..SLEB128, ..DWARF
        import Base: ==
        using ObjFileBase: printfield

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
            name::String
            dir_idx::UInt
            timestamp::UInt
            filelength::UInt
        end

        Base.isequal(x::FileEntry,y::FileEntry) =
            (x.name == y.name && x.dir_idx == y.dir_idx && x.timestamp == y.timestamp && x.filelength == y.filelength)
        ==(x::FileEntry, y::FileEntry) = isequal(x,y)

        function Base.read(io::IO,::Type{FileEntry})
            s = readstring(io)
            if endof(s) == 0
                return FileEntry(s,0,0,0)
            end
            return FileEntry(s,read(io,ULEB128{UInt}),read(io,ULEB128{UInt}),read(io,ULEB128{UInt}))
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
            include_directories::Vector{String}
            file_names::Vector{FileEntry}
        end

        function readstring(io)
            ret = Array(UInt8,0)
            while true
                c = read(io,UInt8)
                c == 0 && break
                push!(ret,c)
            end
            String(ret)
        end

        function read_header(io)
            stub = unpack(io,HeaderStub)
            standard_opcode_lengths = Array(UInt8,max(0,stub.opcode_base-1))
            read!(io,standard_opcode_lengths)
            include_directories = String[]
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
            address::Int
            op_index::Int
            file::Int
            line::Int
            column::UInt
            is_stmt::Bool
            basic_block::Bool
            end_sequence::Bool
            prologue_end::Bool
            epilogue_begin::Bool
            isa::Int
            discriminator::Int

            # Initial Register state as defined by DWARF standard
            function RegisterState(default_is_stmt::Bool)
                new(Int(0),Int(0),Int(1),Int(1),Int(0),default_is_stmt,
                    false,false,false,false,Int(0),Int(0))
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

        function pcl_adv!(m::StateMachine,op; advance_line = true)
            adj_opc = op - m.header.stub.opcode_base
            pc_adv!(m,div(adj_opc,m.header.stub.line_range))
            if advance_line
                m.state = RegisterState(m.state,
                    line = m.state.line + m.header.stub.line_base + mod(adj_opc,m.header.stub.line_range))
            end
        end

        const DW_LNE_special_adv = 0x80
        const DW_LNS_OFF = 0x20

        function decode_next(io, header)
            op = read(io,UInt8)
            if op == 0
                # Extended opcode
                pos = position(io)
                size::UInt = read(io,ULEB128{UInt})
                ex_op = read(io,UInt8)
                if ex_op == DWARF.DW_LNE_end_sequence
                    position(io) > pos+size+1 && error("Malformed extended instruction")
                    return (DW_LNS_OFF+ex_op,())
                elseif ex_op == DWARF.DW_LNE_set_address
                    addrsize = pos+size - position(io) + 1
                    if addrsize == 4
                        return (DW_LNS_OFF+ex_op,(read(io,UInt32),))
                    elseif addrsize == 8
                        return (DW_LNS_OFF+ex_op,(read(io,UInt64),))
                    else
                        error("Unsupported target address size $addrsize")
                    end
                elseif ex_op == DWARF.DW_LNE_define_file
                    return (DW_LNS_OFF+ex_op,(read(io,FileEntry),))
                elseif ex_op == DWARF.DW_LNE_set_discriminator
                    return (DW_LNS_OFF+ex_op,(read(io,ULEB128),))
                else
                    error("Unrecognized extended opcode $ex_op")
                end
                position(io) > pos+size+1 && error("Malformed extended instruction (op=$ex_op, pos=$pos, size=$size, iopos=$(position(io)))")
            elseif op < header.stub.opcode_base
                # standard opcode
                if op == DWARF.DW_LNS_copy || op == DWARF.DW_LNS_negate_stmt || op == DWARF.DW_LNS_set_basic_block ||
                        op == DWARF.DW_LNS_const_add_pc || op == DWARF.DW_LNS_set_prologue_end ||
                        op == DWARF.DW_LNS_set_epilogue_begin
                    if header.standard_opcode_lengths[op] != 0
                        error("Malformed Instruction")
                    end
                    return (op,())
                elseif op == DWARF.DW_LNS_advance_pc || op == DWARF.DW_LNS_set_column || op == DWARF.DW_LNS_set_file ||
                        op == DWARF.DW_LNS_set_isa
                    if header.standard_opcode_lengths[op] != 1
                        error("Malformed Instruction")
                    end
                    return (op,(read(io,ULEB128),))
                elseif op == DWARF.DW_LNS_advance_line
                    if header.standard_opcode_lengths[op] != 1
                        error("Malformed Instruction")
                    end
                    return (op,(read(io,SLEB128),))
                elseif op == DWARF.DW_LNS_fixed_advance_pc
                    if header.standard_opcode_lengths[op] != 1
                        error("Malformed Instruction")
                    end
                    return (op,(read(io,UInt16),))
                else
                    error("Unknown opcode")
                end
            else
                # special opcode
                # decode the opcode
                return (DW_LNE_special_adv,(op,))
            end
        end

        function step(io,m::StateMachine)
            opcode, operands = decode_next(io, m.header)
            if opcode == DW_LNS_OFF+DWARF.DW_LNE_end_sequence
                m.state = RegisterState(m.state,end_sequence = true)
                ret = (true,m.state)
                m.state = RegisterState(m.header.stub.default_is_stmt > 0)
                return ret
            elseif opcode == DW_LNS_OFF+DWARF.DW_LNE_set_address
                m.state = RegisterState(m.state,address = operands[1])
            elseif opcode == DW_LNS_OFF+DWARF.DW_LNE_define_file
                push!(m.file_names,operands[1])
            elseif opcode == DW_LNS_OFF+DWARF.DW_LNE_set_discriminator
                m.state = RegisterState(m.state,discriminator = operands[1])
            elseif opcode == DWARF.DW_LNS_copy
                ret = (true,m.state)
                m.state = RegisterState(m.state,
                    discriminator = 0,
                    basic_block = false,
                    prologue_end = false,
                    epilogue_begin = false)
                return ret
            elseif opcode == DWARF.DW_LNS_advance_pc
                pc_adv!(m,UInt(operands[1]))
            elseif opcode == DWARF.DW_LNS_advance_line
                m.state = RegisterState(m.state,line = m.state.line + Int(operands[1]))
            elseif opcode == DWARF.DW_LNS_set_file
                m.state = RegisterState(m.state,file = operands[1])
            elseif opcode == DWARF.DW_LNS_set_column
                m.state = RegisterState(m.state,column = operands[1])
            elseif opcode == DWARF.DW_LNS_negate_stmt
                m.state = RegisterState(m.state,is_stmt = !m.state.is_stmt)
            elseif opcode == DWARF.DW_LNS_set_basic_block
                m.state = RegisterState(m.state,basic_block = true)
            elseif opcode == DWARF.DW_LNS_const_add_pc
                pcl_adv!(m,255; advance_line = false)
            elseif opcode == DWARF.DW_LNS_fixed_advance_pc
                m.state = RegisterState(m.state,
                    address = m.state.address + operands[1],
                    op_index = 0)
            elseif opcode == DWARF.DW_LNS_set_prologue_end
                if m.header.standard_opcode_lengths[DWARF.DW_LNS_set_prologue_end] != 0
                    error("Malformed Instruction")
                end
                m.state = RegisterState(m.state, prologue_end = false)
            elseif opcode == DWARF.DW_LNS_set_epilogue_begin
                m.state = RegisterState(m.state, epilogue_begin = false)
            elseif opcode == DWARF.DW_LNS_set_isa
                m.state = RegisterState(m.state, isa = operands[1])
            elseif opcode == DW_LNE_special_adv
                pcl_adv!(m,operands[1])
                ret = (true, m.state)
                m.state = RegisterState(m.state, basic_block = false, prologue_end = false, epilogue_begin = false,
                    discriminator = 0)
                return ret
            else
                error("Unhandled opcode")
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

        function dump_program(out::IO, x::LineTable)
            seek(x.io,x.start + x.header.stub.header_length + 2*sizeof(header_type(x.header)) + sizeof(UInt16) +
                (header_type(x.header) == UInt64 ? sizeof(UInt32) : 0))
            while position(x.io) <= (x.start + x.header.stub.length)
                opcode, operands = decode_next(x.io, x.header)
                print_with_color(:blue, out, opcode == DW_LNE_special_adv ? "DW_LNE_special_adv" :
                    opcode > DW_LNS_OFF ? DWARF.DW_LNE[opcode-DW_LNS_OFF] : DWARF.DW_LNS[opcode])
                for operand in operands
                    print(out, ' ')
                    if opcode == DWARF.DW_LNE_set_address+DW_LNS_OFF
                        print(out, "0x", hex(operand))
                    elseif isa(operand, ULEB128) || isa(operand, SLEB128)
                        print(out, typeof(operand).parameters[1](operand))
                    else
                        print(out, operand)
                    end
                end
                println(out)
            end
        end

        function Base.showcompact(io::IO, state::RegisterState)
            printfield(io, string("0x",hex(state.address)), 18); print(io,' ')
            printfield(io, state.line, 6); print(io,' ')
            printfield(io, state.column, 6); print(io,' ')
            printfield(io, state.file, 6); print(io,' ')
            printfield(io, state.isa, 3); print(io,' ')
            printfield(io, state.discriminator, 13, align = :right); print(io,' ')
            state.is_stmt && print(io, "is_stmt ")
            state.end_sequence && print(io, "end_sequence ")
            state.prologue_end && print(io, "prologue_end ")
            state.epilogue_begin && print(io, "epilogue_begin ")
            println(io)
        end

        # Follow llvm-dwarfdump format
        function dump_table(io::IO, x::LineTable)
            println(io, "Address            Line   Column File   ISA Discriminator Flags")
            println(io, "------------------ ------ ------ ------ --- ------------- -------------")
            for state in x
                showcompact(io, state)
            end
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

    zero(::Type{AttributeSpecification}) = AttributeSpecification(0,0)

    const tag_color = :blue

    function tag_name(tag)
        get(DW_TAG, tag, "Unknown tag $tag")
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

    # aranges tables
    function read(io::IO,::Type{ARTableSet},endianness::Symbol)
        header = read(io,DWARFARHeader,endianness)
        t = ARTableEntry{size_to_inttype(header.segment_size),size_to_inttype(header.address_size)}
        table = ARTableSet(header,Array(t,0))
        entry_size = sizeof(t)
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
        offset = read(io,T.types[1])
        StructIO.needs_bswap(endianness) && (offset = bswap(offset))
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

    function read{T}(io::IO,::Type{LocationList{T}})
        ret = LocationListEntry{T}[]
        while true
            pos = position(io)
            start = read(io, T)
            last = read(io, T)
            if start == typemax(T)
                error("Base address selection not implemented")
            elseif start == 0 && last == 0
                break
            else
                length = read(io, UInt16)
                push!(ret,LocationListEntry{T}(start,last,read(io,length)))
            end
        end
        LocationList{T}(ret)
    end

    include("navigate.jl")
    include("cfi.jl")
    include("precompile.jl")
end #module
