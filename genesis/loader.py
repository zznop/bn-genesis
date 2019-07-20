from binaryninja import *
import struct
traceback

class GenesisView(binaryview.BinaryView):
    name = 'SG/SMD'
    long_name = 'SEGA Genesis/Megadrive ROM'

    def __init__(self, data):
        binaryview.BinaryView.__init__(self, parent_view=data, file_metadata=data.file)
        self.platform = Architecture['M68000'].standalone_platform
        self.raw = data

    @classmethod
    def is_valid_for_data(self, data):
        console_name = data[0x100:0x110].decode('utf-8')
        if 'SEGA' not in console_name.upper():
            return False

        rom_start = struct.unpack('>I', data[0x1a0:0x1a4])[0]
        if rom_start != 0:
            return False

        ram_start = struct.unpack('>I', data[0x1a8:0x1ac])[0]
        if ram_start != 0xff0000:
            return False

        return True

    def create_datatype_and_name(self, addr, name, _type):
        self.define_auto_symbol(Symbol(SymbolType.DataSymbol, addr, name))
        self.define_user_data_var(addr, _type)

    def create_segments(self):
        rom_start = struct.unpack('>I', self.raw[0x1a0:0x1a4])[0]
        rom_end = struct.unpack('>I', self.raw[0x1a4:0x1a8])[0]
        self.add_auto_segment(rom_start, rom_end-rom_start,
            0, 0, SegmentFlag.SegmentReadable|SegmentFlag.SegmentExecutable)

        ram_start = struct.unpack('>I', self.raw[0x1a8:0x1ac])[0]
        ram_end = struct.unpack('>I', self.raw[0x1ac:0x1b0])[0]
        self.add_auto_segment(ram_start, ram_end-ram_start,
            0, 0, SegmentFlag.SegmentReadable|SegmentFlag.SegmentExecutable|SegmentFlag.SegmentWritable)

    def create_functions(self):
        for idx in range(4, 252, 4):
            addr = struct.unpack('>I', self.raw[idx:idx+4])[0]
            self.add_function(addr)
            if idx == 4:
                self.add_entry_point(addr)
                self.define_auto_symbol(Symbol(SymbolType.FunctionSymbol, addr, "_start"))

    def init(self):
        try:
            self.create_segments()
            void_ptr = Type.pointer(Architecture["M68000"], Type.void())
            self.create_datatype_and_name(0, 'PtrInitialStack', void_ptr)
            self.create_datatype_and_name(4, 'PtrProgramStart', void_ptr)
            self.create_datatype_and_name(8, 'VectPtrBusError', void_ptr)
            self.create_datatype_and_name(12, 'VectPtrAddressError', void_ptr)
            self.create_datatype_and_name(16, 'VectPtrIllegalInstruction', void_ptr)
            self.create_datatype_and_name(20, 'VectPtrDivisionByZero', void_ptr)
            self.create_datatype_and_name(24, 'VectPtrChkException', void_ptr)
            self.create_datatype_and_name(28, 'VectPtrTrapVException', void_ptr)
            self.create_datatype_and_name(32, 'VectPtrPrivilegeViolation', void_ptr)
            self.create_datatype_and_name(36, 'VectPtrTraceException', void_ptr)
            self.create_datatype_and_name(40, 'VectPtrLineAEmulator', void_ptr)
            self.create_datatype_and_name(44, 'VectPtrLineFEmulator', void_ptr)
            self.create_datatype_and_name(48, 'VectUnused00', void_ptr)
            self.create_datatype_and_name(52, 'VectUnused01', void_ptr)
            self.create_datatype_and_name(56, 'VectUnused02', void_ptr)
            self.create_datatype_and_name(60, 'VectUnused03', void_ptr)
            self.create_datatype_and_name(64, 'VectUnused04', void_ptr)
            self.create_datatype_and_name(68, 'VectUnused05', void_ptr)
            self.create_datatype_and_name(72, 'VectUnused06', void_ptr)
            self.create_datatype_and_name(76, 'VectUnused07', void_ptr)
            self.create_datatype_and_name(80, 'VectUnused08', void_ptr)
            self.create_datatype_and_name(84, 'VectUnused09', void_ptr)
            self.create_datatype_and_name(88, 'VectUnused10', void_ptr)
            self.create_datatype_and_name(92, 'VectUnused11', void_ptr)
            self.create_datatype_and_name(96, 'VectPtrSpuriousException', void_ptr)
            self.create_datatype_and_name(100, 'VectPtrIrqL1', void_ptr)
            self.create_datatype_and_name(104, 'VectPtrIrqL2', void_ptr)
            self.create_datatype_and_name(108, 'VectPtrIrqL3', void_ptr)
            self.create_datatype_and_name(112, 'VectPtrIrqL4', void_ptr)
            self.create_datatype_and_name(116, 'VectPtrIrqL5', void_ptr)
            self.create_datatype_and_name(120, 'VectPtrIrqL6', void_ptr)
            self.create_datatype_and_name(124, 'VectPtrIrqL7', void_ptr)
            self.create_datatype_and_name(128, 'VectPtrTrap00', void_ptr)
            self.create_datatype_and_name(132, 'VectPtrTrap01', void_ptr)
            self.create_datatype_and_name(136, 'VectPtrTrap02', void_ptr)
            self.create_datatype_and_name(140, 'VectPtrTrap03', void_ptr)
            self.create_datatype_and_name(144, 'VectPtrTrap04', void_ptr)
            self.create_datatype_and_name(148, 'VectPtrTrap05', void_ptr)
            self.create_datatype_and_name(152, 'VectPtrTrap06', void_ptr)
            self.create_datatype_and_name(156, 'VectPtrTrap07', void_ptr)
            self.create_datatype_and_name(160, 'VectPtrTrap08', void_ptr)
            self.create_datatype_and_name(164, 'VectPtrTrap09', void_ptr)
            self.create_datatype_and_name(168, 'VectPtrTrap10', void_ptr)
            self.create_datatype_and_name(172, 'VectPtrTrap11', void_ptr)
            self.create_datatype_and_name(176, 'VectPtrTrap12', void_ptr)
            self.create_datatype_and_name(180, 'VectPtrTrap13', void_ptr)
            self.create_datatype_and_name(184, 'VectPtrTrap14', void_ptr)
            self.create_datatype_and_name(188, 'VectPtrTrap15', void_ptr)
            self.create_datatype_and_name(192, 'VectUnused12', void_ptr)
            self.create_datatype_and_name(196, 'VectUnused13', void_ptr)
            self.create_datatype_and_name(200, 'VectUnused14', void_ptr)
            self.create_datatype_and_name(204, 'VectUnused15', void_ptr)
            self.create_datatype_and_name(208, 'VectUnused16', void_ptr)
            self.create_datatype_and_name(212, 'VectUnused17', void_ptr)
            self.create_datatype_and_name(216, 'VectUnused18', void_ptr)
            self.create_datatype_and_name(220, 'VectUnused19', void_ptr)
            self.create_datatype_and_name(224, 'VectUnused20', void_ptr)
            self.create_datatype_and_name(228, 'VectUnused21', void_ptr)
            self.create_datatype_and_name(232, 'VectUnused22', void_ptr)
            self.create_datatype_and_name(236, 'VectUnused23', void_ptr)
            self.create_datatype_and_name(240, 'VectUnused24', void_ptr)
            self.create_datatype_and_name(244, 'VectUnused25', void_ptr)
            self.create_datatype_and_name(248, 'VectUnused26', void_ptr)
            self.create_datatype_and_name(252, 'VectUnused27', void_ptr)
            self.create_functions()
            return True

        except Exception:
            log.log_error(traceback.format_exc())
            return False

    def perform_is_executable(self):
        return True

    def perform_get_entry_point(self):
        return struct.unpack('>I', self.raw[4:8])[0]
