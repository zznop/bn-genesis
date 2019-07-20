from binaryninja import *
import struct
import traceback

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

    def create_vector_table(self):
        self.define_auto_symbol(Symbol(SymbolType.DataSymbol, 8, 'VectPtrBusError'))
        self.define_auto_symbol(Symbol(SymbolType.DataSymbol, 12, 'VectPtrAddressError'))
        self.define_auto_symbol(Symbol(SymbolType.DataSymbol, 16, 'VectPtrIllegalInstruction'))
        self.define_auto_symbol(Symbol(SymbolType.DataSymbol, 20, 'VectPtrDivisionByZero'))
        self.define_auto_symbol(Symbol(SymbolType.DataSymbol, 24, 'VectPtrChkException'))
        self.define_auto_symbol(Symbol(SymbolType.DataSymbol, 28, 'VectPtrTrapVException'))
        self.define_auto_symbol(Symbol(SymbolType.DataSymbol, 32, 'VectPtrPrivilegeViolation'))
        self.define_auto_symbol(Symbol(SymbolType.DataSymbol, 36, 'VectPtrTraceException'))
        self.define_auto_symbol(Symbol(SymbolType.DataSymbol, 40, 'VectPtrLineAEmulator'))
        self.define_auto_symbol(Symbol(SymbolType.DataSymbol, 44, 'VectPtrLineFEmulator'))
        self.define_auto_symbol(Symbol(SymbolType.DataSymbol, 48, 'VectUnused00'))
        self.define_auto_symbol(Symbol(SymbolType.DataSymbol, 52, 'VectUnused01'))
        self.define_auto_symbol(Symbol(SymbolType.DataSymbol, 56, 'VectUnused02'))
        self.define_auto_symbol(Symbol(SymbolType.DataSymbol, 60, 'VectUnused03'))
        self.define_auto_symbol(Symbol(SymbolType.DataSymbol, 64, 'VectUnused04'))
        self.define_auto_symbol(Symbol(SymbolType.DataSymbol, 68, 'VectUnused05'))
        self.define_auto_symbol(Symbol(SymbolType.DataSymbol, 72, 'VectUnused06'))
        self.define_auto_symbol(Symbol(SymbolType.DataSymbol, 76, 'VectUnused07'))
        self.define_auto_symbol(Symbol(SymbolType.DataSymbol, 80, 'VectUnused08'))
        self.define_auto_symbol(Symbol(SymbolType.DataSymbol, 84, 'VectUnused09'))
        self.define_auto_symbol(Symbol(SymbolType.DataSymbol, 88, 'VectUnused10'))
        self.define_auto_symbol(Symbol(SymbolType.DataSymbol, 92, 'VectUnused11'))
        self.define_auto_symbol(Symbol(SymbolType.DataSymbol, 96, 'VectPtrSpuriousException'))
        self.define_auto_symbol(Symbol(SymbolType.DataSymbol, 100, 'VectPtrIrqL1'))
        self.define_auto_symbol(Symbol(SymbolType.DataSymbol, 104, 'VectPtrIrqL2'))
        self.define_auto_symbol(Symbol(SymbolType.DataSymbol, 108, 'VectPtrIrqL3'))
        self.define_auto_symbol(Symbol(SymbolType.DataSymbol, 112, 'VectPtrIrqL4'))
        self.define_auto_symbol(Symbol(SymbolType.DataSymbol, 116, 'VectPtrIrqL5'))
        self.define_auto_symbol(Symbol(SymbolType.DataSymbol, 120, 'VectPtrIrqL6'))
        self.define_auto_symbol(Symbol(SymbolType.DataSymbol, 124, 'VectPtrIrqL7'))
        self.define_auto_symbol(Symbol(SymbolType.DataSymbol, 128, 'VectPtrTrap00'))
        self.define_auto_symbol(Symbol(SymbolType.DataSymbol, 132, 'VectPtrTrap01'))
        self.define_auto_symbol(Symbol(SymbolType.DataSymbol, 136, 'VectPtrTrap02'))
        self.define_auto_symbol(Symbol(SymbolType.DataSymbol, 140, 'VectPtrTrap03'))
        self.define_auto_symbol(Symbol(SymbolType.DataSymbol, 144, 'VectPtrTrap04'))
        self.define_auto_symbol(Symbol(SymbolType.DataSymbol, 148, 'VectPtrTrap05'))
        self.define_auto_symbol(Symbol(SymbolType.DataSymbol, 152, 'VectPtrTrap06'))
        self.define_auto_symbol(Symbol(SymbolType.DataSymbol, 156, 'VectPtrTrap07'))
        self.define_auto_symbol(Symbol(SymbolType.DataSymbol, 160, 'VectPtrTrap08'))
        self.define_auto_symbol(Symbol(SymbolType.DataSymbol, 164, 'VectPtrTrap09'))
        self.define_auto_symbol(Symbol(SymbolType.DataSymbol, 168, 'VectPtrTrap10'))
        self.define_auto_symbol(Symbol(SymbolType.DataSymbol, 172, 'VectPtrTrap11'))
        self.define_auto_symbol(Symbol(SymbolType.DataSymbol, 176, 'VectPtrTrap12'))
        self.define_auto_symbol(Symbol(SymbolType.DataSymbol, 180, 'VectPtrTrap13'))
        self.define_auto_symbol(Symbol(SymbolType.DataSymbol, 184, 'VectPtrTrap14'))
        self.define_auto_symbol(Symbol(SymbolType.DataSymbol, 188, 'VectPtrTrap15'))
        self.define_auto_symbol(Symbol(SymbolType.DataSymbol, 192, 'VectUnused12'))
        self.define_auto_symbol(Symbol(SymbolType.DataSymbol, 196, 'VectUnused13'))
        self.define_auto_symbol(Symbol(SymbolType.DataSymbol, 200, 'VectUnused14'))
        self.define_auto_symbol(Symbol(SymbolType.DataSymbol, 204, 'VectUnused15'))
        self.define_auto_symbol(Symbol(SymbolType.DataSymbol, 208, 'VectUnused16'))
        self.define_auto_symbol(Symbol(SymbolType.DataSymbol, 212, 'VectUnused17'))
        self.define_auto_symbol(Symbol(SymbolType.DataSymbol, 216, 'VectUnused18'))
        self.define_auto_symbol(Symbol(SymbolType.DataSymbol, 220, 'VectUnused19'))
        self.define_auto_symbol(Symbol(SymbolType.DataSymbol, 224, 'VectUnused20'))
        self.define_auto_symbol(Symbol(SymbolType.DataSymbol, 228, 'VectUnused21'))
        self.define_auto_symbol(Symbol(SymbolType.DataSymbol, 232, 'VectUnused22'))
        self.define_auto_symbol(Symbol(SymbolType.DataSymbol, 236, 'VectUnused23'))
        self.define_auto_symbol(Symbol(SymbolType.DataSymbol, 240, 'VectUnused24'))
        self.define_auto_symbol(Symbol(SymbolType.DataSymbol, 244, 'VectUnused25'))
        self.define_auto_symbol(Symbol(SymbolType.DataSymbol, 248, 'VectUnused26'))
        self.define_auto_symbol(Symbol(SymbolType.DataSymbol, 252, 'VectUnused27'))

    def create_header(self):
        self.define_auto_symbol(Symbol(SymbolType.DataSymbol, 256, 'ConsoleName'))
        self.define_auto_symbol(Symbol(SymbolType.DataSymbol, 272, 'Copyright'))
        self.define_auto_symbol(Symbol(SymbolType.DataSymbol, 288, 'DomesticName'))
        self.define_auto_symbol(Symbol(SymbolType.DataSymbol, 336, 'InternationalName'))
        self.define_auto_symbol(Symbol(SymbolType.DataSymbol, 384, 'SerialRevision'))
        self.define_auto_symbol(Symbol(SymbolType.DataSymbol, 398, 'Checksum'))
        self.define_auto_symbol(Symbol(SymbolType.DataSymbol, 400, 'IoSupport'))
        self.define_auto_symbol(Symbol(SymbolType.DataSymbol, 416, 'RomStart'))
        self.define_auto_symbol(Symbol(SymbolType.DataSymbol, 420, 'RomEnd'))
        self.define_auto_symbol(Symbol(SymbolType.DataSymbol, 424, 'RamStart'))
        self.define_auto_symbol(Symbol(SymbolType.DataSymbol, 428, 'RamEnd'))
        self.define_auto_symbol(Symbol(SymbolType.DataSymbol, 432, 'SramInfo'))
        self.define_auto_symbol(Symbol(SymbolType.DataSymbol, 444, 'Notes'))
        self.define_auto_symbol(Symbol(SymbolType.DataSymbol, 496, 'Region'))

    def init(self):
        try:
            self.create_segments()
            self.create_vector_table()
            self.define_auto_symbol(Symbol(SymbolType.DataSymbol, 0, 'PtrInitialStack'))
            self.define_auto_symbol(Symbol(SymbolType.DataSymbol, 4, 'PtrProgramStart'))
            self.add_entry_point(struct.unpack('>I', self.raw[4:8])[0])
            #self.create_functions()
            self.create_header()
            return True
        except Exception:
            log.log_error(traceback.format_exc())
            return False

    def perform_is_executable(self):
        return True

    def perform_get_entry_point(self):
        return struct.unpack('>I', self.raw[4:8])[0]
