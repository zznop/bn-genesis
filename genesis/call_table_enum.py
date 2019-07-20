'''Locates and disassembles common call tables present in certain ROM's
'''

from binaryninja import *
import struct

__author__     = 'zznop'
__copyright__  = 'Copyright 2019, zznop'
__license__    = 'GPL'
__version__    = '1.0'
__email__      = 'zznop0x90@gmail.com'

class GenesisCallTableEnum(BackgroundTaskThread):
    def __init__(self, bv):
        BackgroundTaskThread.__init__(self, "", True)
        self.progress = 'gensis: Enumerating call tables...'
        self.bv = bv
        self.br = BinaryReader(self.bv)

    def find_call_tables(self):
        '''Find call table base addresses using MLIL
        '''
        base_addrs = []
        for func in self.bv:
            for block in func.medium_level_il.ssa_form:
                for instr in block:
                    branch_operations = [
                        MediumLevelILOperation.MLIL_CALL_UNTYPED_SSA,
                        MediumLevelILOperation.MLIL_JUMP,
                        MediumLevelILOperation.MLIL_GOTO
                    ]
                    if instr.operation in branch_operations:
                        if type(instr.dest) == long:
                            continue

                        if instr.dest.operation == MediumLevelILOperation.MLIL_ADD:
                            if instr.dest.operands[0].operation == MediumLevelILOperation.MLIL_CONST:
                                base_addrs.append(instr.dest.operands[0].constant)
        return base_addrs

    def disas_call_tables(self, base_addrs):
        '''Disassemble the instructions in the call table
        '''
        count = 0
        for addr in base_addrs:
            i = addr
            while True:
                self.br.seek(i)
                opcode = self.br.read32be()
                if (opcode >> 24) == 0x60:
                    if not self.bv.get_function_at(i):
                        self.bv.add_function(i)
                        count += 1
                else:
                    break
                i += 4

        return count

    def run(self):
        '''Locate and disassemble call tables
        '''
        self.bv.platform = Platform['M68000']
        call_table_addrs = self.find_call_tables()
        count = self.disas_call_tables(call_table_addrs)
        show_message_box('genesis', 'Disassembled {} call table instructions'.format(count))

if __name__ == '__main__':
    pass
