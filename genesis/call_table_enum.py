"""Locates and disassembles common call tables present in certain ROM's
"""

from binaryninja import (BackgroundTaskThread, BinaryReader,
                         MediumLevelILOperation, Platform, show_message_box)


class GenesisCallTableEnum(BackgroundTaskThread):
    def __init__(self, bv):
        BackgroundTaskThread.__init__(self, "", True)
        self.progress = 'genesis: Enumerating call tables...'
        self.bv = bv
        self.br = BinaryReader(self.bv)

    def find_call_tables(self):
        base_addrs = []
        for func in self.bv:
            if not func.medium_level_il.ssa_form:
                continue

            for block in func.medium_level_il.ssa_form:
                for instr in block:
                    branch_operations = [
                        MediumLevelILOperation.MLIL_CALL_UNTYPED_SSA,
                        MediumLevelILOperation.MLIL_JUMP,
                        MediumLevelILOperation.MLIL_GOTO
                    ]

                    if instr.operation not in branch_operations:
                        continue

                    if type(instr.dest) == int:
                        continue

                    if instr.dest.operation == MediumLevelILOperation.MLIL_ADD:
                        if instr.dest.operands[0].operation == MediumLevelILOperation.MLIL_CONST:
                            base_addrs.append(instr.dest.operands[0].constant)
        return base_addrs

    def disas_call_tables(self, base_addrs):
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
        self.bv.platform = Platform['M68000']
        call_table_addrs = self.find_call_tables()
        if not call_table_addrs:
            return
        count = self.disas_call_tables(call_table_addrs)
        show_message_box(
            'genesis',
            'Disassembled {} call table instructions'.format(count)
        )


if __name__ == '__main__':
    pass
