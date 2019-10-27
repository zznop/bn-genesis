from binaryninja import *
from enum import Enum

class ArtDataType(Enum):
    """
    Enums for seperating palette writes from sprite writes
    """

    PALETTE = 1
    SPRITE  = 2
    UNKNOWN = 3

class SpriteFinder(BackgroundTaskThread):
    """
    Class for aiding in locating, displaying, and patching SMD artwork in ROM's
    """

    def __init__(self, bv):
        BackgroundTaskThread.__init__(self, '', True)
        self.process = 'genesis: Attempting to locate sprites...'
        self.bv = bv

    def _resolve_art_data_type(self, instr):
        """
        Determine whether the instruction is setting up for a palette write to
        CRAM or a sprite write to VRAM
        """

        if instr.src.operation == MediumLevelILOperation.MLIL_CONST: # Constant src
            if ((instr.src.operands[0] >> 30) & 0b11) == 0b11:
                return ArtDataType.PALETTE
            return ArtDataType.SPRITE
        # TODO: Add support for register src operands with possible_values check
        return ArtDataType.UNKNOWN

    def _find_vdp_ctrl_instrs(self):
        """
        Locate code that writes to VRAM

        :return: A list of MLIL intrs that write to the VDP control register
        """

        instrs = {}
        for func in self.bv:
            for block in func.medium_level_il.ssa_form:
                for instr in block:
                    if instr.operation is MediumLevelILOperation.MLIL_STORE_SSA:
                        if instr.dest.operands[0] == 0xc00004:
                            instrs[instr.address] = {}
                            instrs[instr.address]['instr'] = instr
                            instrs[instr.address]['type'] = self._resolve_art_data_type(instr)
        return instrs

    def run(self):
        """
        Run the plugin
        """

        ctl_instrs = self._find_vdp_ctrl_instrs()
        print(ctl_instrs)

if __name__ == '__main__':
    pass