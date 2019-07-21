from binaryninja import *
import argparse

class _Const(object):
    @constant
    def VDP_CONTROL():
        return 0x00C00004
    @constant
    def VDP_DATA():
        return 0x00C00000
    @constant
    def VDP_VRAM_WRITE():
        return 0x40000000
    @constant
    def VDP_CRAM_WRITE():
        return 0xC0000000

class SpriteExtraction:
    def __init__(self, bv, outdir):
        self.bv = bv
        self.outdir = outdir
        self.vdp_control = 0x00C00004
        self.vdp_data = 
        self.CONST = _Const()

    def find_pallettes():
        """
        Traverse code to locate palettes that are being written to CRAM
        """
        for func in self.bv:
            for block in func.medium_level_il.ssa_form:
                for instr in block:
                    print(instr)

def parse_args():
    """
    Parse command line arguments
    """
    parser = argparse.ArgumentParser()
    parser.add_argument('infile', type=str,
        help='Database or binary under analysis')
    parser.add_argument('--outdir', '-o', type=str,
        help='Path to directory for extracted sprite files')
    return parser.parse_args()

def main():
    """
    Main
    """
    try:
        args = parse_args()
        bv = BinaryViewType.get_view_of_file(args.infile)
        extractor = SpriteExtraction(bv, args.outdir)
    except Exception:
        print(traceback.format_exc())

if __name__ == '__main__':
    main()
