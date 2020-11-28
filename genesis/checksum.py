"""Calculates the new ROM checksum and writes it back to the binary
"""

from binaryninja import BackgroundTaskThread, BinaryReader, show_message_box
import struct


class GenesisChecksum(BackgroundTaskThread):
    def __init__(self, bv):
        BackgroundTaskThread.__init__(self, "", True)
        self.progress = 'genesis: Fixing up ROM checksum...'
        self.rom_start = 0x200
        self.checksum_off = 0x18e
        self.bv = bv
        self.br = BinaryReader(self.bv)

    def _calculate_checksum(self):
        self.br.seek(self.rom_start)
        checksum = self.br.read16be()
        while True:
            checksum = (checksum + self.br.read16be()) & 0x0000ffff
            if self.br.eof:
                break

        return checksum

    def run(self):
        checksum = self._calculate_checksum()
        self.bv.write(self.checksum_off, struct.pack('>H', checksum))
        show_message_box('genesis', 'ROM checksum has been updated')


if __name__ == '__main__':
    print('! this plugin does not run headless')
