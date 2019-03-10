from binaryninja import *
from genesis import *

def checksum(view):
    checksum = GenesisChecksum(view)
    checksum.start()

def assemble(view):
    assemble = GenesisAssemble(view)
    assemble.start()

PluginCommand.register(
    'genesis: Fixup ROM checksum',
    'Fixup the SEGA Genesis ROM checksum',
    checksum
)

PluginCommand.register(
    'genesis: Assemble and patch',
    'Assemble M68K code and apply blob as patch',
    assemble
)
