from binaryninja import *
from genesis import *

def checksum(view):
    checksum = GenesisChecksum(view)
    checksum.start()

def assemble(view):
    assemble = GenesisAssemble(view)
    assemble.start()

def call_table_enum(view):
    cte = GenesisCallTableEnum(view)
    cte.start()

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
PluginCommand.register(
    'genesis: Enumerate call tables',
    'Locate and disassemble call tables',
    call_table_enum
)
