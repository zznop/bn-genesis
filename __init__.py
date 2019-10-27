from binaryninja import *
from genesis import *

def checksum(view):
    checksum = GenesisChecksum(view)
    checksum.start()

def assemble(view):
    assemble = GenesisAssemble(view)
    assemble.start()

def load(view):
    load = GenesisLoad(view)
    load.start()

def call_table_enum(view):
    cte = GenesisCallTableEnum(view)
    cte.start()

def find_sprites(view):
    spf = SpriteFinder(view)
    spf.start()

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
    'genesis: Load ROM',
    'Create vector table and start disassembly',
    load
)

PluginCommand.register(
    'genesis: Enumerate call tables',
    'Locate and disassemble call tables',
    call_table_enum
)

PluginCommand.register(
    'genesis: Locate sprites',
    'Locate sprites and tiles',
    find_sprites
)
