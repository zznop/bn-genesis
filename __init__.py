from binaryninja import PluginCommand
from .genesis import GenesisChecksum, GenesisAssemble, GenesisCallTableEnum


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
    'genesis: fixup ROM checksum',
    'Fixup the SEGA Genesis ROM checksum',
    checksum
)

PluginCommand.register(
    'genesis: assemble and patch',
    'Assemble M68K code and apply blob as patch',
    assemble
)
PluginCommand.register(
    'genesis: enumerate call tables',
    'Locate and disassemble call tables',
    call_table_enum
)
