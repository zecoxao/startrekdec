"""
Cell and code naming.

The headless pipeline names RAM cells from a curated table of Kirk MMIO
registers (:data:`startrekdec.commands.MMIO`) and falls back to a stable
``v<hex>`` identifier.  Inside IDA the :class:`Namer` is fed IDA's own names so
the decompilation reuses whatever the analyst has labelled.
"""

from . import commands
from .isa import RAMBASE


class Namer:
    def __init__(self, cell_names=None, code_names=None):
        self.cell_names = dict(commands.MMIO)
        if cell_names:
            self.cell_names.update(cell_names)
        self.code_names = dict(code_names or {})

    def cell(self, addr):
        n = self.cell_names.get(addr)
        if n:
            return n
        off = addr - RAMBASE if addr >= RAMBASE else addr
        return "v%04X" % (off & 0xFFFFFFFF)

    def code(self, ea):
        n = self.code_names.get(ea)
        if n:
            return n
        return "sub_%X" % ea

    def label(self, ea):
        n = self.code_names.get(ea)
        if n:
            return n
        return "loc_%X" % ea
