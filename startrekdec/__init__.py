"""
startrekdec -- a decompiler for the PSP Kirk and Spock crypto processors.

The Kirk and Spock engines share one small big-endian memory-to-memory core
(ProximaV's "Star Trek PSP Processors").  This package decodes a raw ROM image,
lifts it to IR, and emits structured pseudo-C -- the Kirk/Spock analogue of
zecoxao's ``spudec`` for the Cell SPU.

Pipeline (mirroring spudec, minus the SPU's vector machinery):

    decoder -> lifter -> cfg -> opt -> structure -> cgen

Headless entry points work on a ``.bin`` with no IDA present; inside IDA the
same IR is produced from the KIRK processor module via
:mod:`startrekdec.ida_bridge`.
"""

from . import decoder, cfg, opt, structure, cgen
from .names import Namer

__version__ = "0.1.0"

BANNER = [
    "/*",
    " * Decompiled by startrekdec -- PSP Kirk/Spock crypto processor.",
    " * Cells are 32-bit RAM words at RAMBASE (0xE0000000); flag compares",
    " * (>, <) are signed.  Opaque opcodes are printed as pseudo-calls.",
    " */",
    "typedef unsigned int   u32;",
    "typedef unsigned char  u8;",
    "",
]


class Function:
    def __init__(self, entry, name, func, tree, lines):
        self.entry = entry
        self.name = name
        self.cfg = func
        self.tree = tree
        self.lines = lines


class Program:
    def __init__(self, rom, insns, funcs, namer):
        self.rom = rom
        self.insns = insns
        self.funcs = funcs          # entry -> Function
        self.namer = namer

    def listing(self, banner=True):
        out = list(BANNER) if banner else []
        for entry in sorted(self.funcs):
            out.extend(self.funcs[entry].lines)
            out.append("")
        return "\n".join(out)


def _default_code_names(entries):
    # _start is the reset dispatcher; everything else stays sub_XXXX unless the
    # caller supplies IDA names.
    names = {}
    if 4 in entries:
        names[4] = "_start"
    return names


def decompile_rom(rom, extra_entries=(0, 4), cell_names=None, code_names=None):
    insns, calls = decoder.decode(rom, entries=extra_entries)
    funcs = cfg.build_functions(insns, calls, extra_entries=extra_entries)

    cn = _default_code_names(set(funcs))
    if code_names:
        cn.update(code_names)
    namer = Namer(cell_names=cell_names, code_names=cn)

    out = {}
    for entry, f in funcs.items():
        opt.optimize(f)
        tree = structure.structure(f)
        lines = cgen.generate(f, tree, namer)
        out[entry] = Function(entry, namer.code(entry), f, tree, lines)
    return Program(rom, insns, out, namer)


def decompile_file(path, name=None, **kw):
    rom = decoder.load(path, name)
    return decompile_rom(rom, **kw)
