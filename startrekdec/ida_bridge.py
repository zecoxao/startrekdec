"""
IDA integration for startrekdec.

When run inside IDA on a database opened with ProximaV's KIRK processor module,
this bridge feeds the *same* headless pipeline: it reads the ROM bytes straight
out of the database, uses IDA's function boundaries as entry points, and wraps
the naming layer so the decompilation reuses whatever labels the analyst has
applied (``PSP_KIRK_CMD``, ``aes_encrypt_cbc``, ``kirk_5`` ...).

This module imports IDA only lazily, so importing :mod:`startrekdec` outside IDA
stays clean.
"""

from . import decoder, cfg, opt, structure, cgen
from .names import Namer
from . import Program, Function, BANNER, __version__  # noqa: F401


def _ida():
    import ida_bytes, ida_funcs, ida_name, ida_segment, idautils, idc
    return ida_bytes, ida_funcs, ida_name, ida_segment, idautils, idc


class IdaNamer(Namer):
    """Names come from IDA first, then the curated tables, then v<hex>."""

    def __init__(self):
        super().__init__()
        import ida_name
        self._ida_name = ida_name

    def _lookup(self, ea):
        n = self._ida_name.get_name(ea)
        return n or None

    def cell(self, addr):
        return self._lookup(addr) or super().cell(addr)

    def code(self, ea):
        return self._lookup(ea) or super().code(ea)

    def label(self, ea):
        return self._lookup(ea) or super().label(ea)


def _read_rom():
    ida_bytes, ida_funcs, ida_name, ida_segment, idautils, idc = _ida()
    # concatenate all code segments from their minimum ea, filling gaps.
    seg = ida_segment.get_first_seg()
    lo = None
    hi = 0
    while seg is not None:
        lo = seg.start_ea if lo is None else min(lo, seg.start_ea)
        hi = max(hi, seg.end_ea)
        seg = ida_segment.get_next_seg(seg.start_ea)
    if lo is None:
        return None, 0
    lo = 0 if lo < 0x1000 else lo          # Kirk ROM is based at 0
    size = hi - lo
    data = ida_bytes.get_bytes(lo, size) or b""
    return decoder.Rom(bytes(data)), lo


def _entries():
    ida_bytes, ida_funcs, ida_name, ida_segment, idautils, idc = _ida()
    return sorted(idautils.Functions())


def decompile_program():
    rom, base = _read_rom()
    if rom is None:
        raise RuntimeError("startrekdec: no segments in this database")
    entries = _entries() or [0, 4]
    insns, calls = decoder.decode(rom, entries=entries)
    funcs = cfg.build_functions(insns, calls, extra_entries=entries)

    namer = IdaNamer()
    out = {}
    for entry, f in funcs.items():
        opt.optimize(f)
        tree = structure.structure(f)
        lines = cgen.generate(f, tree, namer)
        out[entry] = Function(entry, namer.code(entry), f, tree, lines)
    return Program(rom, insns, out, namer)


def decompile_one(ea):
    """Decompile just the function containing *ea*."""
    ida_bytes, ida_funcs, ida_name, ida_segment, idautils, idc = _ida()
    f = ida_funcs.get_func(ea)
    entry = f.start_ea if f is not None else ea

    rom, base = _read_rom()
    insns, calls = decoder.decode(rom, entries=[entry] + _entries())
    func = cfg.build_func(insns, entry, set(calls) | set(_entries()))
    if func is None:
        raise RuntimeError("startrekdec: nothing decoded at 0x%X" % entry)
    namer = IdaNamer()
    opt.optimize(func)
    tree = structure.structure(func)
    lines = cgen.generate(func, tree, namer, banner=BANNER)
    return Function(entry, namer.code(entry), func, tree, lines)
