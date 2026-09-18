"""
Standalone Kirk/Spock decoder.

Turns raw ROM bytes into :class:`Insn` objects using :mod:`startrekdec.isa`.
It is deliberately independent of IDA so the whole pipeline can run headless
against a ``.bin`` (see :mod:`startrekdec.cli`); inside IDA the same ``Insn``
shape is produced by :mod:`startrekdec.ida_bridge`.

Decoding is recursive-descent: a linear sweep is useless here because the ROM
freely interleaves code, 256-bit key tables and 0xFF padding, and because the
8-byte ``addr_data`` instructions carry a full data word that would otherwise be
mis-read as an opcode.  We start from a set of entry points (0 and every call
target we discover) and follow control flow, marking exactly the bytes that are
reached as code.
"""

import struct

from . import isa
from .isa import K


class Insn:
    """One decoded instruction."""

    __slots__ = ("ea", "size", "op", "raw", "addr1", "addr2",
                 "imm1", "imm2", "data", "branch")

    def __init__(self, ea, op, raw, size):
        self.ea = ea
        self.op = op            # isa.Op
        self.raw = raw          # first 32-bit word
        self.size = size
        self.addr1 = None
        self.addr2 = None
        self.imm1 = None
        self.imm2 = None
        self.data = None        # trailing 32-bit word of addr_data forms
        self.branch = None      # absolute code byte offset

    @property
    def mnem(self):
        return self.op.mnem

    @property
    def kind(self):
        return self.op.kind

    def is_cond_branch(self):
        return self.op.kind == K.BCC

    def is_flow(self):
        return self.op.kind in isa.FLOW

    def ends_block(self):
        # b/ret end a block; conditional branches and calls fall through
        return self.op.kind in isa.STOP

    def __repr__(self):
        return "<Insn %04X %s>" % (self.ea, self.mnem)


class Rom:
    """A flat ROM image addressed by byte offset from 0."""

    def __init__(self, data, name="rom"):
        self.data = bytes(data)
        self.name = name

    def __len__(self):
        return len(self.data)

    def word(self, ea):
        if ea + 4 > len(self.data):
            return None
        return struct.unpack_from(">I", self.data, ea)[0]

    def in_range(self, ea):
        return 0 <= ea < len(self.data)


def decode_one(rom, ea):
    """Decode a single instruction at *ea*, or ``None`` if it is not code."""
    w = rom.word(ea)
    if w is None:
        return None
    op = isa.OPCODES.get((w >> 24) & 0xFF)
    if op is None:
        return None
    if ea + op.size > len(rom):
        return None

    f = isa.decode_fields(w)
    ins = Insn(ea, op, w, op.size)
    shape = op.shape
    if shape == isa.ADDR:
        ins.addr1 = f["addr1"]
        ins.imm2 = f["imm2"]
    elif shape == isa.ADDR_ADDR:
        # ana.cpp: Op1 = addr2 (destination), Op2 = addr1 (source)
        ins.addr1 = f["addr2"]
        ins.addr2 = f["addr1"]
    elif shape == isa.ADDR_IMM:
        ins.addr1 = f["addr1"]
        ins.imm2 = f["imm2"]
    elif shape == isa.IMM_IMM:
        ins.imm1 = f["imm1"]
        ins.imm2 = f["imm2"]
    elif shape == isa.BRANCH:
        ins.branch = f["branch"]
    elif shape == isa.ADDR_DATA:
        ins.addr1 = f["addr1"]
        ins.data = rom.word(ea + 4)
    return ins


def _successors(ins):
    """Static control-flow successors of *ins* as (kind, target) pairs."""
    out = []
    k = ins.op.kind
    if k == K.BRA:
        out.append(("jump", ins.branch))
    elif k == K.BCC:
        out.append(("jump", ins.branch))
        out.append(("fall", ins.ea + ins.size))
    elif k == K.CALL:
        out.append(("call", ins.branch))
        out.append(("fall", ins.ea + ins.size))
    elif k == K.RET:
        pass
    else:
        out.append(("fall", ins.ea + ins.size))
    return out


def decode(rom, entries=(0,)):
    """Recursive-descent decode.

    Returns ``(insns, calls)`` where *insns* maps ``ea -> Insn`` for every byte
    reached as code and *calls* is the set of discovered call targets (i.e. the
    entry points of sub-routines).
    """
    insns = {}
    calls = set()
    seen = set()
    work = [e for e in entries if rom.in_range(e)]
    while work:
        ea = work.pop()
        if ea in seen or not rom.in_range(ea):
            continue
        seen.add(ea)
        ins = decode_one(rom, ea)
        if ins is None:
            continue
        insns[ea] = ins
        for how, tgt in _successors(ins):
            if tgt is None or not rom.in_range(tgt):
                continue
            if how == "call":
                calls.add(tgt)
            work.append(tgt)
    return insns, calls


def load(path, name=None):
    with open(path, "rb") as fp:
        data = fp.read()
    return Rom(data, name or path)
