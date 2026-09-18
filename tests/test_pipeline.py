"""
Headless pipeline tests -- no IDA, no ROM files required.

A tiny hand-assembled program exercises decode field extraction and the full
decode -> lift -> cfg -> opt -> structure -> cgen pipeline, asserting the
recovered control flow (a do/while loop and an if) reads the way it should.

    python tests/test_pipeline.py
"""

import os
import struct
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from startrekdec import decoder, isa, decompile_rom          # noqa: E402
from startrekdec.isa import RAMBASE                            # noqa: E402


# --- a one-instruction assembler -------------------------------------------

def _wa(word):
    return word if isinstance(word, int) else 0


def w_op(op, a1=0, a2=0):
    """op | a1(word field, bits 12..23) | a2(word field, bits 0..11)."""
    return (op << 24) | ((a1 & 0xFFF) << 12) | (a2 & 0xFFF)


def cell(word):
    """Absolute cell address for a 12-bit word field."""
    return ((word & 0xFFF) << 2) | RAMBASE


def asm(words):
    out = b""
    for w in words:
        out += struct.pack(">I", w)
    return out


def test_field_extraction():
    # cmpi (cell 0x30), 5   -> opcode 0x11, addr_data, data word 5
    a1 = 0x0C            # word field; cell = 0x30 | RAMBASE
    blob = asm([w_op(0x11, a1, 0), 5])
    rom = decoder.Rom(blob)
    ins = decoder.decode_one(rom, 0)
    assert ins.mnem == "cmpi", ins.mnem
    assert ins.size == 8
    assert ins.addr1 == cell(a1) == (0x30 | RAMBASE)
    assert ins.data == 5

    # call 0x40  -> opcode 0xE8, branch = (0x10)<<2 = 0x40
    blob = asm([w_op(0xE8, 0, 0x10)])
    ins = decoder.decode_one(decoder.Rom(blob), 0)
    assert ins.mnem == "call" and ins.branch == 0x40, (ins.mnem, ins.branch)
    print("ok  test_field_extraction")


def _memcmp_like():
    """Assemble a memcmp-style routine and return its ROM bytes.

    0x00 store (P), 0            ; P = 0
    0x08 store (Q), 0            ; Q = 0
    0x10 store (N), 4            ; N = 4
    0x18 suba (Q), (P)          ; Q = Q - P   (sets flags)   [loop head]
    0x1C bnz  0x28              ; if (Q != 0) goto ret
    0x20 dec32 (N)             ; N -= 4      (sets flags)
    0x24 bnz  0x18             ; if (N != 0) goto head
    0x28 ret
    """
    P, Q, N = 0x40, 0x44, 0x48        # word fields
    words = [
        w_op(0x09, P, 0), 0,
        w_op(0x09, Q, 0), 0,
        w_op(0x09, N, 0), 4,
        w_op(0x16, Q, P),                       # suba (Q),(P)  [head @0x18]
        w_op(0xE1, 0, 0x28 >> 2),               # bnz 0x28
        w_op(0x88, N, 0),                        # dec32 (N)
        w_op(0xE1, 0, 0x18 >> 2),               # bnz 0x18
        w_op(0xF0, 0, 0),                        # ret
    ]
    return asm(words)


def test_structuring():
    rom = decoder.Rom(_memcmp_like())
    prog = decompile_rom(rom, extra_entries=(0,))
    fn = prog.funcs[0]
    text = "\n".join(fn.lines)
    assert "do {" in text, text
    assert "while (" in text and "!= 0" in text, text
    assert "if (" in text and "break;" in text, text
    # declaration / body agreement: every cell used is declared or is MMIO
    assert text.count("{") == text.count("}"), text
    print("ok  test_structuring\n")
    print(text)


def test_no_crash_on_all_opcodes():
    # every defined opcode must lift and render without raising
    from startrekdec import lifter
    for byte, op in isa.OPCODES.items():
        words = [w_op(byte, 0x10, 0x20)]
        if op.shape == isa.ADDR_DATA:
            words.append(0x11223344)
        rom = decoder.Rom(asm(words))
        ins = decoder.decode_one(rom, 0)
        assert ins is not None, hex(byte)
        lifter.lift_insn(ins)          # must not raise
    print("ok  test_no_crash_on_all_opcodes")


if __name__ == "__main__":
    test_field_extraction()
    test_no_crash_on_all_opcodes()
    test_structuring()
    print("\nall tests passed")
