"""
Kirk / Spock instruction-set description.

The Kirk and Spock crypto co-processors embedded in the PSP's Tachyon SoC share
one small, big-endian, memory-to-memory CPU core (ProximaV names the family the
"Star Trek PSP Processors").  This module is the single source of truth for how
a 32-bit instruction word decodes; :mod:`startrekdec.decoder` and
:mod:`startrekdec.lifter` are both driven by the ``OPCODES`` table below.

Encoding (32-bit big-endian, opcode in the top byte):

    opcode  = (w >> 24) & 0xFF
    addr1   = ((w >> 12) & 0xFFF) << 2 | RAMBASE     # first  RAM cell address
    addr2   = ( w        & 0xFFF) << 2 | RAMBASE     # second RAM cell address
    imm1    =  (w >> 12) & 0xFFF
    imm2    =   w        & 0xFFF
    branch  = ( w        & 0xFFF) << 2               # byte offset in code space

Data lives in RAM at ``RAMBASE`` (0xE0000000); operands are *cell addresses*,
never registers, which is why the disassembly reads ``xora (r_a), (r_b)``.

This reconciles three public sources that occasionally disagree, and where they
do the disagreement is recorded in the ``note`` field rather than hidden:

    * ProximaV/kirk        ana.cpp   -- authoritative field extraction / sizes
    * ProximaV/kirk        ins.cpp   -- the mnemonics IDA prints
    * LemonHaze420/ghidra_kirk kirk32.sinc -- p-code semantics
"""

RAMBASE = 0xE0000000
CODE_MASK = 0xFFF << 2            # branch targets are 14-bit byte offsets


# ---------------------------------------------------------------------------
# operand shapes  --  what fields an instruction word carries
# ---------------------------------------------------------------------------

NOOP = "noop"          # 4 bytes, no operands
ADDR = "addr"          # 4 bytes, one cell address (low imm2 also available)
ADDR_ADDR = "addr2"    # 4 bytes, two cell addresses
ADDR_IMM = "addr_imm"  # 4 bytes, cell address + 12-bit immediate
IMM_IMM = "imm2"       # 4 bytes, two 12-bit immediates
BRANCH = "branch"      # 4 bytes, code target
ADDR_DATA = "addr_data"  # 8 bytes, cell address + trailing 32-bit data word

SIZE = {NOOP: 4, ADDR: 4, ADDR_ADDR: 4, ADDR_IMM: 4, IMM_IMM: 4,
        BRANCH: 4, ADDR_DATA: 8}


# ---------------------------------------------------------------------------
# semantic kinds  --  how the lifter turns an instruction into IR
# ---------------------------------------------------------------------------

class K:
    NOP = "nop"
    STORE = "store"        # cell = imm/data
    STORE8 = "store8"      # (byte) cell = imm
    COPY = "copy"          # dst_cell = src_cell   (width in .width)
    ADD = "add"            # dst += src
    SUB = "sub"
    OR = "or"
    XOR = "xor"
    AND = "and"
    ADDI = "addi"          # cell op= data      (immediate forms)
    SUBI = "subi"
    ORI = "ori"
    XORI = "xori"
    ANDI = "andi"
    SHL = "shl"            # cell <<= imm
    SHR = "shr"            # cell >>= imm
    INC = "inc"            # cell += 4 + 4*imm
    DEC = "dec"            # cell -= 4 + 4*imm
    BITSET = "bitset"      # cell |= 1<<imm
    BITCLR = "bitclr"      # cell &= ~(1<<imm)
    BSWAP = "bswap"        # cell = byteswap(cell)
    CMP = "cmp"            # flags = cmp(cell, data/imm/cell2)
    CLRZ = "clrz"
    SETZ = "setz"
    BRA = "bra"            # unconditional branch
    BCC = "bcc"            # conditional branch (see COND)
    CALL = "call"
    RET = "ret"
    INTR = "intr"          # crypto command trigger (__builtin_crypto_hash_dma)
    SETMODE = "setmode"
    INTRINSIC = "intrinsic"  # modelled but semantics not public -> pseudo-call


# branch condition -> relational rendering on the Z/NG flags (from kirk32.sinc)
#   E1 nz : !ZR      E2 z : ZR      E3 gt : NG      E4 lt : !NG && !ZR
COND = {
    0x62: "z",     # jz   -- treated as "if zero" (sources disagree, see note)
    0x68: "nz",    # jnz
    0xE1: "nz",
    0xE2: "z",
    0xE3: "gt",
    0xE4: "lt",
}


class Op:
    __slots__ = ("byte", "mnem", "shape", "kind", "width", "note")

    def __init__(self, byte, mnem, shape, kind, width=4, note=""):
        self.byte = byte
        self.mnem = mnem
        self.shape = shape
        self.kind = kind
        self.width = width
        self.note = note

    @property
    def size(self):
        return SIZE[self.shape]


def _t(*rows):
    return {r.byte: r for r in rows}


# The table.  byte -> Op.  Anything absent decodes as raw data.
OPCODES = _t(
    Op(0x00, "nop",      NOOP,      K.NOP),
    Op(0x08, "store2",   ADDR_DATA, K.INTRINSIC, note="store variant; semantics not public"),
    Op(0x09, "store",    ADDR_DATA, K.STORE),
    Op(0x0A, "movX",     ADDR_ADDR, K.COPY),
    Op(0x0B, "mov32",    ADDR_ADDR, K.COPY),
    Op(0x0C, "movY",     ADDR_ADDR, K.COPY, note="ghidra copies the address, not the cell"),
    Op(0x0D, "mov32a",   ADDR_ADDR, K.COPY),
    Op(0x0E, "mov32aa",  ADDR_ADDR, K.COPY),
    Op(0x10, "cmpX",     ADDR_DATA, K.CMP),
    Op(0x11, "cmpi",     ADDR_DATA, K.CMP),
    Op(0x12, "cmp+",     ADDR_DATA, K.CMP, note="compare variant"),
    Op(0x13, "cmpa",     ADDR_ADDR, K.CMP),
    Op(0x16, "suba",     ADDR_ADDR, K.SUB),
    Op(0x19, "addi",     ADDR_DATA, K.ADDI),
    Op(0x1B, "adda",     ADDR_ADDR, K.ADD),
    Op(0x21, "addc",     ADDR_DATA, K.ADDI, note="add-with-carry; carry-in not modelled"),
    Op(0x29, "subi",     ADDR_DATA, K.SUBI),
    Op(0x30, "op30",     ADDR_DATA, K.INTRINSIC, note="semantics not public"),
    Op(0x38, "op38",     ADDR_DATA, K.INTRINSIC, note="semantics not public"),
    Op(0x39, "andi",     ADDR_DATA, K.ANDI),
    Op(0x3A, "anda",     ADDR_DATA, K.ANDI, note="ghidra decodes 2nd field as data"),
    Op(0x41, "mov8",     ADDR_DATA, K.STORE8),
    Op(0x43, "mov16",    ADDR_ADDR, K.COPY, width=2),
    Op(0x44, "ora",      ADDR_ADDR, K.OR),
    Op(0x49, "xori",     ADDR_DATA, K.XORI),
    Op(0x4B, "xora",     ADDR_ADDR, K.XOR),
    Op(0x4E, "xorx",     ADDR_ADDR, K.XOR),
    Op(0x53, "mov128",   ADDR_ADDR, K.COPY, width=16),
    Op(0x62, "jz",       BRANCH,    K.BCC),
    Op(0x68, "jnz",      BRANCH,    K.BCC),
    Op(0x80, "inc32",    ADDR,      K.INC),
    Op(0x88, "dec32",    ADDR,      K.DEC),
    Op(0x89, "op89",     ADDR_DATA, K.INTRINSIC, note="semantics not public"),
    Op(0x8B, "op8B",     ADDR_ADDR, K.INTRINSIC, note="semantics not public"),
    Op(0x90, "lsh",      ADDR_IMM,  K.SHL),
    Op(0x98, "rsh",      ADDR_IMM,  K.SHR),
    Op(0xA0, "setmode",  ADDR_IMM,  K.SETMODE),
    Op(0xB0, "byteswap", ADDR,      K.BSWAP),
    Op(0xC0, "test",     ADDR_IMM,  K.CMP),
    Op(0xC3, "check3",   ADDR_IMM,  K.CMP),
    Op(0xC6, "check6",   ADDR_IMM,  K.CMP),
    Op(0xC7, "check7",   ADDR_IMM,  K.CMP),
    Op(0xC8, "bitset",   ADDR_IMM,  K.BITSET),
    Op(0xC9, "check9",   ADDR_IMM,  K.CMP),
    Op(0xD0, "bitclear", ADDR_IMM,  K.BITCLR),
    Op(0xDA, "clrz",     NOOP,      K.CLRZ),
    Op(0xDB, "setz",     NOOP,      K.SETZ),
    Op(0xE0, "b",        BRANCH,    K.BRA),
    Op(0xE1, "bnz",      BRANCH,    K.BCC),
    Op(0xE2, "bz",       BRANCH,    K.BCC),
    Op(0xE3, "bgt",      BRANCH,    K.BCC),
    Op(0xE4, "blt",      BRANCH,    K.BCC),
    Op(0xE8, "call",     BRANCH,    K.CALL),
    Op(0xE9, "call2",    BRANCH,    K.CALL, note="alias of E8; usually a data mis-decode"),
    Op(0xF0, "ret",      NOOP,      K.RET),
    Op(0xF8, "intr",     IMM_IMM,   K.INTR),
)

# opcodes that end a basic block
STOP = {K.BRA, K.RET}
FLOW = {K.BRA, K.BCC, K.CALL, K.RET}


def decode_fields(w):
    """Return the raw bit-fields of a 32-bit instruction word."""
    return {
        "op": (w >> 24) & 0xFF,
        "addr1": (((w >> 12) & 0xFFF) << 2) | RAMBASE,
        "addr2": ((w & 0xFFF) << 2) | RAMBASE,
        "imm1": (w >> 12) & 0xFFF,
        "imm2": w & 0xFFF,
        "branch": (w & 0xFFF) << 2,
    }
