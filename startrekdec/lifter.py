"""
Lift decoded :class:`~startrekdec.decoder.Insn` objects into IR statements.

One clause per semantic kind (:class:`startrekdec.isa.K`), following the p-code
in ghidra_kirk's ``kirk32.sinc`` where it is defined and emitting an honest
:class:`~startrekdec.ir.Intrinsic` where the public semantics are not.
"""

from . import ir
from .isa import K


def _cell(addr, width=4):
    return ir.Var(addr, width)


def lift_insn(ins):
    """Return a list of IR statements for one instruction."""
    k = ins.kind
    ea = ins.ea
    w = ins.op.width

    if k == K.NOP:
        return [ir.Nop(ea)]

    # --- data movement -----------------------------------------------------
    if k == K.STORE:
        return [ir.Assign(ea, _cell(ins.addr1), ir.Const(ins.data))]
    if k == K.STORE8:
        return [ir.Assign(ea, _cell(ins.addr1, 1), ir.Const(ins.data & 0xFF))]
    if k == K.COPY:
        return [ir.Assign(ea, _cell(ins.addr1, w), _cell(ins.addr2, w))]

    # --- arithmetic / logic (cell op= other) -------------------------------
    if k in (K.ADD, K.SUB, K.OR, K.XOR, K.AND):
        opc = {K.ADD: "+", K.SUB: "-", K.OR: "|",
               K.XOR: "^", K.AND: "&"}[k]
        dst = _cell(ins.addr1)
        src = _cell(ins.addr2)
        flag = ir.FlagDef("result", a=dst) if k == K.SUB else None
        return [ir.Assign(ea, dst, ir.Bin(opc, dst, src), flag=flag)]

    if k in (K.ADDI, K.SUBI, K.ORI, K.XORI, K.ANDI):
        opc = {K.ADDI: "+", K.SUBI: "-", K.ORI: "|",
               K.XORI: "^", K.ANDI: "&"}[k]
        dst = _cell(ins.addr1)
        flag = ir.FlagDef("result", a=dst) if k == K.SUBI else None
        return [ir.Assign(ea, dst, ir.Bin(opc, dst, ir.Const(ins.data)), flag=flag)]

    if k in (K.SHL, K.SHR):
        opc = "<<" if k == K.SHL else ">>"
        dst = _cell(ins.addr1)
        return [ir.Assign(ea, dst, ir.Bin(opc, dst, ir.Const(ins.imm2)))]

    if k in (K.INC, K.DEC):
        dst = _cell(ins.addr1)
        step = 4 + 4 * (ins.imm2 or 0)
        opc = "+" if k == K.INC else "-"
        flag = ir.FlagDef("result", a=dst)
        return [ir.Assign(ea, dst, ir.Bin(opc, dst, ir.Const(step)), flag=flag)]

    if k == K.BITSET:
        dst = _cell(ins.addr1)
        return [ir.Assign(ea, dst, ir.Bin("|", dst, ir.Const(1 << ins.imm2)))]
    if k == K.BITCLR:
        dst = _cell(ins.addr1)
        return [ir.Assign(ea, dst, ir.Bin("&", dst, ir.Const((~(1 << ins.imm2)) & 0xFFFFFFFF)))]
    if k == K.BSWAP:
        dst = _cell(ins.addr1)
        return [ir.Assign(ea, dst, ir.IntrExpr("__bswap32", [dst]))]

    # --- flags -------------------------------------------------------------
    if k == K.CMP:
        if ins.data is not None:            # addr_data compare
            b = ir.Const(ins.data)
        elif ins.addr2 is not None:         # addr_addr compare (cmpa)
            b = _cell(ins.addr2)
        else:                               # addr_imm compare (test/checkN)
            b = ir.Const(ins.imm2)
        return [ir.Compare(ea, ir.FlagDef("cmp", a=_cell(ins.addr1), b=b))]
    if k == K.CLRZ:
        return [ir.SetFlag(ea, ir.FlagDef("z", zval=0))]
    if k == K.SETZ:
        return [ir.SetFlag(ea, ir.FlagDef("z", zval=1))]

    # --- control flow ------------------------------------------------------
    if k == K.BRA:
        return [ir.Goto(ea, ins.branch)]
    if k == K.BCC:
        from .isa import COND
        return [ir.Branch(ea, COND[ins.op.byte], ins.branch, ins.ea + ins.size)]
    if k == K.CALL:
        return [ir.Call(ea, ins.branch)]
    if k == K.RET:
        return [ir.Ret(ea)]

    # --- crypto / opaque ---------------------------------------------------
    if k == K.INTR:
        # The command trigger: hands (imm1, imm2) to the crypto/DMA engine.
        return [ir.Intrinsic(ea, "kirk_engine", [ir.Const(ins.imm1), ir.Const(ins.imm2)],
                             note="engine command trigger")]
    if k == K.SETMODE:
        return [ir.Intrinsic(ea, "setmode", [_cell(ins.addr1), ir.Const(ins.imm2)])]
    if k == K.INTRINSIC:
        args = []
        if ins.addr1 is not None:
            args.append(_cell(ins.addr1))
        if ins.addr2 is not None:
            args.append(_cell(ins.addr2))
        if ins.data is not None:
            args.append(ir.Const(ins.data))
        return [ir.Intrinsic(ea, ins.mnem, args, note=ins.op.note)]

    return [ir.Nop(ea)]
