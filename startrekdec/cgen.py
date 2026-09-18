"""
Pseudo-C back-end: render the structured tree from :mod:`startrekdec.structure`
into a readable listing.

All RAM cells are 32-bit, so every cell reads as a ``u32`` variable named by
:class:`startrekdec.names.Namer` (Kirk MMIO registers keep their documented
names).  Relational conditions are printed as C comparisons; the ``s>``/``s<``
signedness of the flag compares is noted once in the function banner rather than
littered through the body.
"""

from . import ir
from . import structure as S
from .isa import RAMBASE


class _Emit:
    def __init__(self, namer):
        self.namer = namer
        self.lines = []
        self.used_labels = set()
        self._pending = []      # (indent, text, label_ea_or_None)

    # -- expressions --------------------------------------------------------

    def expr(self, e, top=True):
        if isinstance(e, ir.Const):
            v = e.value
            return str(v) if v < 10 else "0x%X" % v
        if isinstance(e, ir.Var):
            return self.namer.cell(e.addr)
        if isinstance(e, ir.Bin):
            s = "%s %s %s" % (self.expr(e.l, False), e.op, self.expr(e.r, False))
            return s if top else "(%s)" % s
        if isinstance(e, ir.Un):
            return "%s(%s)" % (e.op, self.expr(e.e, False)) if e.op == "!" \
                else "%s%s" % (e.op, self.expr(e.e, False))
        if isinstance(e, ir.IntrExpr):
            if not e.args:
                return e.name
            return "%s(%s)" % (e.name, ", ".join(self.expr(a) for a in e.args))
        return "?"

    # -- statements ---------------------------------------------------------

    def _assign(self, s):
        dst = self.namer.cell(s.dst.addr)
        if isinstance(s.src, ir.Var) and s.dst.width in (2, 16):
            n = s.dst.width
            return "memcpy(&%s, &%s, %d);" % (dst, self.namer.cell(s.src.addr), n)
        if s.dst.width == 1:
            return "*(u8*)&%s = %s;" % (dst, self.expr(s.src))
        return "%s = %s;" % (dst, self.expr(s.src))

    def stmt(self, s):
        if isinstance(s, ir.Assign):
            return self._assign(s)
        if isinstance(s, ir.Call):
            return "%s();" % self.namer.code(s.target)
        if isinstance(s, ir.Intrinsic):
            call = "%s(%s);" % (s.name, ", ".join(self.expr(a) for a in s.args))
            return call + ("   /* %s */" % s.note if s.note else "")
        if isinstance(s, ir.SetFlag):
            return "ZF = %d;" % (s.flag.zval if s.flag else 0)
        return "/* %s */" % type(s).__name__

    # -- tree ---------------------------------------------------------------

    def emit(self, nodes, ind):
        pad = "    " * ind
        for n in nodes:
            if isinstance(n, S.SLabel):
                self._pending.append((ind, None, n.ea))
            elif isinstance(n, S.SStmt):
                self._pending.append((ind, pad + self.stmt(n.stmt), None))
            elif isinstance(n, S.SRet):
                self._pending.append((ind, pad + "return;", None))
            elif isinstance(n, S.SGoto):
                self.used_labels.add(n.ea)
                self._pending.append((ind, pad + "goto %s;" % self.namer.label(n.ea), None))
            elif isinstance(n, S.SIfGoto):
                self.used_labels.add(n.ea)
                self._pending.append((ind, pad + "if (%s) goto %s;"
                                      % (self.expr(n.cond), self.namer.label(n.ea)), None))
            elif isinstance(n, S.SBreak):
                self._pending.append((ind, pad + "break;", None))
            elif isinstance(n, S.SBreakIf):
                self._pending.append((ind, pad + "if (%s) break;" % self.expr(n.cond), None))
            elif isinstance(n, S.SContinue):
                if n.cond is None:
                    self._pending.append((ind, pad + "continue;", None))
                else:
                    self._pending.append((ind, pad + "if (%s) continue;" % self.expr(n.cond), None))
            elif isinstance(n, S.SIf):
                self._pending.append((ind, pad + "if (%s) {" % self.expr(n.cond), None))
                self.emit(n.then, ind + 1)
                if n.els:
                    self._pending.append((ind, pad + "} else {", None))
                    self.emit(n.els, ind + 1)
                self._pending.append((ind, pad + "}", None))
            elif isinstance(n, S.SWhile):
                self._emit_while(n, ind)

    def _emit_while(self, n, ind):
        pad = "    " * ind
        body = list(n.body)
        # do-while peephole: trailing conditional continue -> while (cond)
        tail = None
        if body and isinstance(body[-1], S.SContinue) and body[-1].cond is not None:
            tail = body[-1].cond
            body = body[:-1]
        if tail is not None:
            self._pending.append((ind, pad + "do {", None))
            self.emit(body, ind + 1)
            self._pending.append((ind, pad + "} while (%s);" % self.expr(tail), None))
        else:
            self._pending.append((ind, pad + "while (1) {", None))
            self.emit(body, ind + 1)
            self._pending.append((ind, pad + "}", None))

    # -- finalise -----------------------------------------------------------

    def flush(self):
        out = []
        for ind, text, label_ea in self._pending:
            if label_ea is not None:
                if label_ea in self.used_labels:
                    out.append("%s:" % self.namer.label(label_ea))
                continue
            out.append(text)
        return out


def _collect_cells(func):
    cells = {}

    def visit(e):
        if isinstance(e, ir.Var):
            cells[e.addr] = max(cells.get(e.addr, 0), e.width)
        elif isinstance(e, ir.Bin):
            visit(e.l); visit(e.r)
        elif isinstance(e, ir.Un):
            visit(e.e)
        elif isinstance(e, ir.IntrExpr):
            for a in e.args:
                visit(a)

    for b in func.blocks.values():
        for s in b.stmts:
            if isinstance(s, ir.Assign):
                cells[s.dst.addr] = max(cells.get(s.dst.addr, 0), s.dst.width)
                visit(s.src)
            elif isinstance(s, (ir.Compare, ir.SetFlag)) and s.flag:
                if s.flag.a is not None:
                    visit(s.flag.a)
                if s.flag.b is not None:
                    visit(s.flag.b)
            elif isinstance(s, ir.Intrinsic):
                for a in s.args:
                    visit(a)
    return cells


def generate(func, tree, namer, banner=None):
    from .commands import MMIO
    em = _Emit(namer)
    em.emit(tree, 1)
    body = em.flush()

    cells = _collect_cells(func)
    decls = []
    for addr in sorted(cells):
        if addr in MMIO:
            continue
        name = namer.cell(addr)
        if not name[0].isalpha() and name[0] != "_":
            continue
        decls.append("    u32 %s;   /* @0x%08X */" % (name, addr))

    out = []
    if banner:
        out.extend(banner)
    out.append("void %s(void)" % (namer.code(func.entry)))
    out.append("{")
    out.extend(decls)
    if decls:
        out.append("")
    out.extend(body)
    out.append("}")
    return out
