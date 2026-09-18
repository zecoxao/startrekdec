"""
Control-flow structuring.

These ROMs are small, reducible and laid out in address order, so a recursive
address-range structurer recovers ``if`` / ``while`` / ``do-while`` cleanly while
always leaving a correct ``goto`` + label fallback for anything that does not fit
a structured shape.  The output is a tree of ``S*`` nodes consumed by
:mod:`startrekdec.cgen`.
"""

from . import ir


# --- high-level nodes -------------------------------------------------------

class SStmt:
    def __init__(self, stmt): self.stmt = stmt
class SLabel:
    def __init__(self, ea): self.ea = ea
class SGoto:
    def __init__(self, ea): self.ea = ea
class SRet:
    pass
class SIf:
    def __init__(self, cond, then, els): self.cond = cond; self.then = then; self.els = els
class SIfGoto:
    def __init__(self, cond, ea): self.cond = cond; self.ea = ea
class SWhile:
    def __init__(self, body, cond=None, dowhile=False):
        self.body = body; self.cond = cond; self.dowhile = dowhile
class SBreak:
    pass
class SContinue:
    def __init__(self, cond=None): self.cond = cond
class SBreakIf:
    def __init__(self, cond): self.cond = cond


# --- condition rendering ----------------------------------------------------

_REL = {"z": "==", "nz": "!=", "gt": ">", "lt": "<"}
_NEG = {"==": "!=", "!=": "==", ">": "<=", "<": ">=", ">=": "<", "<=": ">"}
_FLAG = {"z": "ZF", "nz": "!ZF", "gt": "SF", "lt": "!SF"}


def cond_expr(branch):
    flag, c = branch.flag, branch.cond
    if flag is None:
        return ir.IntrExpr(_FLAG[c], [])
    if flag.kind == "cmp":
        return ir.Bin(_REL[c], flag.a, flag.b)
    if flag.kind == "result":
        return ir.Bin(_REL[c], flag.a, ir.Const(0))
    if flag.kind == "z":
        taken = (c == "z" and flag.zval == 1) or (c == "nz" and flag.zval == 0)
        return ir.Const(1 if taken else 0)
    return ir.IntrExpr(_FLAG[c], [])


def negate(e):
    if isinstance(e, ir.Bin) and e.op in _NEG:
        return ir.Bin(_NEG[e.op], e.l, e.r)
    if isinstance(e, ir.IntrExpr) and not e.args:
        return ir.IntrExpr(e.name[1:] if e.name.startswith("!") else "!" + e.name, [])
    if isinstance(e, ir.Const):
        return ir.Const(0 if e.value else 1)
    return ir.Un("!", e)


# --- structurer -------------------------------------------------------------

class _Structurer:
    def __init__(self, func):
        self.f = func
        self.order = func.ordered()
        self.starts = [b.start for b in self.order]
        self.idx = {b.start: i for i, b in enumerate(self.order)}
        self.blocks = self.order
        self._open = set()      # header indices currently being expanded

    def run(self):
        return self._emit(0, len(self.blocks), loop=None)

    def _in_range(self, ea, lo, hi):
        i = self.idx.get(ea)
        return i is not None and lo <= i < hi

    def _find_latch(self, header_idx, hi):
        """Largest index j in (header_idx, hi) whose block branches/jumps back
        to the header -- i.e. a back edge making [header, j] a loop."""
        h = self.blocks[header_idx].start
        latch = None
        for j in range(header_idx, hi):
            for _, tgt in self.blocks[j].succ:
                if tgt == h and j > header_idx:
                    latch = j
        return latch

    def _body_stmts(self, block):
        out = []
        for s in block.stmts:
            # control flow is rebuilt structurally; Compare only feeds the
            # branch condition it was already resolved into.
            if isinstance(s, (ir.Goto, ir.Branch, ir.Ret, ir.Nop, ir.Compare)):
                continue
            out.append(SStmt(s))
        return out

    def _emit(self, lo, hi, loop):
        out = []
        i = lo
        while i < hi:
            b = self.blocks[i]
            out.append(SLabel(b.start))

            latch = None if i in self._open else self._find_latch(i, hi)
            if latch is not None:
                node, nxt = self._emit_loop(i, latch, hi)
                out.append(node)
                i = nxt
                continue

            out.extend(self._body_stmts(b))
            term = b.term
            if term == "ret":
                out.append(SRet())
                i += 1
                continue
            if term == "goto":
                tgt = b.succ[0][1]
                self._emit_edge(out, tgt, lo, hi, loop, fall_i=i + 1)
                if not self._is_fall(out):
                    i += 1
                    continue
                i += 1
                continue
            if term == "branch":
                cond = cond_expr(self._branch_of(b))
                taken = b.succ[0][1]
                fall = b.succ[1][1]
                # 1. loop-aware break/continue on the taken edge (checked first
                #    so a branch to the loop follow becomes `break`, not an if).
                if loop is not None and taken in (loop[0], loop[1]):
                    out.append(SContinue(cond) if taken == loop[0] else SBreakIf(cond))
                    self._fall_after(out, fall, lo, hi, loop, i)
                    i += 1
                    continue
                # 2. structured if-then: taken is a forward join strictly inside
                #    the region (ti == hi would drop the taken edge -> use goto).
                ti = self.idx.get(taken)
                if ti is not None and i + 1 <= ti < hi and taken != b.start \
                        and (loop is None or taken not in (loop[0], loop[1])):
                    then = self._emit(i + 1, ti, loop)
                    out.append(SIf(negate(cond), then, None))
                    i = ti
                    continue
                # 3. fallback: if (cond) goto taken; then the fall edge.
                out.append(SIfGoto(cond, taken))
                self._fall_after(out, fall, lo, hi, loop, i)
                i += 1
                continue
            # plain fall
            if b.succ:
                tgt = b.succ[0][1]
                if self.idx.get(tgt) != i + 1:
                    self._emit_edge(out, tgt, lo, hi, loop, fall_i=i + 1)
            i += 1
        return out

    def _emit_loop(self, hidx, latch, hi):
        """Emit blocks [hidx, latch] as a loop; return (node, next_index)."""
        loop_lo, loop_hi = hidx, latch + 1
        header = self.blocks[hidx].start
        # follow = fall-through out of the latch, else first index after latch
        follow_ea = None
        for k, tgt in self.blocks[latch].succ:
            if not self._in_range(tgt, loop_lo, loop_hi):
                follow_ea = tgt
                break
        loop_ctx = (header, follow_ea)
        self._open.add(hidx)
        body = self._emit(loop_lo, loop_hi, loop_ctx)
        self._open.discard(hidx)
        node = SWhile(body, cond=None, dowhile=False)
        nxt = latch + 1
        if follow_ea is not None and self.idx.get(follow_ea) is not None:
            nxt = self.idx[follow_ea]
        return node, nxt

    def _branch_of(self, block):
        for s in block.stmts:
            if isinstance(s, ir.Branch):
                return s
        return None

    def _is_fall(self, out):
        return False

    def _fall_after(self, out, fall, lo, hi, loop, i):
        """Route the fall-through edge that follows a conditional branch."""
        if self.idx.get(fall) == i + 1:
            return                       # natural fall to the next block
        if loop is not None:
            if fall == loop[0]:
                out.append(SContinue())
                return
            if fall == loop[1]:
                out.append(SBreak())
                return
        out.append(SGoto(fall))

    def _emit_edge(self, out, tgt, lo, hi, loop, fall_i):
        if loop is not None:
            if tgt == loop[0]:
                out.append(SContinue())
                return
            if tgt == loop[1]:
                out.append(SBreak())
                return
        if self.idx.get(tgt) == fall_i:
            return
        out.append(SGoto(tgt))


def structure(func):
    return _Structurer(func).run()
