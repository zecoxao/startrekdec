"""
Conservative, block-local optimisation.

Cells are global memory, so nothing is eliminated across blocks and stores are
never dropped (another function may read them).  Within a block we fold constant
expressions and propagate constants and plain copies into later uses, killing an
entry the moment its cell -- or any cell it mentions -- is written, or a call /
intrinsic clobbers memory.  This is enough to turn the flat three-address code
into readable expressions without risking a wrong result.
"""

from . import ir


def _fold(e):
    if isinstance(e, ir.Bin):
        l = _fold(e.l)
        r = _fold(e.r)
        if isinstance(l, ir.Const) and isinstance(r, ir.Const):
            v = _apply(e.op, l.value, r.value)
            if v is not None:
                return ir.Const(v)
        # identities
        if e.op in ("+", "-", "|", "^", "<<", ">>") and isinstance(r, ir.Const) and r.value == 0:
            return l
        if e.op == "&" and isinstance(r, ir.Const) and r.value == 0xFFFFFFFF:
            return l
        return ir.Bin(e.op, l, r)
    if isinstance(e, ir.Un):
        return ir.Un(e.op, _fold(e.e))
    if isinstance(e, ir.IntrExpr):
        return ir.IntrExpr(e.name, [_fold(a) for a in e.args])
    return e


def _apply(op, a, b):
    a &= 0xFFFFFFFF
    b &= 0xFFFFFFFF
    try:
        if op == "+":
            return (a + b) & 0xFFFFFFFF
        if op == "-":
            return (a - b) & 0xFFFFFFFF
        if op == "|":
            return a | b
        if op == "^":
            return a ^ b
        if op == "&":
            return a & b
        if op == "<<":
            return (a << (b & 31)) & 0xFFFFFFFF
        if op == ">>":
            return a >> (b & 31)
    except Exception:
        return None
    return None


def _mentions(e, addr):
    if isinstance(e, ir.Var):
        return e.addr == addr
    if isinstance(e, ir.Bin):
        return _mentions(e.l, addr) or _mentions(e.r, addr)
    if isinstance(e, ir.Un):
        return _mentions(e.e, addr)
    if isinstance(e, ir.IntrExpr):
        return any(_mentions(a, addr) for a in e.args)
    return False


def _subst(e, env):
    if isinstance(e, ir.Var):
        repl = env.get(e.addr)
        return repl if repl is not None else e
    if isinstance(e, ir.Bin):
        return ir.Bin(e.op, _subst(e.l, env), _subst(e.r, env))
    if isinstance(e, ir.Un):
        return ir.Un(e.op, _subst(e.e, env))
    if isinstance(e, ir.IntrExpr):
        return ir.IntrExpr(e.name, [_subst(a, env) for a in e.args])
    return e


def _kill(env, addr):
    for k in [k for k, v in env.items() if k == addr or _mentions(v, addr)]:
        del env[k]


def _opt_block(block):
    env = {}
    for s in block.stmts:
        if isinstance(s, ir.Assign):
            s.src = _fold(_subst(s.src, env))
            _kill(env, s.dst.addr)
            # only propagate values that cannot grow or re-evaluate unsafely
            if isinstance(s.src, (ir.Const, ir.Var)):
                env[s.dst.addr] = s.src
        elif isinstance(s, ir.Compare):
            if s.flag is not None:
                if s.flag.a is not None:
                    s.flag.a = _fold(_subst(s.flag.a, env))
                if s.flag.b is not None:
                    s.flag.b = _fold(_subst(s.flag.b, env))
        elif isinstance(s, ir.Intrinsic):
            s.args = [_fold(_subst(a, env)) for a in s.args]
            env.clear()          # may clobber memory
        elif isinstance(s, ir.Call):
            env.clear()


def optimize(func):
    for b in func.blocks.values():
        _opt_block(b)
    return func
