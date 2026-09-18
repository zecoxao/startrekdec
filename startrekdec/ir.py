"""
Intermediate representation for the Kirk/Spock decompiler.

The core is a memory-to-memory machine: every operand is a 32-bit RAM cell, so
the IR's only "variables" are cells (:class:`Var`).  Expressions are built up by
the optimiser inlining single-use cell definitions; the lifter emits flat
three-address code.

Flag handling is explicit.  Only ``cmp*``/``suba``/``inc32``/``dec32`` affect the
Z/NG flags (logical ops touch only C/V per kirk32.sinc), so a conditional branch
resolves its condition against the nearest reaching :class:`FlagDef`, letting the
back-end print ``if (a == b)`` instead of an opaque flag.
"""


# ---------------------------------------------------------------------------
# expressions
# ---------------------------------------------------------------------------

class Expr:
    pass


class Const(Expr):
    __slots__ = ("value",)

    def __init__(self, value):
        self.value = value & 0xFFFFFFFF

    def __eq__(self, o):
        return isinstance(o, Const) and o.value == self.value

    def __hash__(self):
        return hash(("const", self.value))


class Var(Expr):
    """A RAM cell, identified by its absolute address."""
    __slots__ = ("addr", "width")

    def __init__(self, addr, width=4):
        self.addr = addr
        self.width = width

    def __eq__(self, o):
        return isinstance(o, Var) and o.addr == self.addr

    def __hash__(self):
        return hash(("var", self.addr))


class Bin(Expr):
    __slots__ = ("op", "l", "r")

    def __init__(self, op, l, r):
        self.op = op
        self.l = l
        self.r = r


class Un(Expr):
    __slots__ = ("op", "e")

    def __init__(self, op, e):
        self.op = op
        self.e = e


class IntrExpr(Expr):
    """An intrinsic used as a value (e.g. byteswap)."""
    __slots__ = ("name", "args")

    def __init__(self, name, args):
        self.name = name
        self.args = args


# ---------------------------------------------------------------------------
# flag descriptors
# ---------------------------------------------------------------------------

class FlagDef:
    """
    What set the flags most recently.

    kind == "cmp"    : Z = (a == b), NG = (a > b) signed     (a,b unmodified)
    kind == "result" : Z = (res == 0), NG = (res > 0) signed (res = a in cell)
    kind == "z"      : Z forced to a constant (clrz/setz), NG unknown
    """
    __slots__ = ("kind", "a", "b", "zval")

    def __init__(self, kind, a=None, b=None, zval=None):
        self.kind = kind
        self.a = a
        self.b = b
        self.zval = zval


# ---------------------------------------------------------------------------
# statements
# ---------------------------------------------------------------------------

class Stmt:
    __slots__ = ("ea",)


class Assign(Stmt):
    __slots__ = ("ea", "dst", "src", "flag")

    def __init__(self, ea, dst, src, flag=None):
        self.ea = ea
        self.dst = dst          # Var
        self.src = src          # Expr
        self.flag = flag        # FlagDef or None (side effect on flags)


class Compare(Stmt):
    """A compare that only touches flags (no cell written)."""
    __slots__ = ("ea", "flag")

    def __init__(self, ea, flag):
        self.ea = ea
        self.flag = flag


class SetFlag(Stmt):
    """clrz / setz."""
    __slots__ = ("ea", "flag")

    def __init__(self, ea, flag):
        self.ea = ea
        self.flag = flag


class Call(Stmt):
    __slots__ = ("ea", "target")

    def __init__(self, ea, target):
        self.ea = ea
        self.target = target


class Intrinsic(Stmt):
    """A modelled-but-opaque operation printed as a pseudo-call."""
    __slots__ = ("ea", "name", "args", "note")

    def __init__(self, ea, name, args, note=""):
        self.ea = ea
        self.name = name
        self.args = args
        self.note = note


class Ret(Stmt):
    __slots__ = ("ea",)

    def __init__(self, ea):
        self.ea = ea


class Goto(Stmt):
    __slots__ = ("ea", "target")

    def __init__(self, ea, target):
        self.ea = ea
        self.target = target


class Branch(Stmt):
    """Conditional branch.  ``cond`` is one of z/nz/gt/lt; ``flag`` is the
    resolved reaching FlagDef (filled by the flag pass)."""
    __slots__ = ("ea", "cond", "target", "fallthrough", "flag")

    def __init__(self, ea, cond, target, fallthrough):
        self.ea = ea
        self.cond = cond
        self.target = target
        self.fallthrough = fallthrough
        self.flag = None


class Nop(Stmt):
    __slots__ = ("ea",)

    def __init__(self, ea):
        self.ea = ea
