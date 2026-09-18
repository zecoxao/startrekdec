"""
Control-flow graph: carve the decoded instruction stream into functions and
basic blocks, lift each block to IR, and resolve branch conditions against the
reaching flag definition.
"""

from . import ir
from .lifter import lift_insn
from .isa import K


class Block:
    __slots__ = ("start", "insns", "stmts", "succ", "term")

    def __init__(self, start):
        self.start = start
        self.insns = []      # decoder.Insn
        self.stmts = []      # ir.Stmt
        self.succ = []       # list of (kind, target_ea): "jump"/"fall"/"cond"
        self.term = None     # "goto"/"branch"/"ret"/"fall"

    def __repr__(self):
        return "<Block %04X n=%d %s>" % (self.start, len(self.insns), self.term)


class Func:
    __slots__ = ("entry", "blocks", "calls", "name")

    def __init__(self, entry):
        self.entry = entry
        self.blocks = {}     # start_ea -> Block
        self.calls = set()
        self.name = None

    def ordered(self):
        return [self.blocks[k] for k in sorted(self.blocks)]


def _intra_succ(ins):
    """Successors that stay inside a function (calls excluded)."""
    k = ins.kind
    if k == K.BRA:
        return [("jump", ins.branch)]
    if k == K.BCC:
        return [("cond", ins.branch), ("fall", ins.ea + ins.size)]
    if k == K.RET:
        return []
    if k == K.CALL:
        return [("fall", ins.ea + ins.size)]
    return [("fall", ins.ea + ins.size)]


def _collect_body(insns, entry, entry_set):
    """Instruction addresses reachable from *entry* without entering another
    function.  A jump/fall into a different function entry is left as an
    external edge and not traversed."""
    body = set()
    work = [entry]
    while work:
        ea = work.pop()
        if ea in body or ea not in insns:
            continue
        body.add(ea)
        ins = insns[ea]
        for how, tgt in _intra_succ(ins):
            if tgt in insns and (tgt == entry or tgt not in entry_set):
                work.append(tgt)
    return body


def _leaders(insns, body):
    leaders = set()
    for ea in body:
        ins = insns[ea]
        if ins.kind in (K.BRA, K.BCC):
            if ins.branch in body:
                leaders.add(ins.branch)
        if ins.kind == K.BCC or ins.kind == K.CALL:
            nxt = ins.ea + ins.size
            if nxt in body:
                leaders.add(nxt)
        # instruction following an unconditional terminator starts a block
        if ins.kind in (K.BRA, K.RET):
            nxt = ins.ea + ins.size
            if nxt in body:
                leaders.add(nxt)
    return leaders


def build_func(insns, entry, entry_set):
    body = _collect_body(insns, entry, entry_set)
    if not body:
        return None
    leaders = _leaders(insns, body)
    leaders.add(entry)

    f = Func(entry)
    ordered = sorted(body)
    cur = None
    for ea in ordered:
        ins = insns[ea]
        if ea in leaders or cur is None:
            cur = Block(ea)
            f.blocks[ea] = cur
        cur.insns.append(ins)
        # terminate the block on control flow or just before the next leader
        nxt = ins.ea + ins.size
        term = None
        if ins.kind == K.BRA:
            term = ("goto", [("jump", ins.branch)])
        elif ins.kind == K.BCC:
            term = ("branch", [("cond", ins.branch), ("fall", nxt)])
        elif ins.kind == K.RET:
            term = ("ret", [])
        elif nxt in leaders or nxt not in body:
            term = ("fall", [("fall", nxt)] if nxt in body else [])
        if term is not None:
            cur.term, cur.succ = term
            cur = None

    # lift + collect calls
    for b in f.blocks.values():
        for ins in b.insns:
            if ins.kind == K.CALL and ins.branch is not None:
                f.calls.add(ins.branch)
            b.stmts.extend(lift_insn(ins))

    _resolve_flags(f)
    return f


def _resolve_flags(f):
    """Attach the reaching FlagDef to every conditional Branch.

    Flags are almost always set within the same block just before the branch;
    for a branch that leads a block we take the unique predecessor's exit flag.
    """
    flag_out = {}   # block.start -> FlagDef or None

    def scan(block, incoming):
        cur = incoming
        for s in block.stmts:
            if isinstance(s, (ir.Compare, ir.SetFlag)):
                cur = s.flag
            elif isinstance(s, ir.Assign) and s.flag is not None:
                cur = s.flag
            elif isinstance(s, ir.Branch):
                s.flag = cur
        return cur

    # single pass in address order, then a fixpoint for cross-block flags
    preds = {}
    for b in f.blocks.values():
        for _, tgt in b.succ:
            preds.setdefault(tgt, []).append(b.start)

    for _ in range(4):
        changed = False
        for b in f.ordered():
            pl = preds.get(b.start, [])
            incoming = None
            if len(pl) == 1:
                incoming = flag_out.get(pl[0])
            out = scan(b, incoming)
            if flag_out.get(b.start) is not out:
                flag_out[b.start] = out
                changed = True
        if not changed:
            break


def build_functions(insns, calls, extra_entries=()):
    entry_set = set(calls) | set(extra_entries)
    entry_set = {e for e in entry_set if e in insns}
    funcs = {}
    for entry in sorted(entry_set):
        f = build_func(insns, entry, entry_set)
        if f is not None:
            funcs[entry] = f
    return funcs
