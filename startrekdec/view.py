"""
IDA custom viewer for startrekdec output.  Imported only inside IDA.

Lines are syntax-highlighted with :mod:`startrekdec.highlight`, and double-click
(or Enter) on a line that carries an address -- a function header, a ``loc_``
label, or a ``/* @0x... */`` declaration -- jumps the disassembly there.
"""

import re

import ida_kernwin
import idaapi

from . import highlight

_EA = re.compile(r"\b(?:loc_|sub_)([0-9A-Fa-f]+)\b|@\s*0x([0-9A-Fa-f]+)")


def _line_ea(line):
    m = _EA.search(line)
    if not m:
        return None
    try:
        return int(m.group(1) or m.group(2), 16)
    except (TypeError, ValueError):
        return None


class _Viewer(ida_kernwin.simplecustviewer_t):
    def __init__(self):
        super(_Viewer, self).__init__()
        self.line_ea = []

    def build(self, title, lines):
        if not ida_kernwin.simplecustviewer_t.Create(self, title):
            return False
        self.line_ea = []
        for ln in lines:
            self.AddLine(highlight.colorize(ln))
            self.line_ea.append(_line_ea(ln))
        return True

    def _jump(self):
        n = self.GetLineNo()
        if n is None or n >= len(self.line_ea):
            return False
        ea = self.line_ea[n]
        if ea is None:
            return False
        idaapi.jumpto(ea)
        return True

    def OnDblClick(self, shift):
        return self._jump()

    def OnKeydown(self, vkey, shift):
        if vkey == 13:            # Enter
            return self._jump()
        if vkey == 27:            # Esc
            self.Close()
            return True
        return False


def show(function):
    title = "startrekdec: %s" % (function.name or "sub_%X" % function.entry)
    v = _Viewer()
    if v.build(title, function.lines):
        v.Show()
        return v
    return None


def show_listing(title, lines):
    v = _Viewer()
    if v.build(title, lines):
        v.Show()
        return v
    return None
