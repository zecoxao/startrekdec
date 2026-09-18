"""
Minimal IDA custom viewer for startrekdec output.  Imported only inside IDA.
"""

import ida_kernwin


class _Viewer(ida_kernwin.simplecustviewer_t):
    def Create(self, title, lines):
        if not ida_kernwin.simplecustviewer_t.Create(self, title):
            return False
        for ln in lines:
            self.AddLine(ln)
        return True


def show(function):
    title = "startrekdec: %s" % (function.name or "sub_%X" % function.entry)
    v = _Viewer()
    if v.Create(title, function.lines):
        v.Show()
        return v
    return None


def show_listing(title, lines):
    v = _Viewer()
    if v.Create(title, lines):
        v.Show()
        return v
    return None
