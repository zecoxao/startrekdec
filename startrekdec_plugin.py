"""
IDA plugin entry point for startrekdec, the Kirk/Spock decompiler front end.

Install by copying this file *and* the ``startrekdec`` package directory next to
each other into IDA's user plugin directory:

    %APPDATA%\\Hex-Rays\\IDA Pro\\plugins\\

It runs on a database opened with ProximaV's KIRK processor module
(https://github.com/ProximaV/kirk):

    Ctrl-Shift-S   decompile the function under the cursor
    Ctrl-F5        decompile every function in the database

The KIRK module decodes both the Kirk and Spock ROMs (they share one core), so
the same plugin handles ``kirk.bin`` and ``spock.bin``.
"""

import os
import sys
import time
import traceback

import ida_idaapi
import ida_idp
import ida_kernwin
import ida_funcs

_HERE = os.path.dirname(os.path.abspath(__file__))
if _HERE not in sys.path:
    sys.path.insert(0, _HERE)

HOTKEY_ONE = "Ctrl-Shift-S"
HOTKEY_ALL = "Ctrl-F5"

# ProximaV's KIRK module id (0x8000 + 0x1701); also matched by short name.
PLFM_KIRK = 0x9701

_views = []
_hotkeys = []


def _is_kirk():
    try:
        if ida_idp.ph_get_id() == PLFM_KIRK:
            return True
    except Exception:
        pass
    try:
        return ida_idp.get_idp_name().upper().startswith("KIRK")
    except Exception:
        return False


def _run_one():
    from startrekdec import ida_bridge, view
    if not _is_kirk():
        ida_kernwin.warning("startrekdec: this database is not a KIRK/Spock ROM.\n"
                            "Open it with ProximaV's KIRK processor module first.")
        return
    ea = ida_kernwin.get_screen_ea()
    if ida_funcs.get_func(ea) is None:
        ida_kernwin.warning("startrekdec: no function at 0x%X. Press 'P' to create one." % ea)
        return
    try:
        fn = ida_bridge.decompile_one(ea)
    except Exception:
        ida_kernwin.warning("startrekdec failed:\n\n%s" % traceback.format_exc())
        return
    v = view.show(fn)
    if v is not None:
        _views.append(v)
    print("startrekdec: %s -> %d blocks" % (fn.name, len(fn.cfg.blocks)))


def _run_all():
    from startrekdec import ida_bridge, view
    import ida_nalt
    if not _is_kirk():
        ida_kernwin.warning("startrekdec: this database is not a KIRK/Spock ROM.")
        return
    ida_kernwin.show_wait_box("startrekdec: decompiling all functions...")
    t0 = time.time()
    try:
        prog = ida_bridge.decompile_program()
    except Exception:
        ida_kernwin.hide_wait_box()
        ida_kernwin.warning("startrekdec: decompile all failed:\n\n%s" % traceback.format_exc())
        return
    finally:
        try:
            ida_kernwin.hide_wait_box()
        except Exception:
            pass
    lines = prog.listing().splitlines()
    print("startrekdec: %d functions in %.1fs" % (len(prog.funcs), time.time() - t0))

    default = os.path.splitext(ida_nalt.get_input_file_path() or "kirk")[0] + ".c"
    path = ida_kernwin.ask_file(True, default, "Save the decompiled listing")
    if path:
        try:
            with open(path, "w", encoding="utf-8") as fp:
                fp.write("\n".join(lines) + "\n")
            print("startrekdec: wrote %d lines to %s" % (len(lines), path))
        except Exception as exc:
            ida_kernwin.warning("startrekdec: could not write %s:\n%s" % (path, exc))
    v = view.show_listing("startrekdec - all functions", lines)
    if v is not None:
        _views.append(v)


class StarTrekDecPlugin(ida_idaapi.plugin_t):
    flags = 0
    comment = "Kirk/Spock crypto processor decompiler (lifter + SSA-lite + pseudo-C)"
    help = "%s decompiles the current function, %s decompiles everything." % (HOTKEY_ONE, HOTKEY_ALL)
    wanted_name = "Kirk/Spock decompiler (startrekdec)"
    wanted_hotkey = HOTKEY_ONE

    def init(self):
        if not _is_kirk():
            return ida_idaapi.PLUGIN_SKIP
        ctx = ida_kernwin.add_hotkey(HOTKEY_ALL, _run_all)
        if ctx is not None:
            _hotkeys.append(ctx)
        print("startrekdec: loaded -- %s = this function, %s = decompile all"
              % (HOTKEY_ONE, HOTKEY_ALL))
        return ida_idaapi.PLUGIN_KEEP

    def run(self, arg):
        _run_one()

    def term(self):
        for ctx in _hotkeys:
            try:
                ida_kernwin.del_hotkey(ctx)
            except Exception:
                pass
        del _hotkeys[:]
        del _views[:]


def PLUGIN_ENTRY():
    return StarTrekDecPlugin()
