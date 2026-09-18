"""
Headless command-line front end:

    python -m startrekdec kirk.bin
    python -m startrekdec spock.bin -o spock.c --entry 0 --entry 4
    python -m startrekdec kirk.bin --func 0x1a60      # one function

No IDA required.
"""

import argparse
import sys

from . import decompile_file


def _parse_int(s):
    return int(s, 0)


def main(argv=None):
    argv = argv if argv is not None else sys.argv[1:]
    ap = argparse.ArgumentParser(prog="startrekdec",
                                 description="Decompile a PSP Kirk/Spock ROM to pseudo-C.")
    ap.add_argument("rom", help="raw Kirk/Spock ROM image (.bin)")
    ap.add_argument("-o", "--out", help="write listing to this file (default: stdout)")
    ap.add_argument("--entry", type=_parse_int, action="append", default=None,
                    help="extra entry point (repeatable); defaults to 0 and 4")
    ap.add_argument("--func", type=_parse_int, default=None,
                    help="only emit the function at this address")
    ap.add_argument("--no-banner", action="store_true", help="omit the file banner")
    args = ap.parse_args(argv)

    entries = tuple(args.entry) if args.entry else (0, 4)
    prog = decompile_file(args.rom, extra_entries=entries)

    if args.func is not None:
        f = prog.funcs.get(args.func)
        if f is None:
            ap.error("no function decoded at 0x%X (try --entry 0x%X)"
                     % (args.func, args.func))
        text = "\n".join((["\n".join(prog.listing(banner=True).splitlines()[:8])]
                          if not args.no_banner else []) + f.lines)
    else:
        text = prog.listing(banner=not args.no_banner)

    if args.out:
        with open(args.out, "w", encoding="utf-8") as fp:
            fp.write(text + "\n")
        print("startrekdec: wrote %d functions (%d lines) to %s"
              % (len(prog.funcs), text.count("\n") + 1, args.out), file=sys.stderr)
    else:
        print(text)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
