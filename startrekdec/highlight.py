"""
C syntax highlighting for the startrekdec viewers.

Token-level, using IDA's own ``SCOLOR_*`` tags rather than fixed RGB so the
colours follow whatever theme the user has set (a dark theme does not end up
black-on-black).  Imported only inside IDA -- ``ida_lines`` is the sole IDA
dependency and there is no database access, so the tokenizer itself is pure.
"""

import re

import ida_lines

C_KEYWORDS = frozenset((
    "if", "else", "while", "do", "for", "return", "break", "continue",
    "goto", "switch", "case", "default", "sizeof", "typedef",
))

C_TYPES = frozenset((
    "void", "char", "short", "int", "long", "unsigned", "signed",
    "float", "double", "const", "struct", "union", "enum",
    # what this decompiler emits
    "u8", "u16", "u32", "u64",
))

# Pseudo-calls the back-end emits for opaque / crypto opcodes -- colour them as
# operations, not variables, even without a trailing '(' visible on the line.
INTRINSICS = frozenset((
    "kirk_engine", "setmode", "memcpy", "__bswap32",
    "store2", "op30", "op38", "op89", "op8B",
))

_TOK = re.compile(r"""
      (?P<comment>/\*.*?\*/|//.*)
    | (?P<string>"(?:[^"\\]|\\.)*")
    | (?P<hex>-?\b0[xX][0-9A-Fa-f]+)
    | (?P<num>-?\b\d+\b)
    | (?P<ident>[A-Za-z_$][A-Za-z_0-9$]*)
    | (?P<ws>\s+)
    | (?P<op>.)
""", re.VERBOSE)

_CALL_AHEAD = re.compile(r"\s*\(")
_LABEL = re.compile(r"^[A-Za-z_]\w*:\s*$")


def _tag(text, color):
    return ida_lines.COLSTR(text, color)


def colorize(line):
    """Return ``line`` with IDA colour tags around each token."""
    if not line:
        return line

    stripped = line.lstrip()
    # Whole-line and banner comments: skip the tokenizer.
    if stripped.startswith(("//", "/*", "*", "*/")):
        return _tag(line, ida_lines.SCOLOR_AUTOCMT)
    # A bare label line (loc_1234:) reads best as a code-ref tag.
    if _LABEL.match(stripped):
        return _tag(line, ida_lines.SCOLOR_CREFTAIL)

    out = []
    pos, n = 0, len(line)
    while pos < n:
        m = _TOK.match(line, pos)
        if m is None:
            out.append(line[pos])
            pos += 1
            continue
        kind = m.lastgroup
        text = m.group()
        pos = m.end()

        if kind == "ws":
            out.append(text)
        elif kind == "comment":
            out.append(_tag(text, ida_lines.SCOLOR_AUTOCMT))
        elif kind == "string":
            out.append(_tag(text, ida_lines.SCOLOR_STRING))
        elif kind in ("hex", "num"):
            out.append(_tag(text, ida_lines.SCOLOR_NUMBER))
        elif kind == "ident":
            out.append(_tag(text, _ident_color(text, line, pos)))
        else:
            out.append(_tag(text, ida_lines.SCOLOR_SYMBOL))
    return "".join(out)


def _ident_color(text, line, after):
    if text in C_KEYWORDS:
        return ida_lines.SCOLOR_KEYWORD
    if text in C_TYPES:
        return ida_lines.SCOLOR_TYPE
    if text.startswith(("loc_", "sub_", "def_", "jpt_")):
        return ida_lines.SCOLOR_CREFTAIL
    if text in INTRINSICS or _CALL_AHEAD.match(line, after):
        return ida_lines.SCOLOR_CNAME
    return ida_lines.SCOLOR_REG


def colorize_all(lines):
    return [colorize(ln) for ln in lines]
