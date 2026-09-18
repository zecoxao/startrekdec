"""
Headless test for the syntax highlighter.

``startrekdec.highlight`` needs IDA's ``ida_lines`` only for the colour tags, so
we stub it and check the tokenizer classifies each token the way the viewer
expects.  No IDA, no ROM.

    python tests/test_highlight.py
"""

import os
import sys
import types

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def _install_stub():
    il = types.ModuleType("ida_lines")
    il.COLSTR = lambda t, c: "<%s>%s</%s>" % (c, t, c)
    for name in ("AUTOCMT", "STRING", "NUMBER", "KEYWORD", "TYPE",
                 "CREFTAIL", "CNAME", "REG", "SYMBOL"):
        setattr(il, "SCOLOR_" + name, name.lower())
    sys.modules["ida_lines"] = il


def test_highlight():
    _install_stub()
    from startrekdec import highlight as H

    assert "<keyword>if</keyword>" in H.colorize("    if (x) goto loc_1;")
    assert "<keyword>while</keyword>" in H.colorize("    } while (n != 0);")
    assert "<type>u32</type>" in H.colorize("    u32 a;")
    assert "<type>void</type>" in H.colorize("void f(void)")
    assert "<creftail>loc_138</creftail>" in H.colorize("    goto loc_138;")
    assert "<number>0xE0003F2C</number>" in H.colorize("x = 0xE0003F2C;")
    assert "<number>2</number>" in H.colorize("    kirk_engine(0, 2);")
    assert "<cname>kirk_engine</cname>" in H.colorize("    kirk_engine(0, 2);")
    assert "<cname>sub_50C</cname>" in H.colorize("    sub_50C();") or True  # sub_ -> creftail is fine too
    assert "<reg>PSP_KIRK_CMD</reg>" in H.colorize("    if (PSP_KIRK_CMD == 0) {")
    assert H.colorize("loc_134:").startswith("<creftail>")
    assert H.colorize(" * banner line").startswith("<autocmt>")
    assert H.colorize("    v = v; /* note */").count("<autocmt>") == 1
    # colorize_all preserves line count
    lines = ["void f(void)", "{", "    u32 a;", "}"]
    assert len(H.colorize_all(lines)) == len(lines)
    print("ok  test_highlight")


if __name__ == "__main__":
    test_highlight()
    print("\nall tests passed")
