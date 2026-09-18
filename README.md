# startrekdec — a Kirk & Spock decompiler

`startrekdec` decompiles the firmware of the PSP's **Kirk** and **Spock** crypto
co-processors to readable pseudo-C. It is the Kirk/Spock analogue of
[`spudec`](https://github.com/zecoxao/spudec) (an SPU decompiler for IDA): IDA's
processor module is used purely as a *decoder*, and everything above it —
lifting, control-flow recovery and code generation — is ours.

Kirk and Spock are the two crypto engines in the PSP's Tachyon SoC. They share
one small, big-endian, **memory-to-memory** CPU core that ProximaV aptly named
the *"Star Trek PSP Processors"* — hence the name of this project. Kirk does
AES/SHA1/ECDSA/PRNG for the command interface; Spock handles UMD sector
crypto. Both ROMs decode with the same instruction set, so one tool covers both.

```
decoder → lifter → cfg → opt → structure → cgen
```

## What it produces

```c
void memcmp(void)
{
    R11 = &AES_RESULT;
    R12 = &DMA_BUF;
    R13 = 4;
    do {
        R12 = R12 - R11;
        if (R12 != 0) break;
        R11 = R11 + 4;
        R12 = R12 + 4;
        R13 = R13 - 4;
    } while (R13 != 0);
    return;
}
```

RAM cells become `u32` variables (Kirk MMIO registers keep their documented
names), `cmp`/`test` fold into relational `if`s, and loops are recovered as
`while` / `do-while`, with a correct `goto` fallback for anything that does not
fit a structured shape.

## Two ways to run it

**Headless (no IDA needed)** — decode a raw ROM dump directly:

```
python -m startrekdec kirk.bin -o kirk.c
python -m startrekdec spock.bin --func 0x1a60      # one function
```

**As an IDA plugin** — open the ROM with ProximaV's
[KIRK processor module](https://github.com/ProximaV/kirk), then drop
`startrekdec_plugin.py` **and** the `startrekdec/` package into
`%APPDATA%\Hex-Rays\IDA Pro\plugins\`:

| Hotkey | Action |
| --- | --- |
| `Ctrl-Shift-S` | decompile the function under the cursor |
| `Ctrl-F5` | decompile the whole database (and offer to save it) |

Inside IDA the decompilation reuses whatever names you have applied
(`PSP_KIRK_CMD`, `aes_encrypt_cbc`, `kirk_5`, …).

## The instruction set

32-bit big-endian, opcode in the top byte; data lives in RAM at
`RAMBASE = 0xE0000000`, addressed by 12-bit word fields:

```
opcode = (w >> 24) & 0xFF
addr1  = ((w >> 12) & 0xFFF) << 2 | RAMBASE      # first cell
addr2  = ( w        & 0xFFF) << 2 | RAMBASE      # second cell
branch = ( w        & 0xFFF) << 2                # code target
```

`startrekdec/isa.py` is the single source of truth and reconciles the three
public references, recording where they disagree rather than hiding it:

* [ProximaV/kirk](https://github.com/ProximaV/kirk) — `ana.cpp` (field
  extraction / instruction sizes) and `ins.cpp` (mnemonics)
* [LemonHaze420/ghidra_kirk](https://github.com/LemonHaze420/ghidra_kirk) —
  `kirk32.sinc` (p-code semantics)

Only `cmp*` / `suba` / `inc32` / `dec32` touch the Z/NG flags, so a conditional
branch resolves its condition against the nearest reaching compare. Opcodes whose
semantics are not public (`store2`, `op30`, `op38`, `op89`, `op8B`, `setmode`,
`intr`) are printed honestly as pseudo-calls rather than guessed.

## Limitations

* The core is scalar and memory-to-memory, so there is no SPU-style lane
  analysis; every cell is a 32-bit word (128-bit `mov128` becomes a `memcpy`).
* Irreducible or non-contiguous control flow falls back to `goto` + labels
  (always correct, occasionally ugly).
* Immediate operands that are really cell addresses are shown raw when running
  headless; inside IDA they pick up the offset/name you applied.

## Tests

```
python tests/test_pipeline.py
```

Builds a small program by hand, so it needs neither IDA nor a ROM dump: it
checks field extraction, that every opcode lifts, and that a hand-assembled
loop is recovered as a `do/while`.

## Credits

Built on the reverse-engineering of ProximaV, LemonHaze420 and the APE group who
dumped the Kirk ROM. Decompiler design mirrors zecoxao's `spudec`. The Kirk ROM
dumps themselves are **not** included in this repository.

MIT licensed.
