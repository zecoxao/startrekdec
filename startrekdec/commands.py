"""
Kirk domain knowledge: the crypto command numbers and the well-known
memory-mapped registers, used to annotate the decompiled output.

Command numbers follow the conventional Kirk list established by
libkirk / kirk_engine (Draan, Proxima) and psdevwiki.  The ROM's ``kirk_N``
handlers are dispatched from ``_start`` by comparing PSP_KIRK_CMD against N.
"""

# Kirk crypto command numbers (as dispatched by _start).
COMMAND_NAMES = {
    0x0: "KIRK_CMD_0 (reserved / null)",
    0x1: "KIRK_CMD_DECRYPT_PRIVATE (AES-CBC decrypt + ECDSA/CMAC verify, kbooti)",
    0x2: "KIRK_CMD_2 (encrypt-sign, per-console)",
    0x3: "KIRK_CMD_3 (decrypt-verify, per-console)",
    0x4: "KIRK_CMD_ENCRYPT_IV_0 (AES-CBC encrypt, static key, zero IV)",
    0x5: "KIRK_CMD_ENCRYPT_IV_FUSE (AES-CBC encrypt, per-console fuse key)",
    0x6: "KIRK_CMD_ENCRYPT_IV_USER (AES-CBC encrypt, user key/IV)",
    0x7: "KIRK_CMD_DECRYPT_IV_0 (AES-CBC decrypt, static key, zero IV)",
    0x8: "KIRK_CMD_DECRYPT_IV_FUSE (AES-CBC decrypt, per-console fuse key)",
    0x9: "KIRK_CMD_DECRYPT_IV_USER (AES-CBC decrypt, user key/IV)",
    0xA: "KIRK_CMD_PRIV_SIG_CHECK (CMAC signature check)",
    0xB: "KIRK_CMD_SHA1_HASH",
    0xC: "KIRK_CMD_ECDSA_GEN_KEYS",
    0xD: "KIRK_CMD_ECDSA_MULTIPLY_POINT",
    0xE: "KIRK_CMD_PRNG (pseudo-random number generation)",
    0xF: "KIRK_CMD_INIT (seed the PRNG)",
    0x10: "KIRK_CMD_ECDSA_SIGN",
    0x11: "KIRK_CMD_ECDSA_VERIFY",
    0x12: "KIRK_CMD_CERT_VERIFY",
}


# Well-known memory-mapped registers / globals, harvested from the annotated
# kirk.bin.i64.  Addresses are absolute RAM cell addresses (RAMBASE-based).
MMIO = {
    0xE0003880: "PSP_KIRK_REG",
    0xE0003884: "PSP_KIRK_STATUS",
    0xE0003888: "PSP_KIRK_PHASE",
    0xE00038C0: "PSP_KIRK_CMD",
    0xE00038CC: "PSP_KIRK_RESULT",
    0xE0003840: "DMA_BUF",
    0xE0003FFC: "kirk_semaphor",
    0xE0000E64: "AES_RESULT",
}


def command_note(index):
    return COMMAND_NAMES.get(index)
