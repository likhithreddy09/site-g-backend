"""Tiny HyperLogLog for counting distinct visitor sessions without storing them.

Registers live in a sparse sub-document ({"17": 3, ...}) and are merged with Mongo's `$max`,
so counting visitors costs no extra database operations. 1024 registers ≈ 3% standard error,
and small counts are effectively exact thanks to linear counting.
"""
import hashlib
import math

P = 10
M = 1 << P
_ALPHA = 0.7213 / (1 + 1.079 / M)


def register(value: str) -> tuple[str, int]:
    h = int.from_bytes(hashlib.blake2b(value.encode(), digest_size=8).digest(), "big")
    idx = h >> (64 - P)
    rest = h & ((1 << (64 - P)) - 1)
    rho = (64 - P) - rest.bit_length() + 1
    return str(idx), rho


def max_ops(values, prefix: str = "hll") -> dict:
    out: dict = {}
    for v in values:
        k, r = register(v)
        key = f"{prefix}.{k}"
        if r > out.get(key, 0):
            out[key] = r
    return out


def merge(*regs: dict | None) -> dict:
    out: dict = {}
    for r in regs:
        for k, v in (r or {}).items():
            if v > out.get(k, 0):
                out[k] = v
    return out


def estimate(regs: dict | None) -> int:
    regs = regs or {}
    if not regs:
        return 0
    z = (M - len(regs)) + sum(2.0 ** -v for v in regs.values())
    e = _ALPHA * M * M / z
    zeros = M - len(regs)
    if e <= 2.5 * M and zeros:
        e = M * math.log(M / zeros)
    return int(round(e))
