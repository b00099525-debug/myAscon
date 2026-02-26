#!/usr/bin/env python3
"""
Node code (Academic IoT Research - Updated):
- Generates traffic of varying lengths
- Measures 5 metrics: Length, Criticality, Threat Level, CPU, RAM
- Converts each metric to a 1..4 star score
- Sums stars (max 20), converts to percentage
- Chooses security profile based on decimal-score bands
- Encrypts with Ascon using selected profile
- Mathematical Energy Estimation: E = P × t
    P_current = 3.0 + (3.0 × CPU/100)   [idle=3W, max=6W]
- Sends to gateway over UDP (JSON packet) with timestamp for Delay calculation
"""

from __future__ import annotations

import argparse
import json
import os
import random
import socket
import time
from dataclasses import dataclass
from typing import Literal, TypeAlias, Iterable

# -------------------- pyJoules (optional, not available on ARM) --------------------
# The mathematical energy model below replaces pyJoules for Raspberry Pi ARM targets.
# The import is kept so the code still works if pyJoules is installed on x86 hosts.
try:
    from pyJoules.energy_meter import EnergyMeter
    PYJOULES_AVAILABLE = True
except ImportError:
    PYJOULES_AVAILABLE = False
    print("Warning: pyJoules not installed / not supported on this platform. "
          "Using mathematical energy model (E = P × t) instead.")

# -------------------- Types --------------------

BytesLike: TypeAlias = bytes | bytearray | memoryview
AsconAeadVariant: TypeAlias = Literal["Ascon-128", "Ascon-128a", "Ascon-80pq"]
ProfileId: TypeAlias = Literal[1, 2, 3, 4]

# -------------------- Debug --------------------

debug = False
debugpermutation = False

# -------------------- AEAD Parameters --------------------

@dataclass(frozen=True)
class AeadParams:
    key_len: int
    nonce_len: int
    rate: int
    a: int
    b: int
    tag_len: int
    iv: bytes

AEAD_PARAMS: dict[AsconAeadVariant, AeadParams] = {
    "Ascon-128":  AeadParams(16, 16, 8, 12, 6, 16, bytes.fromhex("80400c0600000000")),
    "Ascon-128a": AeadParams(16, 16, 16, 12, 8, 16, bytes.fromhex("80800c0800000000")),
    "Ascon-80pq": AeadParams(20, 16, 8, 12, 6, 16, bytes.fromhex("a0400c06")),
}

@dataclass(frozen=True)
class SecurityProfile:
    name: str
    variant: AsconAeadVariant
    tag_len: int

SECURITY_PROFILES: dict[ProfileId, SecurityProfile] = {
    1: SecurityProfile("Lightweight (IoT)", "Ascon-128", 8),
    2: SecurityProfile("Standard (default)", "Ascon-128", 16),
    3: SecurityProfile("High Security", "Ascon-128a", 16),
    4: SecurityProfile("Critical / Long-Term", "Ascon-80pq", 16),
}

# -------------------- Mathematical Energy Estimation --------------------

IDLE_POWER_W  = 3.0   # Watts at 0% CPU
MAX_POWER_W   = 6.0   # Watts at 100% CPU
POWER_RANGE_W = MAX_POWER_W - IDLE_POWER_W   # = 3.0 W


def estimate_energy(cpu_percent: float, duration_s: float) -> tuple[float, float]:
    """
    Mathematical energy model: E = P × t
    P_current = 3.0 + (3.0 × CPU / 100)
    Returns (power_watts, energy_joules)
    """
    p_current = IDLE_POWER_W + (POWER_RANGE_W * (cpu_percent / 100.0))
    energy_j  = p_current * duration_s
    return p_current, energy_j


# -------------------- Metrics --------------------

LengthBand     = Literal["Short", "Normal", "Long", "Very Long"]
CriticalityLevel = Literal["Low", "Moderate", "High", "Critical"]
ThreatLevel    = Literal["Zero", "Low", "Moderate", "High"]


@dataclass(frozen=True)
class MetricScores:
    length_band: LengthBand
    length_bytes: int
    length_stars: int

    criticality: CriticalityLevel
    criticality_stars: int

    threat: ThreatLevel
    threat_stars: int

    cpu_percent: float
    cpu_stars: int

    ram_percent: float
    ram_stars: int

    sum_stars: int
    percent_score: int
    decimal_score: float


def _score_length(n: int) -> tuple[LengthBand, int]:
    if 0 <= n <= 64:   return ("Short", 4)
    if 65 <= n <= 254:  return ("Normal", 3)
    if 255 <= n <= 1024: return ("Long", 2)
    return ("Very Long", 1)


def _score_criticality(level: CriticalityLevel) -> int:
    return {"Low": 1, "Moderate": 2, "High": 3, "Critical": 4}[level]


def measure_threat_level() -> tuple[ThreatLevel, int]:
    try:
        import psutil
        conns = psutil.net_connections(kind='inet')
        suspicious_states = ('SYN_RECV', 'TIME_WAIT', 'CLOSE_WAIT')
        suspicious_count = sum(1 for c in conns if c.status in suspicious_states)
        total_count = len(conns)
        if suspicious_count > 30 or total_count > 150: return ("High", 1)
        elif suspicious_count > 15 or total_count > 75:  return ("Moderate", 2)
        elif suspicious_count > 5  or total_count > 30:  return ("Low", 3)
        else:                                             return ("Zero", 4)
    except Exception:
        return ("Zero", 4)


def _score_utilization(percent: float) -> int:
    if 0  <= percent < 25: return 4
    if 25 <= percent < 50: return 3
    if 50 <= percent < 75: return 2
    return 1


def measure_cpu_ram() -> tuple[float, float]:
    try:
        import psutil
        cpu = float(psutil.cpu_percent(interval=0.2))
        ram = float(psutil.virtual_memory().percent)
        return max(0.0, min(100.0, cpu)), max(0.0, min(100.0, ram))
    except Exception:
        return random.uniform(0, 60), random.uniform(10, 70)


def choose_security_profile(percent_score: int) -> ProfileId:
    percent_score = max(0, min(100, int(percent_score)))
    x = percent_score / 100.0
    if x < 0.4375: return 1
    if x < 0.625:  return 2
    if x < 0.8125: return 3
    return 4


def compute_metrics(payload_len: int) -> MetricScores:
    length_band, length_stars = _score_length(payload_len)

    criticality: CriticalityLevel = random.choice(["Low", "Moderate", "High", "Critical"])
    criticality_stars = _score_criticality(criticality)

    threat, threat_stars = measure_threat_level()

    cpu_percent, ram_percent = measure_cpu_ram()
    cpu_stars = _score_utilization(cpu_percent)
    ram_stars = _score_utilization(ram_percent)

    sum_stars     = length_stars + criticality_stars + threat_stars + cpu_stars + ram_stars
    percent_score = max(0, min(100, int(sum_stars * 5)))
    decimal_score = percent_score / 100.0

    return MetricScores(
        length_band=length_band,
        length_bytes=payload_len,
        length_stars=length_stars,
        criticality=criticality,
        criticality_stars=criticality_stars,
        threat=threat,
        threat_stars=threat_stars,
        cpu_percent=cpu_percent,
        cpu_stars=cpu_stars,
        ram_percent=ram_percent,
        ram_stars=ram_stars,
        sum_stars=sum_stars,
        percent_score=percent_score,
        decimal_score=decimal_score,
    )


# -------------------- Ascon Core --------------------

def ascon_encrypt(
    key: BytesLike,
    nonce: BytesLike,
    associateddata: BytesLike,
    plaintext: BytesLike,
    variant: AsconAeadVariant = "Ascon-128",
    tag_len: int | None = None,
) -> bytes:
    p = AEAD_PARAMS[variant]
    if tag_len is None:
        tag_len = p.tag_len
    assert len(key) == p.key_len
    assert len(nonce) == p.nonce_len
    assert 0 < tag_len <= 16
    S = [0, 0, 0, 0, 0]
    ascon_initialize(S, p, key, nonce)
    ascon_process_associated_data(S, p.b, p.rate, associateddata)
    ciphertext = ascon_process_plaintext(S, p.b, p.rate, plaintext)
    full_tag = ascon_finalize(S, p, key)
    return ciphertext + full_tag[:tag_len]


def ascon_decrypt(
    key: BytesLike,
    nonce: BytesLike,
    associateddata: BytesLike,
    ciphertext: BytesLike,
    variant: AsconAeadVariant = "Ascon-128",
    tag_len: int | None = None,
) -> bytes | None:
    p = AEAD_PARAMS[variant]
    if tag_len is None:
        tag_len = p.tag_len
    assert len(key) == p.key_len
    assert len(nonce) == p.nonce_len
    assert 0 < tag_len <= 16
    assert len(ciphertext) >= tag_len
    ct, tag = ciphertext[:-tag_len], ciphertext[-tag_len:]
    S = [0, 0, 0, 0, 0]
    ascon_initialize(S, p, key, nonce)
    ascon_process_associated_data(S, p.b, p.rate, associateddata)
    plaintext = ascon_process_ciphertext(S, p.b, p.rate, ct)
    full_tag = ascon_finalize(S, p, key)
    if full_tag[:tag_len] == tag:
        return plaintext
    return None


def ascon_initialize(S: list[int], p: AeadParams, key: BytesLike, nonce: BytesLike) -> None:
    iv_len = 24 - p.key_len
    assert len(p.iv) == iv_len, f"IV length mismatch: expected {iv_len}, got {len(p.iv)}"
    init = p.iv + to_bytes(key) + to_bytes(nonce)
    S[0], S[1], S[2], S[3], S[4] = bytes_to_state(init)
    if debug: printstate(S, "initial value:")
    ascon_permutation(S, p.a)
    buf = bytearray(state_to_bytes(S))
    off = 40 - p.key_len
    for i in range(p.key_len):
        buf[off + i] ^= key[i]
    S[0], S[1], S[2], S[3], S[4] = bytes_to_state(bytes(buf))
    if debug: printstate(S, "initialization:")


def ascon_process_associated_data(S: list[int], b: int, rate: int, associateddata: BytesLike) -> None:
    if len(associateddata) > 0:
        a_padding = to_bytes([0x01]) + zero_bytes(rate - (len(associateddata) % rate) - 1)
        a_padded  = to_bytes(associateddata) + a_padding
        for block in range(0, len(a_padded), rate):
            S[0] ^= bytes_to_int(a_padded[block:block + 8])
            if rate == 16:
                S[1] ^= bytes_to_int(a_padded[block + 8:block + 16])
            ascon_permutation(S, b)
    S[4] ^= 1 << 63
    if debug: printstate(S, "process associated data:")


def ascon_process_plaintext(S: list[int], b: int, rate: int, plaintext: BytesLike) -> bytes:
    p_lastlen = len(plaintext) % rate
    p_padding = to_bytes([0x01]) + zero_bytes(rate - p_lastlen - 1)
    p_padded  = to_bytes(plaintext) + p_padding
    ciphertext = b""
    for block in range(0, len(p_padded) - rate, rate):
        S[0] ^= bytes_to_int(p_padded[block:block + 8])
        if rate == 16:
            S[1] ^= bytes_to_int(p_padded[block + 8:block + 16])
            ciphertext += int_to_bytes(S[0], 8) + int_to_bytes(S[1], 8)
        else:
            ciphertext += int_to_bytes(S[0], 8)
        ascon_permutation(S, b)
    block = len(p_padded) - rate
    S[0] ^= bytes_to_int(p_padded[block:block + 8])
    if rate == 16:
        S[1] ^= bytes_to_int(p_padded[block + 8:block + 16])
        out = int_to_bytes(S[0], 8) + int_to_bytes(S[1], 8)
    else:
        out = int_to_bytes(S[0], 8)
    ciphertext += out[:p_lastlen]
    if debug: printstate(S, "process plaintext:")
    return ciphertext


def ascon_process_ciphertext(S: list[int], b: int, rate: int, ciphertext: BytesLike) -> bytes:
    c_lastlen = len(ciphertext) % rate
    c_padded  = to_bytes(ciphertext) + zero_bytes(rate - c_lastlen)
    plaintext = b""
    for block in range(0, len(c_padded) - rate, rate):
        c0 = bytes_to_int(c_padded[block:block + 8])
        if rate == 16:
            c1 = bytes_to_int(c_padded[block + 8:block + 16])
            plaintext += int_to_bytes(S[0] ^ c0, 8) + int_to_bytes(S[1] ^ c1, 8)
            S[0], S[1] = c0, c1
        else:
            plaintext += int_to_bytes(S[0] ^ c0, 8)
            S[0] = c0
        ascon_permutation(S, b)
    block = len(c_padded) - rate
    c0 = bytes_to_int(c_padded[block:block + 8])
    if rate == 16:
        c1  = bytes_to_int(c_padded[block + 8:block + 16])
        out = (int_to_bytes(S[0] ^ c0, 8) + int_to_bytes(S[1] ^ c1, 8))[:c_lastlen]
        plaintext += out
        c_padx = zero_bytes(c_lastlen) + to_bytes([0x01]) + zero_bytes(rate - c_lastlen - 1)
        c_mask = zero_bytes(c_lastlen) + ff_bytes(rate - c_lastlen)
        cm0, cm1 = c_mask[0:8], c_mask[8:16]
        px0, px1 = c_padx[0:8], c_padx[8:16]
        S[0] = (S[0] & bytes_to_int(cm0)) ^ c0 ^ bytes_to_int(px0)
        S[1] = (S[1] & bytes_to_int(cm1)) ^ c1 ^ bytes_to_int(px1)
    else:
        out = int_to_bytes(S[0] ^ c0, 8)[:c_lastlen]
        plaintext += out
        c_padx = zero_bytes(c_lastlen) + to_bytes([0x01]) + zero_bytes(rate - c_lastlen - 1)
        c_mask = zero_bytes(c_lastlen) + ff_bytes(rate - c_lastlen)
        S[0] = (S[0] & bytes_to_int(c_mask[0:8])) ^ c0 ^ bytes_to_int(c_padx[0:8])
    if debug: printstate(S, "process ciphertext:")
    return plaintext


def ascon_finalize(S: list[int], p: AeadParams, key: BytesLike) -> bytes:
    assert len(key) == p.key_len
    buf    = bytearray(state_to_bytes(S))
    pre_off = p.rate
    for i in range(p.key_len):
        if pre_off + i < 40:
            buf[pre_off + i] ^= key[i]
    S[0], S[1], S[2], S[3], S[4] = bytes_to_state(bytes(buf))
    ascon_permutation(S, p.a)
    buf      = bytearray(state_to_bytes(S))
    post_off = 40 - p.key_len
    for i in range(p.key_len):
        buf[post_off + i] ^= key[i]
    S[0], S[1], S[2], S[3], S[4] = bytes_to_state(bytes(buf))
    tag = int_to_bytes(S[3], 8) + int_to_bytes(S[4], 8)
    if debug: printstate(S, "finalization:")
    return tag


def ascon_permutation(S: list[int], rounds: int = 1) -> None:
    assert rounds <= 12
    if debugpermutation: printwords(S, "permutation input:")
    for r in range(12 - rounds, 12):
        S[2] ^= (0xF0 - r * 0x10 + r * 0x1)
        S[0] ^= S[4]; S[4] ^= S[3]; S[2] ^= S[1]
        T = [(S[i] ^ 0xFFFFFFFFFFFFFFFF) & S[(i + 1) % 5] for i in range(5)]
        for i in range(5): S[i] ^= T[(i + 1) % 5]
        S[1] ^= S[0]; S[0] ^= S[4]; S[3] ^= S[2]; S[2] ^= 0xFFFFFFFFFFFFFFFF
        S[0] ^= rotr(S[0], 19) ^ rotr(S[0], 28)
        S[1] ^= rotr(S[1], 61) ^ rotr(S[1], 39)
        S[2] ^= rotr(S[2], 1)  ^ rotr(S[2], 6)
        S[3] ^= rotr(S[3], 10) ^ rotr(S[3], 17)
        S[4] ^= rotr(S[4], 7)  ^ rotr(S[4], 41)


# -------------------- Helpers --------------------

def get_random_bytes(num: int) -> bytes:
    return os.urandom(num)

def zero_bytes(n: int) -> bytes:
    return n * b"\x00"

def ff_bytes(n: int) -> bytes:
    return n * b"\xFF"

def to_bytes(l: BytesLike | Iterable[int]) -> bytes:
    return bytes(l)

def bytes_to_int(b: BytesLike) -> int:
    return int.from_bytes(b, "little")

def bytes_to_state(b: bytes) -> list[int]:
    assert len(b) == 40, f"state must be 40 bytes, got {len(b)}"
    return [bytes_to_int(b[8 * w:8 * (w + 1)]) for w in range(5)]

def state_to_bytes(S: list[int]) -> bytes:
    return b"".join(int_to_bytes(w, 8) for w in S)

def int_to_bytes(integer: int, nbytes: int) -> bytes:
    return integer.to_bytes(nbytes, "little")

def rotr(val: int, r: int) -> int:
    return (val >> r) | ((val & ((1 << r) - 1)) << (64 - r))

def bytes_to_hex(b: bytes) -> str:
    return b.hex()

def hex_to_bytes(s: str) -> bytes:
    return bytes.fromhex(s)

def printstate(S: list[int], description: str = "") -> None:
    print(" " + description)
    print(" ".join(["{s:016x}".format(s=s) for s in S]))

def printwords(S: list[int], description: str = "") -> None:
    print(" " + description)
    print("\n".join(["  x{i}={s:016x}".format(**locals()) for i, s in enumerate(S)]))


# -------------------- Traffic generation --------------------

def generate_payload(length_mode: str) -> bytes:
    if length_mode.startswith("fixed:"):
        n = int(length_mode.split(":", 1)[1])
        return get_random_bytes(max(0, n))
    mode = length_mode.lower().strip()
    if mode == "short":                                  n = random.randint(0, 64)
    elif mode == "normal":                               n = random.randint(65, 254)
    elif mode == "long":                                 n = random.randint(255, 1024)
    elif mode in ("verylong", "very_long", "very-long"): n = random.randint(1025, 2048)
    else:
        choice = random.choice(["short", "normal", "long", "verylong"])
        return generate_payload(choice)
    return get_random_bytes(n)


# -------------------- Keying model (pre-shared) --------------------

def derive_node_master_key(node_id: str) -> bytes:
    seed = (node_id + "|research-master-key").encode("utf-8")
    raw  = bytearray(20)
    acc  = 0
    for i in range(20):
        acc    = (acc + seed[i % len(seed)] + (i * 31)) % 256
        raw[i] = acc
    return bytes(raw)


def profile_key_from_master(master20: bytes, profile: ProfileId) -> bytes:
    if profile == 4:
        return master20
    return master20[:16]


# -------------------- Packet build & send --------------------

def build_packet(
    node_id: str,
    seq: int,
    associated_data: bytes,
    payload: bytes,
) -> dict:
    """
    Build and return the full packet dict (without sending).
    Mirrors the original API so callers that use build_packet() directly continue to work.
    Energy estimation is included in the returned dict under 'energy'.
    """
    metrics = compute_metrics(len(payload))
    profile = choose_security_profile(metrics.percent_score)
    sp      = SECURITY_PROFILES[profile]
    p       = AEAD_PARAMS[sp.variant]

    master = derive_node_master_key(node_id)
    key    = profile_key_from_master(master, profile)
    nonce  = get_random_bytes(p.nonce_len)

    # ---- Mathematical Energy Estimation: E = P × t ----
    enc_start = time.perf_counter()
    ciphertext_and_tag = ascon_encrypt(
        key=key,
        nonce=nonce,
        associateddata=associated_data,
        plaintext=payload,
        variant=sp.variant,
        tag_len=sp.tag_len,
    )
    enc_end     = time.perf_counter()
    enc_time_s  = enc_end - enc_start
    enc_time_us = enc_time_s * 1_000_000

    power_w, energy_j = estimate_energy(metrics.cpu_percent, enc_time_s)
    energy_uj = energy_j * 1_000_000

    pri_raw  = metrics.length_stars + metrics.criticality_stars
    pri_norm = pri_raw / 8.0

    pkt = {
        "type": "ascon_node_msg",
        "node_id": node_id,
        "seq": seq,
        "ts": time.time(),
        "metrics": {
            "length_bytes":       metrics.length_bytes,
            "length_band":        metrics.length_band,
            "length_stars":       metrics.length_stars,
            "criticality":        metrics.criticality,
            "criticality_stars":  metrics.criticality_stars,
            "threat":             metrics.threat,
            "threat_stars":       metrics.threat_stars,
            "cpu_percent":        round(metrics.cpu_percent, 2),
            "cpu_stars":          metrics.cpu_stars,
            "ram_percent":        round(metrics.ram_percent, 2),
            "ram_stars":          metrics.ram_stars,
            "sum_stars":          metrics.sum_stars,
            "percent_score":      metrics.percent_score,
            "decimal_score":      metrics.decimal_score,
        },
        "priority_norm": pri_norm,
        "security": {
            "profile_id":   profile,
            "profile_name": sp.name,
            "variant":      sp.variant,
            "tag_len":      sp.tag_len,
        },
        "ad_hex":    associated_data.hex(),
        "nonce_hex": nonce.hex(),
        "ct_hex":    ciphertext_and_tag.hex(),
        # Energy estimation results (not a metric — reporting only)
        "energy": {
            "model":           "E = P_current × t_encrypt",
            "idle_power_w":    IDLE_POWER_W,
            "max_power_w":     MAX_POWER_W,
            "cpu_percent":     round(metrics.cpu_percent, 2),
            "power_w":         round(power_w, 6),
            "enc_time_s":      round(enc_time_s, 9),
            "enc_time_us":     round(enc_time_us, 4),
            "energy_j":        round(energy_j, 9),
            "energy_uj":       round(energy_uj, 6),
        },
    }
    return pkt


def build_and_send_packet(
    sock: socket.socket,
    gateway_addr: tuple[str, int],
    node_id: str,
    seq: int,
    associated_data: bytes,
    payload: bytes,
) -> None:
    """
    Build packet via build_packet(), transmit it, then print metrics to terminal.
    """
    pkt = build_packet(node_id, seq, associated_data, payload)
    raw = json.dumps(pkt).encode("utf-8")
    sock.sendto(raw, gateway_addr)

    e       = pkt["energy"]
    m       = pkt["metrics"]
    sec     = pkt["security"]
    pr      = pkt["priority_norm"]

    print(
        f"[Node {node_id}] Seq={seq:04d} | "
        f"Profile={sec['profile_id']} ({sec['profile_name']}) | "
        f"Variant={sec['variant']} | "
        f"Payload={m['length_bytes']}B ({m['length_band']}) | "
        f"Stars={m['sum_stars']}/20 ({m['percent_score']}%) | "
        f"Prio={pr:.3f}"
    )
    print(
        f"  Metrics → Length:{m['length_stars']}★ "
        f"Crit:{m['criticality_stars']}★ ({m['criticality']}) "
        f"Threat:{m['threat_stars']}★ ({m['threat']}) "
        f"CPU:{m['cpu_stars']}★ ({m['cpu_percent']:.1f}%) "
        f"RAM:{m['ram_stars']}★ ({m['ram_percent']:.1f}%)"
    )
    print(
        f"  ⚡ Energy Consumed: "
        f"P_current={e['power_w']:.4f} W | "
        f"Enc_time={e['enc_time_us']:.2f} µs | "
        f"Energy={e['energy_j']:.9f} J  ({e['energy_uj']:.4f} µJ)"
    )
    print(f"  Packet size (wire): {len(raw)} bytes")
    print()


# -------------------- Main --------------------

def main() -> None:
    ap = argparse.ArgumentParser(description="IoT Node – Ascon Sender with Mathematical Energy Estimation")
    ap.add_argument("--node-id",       default="node1")
    ap.add_argument("--gateway-host",  default="127.0.0.1")
    ap.add_argument("--gateway-port",  type=int, default=9999)
    ap.add_argument("--count",         type=int, default=20,
                    help="Number of packets to send (0 = infinite)")
    ap.add_argument("--interval",      type=float, default=1.0,
                    help="Seconds between packets")
    ap.add_argument("--length-mode",   default="random",
                    help="short | normal | long | verylong | random | fixed:<N>")
    ap.add_argument("--ad",            default="header",
                    help="Associated data string (authenticated but not encrypted)")
    args = ap.parse_args()

    sock          = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    gateway_addr  = (args.gateway_host, args.gateway_port)
    associated_data = args.ad.encode("utf-8")

    print(f"[node] id={args.node_id}  gateway={args.gateway_host}:{args.gateway_port}")
    print(f"[node] count={args.count}  interval={args.interval}s  length_mode={args.length_mode}")
    print(f"[node] Energy model: P_idle={IDLE_POWER_W}W  P_max={MAX_POWER_W}W")
    print(f"[node] Formula: P_current = {IDLE_POWER_W} + ({POWER_RANGE_W} × CPU/100)")
    print()

    seq       = 0
    infinite  = (args.count == 0)

    try:
        while infinite or seq < args.count:
            payload = generate_payload(args.length_mode)
            build_and_send_packet(
                sock=sock,
                gateway_addr=gateway_addr,
                node_id=args.node_id,
                seq=seq,
                associated_data=associated_data,
                payload=payload,
            )
            seq += 1
            if infinite or seq < args.count:
                time.sleep(args.interval)
    except KeyboardInterrupt:
        print("\n[node] Interrupted by user.")
    finally:
        sock.close()
        print(f"[node] Done. Total packets sent: {seq}")


if __name__ == "__main__":
    main()
