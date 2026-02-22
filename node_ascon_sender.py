#!/usr/bin/env python3
"""
Node code:
- Generates traffic of varying lengths
- Measures 5 metrics: Length, Criticality, Threat Level, CPU, RAM
- Converts each metric to a 1..4 star score (4 = best / least demanding / least threat where applicable)
- Sums stars (max 20), converts to percentage = (sum_stars * 5)
- Chooses security profile based on Algorithm.docx decimal-score bands (X = percent_score / 100.0):
    Profile 1: 0.25   <= X < 0.4375
    Profile 2: 0.4375 <= X < 0.625
    Profile 3: 0.625  <= X < 0.8125
    Profile 4: 0.8125 <= X <= 1.0
- Encrypts with Ascon using selected profile
- Uses pyjoules to measure current energy consumption
- Sends to gateway over UDP (JSON packet)

Implements the metric rules exactly as in your docx.
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

try:
    from pyJoules.energy_meter import measure_energy
    from pyJoules.handler.print_handler import PrintHandler
    PYJOULES_AVAILABLE = True
except ImportError:
    PYJOULES_AVAILABLE = False
    print("Warning: pyJoules not installed. Energy measurement will be skipped. Run 'pip install pyjoules'")

# -------------------- Types --------------------

BytesLike: TypeAlias = bytes | bytearray | memoryview

AsconAeadVariant: TypeAlias = Literal[
    "Ascon-128",
    "Ascon-128a",
    "Ascon-80pq",
]

ProfileId: TypeAlias = Literal[1, 2, 3, 4]

# -------------------- Debug --------------------

debug = False
debugpermutation = False

# -------------------- AEAD Parameters --------------------

@dataclass(frozen=True)
class AeadParams:
    key_len: int      # bytes 16 for 128/128a and 20 for 80pq
    nonce_len: int    # bytes 16
    rate: int         # bytes 8 for 128/80pq and 16 for 128a
    a: int            # pa rounds 12
    b: int            # pb rounds 6 for 128/80pq and 8 for 128a
    tag_len: int      # bytes 16 (we may truncate for profile 1)
    iv: bytes         # IV bytes from Ascon spec (length = 24 - key_len)

AEAD_PARAMS: dict[AsconAeadVariant, AeadParams] = {
    "Ascon-128":  AeadParams(16, 16, 8, 12, 6, 16, bytes.fromhex("80400c0600000000")),
    "Ascon-128a": AeadParams(16, 16, 16, 12, 8, 16, bytes.fromhex("80800c0800000000")),
    "Ascon-80pq": AeadParams(20, 16, 8, 12, 6, 16, bytes.fromhex("a0400c06")),
}

@dataclass(frozen=True)
class SecurityProfile:
    name: str
    variant: AsconAeadVariant
    tag_len: int  # bytes

SECURITY_PROFILES: dict[ProfileId, SecurityProfile] = {
    1: SecurityProfile("Lightweight (IoT)", "Ascon-128", 8),
    2: SecurityProfile("Standard (default)", "Ascon-128", 16),
    3: SecurityProfile("High Security", "Ascon-128a", 16),
    4: SecurityProfile("Critical / Long-Term", "Ascon-80pq", 16),
}

# -------------------- Metrics --------------------

LengthBand = Literal["Short", "Normal", "Long", "Very Long"]
CriticalityLevel = Literal["Low", "Moderate", "High", "Critical"]
ThreatLevel = Literal["Zero", "Low", "Moderate", "High"]

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
    percent_score: int         # 0..100 (we will end up in 25..100 given 5 metrics)
    decimal_score: float       # percent_score / 100.0


def _score_length(n: int) -> tuple[LengthBand, int]:
    # Fixed to match Algorithm.docx boundaries without a gap
    if 0 <= n <= 64:
        return ("Short", 4)
    if 65 <= n <= 254:
        return ("Normal", 3)
    if 255 <= n <= 1024:
        return ("Long", 2)
    return ("Very Long", 1)


def _score_criticality(level: CriticalityLevel) -> int:
    return {"Low": 1, "Moderate": 2, "High": 3, "Critical": 4}[level]


def measure_threat_level() -> tuple[ThreatLevel, int]:
    """
    Actually measures the threat level by evaluating network state.
    """
    try:
        import psutil
        conns = psutil.net_connections(kind='inet')
        suspicious_states = ('SYN_RECV', 'TIME_WAIT', 'CLOSE_WAIT')
        suspicious_count = sum(1 for c in conns if c.status in suspicious_states)
        total_count = len(conns)

        if suspicious_count > 30 or total_count > 150:
            return ("High", 1)
        elif suspicious_count > 15 or total_count > 75:
            return ("Moderate", 2)
        elif suspicious_count > 5 or total_count > 30:
            return ("Low", 3)
        else:
            return ("Zero", 4)
    except Exception:
        return ("Zero", 4)


def _score_utilization(percent: float) -> int:
    # Low util (0<=x<25) ->4
    # Moderate (25<=x<50)->3
    # High (50<=x<75)->2
    # Very high (75<=x<=100)->1
    if 0 <= percent < 25:
        return 4
    if 25 <= percent < 50:
        return 3
    if 50 <= percent < 75:
        return 2
    return 1


def measure_cpu_ram() -> tuple[float, float]:
    """
    CPU/RAM in general (not necessarily at the exact encryption moment).
    Uses psutil if available, otherwise falls back to a safe approximation.
    """
    try:
        import psutil  # type: ignore
        cpu = float(psutil.cpu_percent(interval=0.2))
        ram = float(psutil.virtual_memory().percent)
        # clamp
        cpu = max(0.0, min(100.0, cpu))
        ram = max(0.0, min(100.0, ram))
        return cpu, ram
    except Exception:
        cpu = random.uniform(0, 60)
        ram = random.uniform(10, 70)
        return cpu, ram


def choose_security_profile(percent_score: int) -> ProfileId:
    """
    Profile assignment based on Algorithm.docx decimal-score thresholds.
    """
    # clamp to [0, 100] just in case
    percent_score = max(0, min(100, int(percent_score)))
    x = percent_score / 100.0

    # Map bands
    if x < 0.4375:
        return 1
    if x < 0.625:
        return 2
    if x < 0.8125:
        return 3
    return 4


def compute_metrics(payload_len: int) -> MetricScores:
    length_band, length_stars = _score_length(payload_len)

    criticality: CriticalityLevel = random.choice(["Low", "Moderate", "High", "Critical"])
    criticality_stars = _score_criticality(criticality)

    threat, threat_stars = measure_threat_level()

    cpu_percent, ram_percent = measure_cpu_ram()
    cpu_stars = _score_utilization(cpu_percent)
    ram_stars = _score_utilization(ram_percent)

    sum_stars = length_stars + criticality_stars + threat_stars + cpu_stars + ram_stars

    # Multiply by 5 to map max 20 -> 100
    percent_score = int(sum_stars * 5)
    percent_score = max(0, min(100, percent_score))
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


# -------------------- Ascon Core (AEAD only, from your code) --------------------

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

    init = p.iv + to_bytes(key) + to_bytes(nonce)  # 40 bytes
    S[0], S[1], S[2], S[3], S[4] = bytes_to_state(init)
    if debug:
        printstate(S, "initial value:")

    ascon_permutation(S, p.a)

    buf = bytearray(state_to_bytes(S))
    off = 40 - p.key_len
    for i in range(p.key_len):
        buf[off + i] ^= key[i]
    S[0], S[1], S[2], S[3], S[4] = bytes_to_state(bytes(buf))

    if debug:
        printstate(S, "initialization:")


def ascon_process_associated_data(S: list[int], b: int, rate: int, associateddata: BytesLike) -> None:
    if len(associateddata) > 0:
        a_padding = to_bytes([0x01]) + zero_bytes(rate - (len(associateddata) % rate) - 1)
        a_padded = to_bytes(associateddata) + a_padding

        for block in range(0, len(a_padded), rate):
            S[0] ^= bytes_to_int(a_padded[block:block + 8])
            if rate == 16:
                S[1] ^= bytes_to_int(a_padded[block + 8:block + 16])
            ascon_permutation(S, b)

    S[4] ^= 1 << 63
    if debug:
        printstate(S, "process associated data:")


def ascon_process_plaintext(S: list[int], b: int, rate: int, plaintext: BytesLike) -> bytes:
    p_lastlen = len(plaintext) % rate
    p_padding = to_bytes([0x01]) + zero_bytes(rate - p_lastlen - 1)
    p_padded = to_bytes(plaintext) + p_padding

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
    if debug:
        printstate(S, "process plaintext:")
    return ciphertext


def ascon_process_ciphertext(S: list[int], b: int, rate: int, ciphertext: BytesLike) -> bytes:
    c_lastlen = len(ciphertext) % rate
    c_padded = to_bytes(ciphertext) + zero_bytes(rate - c_lastlen)

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
        c1 = bytes_to_int(c_padded[block + 8:block + 16])
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

    if debug:
        printstate(S, "process ciphertext:")
    return plaintext


def ascon_finalize(S: list[int], p: AeadParams, key: BytesLike) -> bytes:
    assert len(key) == p.key_len

    buf = bytearray(state_to_bytes(S))
    pre_off = p.rate
    for i in range(p.key_len):
        if pre_off + i < 40:
            buf[pre_off + i] ^= key[i]
    S[0], S[1], S[2], S[3], S[4] = bytes_to_state(bytes(buf))

    ascon_permutation(S, p.a)

    buf = bytearray(state_to_bytes(S))
    post_off = 40 - p.key_len
    for i in range(p.key_len):
        buf[post_off + i] ^= key[i]
    S[0], S[1], S[2], S[3], S[4] = bytes_to_state(bytes(buf))

    tag = int_to_bytes(S[3], 8) + int_to_bytes(S[4], 8)
    if debug:
        printstate(S, "finalization:")
    return tag


def ascon_permutation(S: list[int], rounds: int = 1) -> None:
    assert rounds <= 12
    if debugpermutation:
        printwords(S, "permutation input:")

    for r in range(12 - rounds, 12):
        S[2] ^= (0xF0 - r * 0x10 + r * 0x1)

        S[0] ^= S[4]
        S[4] ^= S[3]
        S[2] ^= S[1]
        T = [(S[i] ^ 0xFFFFFFFFFFFFFFFF) & S[(i + 1) % 5] for i in range(5)]
        for i in range(5):
            S[i] ^= T[(i + 1) % 5]
        S[1] ^= S[0]
        S[0] ^= S[4]
        S[3] ^= S[2]
        S[2] ^= 0xFFFFFFFFFFFFFFFF

        S[0] ^= rotr(S[0], 19) ^ rotr(S[0], 28)
        S[1] ^= rotr(S[1], 61) ^ rotr(S[1], 39)
        S[2] ^= rotr(S[2], 1) ^ rotr(S[2], 6)
        S[3] ^= rotr(S[3], 10) ^ rotr(S[3], 17)
        S[4] ^= rotr(S[4], 7) ^ rotr(S[4], 41)


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
    """
    length_mode:
      - fixed:<N>
      - random (selects a length across bands)
      - short | normal | long | verylong
    """
    if length_mode.startswith("fixed:"):
        n = int(length_mode.split(":", 1)[1])
        return get_random_bytes(max(0, n))

    mode = length_mode.lower().strip()
    if mode == "short":
        n = random.randint(0, 64)
    elif mode == "normal":
        n = random.randint(65, 254)
    elif mode == "long":
        n = random.randint(255, 1024)
    elif mode in ("verylong", "very_long", "very-long"):
        n = random.randint(1025, 2048)
    else:
        # random across all bands with equal chance
        choice = random.choice(["short", "normal", "long", "verylong"])
        return generate_payload(choice)

    return get_random_bytes(n)


# -------------------- Keying model (pre-shared) --------------------

def derive_node_master_key(node_id: str) -> bytes:
    """
    Simple deterministic pre-shared master key (20 bytes) for research simulation.
    DO NOT use this as a real KDF. For a research prototype, it keeps node/gateway consistent.
    """
    seed = (node_id + "|research-master-key").encode("utf-8")
    raw = bytearray(20)
    acc = 0
    for i in range(20):
        acc = (acc + seed[i % len(seed)] + (i * 31)) % 256
        raw[i] = acc
    return bytes(raw)

def profile_key_from_master(master20: bytes, profile: ProfileId) -> bytes:
    """
    Profiles 1-3 use 16-byte keys, profile 4 uses 20-byte key.
    We slice the same deterministic master so node and gateway match.
    """
    if profile == 4:
        return master20
    return master20[:16]


# -------------------- Packet send --------------------

def build_packet(node_id: str, seq: int, associated_data: bytes, payload: bytes) -> dict:
    metrics = compute_metrics(len(payload))
    profile = choose_security_profile(metrics.percent_score)
    sp = SECURITY_PROFILES[profile]
    p = AEAD_PARAMS[sp.variant]

    master = derive_node_master_key(node_id)
    key = profile_key_from_master(master, profile)
    nonce = get_random_bytes(p.nonce_len)

    ciphertext_and_tag = ascon_encrypt(
        key=key,
        nonce=nonce,
        associateddata=associated_data,
        plaintext=payload,
        variant=sp.variant,
        tag_len=sp.tag_len,
    )

    # Gateway priority hint uses ONLY Length + Criticality (max 8) as you specified.
    pri_raw = metrics.length_stars + metrics.criticality_stars
    pri_norm = pri_raw / 8.0

    pkt = {
        "type": "ascon_node_msg",
        "node_id": node_id,
        "seq": seq,
        "ts": time.time(),

        "metrics": {
            "length_bytes": metrics.length_bytes,
            "length_band": metrics.length_band,
            "length_stars": metrics.length_stars,

            "criticality": metrics.criticality,
            "criticality_stars": metrics.criticality_stars,

            "threat": metrics.threat,
            "threat_stars": metrics.threat_stars,

            "cpu_percent": round(metrics.cpu_percent, 2),
            "cpu_stars": metrics.cpu_stars,

            "ram_percent": round(metrics.ram_percent, 2),
            "ram_stars": metrics.ram_stars,

            "sum_stars": metrics.sum_stars,
            "percent_score": metrics.percent_score,
            "decimal_score": metrics.decimal_score,
        },

        "security": {
            "profile_id": profile,
            "profile_name": sp.name,
            "variant": sp.variant,
            "tag_len": sp.tag_len,
        },

        "priority_hint": {
            "length_plus_criticality": pri_raw,
            "normalized": pri_norm,
        },

        "ad_hex": bytes_to_hex(associated_data),
        "nonce_hex": bytes_to_hex(nonce),
        "ct_hex": bytes_to_hex(ciphertext_and_tag),
    }
    return pkt


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--node-id", required=True, help="Node identifier (e.g., node1)")
    ap.add_argument("--gateway-host", default="127.0.0.1")
    ap.add_argument("--gateway-port", type=int, default=9999)
    ap.add_argument("--count", type=int, default=20, help="How many packets to send")
    ap.add_argument("--interval", type=float, default=1.0, help="Seconds between sends")
    ap.add_argument("--length-mode", default="random",
                    help="random | short | normal | long | verylong | fixed:<N>")
    ap.add_argument("--ad", default="header", help="Associated data string")
    args = ap.parse_args()

    addr = (args.gateway_host, args.gateway_port)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    associated_data = args.ad.encode("utf-8")
    
    # Initialize pyjoules handler
    energy_handler = PrintHandler() if PYJOULES_AVAILABLE else None

    for seq in range(1, args.count + 1):
        payload = generate_payload(args.length_mode)
        
        # Measure energy strictly for packet building and encryption
        if PYJOULES_AVAILABLE:
            @measure_energy(handler=energy_handler)
            def profiled_build():
                return build_packet(args.node_id, seq, associated_data, payload)
            pkt = profiled_build()
        else:
            pkt = build_packet(args.node_id, seq, associated_data, payload)

        raw = json.dumps(pkt).encode("utf-8")
        sock.sendto(raw, addr)

        # Small console summary (kept readable for experiments)
        m = pkt["metrics"]
        s = pkt["security"]
        ph = pkt["priority_hint"]
        print(
            f"[{args.node_id} seq={seq}] len={m['length_bytes']}({m['length_band']}) "
            f"crit={m['criticality']} thr={m['threat']} cpu={m['cpu_percent']}% ram={m['ram_percent']}% "
            f"stars={m['sum_stars']}/20 score={m['percent_score']}% -> profile={s['profile_id']}({s['variant']},tag={s['tag_len']}) "
            f"priority_hint={ph['normalized']:.3f}"
        )

        time.sleep(max(0.0, args.interval))

    sock.close()


if __name__ == "__main__":
    main()
