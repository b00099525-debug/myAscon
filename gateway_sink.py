#!/usr/bin/env python3
"""
Gateway/Sink code:
- Receives UDP packets from nodes
- Computes priority ONLY from (Length stars + Criticality stars) / 8, as specified.
- Runs two-stage scheduling:
    Stage A: time scheduling (process as received or time-sliced) for a configured duration
    Stage B: priority scheduling (highest normalized priority first; ties broken by oldest arrival)
    Aging mechanism applied to Stage B to prevent starvation.
- Calculates and logs throughput and end-to-end delay per packet.
- Optionally decrypts payload for validation using pre-shared keys (same deterministic model as node)

This is a research prototype scheduler/sink for your two-node setup.
"""

from __future__ import annotations

import argparse
import heapq
import json
import socket
import time
from dataclasses import dataclass
from typing import Any, Literal, TypeAlias, Iterable

BytesLike: TypeAlias = bytes | bytearray | memoryview
AsconAeadVariant: TypeAlias = Literal["Ascon-128", "Ascon-128a", "Ascon-80pq"]
ProfileId: TypeAlias = Literal[1, 2, 3, 4]

# -------------------- Ascon AEAD (minimal subset) --------------------

from dataclasses import dataclass

debug = False
debugpermutation = False

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
    assert len(p.iv) == iv_len

    init = p.iv + to_bytes(key) + to_bytes(nonce)
    S[0], S[1], S[2], S[3], S[4] = bytes_to_state(init)
    ascon_permutation(S, p.a)

    buf = bytearray(state_to_bytes(S))
    off = 40 - p.key_len
    for i in range(p.key_len):
        buf[off + i] ^= key[i]
    S[0], S[1], S[2], S[3], S[4] = bytes_to_state(bytes(buf))

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

    return plaintext

def ascon_finalize(S: list[int], p: AeadParams, key: BytesLike) -> bytes:
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

    return int_to_bytes(S[3], 8) + int_to_bytes(S[4], 8)

def ascon_permutation(S: list[int], rounds: int = 1) -> None:
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

def zero_bytes(n: int) -> bytes:
    return n * b"\x00"

def ff_bytes(n: int) -> bytes:
    return n * b"\xFF"

def to_bytes(l: BytesLike | Iterable[int]) -> bytes:
    return bytes(l)

def bytes_to_int(b: BytesLike) -> int:
    return int.from_bytes(b, "little")

def bytes_to_state(b: bytes) -> list[int]:
    assert len(b) == 40
    return [bytes_to_int(b[8 * w:8 * (w + 1)]) for w in range(5)]

def state_to_bytes(S: list[int]) -> bytes:
    return b"".join(int_to_bytes(w, 8) for w in S)

def int_to_bytes(integer: int, nbytes: int) -> bytes:
    return integer.to_bytes(nbytes, "little")

def rotr(val: int, r: int) -> int:
    return (val >> r) | ((val & ((1 << r) - 1)) << (64 - r))

def hex_to_bytes(s: str) -> bytes:
    return bytes.fromhex(s)

# -------------------- Keying (must match node) --------------------

def derive_node_master_key(node_id: str) -> bytes:
    seed = (node_id + "|research-master-key").encode("utf-8")
    raw = bytearray(20)
    acc = 0
    for i in range(20):
        acc = (acc + seed[i % len(seed)] + (i * 31)) % 256
        raw[i] = acc
    return bytes(raw)

def profile_key_from_master(master20: bytes, profile: int) -> bytes:
    if profile == 4:
        return master20
    return master20[:16]

# -------------------- Scheduling structures --------------------

@dataclass
class InboundItem:
    arrival_ts: float
    node_id: str
    seq: int
    priority_norm: float
    pkt: dict[str, Any]

def heap_key(item: InboundItem) -> tuple[float, float]:
    return (-item.priority_norm, item.arrival_ts)

# -------------------- Gateway main --------------------

def compute_priority_from_packet(pkt: dict[str, Any]) -> float:
    """
    Priority uses ONLY Criticality + Length stars, normalized by 8.
    """
    m = pkt.get("metrics", {})
    length_stars = int(m.get("length_stars", 0))
    criticality_stars = int(m.get("criticality_stars", 0))
    raw = length_stars + criticality_stars
    return max(0.0, min(1.0, raw / 8.0))

def apply_aging(heap: list, current_ts: float, aging_rate: float = 0.05) -> list:
    """
    Increases priority score over time to stop starvation.
    aging_rate decides how fast priority scales per second waiting.
    """
    new_heap = []
    for neg_prio, arr_ts, item in heap:
        wait_time = current_ts - arr_ts
        aged_prio = min(1.0, item.priority_norm + (wait_time * aging_rate))
        new_heap.append((-aged_prio, arr_ts, item))
    heapq.heapify(new_heap)
    return new_heap


def try_decrypt(pkt: dict[str, Any]) -> bytes | None:
    sec = pkt.get("security", {})
    variant = sec.get("variant", "Ascon-128")
    tag_len = int(sec.get("tag_len", 16))
    profile_id = int(sec.get("profile_id", 2))

    node_id = str(pkt.get("node_id"))
    ad = hex_to_bytes(pkt["ad_hex"])
    nonce = hex_to_bytes(pkt["nonce_hex"])
    ct = hex_to_bytes(pkt["ct_hex"])

    master = derive_node_master_key(node_id)
    key = profile_key_from_master(master, profile_id)

    return ascon_decrypt(
        key=key,
        nonce=nonce,
        associateddata=ad,
        ciphertext=ct,
        variant=variant,
        tag_len=tag_len,
    )

def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--bind-host", default="0.0.0.0")
    ap.add_argument("--bind-port", type=int, default=9999)
    ap.add_argument("--time-scheduler-seconds", type=float, default=20.0,
                    help="Duration to run time-based scheduling before switching to priority scheduling")
    ap.add_argument("--process-interval", type=float, default=1.0,
                    help="How often the gateway processes one item from its scheduling policy")
    ap.add_argument("--decrypt", action="store_true", help="Attempt to decrypt and verify each message")
    args = ap.parse_args()

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((args.bind_host, args.bind_port))
    sock.settimeout(0.2)

    print(f"[gateway] listening on {args.bind_host}:{args.bind_port}")
    print(f"[gateway] stage A (FIFO) for {args.time_scheduler_seconds}s, then stage B (Priority with Aging)")
    print(f"[gateway] process_interval={args.process_interval}s decrypt={args.decrypt}")

    start_ts = time.time()
    
    fifo: list[InboundItem] = []
    heap: list[tuple[float, float, InboundItem]] = []
    stage_a_ended = False
    
    total_bytes_received = 0

    while True:
        now = time.time()
        stage_a_active = (now - start_ts) < args.time_scheduler_seconds

        # --- Transition Hook: Moving Stage A packets to Stage B ---
        if not stage_a_active and not stage_a_ended:
            print("\n[gateway] TIME EXPIRED. Switching to Priority Scheduling (Stage B). Moving remaining Stage A packets...")
            while fifo:
                old_item = fifo.pop(0)
                heapq.heappush(heap, (-old_item.priority_norm, old_item.arrival_ts, old_item))
            stage_a_ended = True

        try:
            data, addr = sock.recvfrom(65535)
            total_bytes_received += len(data)
            pkt = json.loads(data.decode("utf-8"))

            if pkt.get("type") != "ascon_node_msg":
                continue

            node_id = str(pkt.get("node_id", "unknown"))
            seq = int(pkt.get("seq", 0))
            pr = compute_priority_from_packet(pkt)

            item = InboundItem(
                arrival_ts=now,
                node_id=node_id,
                seq=seq,
                priority_norm=pr,
                pkt=pkt,
            )

            if stage_a_active:
                fifo.append(item)
                print(f"-> [Stage A In] Node: {item.node_id} Seq: {item.seq}")
            else:
                heapq.heappush(heap, (-item.priority_norm, item.arrival_ts, item))
                print(f"-> [Stage B In] Node: {item.node_id} Seq: {item.seq} Base Prio: {item.priority_norm:.3f}")

        except socket.timeout:
            pass 

        # --- Processing Logic ---
        if stage_a_active:
            if fifo:
                processed_item = fifo.pop(0)
                
                # Metric calculations (End-to-End Delay & Throughput)
                delay = time.time() - processed_item.pkt["ts"]
                throughput = total_bytes_received / max(1.0, time.time() - start_ts)
                
                print(f"<- [Stage A Out] Node: {processed_item.node_id} Seq: {processed_item.seq} | Delay: {delay*1000:.2f}ms | Throughput: {throughput/1024:.2f} KB/s")
                if args.decrypt:
                    decrypted = try_decrypt(processed_item.pkt)
                    print(f"   Decrypted: {decrypted is not None}")

        else:
            if heap:
                # Apply Aging
                heap = apply_aging(heap, now, aging_rate=0.05)
                _, arr_ts, processed_item = heapq.heappop(heap)
                
                # Metric calculations (End-to-End Delay & Throughput)
                delay = time.time() - processed_item.pkt["ts"]
                throughput = total_bytes_received / max(1.0, time.time() - start_ts)

                print(f"<- [Stage B Out] Node: {processed_item.node_id} Seq: {processed_item.seq} | Delay: {delay*1000:.2f}ms | Throughput: {throughput/1024:.2f} KB/s")
                if args.decrypt:
                    decrypted = try_decrypt(processed_item.pkt)
                    print(f"   Decrypted: {decrypted is not None}")
        
        time.sleep(0.01)

if __name__ == "__main__":
    main()
