#!/usr/bin/env python3
"""
Gateway/Sink (Academic IoT Research - Updated):

Stage A : FIFO time-based scheduling for a configured duration.
Stage B : Priority scheduling with Mathematical Queue Aging.

Key academic improvements implemented:
──────────────────────────────────────────────────────────────────────────────
1. Mathematical Queue Aging (no re-sort overhead)
   Aging key pushed into heapq at insertion time:
       Key = -(Priority_base − k × t_arrival)    k = 0.1
   Because t_arrival grows monotonically, older packets have a less-negative
   (i.e. higher) effective priority and automatically bubble to the front
   without any periodic re-sort pass.

2. Event-Driven Processing Worker Thread
   A dedicated daemon thread pulls packets from a thread-safe queue.Queue
   using get(timeout=0.1) so it wakes the microsecond a packet arrives.
   No artificial time.sleep() bottlenecks anywhere in the gateway.

3. Metrics: End-to-End Delay (ms) and Throughput (KB/s) per packet.
──────────────────────────────────────────────────────────────────────────────
"""

from __future__ import annotations

import argparse
import heapq
import json
import queue
import socket
import threading
import time
from dataclasses import dataclass
from typing import Any, Literal, TypeAlias, Iterable

BytesLike: TypeAlias = bytes | bytearray | memoryview
AsconAeadVariant: TypeAlias = Literal["Ascon-128", "Ascon-128a", "Ascon-80pq"]
ProfileId: TypeAlias = Literal[1, 2, 3, 4]

# -------------------- Ascon AEAD --------------------

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
    "Ascon-128":  AeadParams(16, 16, 8,  12, 6, 16, bytes.fromhex("80400c0600000000")),
    "Ascon-128a": AeadParams(16, 16, 16, 12, 8, 16, bytes.fromhex("80800c0800000000")),
    "Ascon-80pq": AeadParams(20, 16, 8,  12, 6, 16, bytes.fromhex("a0400c06")),
}

def ascon_decrypt(
    key: BytesLike, nonce: BytesLike, associateddata: BytesLike,
    ciphertext: BytesLike, variant: AsconAeadVariant = "Ascon-128",
    tag_len: int | None = None,
) -> bytes | None:
    p = AEAD_PARAMS[variant]
    if tag_len is None: tag_len = p.tag_len
    assert len(key) == p.key_len and len(nonce) == p.nonce_len
    assert 0 < tag_len <= 16 and len(ciphertext) >= tag_len
    ct, tag = ciphertext[:-tag_len], ciphertext[-tag_len:]
    S = [0, 0, 0, 0, 0]
    ascon_initialize(S, p, key, nonce)
    ascon_process_associated_data(S, p.b, p.rate, associateddata)
    plaintext = ascon_process_ciphertext(S, p.b, p.rate, ct)
    full_tag = ascon_finalize(S, p, key)
    if full_tag[:tag_len] == tag: return plaintext
    return None

def ascon_initialize(S: list[int], p: AeadParams, key: BytesLike, nonce: BytesLike) -> None:
    iv_len = 24 - p.key_len
    assert len(p.iv) == iv_len
    init = p.iv + to_bytes(key) + to_bytes(nonce)
    S[0], S[1], S[2], S[3], S[4] = bytes_to_state(init)
    ascon_permutation(S, p.a)
    buf = bytearray(state_to_bytes(S))
    off = 40 - p.key_len
    for i in range(p.key_len): buf[off + i] ^= key[i]
    S[0], S[1], S[2], S[3], S[4] = bytes_to_state(bytes(buf))

def ascon_process_associated_data(S: list[int], b: int, rate: int, associateddata: BytesLike) -> None:
    if len(associateddata) > 0:
        a_padding = to_bytes([0x01]) + zero_bytes(rate - (len(associateddata) % rate) - 1)
        a_padded  = to_bytes(associateddata) + a_padding
        for block in range(0, len(a_padded), rate):
            S[0] ^= bytes_to_int(a_padded[block:block + 8])
            if rate == 16: S[1] ^= bytes_to_int(a_padded[block + 8:block + 16])
            ascon_permutation(S, b)
    S[4] ^= 1 << 63

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
    c0    = bytes_to_int(c_padded[block:block + 8])
    if rate == 16:
        c1  = bytes_to_int(c_padded[block + 8:block + 16])
        out = (int_to_bytes(S[0] ^ c0, 8) + int_to_bytes(S[1] ^ c1, 8))[:c_lastlen]
        plaintext += out
        c_padx = zero_bytes(c_lastlen) + to_bytes([0x01]) + zero_bytes(rate - c_lastlen - 1)
        c_mask = zero_bytes(c_lastlen) + ff_bytes(rate - c_lastlen)
        S[0] = (S[0] & bytes_to_int(c_mask[0:8])) ^ c0 ^ bytes_to_int(c_padx[0:8])
        S[1] = (S[1] & bytes_to_int(c_mask[8:16])) ^ c1 ^ bytes_to_int(c_padx[8:16])
    else:
        out = int_to_bytes(S[0] ^ c0, 8)[:c_lastlen]
        plaintext += out
        c_padx = zero_bytes(c_lastlen) + to_bytes([0x01]) + zero_bytes(rate - c_lastlen - 1)
        c_mask = zero_bytes(c_lastlen) + ff_bytes(rate - c_lastlen)
        S[0] = (S[0] & bytes_to_int(c_mask[0:8])) ^ c0 ^ bytes_to_int(c_padx[0:8])
    return plaintext

def ascon_finalize(S: list[int], p: AeadParams, key: BytesLike) -> bytes:
    buf    = bytearray(state_to_bytes(S))
    pre_off = p.rate
    for i in range(p.key_len):
        if pre_off + i < 40: buf[pre_off + i] ^= key[i]
    S[0], S[1], S[2], S[3], S[4] = bytes_to_state(bytes(buf))
    ascon_permutation(S, p.a)
    buf      = bytearray(state_to_bytes(S))
    post_off = 40 - p.key_len
    for i in range(p.key_len): buf[post_off + i] ^= key[i]
    S[0], S[1], S[2], S[3], S[4] = bytes_to_state(bytes(buf))
    return int_to_bytes(S[3], 8) + int_to_bytes(S[4], 8)

def ascon_permutation(S: list[int], rounds: int = 1) -> None:
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

def zero_bytes(n: int) -> bytes:     return n * b"\x00"
def ff_bytes(n: int) -> bytes:       return n * b"\xFF"
def to_bytes(l: BytesLike | Iterable[int]) -> bytes: return bytes(l)
def bytes_to_int(b: BytesLike) -> int: return int.from_bytes(b, "little")
def bytes_to_state(b: bytes) -> list[int]:
    return [bytes_to_int(b[8 * w:8 * (w + 1)]) for w in range(5)]
def state_to_bytes(S: list[int]) -> bytes:
    return b"".join(int_to_bytes(w, 8) for w in S)
def int_to_bytes(integer: int, nbytes: int) -> bytes:
    return integer.to_bytes(nbytes, "little")
def rotr(val: int, r: int) -> int:
    return (val >> r) | ((val & ((1 << r) - 1)) << (64 - r))
def hex_to_bytes(s: str) -> bytes: return bytes.fromhex(s)

# -------------------- Keying (must match node) --------------------

def derive_node_master_key(node_id: str) -> bytes:
    seed = (node_id + "|research-master-key").encode("utf-8")
    raw  = bytearray(20)
    acc  = 0
    for i in range(20):
        acc    = (acc + seed[i % len(seed)] + (i * 31)) % 256
        raw[i] = acc
    return bytes(raw)

def profile_key_from_master(master20: bytes, profile: int) -> bytes:
    if profile == 4: return master20
    return master20[:16]

# -------------------- Scheduling structures --------------------

@dataclass
class InboundItem:
    arrival_ts:    float
    node_id:       str
    seq:           int
    priority_norm: float
    pkt:           dict[str, Any]


# -------------------- Mathematical Aging Key --------------------
#
# Aging factor baked into the heap key at insertion time:
#
#   Key = -(Priority_base - k × t_arrival)
#
# With k = 0.1, as t_arrival increases (newer packets) the key becomes
# *more* negative, meaning they rank lower. Older packets have a less-negative
# key and naturally surface to the front — no periodic re-sort required.
# This eliminates the O(n) apply_aging pass and any associated CPU overhead.

AGING_K = 0.1   # aging coefficient (tunable)


def aging_key(priority_norm: float, arrival_ts: float) -> float:
    """
    Return the heap key implementing mathematical aging.
    heapq is a min-heap, so we negate to get max-priority-first.
    Lower (more negative) key  →  processed first.
    Key = -(Priority_base − k × t_arrival)
    """
    return -(priority_norm - AGING_K * arrival_ts)


# -------------------- Decryption --------------------

def compute_priority_from_packet(pkt: dict[str, Any]) -> float:
    m = pkt.get("metrics", {})
    length_stars     = int(m.get("length_stars", 0))
    criticality_stars = int(m.get("criticality_stars", 0))
    raw = length_stars + criticality_stars
    return max(0.0, min(1.0, raw / 8.0))


def try_decrypt(pkt: dict[str, Any]) -> bytes | None:
    sec      = pkt.get("security", {})
    variant  = sec.get("variant", "Ascon-128")
    tag_len  = int(sec.get("tag_len", 16))
    profile_id = int(sec.get("profile_id", 2))
    node_id  = str(pkt.get("node_id"))
    ad       = hex_to_bytes(pkt["ad_hex"])
    nonce    = hex_to_bytes(pkt["nonce_hex"])
    ct       = hex_to_bytes(pkt["ct_hex"])
    master   = derive_node_master_key(node_id)
    key      = profile_key_from_master(master, profile_id)
    return ascon_decrypt(
        key=key, nonce=nonce, associateddata=ad,
        ciphertext=ct, variant=variant, tag_len=tag_len,
    )


# -------------------- Shared Gateway State --------------------

class GatewayState:
    """
    Thread-safe container for all mutable gateway state.
    The receiver thread writes; the processor thread reads/pops.
    A single threading.Lock protects the FIFO and heap.
    """

    def __init__(self, time_scheduler_seconds: float):
        self.start_ts              = time.time()
        self.time_scheduler_seconds = time_scheduler_seconds

        self.lock      = threading.Lock()
        self.fifo: list[InboundItem] = []
        self.heap: list[tuple[float, float, InboundItem]] = []
        self.stage_a_ended = False

        # bytes received — updated by receiver thread, read by processor thread
        self._total_bytes = 0
        self._bytes_lock  = threading.Lock()

        # Thread-safe work queue: receiver posts (item, stage_label) for processor
        self.work_q: queue.Queue[tuple[InboundItem, str]] = queue.Queue()

    # ---- helpers ----

    def elapsed(self) -> float:
        return time.time() - self.start_ts

    def stage_a_active(self) -> bool:
        return self.elapsed() < self.time_scheduler_seconds

    def add_bytes(self, n: int) -> None:
        with self._bytes_lock:
            self._total_bytes += n

    def total_bytes(self) -> int:
        with self._bytes_lock:
            return self._total_bytes

    def throughput_kbps(self) -> float:
        elapsed = max(1.0, self.elapsed())
        return (self.total_bytes() / elapsed) / 1024.0

    def transition_to_stage_b(self) -> None:
        """
        Move remaining Stage-A FIFO packets into the Stage-B heap.
        Uses mathematical aging key.
        """
        with self.lock:
            if self.stage_a_ended:
                return
            count = len(self.fifo)
            while self.fifo:
                old_item = self.fifo.pop(0)
                key = aging_key(old_item.priority_norm, old_item.arrival_ts)
                heapq.heappush(self.heap, (key, old_item.arrival_ts, old_item))
            self.stage_a_ended = True
        if count:
            print(f"\n[gateway] Transition: moved {count} Stage-A packet(s) into Stage-B heap.")

    def enqueue_stage_a(self, item: InboundItem) -> None:
        with self.lock:
            self.fifo.append(item)
            # pop immediately from FIFO for FIFO processing
            out = self.fifo.pop(0)
        self.work_q.put((out, "A"))

    def enqueue_stage_b(self, item: InboundItem) -> None:
        # Mathematical aging key baked in at insertion — no re-sort ever needed
        key = aging_key(item.priority_norm, item.arrival_ts)
        with self.lock:
            heapq.heappush(self.heap, (key, item.arrival_ts, item))
        # Signal the processor that new work is available
        self._drain_heap_to_work_q()

    def _drain_heap_to_work_q(self) -> None:
        """Pop one item from heap and post to work queue (non-blocking)."""
        with self.lock:
            if self.heap:
                _, _, out = heapq.heappop(self.heap)
                self.work_q.put((out, "B"))


# -------------------- Processor Thread --------------------

def processor_thread(state: GatewayState, do_decrypt: bool) -> None:
    """
    Event-driven worker: blocks on work_q.get(timeout=0.1).
    Wakes the microsecond a packet is enqueued — zero artificial delay.
    """
    print("[gateway] Processor thread started (event-driven, no sleep).")
    while True:
        try:
            item, stage = state.work_q.get(timeout=0.1)
        except queue.Empty:
            # No packet arrived within 0.1 s; loop back immediately.
            # Also drain any queued Stage-B packets that might have piled up.
            state._drain_heap_to_work_q()
            continue

        now       = time.time()
        delay_ms  = (now - item.pkt["ts"]) * 1000.0
        tput_kbps = state.throughput_kbps()

        label = "Stage A Out" if stage == "A" else "Stage B Out"
        print(
            f"<- [{label}] Node: {item.node_id} Seq: {item.seq:04d} | "
            f"BasePrio: {item.priority_norm:.3f} | "
            f"Delay: {delay_ms:.3f} ms | "
            f"Throughput: {tput_kbps:.3f} KB/s"
        )

        if do_decrypt:
            t0        = time.perf_counter()
            decrypted = try_decrypt(item.pkt)
            dec_us    = (time.perf_counter() - t0) * 1_000_000
            status    = "OK" if decrypted is not None else "FAIL"
            print(f"   Decrypt: {status}  ({dec_us:.2f} µs)")

        state.work_q.task_done()


# -------------------- Receiver (main) Thread --------------------

def main() -> None:
    ap = argparse.ArgumentParser(
        description="IoT Gateway – Event-Driven, Mathematical Aging, No Sleep"
    )
    ap.add_argument("--bind-host",              default="0.0.0.0")
    ap.add_argument("--bind-port",              type=int, default=9999)
    ap.add_argument("--time-scheduler-seconds", type=float, default=20.0,
                    help="Duration of Stage A (FIFO) before switching to Stage B (Priority)")
    ap.add_argument("--process-interval", type=float, default=1.0,
                    help="(Legacy parameter – retained for CLI compatibility. "
                         "The event-driven worker processes packets instantly; this value is not used as a sleep delay.)")
    ap.add_argument("--decrypt",                action="store_true",
                    help="Attempt to decrypt and verify each message")
    args = ap.parse_args()

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((args.bind_host, args.bind_port))
    sock.settimeout(0.05)   # short timeout so the loop stays responsive

    state = GatewayState(time_scheduler_seconds=args.time_scheduler_seconds)

    print(f"[gateway] Listening on {args.bind_host}:{args.bind_port}")
    print(f"[gateway] Stage A (FIFO) for {args.time_scheduler_seconds}s → Stage B (Priority + Aging)")
    print(f"[gateway] Aging formula: Key = -(Priority_base − k × t_arrival)  k={AGING_K}")
    print(f"[gateway] Decrypt={args.decrypt}")
    print()

    # Start the event-driven processor in a daemon thread
    proc = threading.Thread(
        target=processor_thread,
        args=(state, args.decrypt),
        daemon=True,
        name="GW-Processor",
    )
    proc.start()

    stage_b_announced = False

    try:
        while True:
            now = time.time()

            # ---- Stage transition ----
            if not state.stage_a_active() and not state.stage_a_ended:
                print(f"\n[gateway] Stage A expired at t={state.elapsed():.1f}s. "
                      "Transitioning to Stage B (Priority Scheduling).")
                state.transition_to_stage_b()

            if state.stage_a_ended and not stage_b_announced:
                print(f"[gateway] Stage B active. Mathematical aging key: "
                      f"Key = -(p − {AGING_K} × t_arrival)\n")
                stage_b_announced = True

            # ---- Receive packet ----
            try:
                data, addr = sock.recvfrom(65535)
            except socket.timeout:
                continue

            state.add_bytes(len(data))

            try:
                pkt = json.loads(data.decode("utf-8"))
            except json.JSONDecodeError:
                print(f"[gateway] Malformed packet from {addr}, ignored.")
                continue

            if pkt.get("type") != "ascon_node_msg":
                continue

            node_id = str(pkt.get("node_id", "unknown"))
            seq     = int(pkt.get("seq", 0))
            pr      = compute_priority_from_packet(pkt)

            item = InboundItem(
                arrival_ts=now,
                node_id=node_id,
                seq=seq,
                priority_norm=pr,
                pkt=pkt,
            )

            if state.stage_a_active():
                print(f"-> [Stage A In]  Node: {node_id}  Seq: {seq:04d}  Prio: {pr:.3f}")
                state.enqueue_stage_a(item)
            else:
                aging_k_val = aging_key(pr, now)
                print(f"-> [Stage B In]  Node: {node_id}  Seq: {seq:04d}  "
                      f"BasePrio: {pr:.3f}  AgingKey: {aging_k_val:.6f}")
                state.enqueue_stage_b(item)

    except KeyboardInterrupt:
        print("\n[gateway] Interrupted by user. Shutting down.")
    finally:
        sock.close()
        print("[gateway] Socket closed.")


if __name__ == "__main__":
    main()
