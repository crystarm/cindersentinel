#!/usr/bin/env python3
"""
Generate CBOR seed corpus for cindersentinel policy fuzzing.

- Writes a mix of valid canonical policies and invalid/edge-case inputs.
- Encodes CBOR directly (no external deps).
- Heavy cases (very large) are optional via --heavy.

Usage:
  ./gen_seed_corpus.py
  ./gen_seed_corpus.py --out-dir /path/to/corpus
  ./gen_seed_corpus.py --heavy
"""
from __future__ import annotations

import argparse
import os
from pathlib import Path
from typing import Iterable, List, Tuple



def _head(major: int, add: int) -> bytes:
    return bytes([(major << 5) | add])


def _encode_uint_with_len(n: int, length: int) -> bytes:
    if length not in (1, 2, 4, 8):
        raise ValueError("length must be 1,2,4,8")
    add = {1: 24, 2: 25, 4: 26, 8: 27}[length]
    return _head(0, add) + n.to_bytes(length, "big")


def enc_uint(n: int) -> bytes:
    if n < 0:
        raise ValueError("enc_uint expects non-negative")
    if n < 24:
        return bytes([n])
    if n <= 0xFF:
        return _head(0, 24) + n.to_bytes(1, "big")
    if n <= 0xFFFF:
        return _head(0, 25) + n.to_bytes(2, "big")
    if n <= 0xFFFFFFFF:
        return _head(0, 26) + n.to_bytes(4, "big")
    return _head(0, 27) + n.to_bytes(8, "big")


def enc_nint(n: int) -> bytes:
    if n >= 0:
        raise ValueError("enc_nint expects negative")
    v = -1 - n
    if v < 24:
        return _head(1, v)
    if v <= 0xFF:
        return _head(1, 24) + v.to_bytes(1, "big")
    if v <= 0xFFFF:
        return _head(1, 25) + v.to_bytes(2, "big")
    if v <= 0xFFFFFFFF:
        return _head(1, 26) + v.to_bytes(4, "big")
    return _head(1, 27) + v.to_bytes(8, "big")


def enc_bytes(b: bytes) -> bytes:
    return enc_uint(len(b)).replace(bytes([0]), bytes([0]))  # no-op, for clarity


def enc_text(s: str) -> bytes:
    b = s.encode("utf-8")
    return _head(3, _len_add(len(b))) + _len_bytes(len(b)) + b


def _len_add(n: int) -> int:
    if n < 24:
        return n
    if n <= 0xFF:
        return 24
    if n <= 0xFFFF:
        return 25
    if n <= 0xFFFFFFFF:
        return 26
    return 27


def _len_bytes(n: int) -> bytes:
    if n < 24:
        return b""
    if n <= 0xFF:
        return n.to_bytes(1, "big")
    if n <= 0xFFFF:
        return n.to_bytes(2, "big")
    if n <= 0xFFFFFFFF:
        return n.to_bytes(4, "big")
    return n.to_bytes(8, "big")


def enc_bytestring(b: bytes) -> bytes:
    return _head(2, _len_add(len(b))) + _len_bytes(len(b)) + b


def enc_array(items: Iterable[bytes]) -> bytes:
    items_list = list(items)
    return _head(4, _len_add(len(items_list))) + _len_bytes(len(items_list)) + b"".join(items_list)


def enc_map(entries: Iterable[Tuple[int, bytes]], canonical: bool = True) -> bytes:
    entries_list = list(entries)
    if canonical:
        entries_list.sort(key=lambda kv: kv[0])
    out = [_head(5, _len_add(len(entries_list))), _len_bytes(len(entries_list))]
    for k, v in entries_list:
        out.append(enc_uint(k))
        out.append(v)
    return b"".join(out)


def enc_map_raw(entries: Iterable[Tuple[bytes, bytes]]) -> bytes:
    entries_list = list(entries)
    out = [_head(5, _len_add(len(entries_list))), _len_bytes(len(entries_list))]
    for k, v in entries_list:
        out.append(k)
        out.append(v)
    return b"".join(out)


def _len_add_for_len(length: int) -> int:
    if length not in (1, 2, 4, 8):
        raise ValueError("length must be 1,2,4,8")
    return {1: 24, 2: 25, 4: 26, 8: 27}[length]


def enc_text_with_len_size(s: str, length: int) -> bytes:
    b = s.encode("utf-8")
    add = _len_add_for_len(length)
    return _head(3, add) + len(b).to_bytes(length, "big") + b


def enc_bytestring_with_len_size(b: bytes, length: int) -> bytes:
    add = _len_add_for_len(length)
    return _head(2, add) + len(b).to_bytes(length, "big") + b


def enc_text_with_declared_len(s: str, declared_len: int) -> bytes:
    b = s.encode("utf-8")
    return _head(3, _len_add(declared_len)) + _len_bytes(declared_len) + b


def enc_bytestring_with_declared_len(b: bytes, declared_len: int) -> bytes:
    return _head(2, _len_add(declared_len)) + _len_bytes(declared_len) + b


def enc_array_with_declared_len(items: Iterable[bytes], declared_len: int) -> bytes:
    items_list = list(items)
    return _head(4, _len_add(declared_len)) + _len_bytes(declared_len) + b"".join(items_list)


def enc_map_with_declared_len(entries: Iterable[Tuple[int, bytes]], declared_len: int, canonical: bool = True) -> bytes:
    entries_list = list(entries)
    if canonical:
        entries_list.sort(key=lambda kv: kv[0])
    out = [_head(5, _len_add(declared_len)), _len_bytes(declared_len)]
    for k, v in entries_list:
        out.append(enc_uint(k))
        out.append(v)
    return b"".join(out)


def enc_indef_array(items: Iterable[bytes]) -> bytes:
    return b"\x9f" + b"".join(items) + b"\xff"


def enc_indef_map(entries: Iterable[Tuple[bytes, bytes]]) -> bytes:
    out = [b"\xbf"]
    for k, v in entries:
        out.append(k)
        out.append(v)
    out.append(b"\xff")
    return b"".join(out)


def enc_indef_bytes(chunks: Iterable[bytes]) -> bytes:
    out = [b"\x5f"]
    for c in chunks:
        out.append(enc_bytestring(c))
    out.append(b"\xff")
    return b"".join(out)


def enc_indef_text(chunks: Iterable[str]) -> bytes:
    out = [b"\x7f"]
    for c in chunks:
        out.append(enc_text(c))
    out.append(b"\xff")
    return b"".join(out)


CSK_KIND = 1
CSK_V = 2
CSK_DEFAULT_ACTION = 3
CSK_RULES = 4
CSK_IPV4_FRAG_POLICY = 5
CSK_IPV4_ENCAP_POLICY = 6

CSR_ACTION = 1
CSR_PROTO = 2
CSR_DPORTS = 3

CSA_LET = 0
CSA_FORBID = 1

CSP_ICMP = 1
CSP_TCP = 2
CSP_UDP = 3


def rule_icmp_forbid() -> bytes:
    return enc_map([
        (CSR_ACTION, enc_uint(CSA_FORBID)),
        (CSR_PROTO, enc_uint(CSP_ICMP)),
    ])


def rule_ports_forbid(proto: int, dports: List[object]) -> bytes:
    dps = []
    for item in dports:
        if isinstance(item, int):
            dps.append(enc_uint(item))
        else:
            lo, hi = item
            dps.append(enc_array([enc_uint(lo), enc_uint(hi)]))
    return enc_map([
        (CSR_ACTION, enc_uint(CSA_FORBID)),
        (CSR_PROTO, enc_uint(proto)),
        (CSR_DPORTS, enc_array(dps)),
    ])


def policy_entries(
    rules: List[bytes],
    *,
    kind: object = "cindersentinel.policy",
    v: object = 1,
    default_action: object = None,
    ipv4_frag: object = None,
    ipv4_encap: object = None,
    extra: List[Tuple[int, bytes]] | None = None,
) -> List[Tuple[int, bytes]]:
    entries: List[Tuple[int, bytes]] = [
        (CSK_KIND, enc_text(kind) if isinstance(kind, str) else kind),
        (CSK_V, enc_uint(v) if isinstance(v, int) else v),
        (CSK_RULES, enc_array(rules)),
    ]
    if default_action is not None:
        entries.append((CSK_DEFAULT_ACTION, enc_uint(default_action) if isinstance(default_action, int) else default_action))
    if ipv4_frag is not None:
        entries.append((CSK_IPV4_FRAG_POLICY, enc_uint(ipv4_frag) if isinstance(ipv4_frag, int) else ipv4_frag))
    if ipv4_encap is not None:
        entries.append((CSK_IPV4_ENCAP_POLICY, enc_uint(ipv4_encap) if isinstance(ipv4_encap, int) else ipv4_encap))
    if extra:
        entries.extend(extra)
    return entries


def policy_bytes(entries: List[Tuple[int, bytes]], canonical: bool = True) -> bytes:
    return enc_map(entries, canonical=canonical)


def add_seed(seeds: List[Tuple[str, bytes]], name: str, data: bytes) -> None:
    seeds.append((name, data))


def gen_seeds(heavy: bool = False) -> List[Tuple[str, bytes]]:
    seeds: List[Tuple[str, bytes]] = []


    add_seed(seeds, "valid_min.cbor",
             policy_bytes(policy_entries([])))
    add_seed(seeds, "valid_icmp_forbid.cbor",
             policy_bytes(policy_entries([rule_icmp_forbid()])))
    add_seed(seeds, "valid_tcp_single.cbor",
             policy_bytes(policy_entries([rule_ports_forbid(CSP_TCP, [80])])))
    add_seed(seeds, "valid_tcp_range.cbor",
             policy_bytes(policy_entries([rule_ports_forbid(CSP_TCP, [(1000, 2000)])])))
    add_seed(seeds, "valid_udp_multi.cbor",
             policy_bytes(policy_entries([rule_ports_forbid(CSP_UDP, [53, 123, (1000, 1002)])])))
    add_seed(seeds, "valid_multi_rules.cbor",
             policy_bytes(policy_entries([
                 rule_icmp_forbid(),
                 rule_ports_forbid(CSP_TCP, [(22, 22), (80, 80), (8000, 8005)]),
                 rule_ports_forbid(CSP_UDP, [53]),
             ], default_action=CSA_LET, ipv4_frag=CSA_FORBID, ipv4_encap=CSA_LET)))



    entries_nc = policy_entries([rule_icmp_forbid()])
    entries_nc = [entries_nc[2], entries_nc[0], entries_nc[1]]  # rules, kind, v
    add_seed(seeds, "invalid_noncanonical_key_order.cbor",
             policy_bytes(entries_nc, canonical=False))

    entries_nc2 = [
        (CSK_KIND, enc_text("cindersentinel.policy")),
        (CSK_V, _encode_uint_with_len(1, 2)),  # non-canonical uint
        (CSK_RULES, enc_array([])),
    ]
    add_seed(seeds, "invalid_noncanonical_uint_encoding.cbor",
             policy_bytes(entries_nc2, canonical=False))

    entries_nc3 = [
        (CSK_KIND, enc_text_with_len_size("cindersentinel.policy", 2)),
        (CSK_V, enc_uint(1)),
        (CSK_RULES, enc_array([])),
    ]
    add_seed(seeds, "invalid_noncanonical_text_length.cbor",
             policy_bytes(entries_nc3, canonical=False))

    rule_nc = enc_map([
        (CSR_DPORTS, enc_array([enc_uint(80)])),
        (CSR_ACTION, enc_uint(CSA_FORBID)),
        (CSR_PROTO, enc_uint(CSP_TCP)),
    ], canonical=False)
    add_seed(seeds, "invalid_noncanonical_rule_key_order.cbor",
             policy_bytes(policy_entries([rule_nc])))

    add_seed(seeds, "invalid_missing_kind.cbor",
             policy_bytes([(CSK_V, enc_uint(1)),
                           (CSK_RULES, enc_array([]))], canonical=True))
    add_seed(seeds, "invalid_missing_v.cbor",
             policy_bytes([(CSK_KIND, enc_text("cindersentinel.policy")),
                           (CSK_RULES, enc_array([]))], canonical=True))
    add_seed(seeds, "invalid_missing_rules.cbor",
             policy_bytes([(CSK_KIND, enc_text("cindersentinel.policy")),
                           (CSK_V, enc_uint(1))], canonical=True))
    add_seed(seeds, "invalid_empty_kind.cbor",
             policy_bytes(policy_entries([], kind="")))
    add_seed(seeds, "invalid_empty_rule_map.cbor",
             policy_bytes(policy_entries([enc_map([])])))

    # CBOR decode errors (structural)
    add_seed(seeds, "invalid_empty.cbor", b"")
    add_seed(seeds, "invalid_truncated_integer.cbor", b"\x19")
    add_seed(seeds, "invalid_additional_info.cbor", b"\x1c")
    add_seed(seeds, "invalid_indefinite_map.cbor", b"\xbf")
    add_seed(seeds, "invalid_break.cbor", b"\xff")
    add_seed(seeds, "invalid_tag.cbor", b"\xc1")
    add_seed(seeds, "invalid_float.cbor", b"\xf9")
    add_seed(seeds, "invalid_simple_value.cbor", b"\xf8")
    add_seed(seeds, "invalid_truncated_text_len.cbor",
             enc_text_with_declared_len("a", 5))
    add_seed(seeds, "invalid_truncated_bytes_len.cbor",
             enc_bytestring_with_declared_len(b"\x00", 5))
    add_seed(seeds, "invalid_array_len_mismatch.cbor",
             enc_array_with_declared_len([enc_uint(1)], 2))
    add_seed(seeds, "invalid_map_len_mismatch.cbor",
             enc_map_with_declared_len([(1, enc_uint(1))], 2, canonical=False))
    add_seed(seeds, "invalid_indefinite_array.cbor",
             enc_indef_array([enc_uint(1)]))
    add_seed(seeds, "invalid_indefinite_bytes.cbor",
             enc_indef_bytes([b"\x00"]))
    add_seed(seeds, "invalid_indefinite_text.cbor",
             enc_indef_text(["a"]))
    add_seed(seeds, "invalid_indefinite_map_with_break.cbor",
             enc_indef_map([(enc_uint(1), enc_uint(1))]))
    add_seed(seeds, "invalid_map_key_not_uint.cbor",
             enc_map_raw([(enc_text("a"), enc_uint(1))]))
    add_seed(seeds, "invalid_duplicate_map_key.cbor",
             enc_map([(1, enc_uint(1)), (1, enc_uint(2))], canonical=False))

    add_seed(seeds, "invalid_negative_integer_overflow.cbor",
             b"\x3b" + (0x8000000000000000).to_bytes(8, "big"))

    add_seed(seeds, "invalid_array_too_large.cbor",
        b"\x9a" + (0x00040001).to_bytes(4, "big"))
    add_seed(seeds, "invalid_map_too_large.cbor",
             b"\xba" + (0x00040001).to_bytes(4, "big"))

    def deep_array(depth: int) -> bytes:
        if depth == 0:
            return enc_uint(1)
        return enc_array([deep_array(depth - 1)])
    add_seed(seeds, "invalid_max_depth.cbor", deep_array(65))

    add_seed(seeds, "invalid_root_not_map.cbor", enc_array([enc_uint(1)]))
    add_seed(seeds, "invalid_missing_required.cbor",
             policy_bytes([(CSK_KIND, enc_text("cindersentinel.policy"))], canonical=True))
    add_seed(seeds, "invalid_unknown_root_field.cbor",
             policy_bytes(policy_entries([], extra=[(99, enc_uint(1))])))
    add_seed(seeds, "invalid_kind_not_text.cbor",
             policy_bytes(policy_entries([], kind=enc_uint(123))))
    add_seed(seeds, "invalid_kind_unexpected.cbor",
             policy_bytes(policy_entries([], kind="other.policy")))
    add_seed(seeds, "invalid_v_not_uint.cbor",
             policy_bytes(policy_entries([], v=enc_text("1"))))
    add_seed(seeds, "invalid_v_unsupported.cbor",
             policy_bytes(policy_entries([], v=2)))
    add_seed(seeds, "invalid_default_action_not_uint.cbor",
             policy_bytes(policy_entries([], default_action=enc_text("let"))))
    add_seed(seeds, "invalid_default_action_forbid.cbor",
             policy_bytes(policy_entries([], default_action=CSA_FORBID)))
    add_seed(seeds, "invalid_ipv4_frag_not_uint.cbor",
             policy_bytes(policy_entries([], ipv4_frag=enc_text("let"))))
    add_seed(seeds, "invalid_ipv4_frag_bad_value.cbor",
             policy_bytes(policy_entries([], ipv4_frag=2)))
    add_seed(seeds, "invalid_ipv4_encap_not_uint.cbor",
             policy_bytes(policy_entries([], ipv4_encap=enc_text("let"))))
    add_seed(seeds, "invalid_ipv4_encap_bad_value.cbor",
             policy_bytes(policy_entries([], ipv4_encap=2)))
    add_seed(seeds, "invalid_rules_not_array.cbor",
             policy_bytes([(CSK_KIND, enc_text("cindersentinel.policy")),
                           (CSK_V, enc_uint(1)),
                           (CSK_RULES, enc_map([(1, enc_uint(1))]))]))

    add_seed(seeds, "invalid_trailing_bytes.cbor",
             policy_bytes(policy_entries([])) + b"\x00")

    add_seed(seeds, "invalid_rule_unknown_field.cbor",
             policy_bytes(policy_entries([enc_map([(CSR_ACTION, enc_uint(CSA_FORBID)),
                                                   (CSR_PROTO, enc_uint(CSP_TCP)),
                                                   (9, enc_uint(1))])])))
    add_seed(seeds, "invalid_rule_missing_action.cbor",
             policy_bytes(policy_entries([enc_map([(CSR_PROTO, enc_uint(CSP_TCP)),
                                                   (CSR_DPORTS, enc_array([enc_uint(80)]))])])))
    add_seed(seeds, "invalid_rule_missing_proto.cbor",
             policy_bytes(policy_entries([enc_map([(CSR_ACTION, enc_uint(CSA_FORBID)),
                                                   (CSR_DPORTS, enc_array([enc_uint(80)]))])])))
    add_seed(seeds, "invalid_rule_action_not_uint.cbor",
             policy_bytes(policy_entries([enc_map([(CSR_ACTION, enc_text("forbid")),
                                                   (CSR_PROTO, enc_uint(CSP_TCP)),
                                                   (CSR_DPORTS, enc_array([enc_uint(80)]))])])))
    add_seed(seeds, "invalid_rule_proto_not_uint.cbor",
             policy_bytes(policy_entries([enc_map([(CSR_ACTION, enc_uint(CSA_FORBID)),
                                                   (CSR_PROTO, enc_text("tcp")),
                                                   (CSR_DPORTS, enc_array([enc_uint(80)]))])])))
    add_seed(seeds, "invalid_rule_action_let.cbor",
             policy_bytes(policy_entries([enc_map([(CSR_ACTION, enc_uint(CSA_LET)),
                                                   (CSR_PROTO, enc_uint(CSP_TCP)),
                                                   (CSR_DPORTS, enc_array([enc_uint(80)]))])])))
    add_seed(seeds, "invalid_rule_action_unknown.cbor",
             policy_bytes(policy_entries([enc_map([(CSR_ACTION, enc_uint(2)),
                                                   (CSR_PROTO, enc_uint(CSP_TCP)),
                                                   (CSR_DPORTS, enc_array([enc_uint(80)]))])])))
    add_seed(seeds, "invalid_rule_proto_unknown.cbor",
             policy_bytes(policy_entries([enc_map([(CSR_ACTION, enc_uint(CSA_FORBID)),
                                                   (CSR_PROTO, enc_uint(9)),
                                                   (CSR_DPORTS, enc_array([enc_uint(80)]))])])))
    add_seed(seeds, "invalid_rule_icmp_with_dports.cbor",
             policy_bytes(policy_entries([enc_map([(CSR_ACTION, enc_uint(CSA_FORBID)),
                                                   (CSR_PROTO, enc_uint(CSP_ICMP)),
                                                   (CSR_DPORTS, enc_array([enc_uint(1)]))])])))
    add_seed(seeds, "invalid_rule_tcp_no_dports.cbor",
             policy_bytes(policy_entries([enc_map([(CSR_ACTION, enc_uint(CSA_FORBID)),
                                                   (CSR_PROTO, enc_uint(CSP_TCP))])])))
    add_seed(seeds, "invalid_rule_udp_no_dports.cbor",
             policy_bytes(policy_entries([enc_map([(CSR_ACTION, enc_uint(CSA_FORBID)),
                                                   (CSR_PROTO, enc_uint(CSP_UDP))])])))

    add_seed(seeds, "invalid_dports_not_array.cbor",
             policy_bytes(policy_entries([enc_map([(CSR_ACTION, enc_uint(CSA_FORBID)),
                                                   (CSR_PROTO, enc_uint(CSP_TCP)),
                                                   (CSR_DPORTS, enc_map([(1, enc_uint(1))]))])])))
    add_seed(seeds, "invalid_dports_empty.cbor",
             policy_bytes(policy_entries([enc_map([(CSR_ACTION, enc_uint(CSA_FORBID)),
                                                   (CSR_PROTO, enc_uint(CSP_TCP)),
                                                   (CSR_DPORTS, enc_array([]))])])))
    add_seed(seeds, "invalid_dport_out_of_range_zero.cbor",
             policy_bytes(policy_entries([enc_map([(CSR_ACTION, enc_uint(CSA_FORBID)),
                                                   (CSR_PROTO, enc_uint(CSP_TCP)),
                                                   (CSR_DPORTS, enc_array([enc_uint(0)]))])])))
    add_seed(seeds, "invalid_dport_out_of_range_high.cbor",
             policy_bytes(policy_entries([enc_map([(CSR_ACTION, enc_uint(CSA_FORBID)),
                                                   (CSR_PROTO, enc_uint(CSP_TCP)),
                                                   (CSR_DPORTS, enc_array([enc_uint(70000)]))])])))
    add_seed(seeds, "invalid_dport_range_bad_size.cbor",
             policy_bytes(policy_entries([enc_map([(CSR_ACTION, enc_uint(CSA_FORBID)),
                                                   (CSR_PROTO, enc_uint(CSP_TCP)),
                                                   (CSR_DPORTS, enc_array([enc_array([enc_uint(1)])]))])])))
    add_seed(seeds, "invalid_dport_range_bounds_not_uint.cbor",
             policy_bytes(policy_entries([enc_map([(CSR_ACTION, enc_uint(CSA_FORBID)),
                                                   (CSR_PROTO, enc_uint(CSP_TCP)),
                                                   (CSR_DPORTS, enc_array([enc_array([enc_text("1"), enc_uint(2)])]))])])))
    add_seed(seeds, "invalid_dport_range_bad_order.cbor",
             policy_bytes(policy_entries([enc_map([(CSR_ACTION, enc_uint(CSA_FORBID)),
                                                   (CSR_PROTO, enc_uint(CSP_TCP)),
                                                   (CSR_DPORTS, enc_array([enc_array([enc_uint(10), enc_uint(5)])]))])])))
    add_seed(seeds, "invalid_dports_element_bad_type.cbor",
             policy_bytes(policy_entries([enc_map([(CSR_ACTION, enc_uint(CSA_FORBID)),
                                                   (CSR_PROTO, enc_uint(CSP_TCP)),
                                                   (CSR_DPORTS, enc_array([enc_text("x")]))])])))

    if heavy:

        rules = [rule_icmp_forbid() for _ in range(4097)]
        add_seed(seeds, "invalid_too_many_rules.cbor",
                 policy_bytes(policy_entries(rules)))


        add_seed(seeds, "invalid_input_too_large.cbor",
                 b"\x5a" + (0x00100001).to_bytes(4, "big") + (b"\x00" * 0x00100001))


        rules = [rule_icmp_forbid() for _ in range(4096)]
        add_seed(seeds, "valid_max_rules.cbor",
                 policy_bytes(policy_entries(rules)))

    return seeds


def main() -> int:
    parser = argparse.ArgumentParser(description="Generate CBOR seed corpus for cindersentinel fuzzing.")
    parser.add_argument("--out-dir", default=None, help="Output corpus directory")
    parser.add_argument("--heavy", action="store_true", help="Generate heavy/large seeds")
    args = parser.parse_args()

    if args.out_dir:
        out_dir = Path(args.out_dir)
    else:
        # default: ../corpus relative to this script
        out_dir = Path(__file__).resolve().parent.parent / "corpus"

    out_dir.mkdir(parents=True, exist_ok=True)

    seeds = gen_seeds(heavy=args.heavy)
    for name, data in seeds:
        (out_dir / name).write_bytes(data)

    print(f"Wrote {len(seeds)} seeds to {out_dir}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
