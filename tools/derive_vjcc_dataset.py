"""Reduce a VM-D VJCC trace (JSON lines, one record per vmd_078 execution) to data/vmd_vjcc_observed.csv.

Each trace record holds the operand pointer (VIP), the flags word read from the context, the condition
code, the taken byte the handler itself wrote, both successor VIPs and a 0xC4-byte context snapshot.
The trace is not shipped; this script documents how the CSV was produced.

Usage: python derive_vjcc_dataset.py TRACE.jsonl.gz OUT.csv
"""
import collections
import gzip
import json
import struct
import sys

VIP_FIELD = 0x25


def main(trace, out):
    rows = collections.Counter()
    meta = {}
    summary = None
    with gzip.open(trace, "rt") as f:
        for line in f:
            e = json.loads(line)
            if "end" in e:
                summary = e
                continue
            assert e["k"] == "0x78", e["k"]
            ctx = bytes.fromhex(e["ctx"])
            vip, slot, flags = int(e["vip"], 16), int(e["slot"], 16), int(e["flags"], 16)
            # The snapshot agrees with the decoded fields: VIP at +0x25, flags at +slot.
            assert struct.unpack_from("<I", ctx, VIP_FIELD)[0] == vip
            assert struct.unpack_from("<I", ctx, slot)[0] == flags
            key = (vip, flags, int(e["taken"]))
            rows[key] += 1
            meta[vip] = (int(e["cc"], 16), slot, int(e["taken_vip"], 16), int(e["fall_vip"], 16))
    with open(out, "w", newline="\n") as f:
        f.write("# vmd_078 executions from one offline run, stage-1 lock to the first MessageBox call\n")
        f.write(f"# records={sum(rows.values())} rows={len(rows)} run_mismatches={summary['mismatch']}\n")
        f.write("vip,cc,slot,flags,taken,taken_vip,fall_vip,count\n")
        for (vip, flags, taken), n in sorted(rows.items()):
            cc, slot, tv, fv = meta[vip]
            f.write(f"{vip:08x},{cc:02x},{slot:04x},{flags:08x},{taken},{tv:08x},{fv:08x},{n}\n")
    print(f"{sum(rows.values())} records -> {len(rows)} rows")


if __name__ == "__main__":
    main(sys.argv[1], sys.argv[2])
