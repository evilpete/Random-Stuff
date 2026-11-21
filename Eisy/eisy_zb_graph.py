#!/usr/bin/env python3
"""
eisy_zb_graph.py - Draw the Zigbee mesh paths seen in EISY / IoX ZBEE.LOG files.

Builds a graph from what the log actually shows:
  * route records (EZSP 0x0059): device -> relay -> relay -> EISY, with how often each path was used
  * join records (EZSP 0x0024): which router each device joined through (its parent)
  * incoming messages (EZSP 0x0045): last-hop LQI/RSSI, and devices heard with no route record
  * Basic cluster data (manufacturer / model) for node labels

Output: a Graphviz .dot file, rendered to .svg and .png when Graphviz ("dot") is installed.

Usage:
    python3 eisy_zb_graph.py ZBEE.LOG [more.log ...] -o zigbee_mesh
    python3 eisy_zb_graph.py ZBEE.LOG --names names.csv     # optional "node,label" overrides

Reading the picture:
  * solid arrows   = hops taken from route records (thicker = used more often)
  * dotted arrows  = parent at join time (end device -> router it joined through)
  * dashed arrows  = device heard with no route record (direct to the EISY, or routed via a
                     router that is itself a direct neighbour)
  * the hop into the EISY is coloured by its RSSI: green > -70 dBm, orange -70..-85, red < -85
  * box = EISY, ellipse = router (seen relaying), note = end device
Only the hop into the EISY carries a measured signal value; Zigbee route records do not
report the quality of the inner hops.
"""

import argparse
import csv
import os
import re
import shutil
import subprocess
from collections import Counter, defaultdict

EZSP_RE = re.compile(r"RECEIVED EZSP: \(([0-9A-Fa-f ]+)\)")
MODEL_RE = re.compile(r"SETDATA devices\.(\d+)\.endpoints\.\d+\.clusters\.0\.data\.(manufacturerName|modelIdentifier) = \"([^\"]+)\"")


def u16(b, i):
    return b[i] | (b[i + 1] << 8)


def s8(v):
    return v - 256 if v > 127 else v


def eui(b, i):
    return ":".join(f"{x:02X}" for x in reversed(b[i:i + 8]))


def rssi_color(r):
    if r is None:
        return "gray50"
    if r > -70:
        return "forestgreen"
    if r >= -85:
        return "darkorange"
    return "red3"


def main():
    ap = argparse.ArgumentParser(description="Draw Zigbee mesh paths from EISY logs.")
    ap.add_argument("files", nargs="+")
    ap.add_argument("-o", "--out", default="zigbee_mesh", help="output file prefix")
    ap.add_argument("--names", help="CSV of node,label to override labels (node decimal or 0xHEX)")
    ap.add_argument("--no-parents", action="store_true", help="hide join-parent arrows")
    args = ap.parse_args()

    routes = Counter()                 # tuple(path) -> count, path = (src, r1, ..., 0)
    last_hop = {}                      # src -> (lqi, rssi) from route records
    heard = {}                         # src -> (lqi, rssi) from incoming messages
    parent = {}                        # src -> parent
    ieee = {}
    model = defaultdict(dict)
    left = set()

    for fn in args.files:
        with open(fn, encoding="utf-8", errors="replace") as fh:
            for line in fh:
                m = MODEL_RE.search(line)
                if m:
                    model[int(m.group(1))][m.group(2)] = m.group(3)
                    continue
                m = EZSP_RE.search(line)
                if not m:
                    continue
                b = [int(x, 16) for x in m.group(1).split()]
                if len(b) < 5:
                    continue
                fid, p = u16(b, 3), b[5:]
                try:
                    if fid == 0x0059:
                        src, cnt = u16(p, 0), p[12]
                        ieee[src] = eui(p, 2)
                        relays = [u16(p, 13 + 2 * k) for k in range(cnt)]
                        routes[(src, *relays, 0)] += 1
                        last_hop[src] = (p[10], s8(p[11]))
                    elif fid == 0x0024:
                        n, st, par = u16(p, 0), p[10], u16(p, 12)
                        ieee[n] = eui(p, 2)
                        if st == 2:
                            left.add(n)
                        else:
                            parent[n] = par
                            left.discard(n)
                    elif fid == 0x0045:
                        sender = u16(p, 14)
                        if sender != 0:
                            heard[sender] = (p[12], s8(p[13]))
                except IndexError:
                    continue

    overrides = {}
    if args.names:
        with open(args.names, newline="") as fh:
            for row in csv.reader(fh):
                if len(row) >= 2 and row[0].strip():
                    k = row[0].strip()
                    overrides[int(k, 16) if k.lower().startswith("0x") else int(k)] = row[1].strip()

    # ---- drop addresses that left the network (stale short addresses of re-paired devices)
    for path in [p for p in routes if p[0] in left]:
        del routes[path]
    for n in left:
        parent.pop(n, None)
        heard.pop(n, None)

    # ---- collect nodes and edges
    routers = {r for path in routes for r in path[1:-1]} | set(parent.values())
    routers.discard(0)
    hop_count = Counter()
    for path, c in routes.items():
        for a, b in zip(path, path[1:]):
            hop_count[(a, b)] += c

    with_route = {path[0] for path in routes}
    direct = {n for n in heard if n not in with_route and n not in routers and n not in left}
    # routers that never appear with a route record but relay traffic are next to the EISY
    nodes = {0} | {n for path in routes for n in path} | set(parent) | set(parent.values()) | direct
    nodes -= left - with_route

    def label(n):
        if n == 0:
            return "EISY\\n0x0000"
        if n in overrides:
            name = overrides[n]
        else:
            md = model.get(n, {})
            name = " ".join(x for x in (md.get("manufacturerName", ""), md.get("modelIdentifier", "")) if x)
        lines = [name] if name else []
        lines.append(f"0x{n:04X} ({n})")
        sig = last_hop.get(n) or heard.get(n)
        if n in with_route:
            hs = sorted({len(p) - 1 for p in routes if p[0] == n})
            txt = f"{hs[0]}" if len(hs) == 1 else f"{hs[0]}–{hs[-1]}"
            lines.append(f"{txt} hop{'s' if hs[-1] > 1 else ''}")
        return "\\n".join(lines)

    out = ['digraph zigbee {',
           '  graph [rankdir=RL, fontname="Helvetica", labelloc=t, '
           'label="Zigbee mesh paths seen in EISY log\\nsolid = route record  dotted = join parent  '
           'dashed = heard without route record", fontsize=12, nodesep=0.35, ranksep=0.9];',
           '  node [fontname="Helvetica", fontsize=10];',
           '  edge [fontname="Helvetica", fontsize=9];']
    for n in sorted(nodes):
        if n == 0:
            out.append('  n0 [label="EISY\\n0x0000", shape=box, style="filled,bold", fillcolor="#1f4e79", fontcolor=white];')
        elif n in routers:
            out.append(f'  n{n} [label="{label(n)}", shape=ellipse, style=filled, fillcolor="#dbe9f6"];')
        else:
            out.append(f'  n{n} [label="{label(n)}", shape=note, style=filled, fillcolor="#fff4d6"];')

    maxc = max(hop_count.values(), default=1)
    for (a, b), c in sorted(hop_count.items()):
        attrs = [f'penwidth={1 + 3 * c / maxc:.1f}', f'tooltip="{c} route record(s)"']
        if b == 0:
            # the hop into the EISY: colour by the last-hop signal of sources using it
            sigs = [last_hop[p[0]][1] for p in routes if p[-2] == a and p[0] in last_hop]
            r = round(sum(sigs) / len(sigs)) if sigs else None
            attrs += [f'color={rssi_color(r)}', f'label="{r} dBm"' if r is not None else ""]
        out.append(f'  n{a} -> n{b} [{", ".join(x for x in attrs if x)}];')

    for n in sorted(direct):
        lqi, r = heard[n]
        out.append(f'  n{n} -> n0 [style=dashed, color={rssi_color(r)}, label="{r} dBm"];')

    if not args.no_parents:
        for n, par in sorted(parent.items()):
            if n in nodes and par in nodes and (n, par) not in hop_count:
                out.append(f'  n{n} -> n{par} [style=dotted, color=gray40, arrowhead=empty, label="parent"];')
    out.append("}")

    dot_path = args.out + ".dot"
    with open(dot_path, "w") as fh:
        fh.write("\n".join(out) + "\n")
    print(f"wrote {dot_path}  ({len(nodes)} nodes, {len(hop_count)} routed hops, {len(direct)} direct-heard)")

    if shutil.which("dot"):
        for fmt in ("svg", "png"):
            subprocess.run(["dot", f"-T{fmt}", "-Gdpi=130" if fmt == "png" else "-Gdpi=72",
                            dot_path, "-o", f"{args.out}.{fmt}"], check=True)
            print(f"wrote {args.out}.{fmt}")
    else:
        print("Graphviz not found: install it (e.g. 'brew install graphviz' / 'apt install graphviz') "
              "or paste the .dot file into https://dreampuf.github.io/GraphvizOnline")

    print("\nPaths (most used first):")
    for path, c in routes.most_common():
        names = " → ".join("EISY" if n == 0 else f"0x{n:04X}" for n in path)
        print(f"  {c:>4}×  {names}")


if __name__ == "__main__":
    try:
        main()
    except BrokenPipeError:
        pass
