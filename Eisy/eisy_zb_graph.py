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

Reading the picture (top-down tree rooted at the EISY):
  * Rank 1 = the EISY; Rank 2 = devices 1 hop away; Rank 3 = 2 hops; and so on.
    A device's rank is the shortest path seen for it in any route record.
  * solid arrows   = each device's link toward the EISY on that shortest path
                     (thicker = used more often)
  * grey dashed    = other hops seen in route records (longer / alternate routes)
  * dotted arrows  = parent at join time, where it differs from the drawn route
  * a device heard with no route record is placed at Rank 2 (talks to the EISY directly)
  * links into the EISY are coloured by RSSI: green > -70 dBm, orange -70..-85, red < -85
  * box = EISY, ellipse = router (seen relaying), note = end device
Only the hop into the EISY carries a measured signal value; Zigbee route records do not
report the quality of the inner hops.
"""

import argparse
import csv
# import os
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
        with open(args.names, newline="", encoding="utf-8") as fh:
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
    hop_count = Counter()              # (closer, farther) -> times seen, i.e. edges point away from the EISY
    for path, c in routes.items():
        for a, b in zip(path, path[1:]):
            hop_count[(b, a)] += c

    with_route = {path[0] for path in routes}
    direct = {n for n in heard if n not in with_route and n not in routers}
    nodes = {0} | {n for path in routes for n in path} | direct
    if not args.no_parents:
        nodes |= {n for n, p in parent.items() if p in nodes or p == 0}

    # ---- hop distance from the EISY: shortest path through any link seen in route records
    #      (a device can be fewer hops away than its own longest record if a relay it uses
    #       was itself seen closer to the EISY)
    dist = {0: 0}
    for n in direct:
        dist[n] = 1
    changed = True
    while changed:
        changed = False
        for (closer, farther) in hop_count:
            if closer in dist and dist[closer] + 1 < dist.get(farther, 99):
                dist[farther] = dist[closer] + 1
                changed = True
    # devices known only from a join: one hop below their parent
    for _ in range(5):
        for n, p in parent.items():
            if n in nodes and n not in dist and p in dist:
                dist[n] = dist[p] + 1
    for n in nodes:
        dist.setdefault(n, 1)

    # ---- primary link for each device: its most-used next hop that is exactly one rank closer
    primary = {}
    for (closer, farther), c in hop_count.items():
        if dist.get(closer, 99) == dist[farther] - 1:
            if farther not in primary or c > hop_count[(primary[farther], farther)]:
                primary[farther] = closer
    for n in direct:
        primary[n] = 0
    for n, p in parent.items():
        if n in nodes and n not in primary and dist.get(p, 99) == dist[n] - 1:
            primary[n] = p

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
        if n in with_route:
            hs = sorted({len(p) - 1 for p in routes if p[0] == n})
            if len(hs) > 1:
                lines.append(f"also seen at {', '.join(str(h) for h in hs if h != dist[n])} hops")
        return "\\n".join(lines)

    maxrank = max(dist.values())
    out = ['digraph zigbee {',
           '  graph [rankdir=TB, fontname="Helvetica", labelloc=t, newrank=true, '
           'label="Zigbee mesh seen in EISY log: rank = hops from the EISY (shortest path seen)\\n'
           'solid = route used (thicker = more often)   grey dashed = other route seen   '
           'dotted = join parent", fontsize=13, nodesep=0.3, ranksep=0.8];',
           '  node [fontname="Helvetica", fontsize=10];',
           '  edge [fontname="Helvetica", fontsize=9];']

    # rank labels down the left side, chained invisibly so they line up with the rows
    for r in range(maxrank + 1):
        txt = "Rank 1\\nEISY" if r == 0 else f"Rank {r + 1}\\n{r} hop{'s' if r > 1 else ''}"
        out.append(f'  rank{r} [label="{txt}", shape=plaintext, fontsize=12, fontcolor=gray30];')
    out.append("  " + " -> ".join(f"rank{r}" for r in range(maxrank + 1)) + " [style=invis];")

    for r in range(maxrank + 1):
        members = sorted(n for n in nodes if dist[n] == r)
        out.append(f'  {{ rank=same; rank{r}; ' + " ".join(f"n{n};" for n in members) + " }")

    for n in sorted(nodes):
        if n == 0:
            out.append('  n0 [label="EISY\\n0x0000", shape=box, style="filled,bold", fillcolor="#1f4e79", fontcolor=white, fontsize=12];')
        elif n in routers:
            out.append(f'  n{n} [label="{label(n)}", shape=ellipse, style=filled, fillcolor="#dbe9f6"];')
        else:
            out.append(f'  n{n} [label="{label(n)}", shape=note, style=filled, fillcolor="#fff4d6"];')

    def signal_label(child):
        sigs = [last_hop[p[0]][1] for p in routes if p[-2] == child and p[0] in last_hop]
        if child in direct:
            sigs = [heard[child][1]]
        return round(sum(sigs) / len(sigs)) if sigs else None

    maxc = max(hop_count.values(), default=1)
    drawn = set()
    for child, par in sorted(primary.items()):
        c = hop_count.get((par, child), 0)
        attrs = [f"penwidth={1 + 3 * c / maxc:.1f}" if c else "penwidth=1"]
        if c:
            attrs.append(f'tooltip="{c} route record(s)"')
            attrs.append(f'weight={c}')
        if par == 0:
            r = signal_label(child)
            attrs += [f"color={rssi_color(r)}", f'label=" {r} dBm"' if r is not None else ""]
        print(f"c={c} r={r}")
        if not c and child in direct:
            attrs.append("style=dashed")
        out.append(f'  n{par} -> n{child} [{", ".join(x for x in attrs if x)}];')
        drawn.add((par, child))

    for (par, child), c in sorted(hop_count.items()):
        if (par, child) in drawn:
            continue
        out.append(f'  n{par} -> n{child} [style=dashed, color=gray60, constraint=false, '
                   f'tooltip="other route, {c} record(s)"];')
        drawn.add((par, child))

    if not args.no_parents:
        for n, par in sorted(parent.items()):
            if n in nodes and par in nodes and (par, n) not in drawn:
                out.append(f'  n{par} -> n{n} [style=dotted, color=gray40, arrowhead=empty, '
                           f'constraint=false, label=" parent"];')
    out.append("}")

    dot_path = args.out + ".dot"
    with open(dot_path, "w", encoding="utf-8") as fh:
        fh.write("\n".join(out) + "\n")

    rendered = []
    if shutil.which("dot"):
        for fmt in ("svg", "png"):
            subprocess.run(["dot", f"-T{fmt}", "-Gdpi=130" if fmt == "png" else "-Gdpi=72",
                            dot_path, "-o", f"{args.out}.{fmt}"], check=True)
            rendered.append(f"{args.out}.{fmt}")
    else:
        print("Graphviz not found: install it (e.g. 'brew install graphviz' / 'apt install graphviz') "
              "or paste the .dot file into https://dreampuf.github.io/GraphvizOnline")

    print(f"wrote {dot_path}  ({len(nodes)} nodes, ranks 1-{maxrank + 1}, {len(hop_count)} routed hops)")
    for f in rendered:
        print(f"wrote {f}")
    print("\nPaths (most used first):")
    for path, c in routes.most_common():
        names = " → ".join("EISY" if n == 0 else f"0x{n:04X}" for n in path)
        print(f"  {c:>4}×  {names}")


if __name__ == "__main__":
    try:
        main()
    except BrokenPipeError:
        pass
