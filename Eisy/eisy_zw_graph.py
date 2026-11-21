#!/usr/bin/env python3
"""
eisy_zw_graph.py - Draw the Z-Wave mesh from an EISY / IoX ZWAY.LOG.

Builds a graph from what the log shows:
  * neighbour tables ("List of neighbours for node N", read from the Z-Wave chip)  -> radio links
  * routes actually used:
      - outgoing: SendData delivery reports (last route repeaters, EZSP-style TX report)
      - incoming: repeaters appended to received frames
  * failed links reported in delivery reports ("failed link from A to B")
  * delivery failures (NO_ACK / FAIL) and average RSSI per node
  * node labels from Z-Way's vendorString / deviceTypeString / givenName

Output: Graphviz .dot, rendered to .svg and .png when Graphviz is installed.

Usage:
    python3 eisy_zw_graph.py ZWAY.LOG -o zwave_mesh                 # tree: rows by hop count
    python3 eisy_zw_graph.py ZWAY.LOG --layout mesh                 # free-form radio map
    python3 eisy_zw_graph.py ZWAY.LOG --all-hops                    # tree + sideways/backward hops
    python3 eisy_zw_graph.py ZWAY.LOG --names names.csv   # optional "node,label" overrides
    python3 eisy_zw_graph.py ZWAY.LOG --no-neighbours     # routes only

Reading the picture:
  * thin grey line   = neighbours (both nodes list each other); dotted = only one side lists it
  * blue line        = a hop used by real traffic (thicker = used more; label = times used)
  * red dashed line  = a link reported as FAILED in a delivery report (label = times)
  * node outline red = node had failed deliveries; label shows failures, avg RSSI, hops
  * box = controller (EISY), ellipse = mains / always-listening, note = battery / sleeping
"""

import argparse
import csv
import re
import shutil
import subprocess
from collections import Counter, defaultdict

FRAME_RE = re.compile(r"\b(SENDING|RECEIVED)(?: \(cb 0x[0-9A-Fa-f]+\))?: \( ([0-9A-Fa-f ]+)\)")
NBR_RE = re.compile(r"List of neighbours for node (\d+): \[([0-9a-fA-F ]*)\]")
STR_RE = re.compile(r"SETDATA devices\.(\d+)\.data\.(vendorString|deviceTypeString|givenName) = \"([^\"]*)\"")
LISTEN_RE = re.compile(r"SETDATA devices\.(\d+)\.data\.isListening = (True|False)")
RSSI_SPECIAL = {0x7F, 0x7E, 0x7D}


def s8(v):
    return v - 256 if v > 127 else v


def main():
    ap = argparse.ArgumentParser(description="Draw the Z-Wave mesh from EISY ZWAY.LOG files.")
    ap.add_argument("files", nargs="+")
    ap.add_argument("-o", "--out", default="zwave_mesh")
    ap.add_argument("--names", help="CSV node,label overrides")
    ap.add_argument("--no-neighbours", action="store_true", help="draw only routes actually used")
    ap.add_argument("--controller", type=int, default=1, help="controller node id (default 1)")
    ap.add_argument("--layout", choices=["tree", "mesh"], default="tree",
                    help="tree (default): rows by hop count from the EISY; mesh: free-form radio map")
    ap.add_argument("--hops", choices=["usual", "min"], default="usual",
                    help="tree row = hop position the device most often holds in real traffic (default), or the fewest hops ever seen")
    ap.add_argument("--all-hops", action="store_true",
                    help="tree layout: also draw hops between nodes on the same row or back toward the EISY")
    args = ap.parse_args()
    ctl = args.controller

    nbrs = {}                                  # node -> set(neighbours), last table read wins
    info = defaultdict(dict)
    listening = {}
    used = Counter()                           # frozenset({a,b}) -> times a route used this hop
    failed = Counter()                         # frozenset({a,b}) -> times reported failed
    paths = Counter()                          # tuple path -> count
    rssi = defaultdict(list)
    nack = Counter()
    tx = Counter()
    cb_dest = {}

    for fn in args.files:
        with open(fn, encoding="utf-8", errors="replace") as fh:
            for line in fh:
                m = NBR_RE.search(line)
                if m:
                    nbrs[int(m.group(1))] = {int(x, 16) for x in m.group(2).split()}
                    continue
                m = STR_RE.search(line)
                if m:
                    if m.group(3):
                        info[int(m.group(1))][m.group(2)] = m.group(3)
                    continue
                m = LISTEN_RE.search(line)
                if m:
                    listening[int(m.group(1))] = m.group(2) == "True"
                    continue
                m = FRAME_RE.search(line)
                if not m:
                    continue
                b = [int(x, 16) for x in m.group(2).split()]
                if len(b) < 5 or b[0] != 1:
                    continue
                ftype, func, p = b[2], b[3], b[4:-1]
                try:
                    if m.group(1) == "SENDING" and func == 0x13:
                        dest, ln = p[0], p[1]
                        if len(p) > 3 + ln:
                            cb_dest[p[3 + ln]] = dest
                        tx[dest] += 1
                    elif m.group(1) == "RECEIVED" and ftype == 0 and func == 0x13 and len(p) >= 21:
                        dest = cb_dest.pop(p[0], None)
                        if dest is None:
                            continue
                        st = p[1]
                        reps = [r for r in p[13:17] if r]
                        if st == 0:
                            path = (ctl, *reps, dest)
                            paths[path] += 1
                            for a, c in zip(path, path[1:]):
                                used[frozenset((a, c))] += 1
                        else:
                            nack[dest] += 1
                        if p[19] and p[20] and p[19] != 0x7F:
                            failed[frozenset((p[19], p[20]))] += 1
                    elif m.group(1) == "RECEIVED" and ftype == 0 and func == 0x04:
                        src, ln = p[1], p[2]
                        tail = p[3 + ln:]
                        if tail and tail[0] not in RSSI_SPECIAL:
                            rssi[src].append(s8(tail[0]))
                        if len(tail) >= 3 and tail[2] <= 4 and len(tail) >= 3 + tail[2]:
                            reps = tail[3:3 + tail[2]]
                            path = (src, *reps, ctl)
                            paths[path] += 1
                            for a, c in zip(path, path[1:]):
                                used[frozenset((a, c))] += 1
                except IndexError:
                    continue

    overrides = {}
    if args.names:
        with open(args.names, newline="") as fh:
            for row in csv.reader(fh):
                if len(row) >= 2 and row[0].strip().isdigit():
                    overrides[int(row[0])] = row[1].strip()

    nodes = {ctl} | set(nbrs) | {n for e in used for n in e} | set(rssi) | set(tx)
    nodes |= {n for s in nbrs.values() for n in s}
    nodes = {n for n in nodes if 0 < n < 233}

    hops = defaultdict(set)
    for path in paths:
        far = path[-1] if path[0] == ctl else path[0]
        hops[far].add(len(path) - 1)

    def label(n):
        if n in overrides:
            name = overrides[n]
        else:
            d = info.get(n, {})
            name = " ".join(x for x in (d.get("vendorString", ""), d.get("deviceTypeString", "")) if x)
        lines = [f"Node {n}" + (" (EISY)" if n == ctl else "")]
        if name:
            import textwrap
            lines += textwrap.wrap(name, 22)[:2]
        if n != ctl:
            bits = []
            if hops.get(n):
                hs = sorted(hops[n])
                bits.append(f"{hs[0]}" + (f"–{hs[-1]}" if len(hs) > 1 else "") + " hop" + ("s" if hs[-1] > 1 else ""))
            if rssi.get(n):
                bits.append(f"{sum(rssi[n]) / len(rssi[n]):.0f} dBm")
            if nack.get(n):
                bits.append(f"{nack[n]}/{tx[n]} sends failed")
            if n in nbrs and not nbrs[n]:
                bits.append("NO neighbours")
            if bits:
                lines.append(", ".join(bits))
        return "\\n".join(lines).replace('"', "'")

    if args.layout == "tree":
        out = build_tree(args, ctl, nodes, paths, failed, nbrs, listening, nack, label)
        engine = "dot"
    else:
        out = build_mesh(args, ctl, nodes, used, failed, nbrs, listening, nack, label)
        engine = "neato"

    with open(args.out + ".dot", "w") as fh:
        fh.write("\n".join(out) + "\n")
    print(f"wrote {args.out}.dot  ({len(nodes)} nodes, {len(used)} used hops, "
          f"{len(failed)} failed links, {sum(len(s) for s in nbrs.values())} neighbour entries)")
    if shutil.which(engine):
        for fmt in ("svg", "png"):
            subprocess.run([engine, f"-T{fmt}", "-Gdpi=130" if fmt == "png" else "-Gdpi=72",
                            args.out + ".dot", "-o", f"{args.out}.{fmt}"], check=True)
            print(f"wrote {args.out}.{fmt}")
    else:
        print(f"Graphviz not found: install it, or paste the .dot into "
              f"https://dreampuf.github.io/GraphvizOnline (engine '{engine}')")

    print("\nRoutes used (most first):")
    for path, c in paths.most_common(25):
        print(f"  {c:>5}×  " + " → ".join("EISY" if n == ctl else str(n) for n in path))
    if failed:
        print("\nFailed links:")
        for e, c in failed.most_common():
            a, b = sorted(e)
            print(f"  {c:>5}×  {a} ↔ {b}")


def node_style(n, ctl, listening, nack, nbrs):
    if n == ctl:
        attrs = ['shape=box', 'style="filled,bold"', 'fillcolor="#1f4e79"', 'fontcolor=white']
    elif listening.get(n) is False:
        attrs = ['shape=note', 'style=filled', 'fillcolor="#fff4d6"']
    else:
        attrs = ['shape=ellipse', 'style=filled', 'fillcolor="#dbe9f6"']
    if nack.get(n) or (n in nbrs and not nbrs[n]):
        attrs += ['color=red3', 'penwidth=2']
    return attrs


def build_tree(args, ctl, nodes, paths, failed, nbrs, listening, nack, label):
    """Directed graph rooted at the EISY: row k = devices whose shortest route seen is k hops."""
    outward = Counter()                       # (a, b) with a nearer the EISY on that route
    for path, c in paths.items():
        p = path if path[0] == ctl else tuple(reversed(path))
        for a, b in zip(p, p[1:]):
            if a != b:
                outward[(a, b)] += c

    level = {ctl: 0}
    if args.hops == "min":
        for path in paths:
            p = path if path[0] == ctl else tuple(reversed(path))
            for i, n in enumerate(p):
                level[n] = min(level.get(n, 99), i)
    else:
        # row = the position a node most often holds across all traffic it takes part in,
        # as the end device or as a relay (weighted by how often each route was used)
        pos = defaultdict(Counter)
        for path, c in paths.items():
            p = path if path[0] == ctl else tuple(reversed(path))
            for i, n in enumerate(p[1:], 1):
                pos[n][i] += c
        for n, cnt in pos.items():
            level[n] = min(cnt.items(), key=lambda kv: (-kv[1], kv[0]))[0]

    # devices never routed: neighbours of the EISY go on row 1, the rest on a "no traffic" row
    ctl_nbrs = nbrs.get(ctl, set()) | {n for n, s in nbrs.items() if ctl in s}
    unrouted = sorted(n for n in nodes if n not in level)
    silent_row = max(level.values(), default=0) + 1
    for n in unrouted:
        level[n] = 1 if n in ctl_nbrs else silent_row

    rows = defaultdict(list)
    for n in nodes:
        rows[level[n]].append(n)

    out = ['digraph zwave {',
           '  graph [rankdir=TB, splines=true, nodesep=0.25, ranksep=1.1, fontname="Helvetica", '
           'labelloc=t, fontsize=12, newrank=true, label="Z-Wave mesh from EISY log: rows = ' + ('fewest hops seen' if args.hops == 'min' else 'hops on the route each device most often sits on') + ' to the EISY\\n'
           'blue = hop used by traffic (thicker = more, dark = busiest parent)   grey dashed = neighbour of EISY, no traffic seen   '
           'red dashed = reported failed link"];',
           '  node [fontname="Helvetica", fontsize=10];',
           '  edge [fontname="Helvetica", fontsize=9, arrowsize=0.7];']

    # row labels down the left side
    for k in sorted(rows):
        txt = "EISY" if k == 0 else ("no traffic seen" if k == silent_row and unrouted
                                     and all(n not in ctl_nbrs for n in rows[k]) else f"{k} hop{'s' if k > 1 else ''}")
        out.append(f'  row{k} [label="{txt}", shape=plaintext, fontsize=12, fontcolor=gray35];')
    ks = sorted(rows)
    for a, b in zip(ks, ks[1:]):
        out.append(f'  row{a} -> row{b} [style=invis];')

    for k in ks:
        out.append(f'  {{ rank=same; row{k}; ' + " ".join(f"n{n};" for n in sorted(rows[k])) + " }")
        for n in sorted(rows[k]):
            attrs = [f'label="{label(n)}"'] + node_style(n, ctl, listening, nack, nbrs)
            out.append(f'  n{n} [{", ".join(attrs)}];')

    # parent edges: hops that go one row further from the EISY
    best_parent = {}
    for (a, b), c in outward.items():
        if level.get(b) == level.get(a, 99) + 1 and c > outward.get((best_parent.get(b), b), 0):
            best_parent[b] = a
    maxc = max(outward.values(), default=1)
    for (a, b), c in sorted(outward.items(), key=lambda kv: -kv[1]):
        if a not in nodes or b not in nodes:
            continue
        w = f"{1 + 4 * c / maxc:.1f}"
        if level.get(b) == level.get(a, 99) + 1:
            color = "#1a4f8b" if best_parent.get(b) == a else "#7fa7d6"
            out.append(f'  n{a} -> n{b} [color="{color}", penwidth={w}, label="{c}"];')
        elif args.all_hops:
            out.append(f'  n{a} -> n{b} [color=gray60, style=dotted, constraint=false, label="{c}"];')

    for n in unrouted:
        if n in ctl_nbrs:
            out.append(f'  n{ctl} -> n{n} [color=gray55, style=dashed, arrowhead=none];')
    for e, c in failed.items():
        a, b = sorted(e, key=lambda x: (level.get(x, 99), x))
        if a in nodes and b in nodes:
            out.append(f'  n{a} -> n{b} [color=red3, style=dashed, constraint=false, '
                       f'label="failed {c}×", fontcolor=red3];')
    out.append("}")
    return out


def build_mesh(args, ctl, nodes, used, failed, nbrs, listening, nack, label):
    out = ['graph zwave {',
           '  graph [layout=neato, overlap=false, splines=true, sep="+18", fontname="Helvetica", '
           'labelloc=t, fontsize=12, label="Z-Wave mesh from EISY log\\n'
           'grey = neighbours (dotted: one-sided)   blue = hop used by traffic   red dashed = reported failed link"];',
           '  node [fontname="Helvetica", fontsize=10];',
           '  edge [fontname="Helvetica", fontsize=9];']
    for n in sorted(nodes):
        attrs = [f'label="{label(n)}"'] + node_style(n, ctl, listening, nack, nbrs)
        if n == ctl:
            attrs.append('pos="0,0!"')
        out.append(f'  n{n} [{", ".join(attrs)}];')

    drawn = set()
    maxu = max(used.values(), default=1)
    for e, c in sorted(used.items(), key=lambda kv: -kv[1]):
        a, b = sorted(e) if len(e) == 2 else (next(iter(e)),) * 2
        if a == b or a not in nodes or b not in nodes:
            continue
        out.append(f'  n{a} -- n{b} [color="#2b6cb0", penwidth={1.2 + 4 * c / maxu:.1f}, label="{c}", len=1.6];')
        drawn.add(e)
    for e, c in failed.items():
        a, b = sorted(e)
        if a in nodes and b in nodes:
            out.append(f'  n{a} -- n{b} [color=red3, style=dashed, penwidth=1.5, label="failed {c}×", len=1.8];')
    if not args.no_neighbours:
        seen = set()
        for a, s in nbrs.items():
            for b in s:
                e = frozenset((a, b))
                if e in seen or e in drawn or a == b or a not in nodes or b not in nodes:
                    continue
                seen.add(e)
                mutual = a in nbrs.get(b, set()) or b not in nbrs
                style = "solid" if mutual else "dotted"
                out.append(f'  n{min(a, b)} -- n{max(a, b)} [color=gray65, style={style}, len=2.2];')
    out.append("}")
    return out


if __name__ == "__main__":
    try:
        main()
    except BrokenPipeError:
        pass
