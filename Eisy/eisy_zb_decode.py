#!/usr/bin/env python3
"""
eisy_zb_decode.py - Decode Zigbee (EZSP) traces from a Universal Devices EISY / IoX log.

It reads the "RECEIVED EZSP" / "SENDING EZSP" lines (already de-framed from ASH by IoX),
decodes the EZSP frame, the APS header, and the ZCL / ZDO payload, and prints one
readable line per event plus an optional per-node summary.

Usage:
    python3 eisy_zb_decode.py ZBEE.LOG                 # decode everything
    python3 eisy_zb_decode.py ZBEE.LOG --node 14899    # one node (decimal or 0x3A33)
    python3 eisy_zb_decode.py ZBEE.LOG --summary       # per-node summary only
    python3 eisy_zb_decode.py ZBEE.LOG --routes --iox  # also route records + IoX node updates
    cat snippet.txt | python3 eisy_zb_decode.py -      # read from stdin

Options:
    --node N      only events to/from node N (decimal or hex, e.g. 56648 or 0xDD48)
    --summary     print only the per-node summary table
    --no-summary  do not print the summary table
    --routes      print route records (hidden by default; still used for IEEE / hops)
    --iox         also print IoX node events (node creation, Update Status, interview)
    --no-tx       hide frames the EISY sends (and their send confirmations)
    --raw         append the raw ZCL/ZDO payload bytes to each line

Covers EZSP pre-v14 callback layouts as used by current IoX builds:
incomingMessageHandler (0x0045), incomingRouteRecordHandler (0x0059),
trustCenterJoinHandler (0x0024), messageSentHandler (0x003F), sendUnicast (0x0034),
sendBroadcast (0x0036), incomingNetworkStatusHandler (0x00C4).
"""

import argparse
import re
import struct
import sys
from collections import defaultdict

# --------------------------------------------------------------------------- tables

CLUSTERS = {
    0x0000: "Basic", 0x0001: "PowerCfg", 0x0003: "Identify", 0x0004: "Groups",
    0x0005: "Scenes", 0x0006: "OnOff", 0x0008: "Level", 0x000A: "Time",
    0x0012: "MultistateIn", 0x0019: "OTA", 0x0020: "PollCtrl", 0x0102: "WindowCovering",
    0x0201: "Thermostat", 0x0300: "Color", 0x0400: "Illuminance", 0x0402: "Temperature",
    0x0403: "Pressure", 0x0405: "Humidity", 0x0406: "Occupancy", 0x0408: "SoilMoisture",
    0x0500: "IASZone", 0x0702: "Metering", 0x0B04: "ElecMeasure", 0x0B05: "Diagnostics",
    0xE000: "Tuya-E000", 0xE001: "Tuya-E001", 0xEF00: "Tuya-EF00", 0xFF01: "Mfr-FF01",
    0xFCC0: "Aqara-FCC0",
}

ZDO = {
    0x0000: "NWK_addr_req", 0x0001: "IEEE_addr_req", 0x0002: "Node_Desc_req",
    0x0003: "Power_Desc_req", 0x0004: "Simple_Desc_req", 0x0005: "Active_EP_req",
    0x0006: "Match_Desc_req", 0x0013: "Device_annce", 0x0021: "Bind_req",
    0x0022: "Unbind_req", 0x0031: "Mgmt_Lqi_req", 0x0032: "Mgmt_Rtg_req",
    0x0034: "Mgmt_Leave_req", 0x0036: "Mgmt_Permit_Joining_req", 0x0038: "Mgmt_NWK_Update_req",
}

ZCL_STATUS = {
    0x00: "SUCCESS", 0x01: "FAILURE", 0x7E: "NOT_AUTHORIZED", 0x80: "MALFORMED_COMMAND",
    0x81: "UNSUP_CLUSTER_COMMAND", 0x82: "UNSUP_GENERAL_COMMAND",
    0x83: "UNSUP_MANUF_CLUSTER_COMMAND", 0x84: "UNSUP_MANUF_GENERAL_COMMAND",
    0x85: "INVALID_FIELD", 0x86: "UNSUPPORTED_ATTRIBUTE", 0x87: "INVALID_VALUE",
    0x88: "READ_ONLY", 0x89: "INSUFFICIENT_SPACE", 0x8B: "NOT_FOUND",
    0x8C: "UNREPORTABLE_ATTRIBUTE", 0x8D: "INVALID_DATA_TYPE", 0x95: "NO_IMAGE_AVAILABLE",
    0xC3: "UNSUPPORTED_CLUSTER",
}

ZDO_STATUS = {
    0x00: "SUCCESS", 0x80: "INV_REQUESTTYPE", 0x81: "DEVICE_NOT_FOUND", 0x82: "INVALID_EP",
    0x83: "NOT_ACTIVE", 0x84: "NOT_SUPPORTED", 0x85: "TIMEOUT", 0x86: "NO_MATCH",
    0x88: "NO_ENTRY", 0x89: "NO_DESCRIPTOR", 0x8C: "TABLE_FULL", 0x8D: "NOT_AUTHORIZED",
}

EMBER_STATUS = {0x00: "SUCCESS", 0x66: "DELIVERY_FAILED", 0x18: "NO_BUFFERS"}

GLOBAL_CMDS = {
    0x00: "ReadAttr", 0x01: "ReadAttrRsp", 0x02: "WriteAttr", 0x04: "WriteAttrRsp",
    0x06: "ConfigReporting", 0x07: "ConfigReportingRsp", 0x08: "ReadReportingCfg",
    0x09: "ReadReportingCfgRsp", 0x0A: "Report", 0x0B: "DefaultRsp", 0x0C: "DiscoverAttr",
    0x0D: "DiscoverAttrRsp", 0x11: "DiscoverCmdsRx", 0x12: "DiscoverCmdsRxRsp",
    0x13: "DiscoverCmdsGen", 0x14: "DiscoverCmdsGenRsp",
}

ATTRS = {
    0x0000: {0x0000: "zclVersion", 0x0001: "appVersion", 0x0002: "stackVersion",
             0x0003: "hwVersion", 0x0004: "manufacturer", 0x0005: "model",
             0x0006: "dateCode", 0x0007: "powerSource", 0x4000: "swBuildId",
             0xFFFD: "clusterRevision", 0xFFFE: "attrReportingStatus"},
    0x0001: {0x0000: "mainsVoltage", 0x0020: "batteryVoltage", 0x0021: "batteryPct"},
    0x0006: {0x0000: "onOff", 0x8004: "tuyaOperationMode"},
    0x0008: {0x0000: "currentLevel"},
    0x0012: {0x004A: "numberOfStates", 0x0051: "outOfService", 0x0055: "presentValue",
             0x006F: "statusFlags"},
    0x0402: {0x0000: "temperature"},
    0x0405: {0x0000: "humidity"},
    0x0408: {0x0000: "soilMoisture"},
    0x0500: {0x0000: "zoneState", 0x0001: "zoneType", 0x0002: "zoneStatus",
             0x0010: "iasCieAddress", 0x0011: "zoneId"},
}

TC_STATUS = {0: "secured rejoin", 1: "unsecured JOIN", 2: "LEFT network", 3: "unsecured rejoin"}
MSG_TYPE = {0: "unicast", 1: "unicast-reply", 2: "multicast", 3: "multicast-loopback",
            4: "broadcast", 5: "broadcast-loopback", 6: "broadcast"}
ZONE_BITS = ["Alarm1", "Alarm2", "Tamper", "BatteryLow", "Supervision", "Restore",
             "Trouble", "ACfault", "Test", "BatteryDefect"]
TUYA_PRESS = {0: "single", 1: "double", 2: "hold"}
MULTISTATE_HINT = {0: "hold/release", 1: "single", 2: "double", 3: "triple", 4: "hold",
                   255: "release"}

# --------------------------------------------------------------------------- helpers

LINE_RE = re.compile(r"^\[(\d{4}-\d\d-\d\d) (\d\d:\d\d:\d\d\.\d+)\].*?(RECEIVED|SENDING) EZSP: \(([0-9A-Fa-f ]+)\)")
IOX_RE = re.compile(r"^\[\S+ (\d\d:\d\d:\d\d\.\d+)\].*\[iox\]\s*(.*)$")
IOX_KEEP = ("creating new node", "Update Status", "Interview completed",
            "Interview Done", "onDeviceRemoved", "primaryClusterId", "ZB-FAIL")


def u16(b, i):
    return b[i] | (b[i + 1] << 8)


def s8(v):
    return v - 256 if v > 127 else v


def eui(b, i):
    return ":".join(f"{x:02X}" for x in reversed(b[i:i + 8]))


def node(n):
    if n == 0:
        return "EISY(0x0000)"
    if n >= 0xFFF8:
        return {0xFFFF: "ALL", 0xFFFD: "RxOnWhenIdle", 0xFFFC: "Routers"}.get(n, f"0x{n:04X}")
    return f"0x{n:04X}({n})"


def cname(c):
    return CLUSTERS.get(c, f"0x{c:04X}")


def hexs(b):
    return " ".join(f"{x:02X}" for x in b)


def parse_value(t, b, i):
    """Parse one ZCL typed value. Returns (value, new_index)."""
    if t in (0x10, 0x18, 0x20, 0x30, 0x08):
        return b[i], i + 1
    if t in (0x19, 0x21, 0x31, 0x09):
        return u16(b, i), i + 2
    if t in (0x22, 0x0A):
        return b[i] | b[i + 1] << 8 | b[i + 2] << 16, i + 3
    if t in (0x1B, 0x23, 0xE2, 0x0B, 0xE0, 0xE1):
        return struct.unpack_from("<I", bytes(b), i)[0], i + 4
    if t == 0x28:
        return s8(b[i]), i + 1
    if t == 0x29:
        return struct.unpack_from("<h", bytes(b), i)[0], i + 2
    if t == 0x2B:
        return struct.unpack_from("<i", bytes(b), i)[0], i + 4
    if t == 0x39:
        return round(struct.unpack_from("<f", bytes(b), i)[0], 3), i + 4
    if t in (0x41, 0x42):
        n = b[i]
        if n == 0xFF:
            return "", i + 1
        raw = bytes(b[i + 1:i + 1 + n])
        return (raw.decode("ascii", "replace") if t == 0x42 else raw.hex()), i + 1 + n
    if t == 0xF0:
        return eui(b, i), i + 8
    raise ValueError(f"type 0x{t:02X}")


def fmt_attr(cluster, attr, val):
    name = ATTRS.get(cluster, {}).get(attr, f"0x{attr:04X}")
    if cluster == 0x0402 and attr == 0 and isinstance(val, int):
        return f"{name}={val / 100:.2f}°C ({val / 100 * 9 / 5 + 32:.2f}°F)"
    if cluster in (0x0405, 0x0408) and attr == 0 and isinstance(val, int):
        return f"{name}={val / 100:.2f}%"
    if cluster == 0x0001 and attr == 0x0020:
        return f"{name}={val / 10:.1f}V"
    if cluster == 0x0001 and attr == 0x0021:
        return f"{name}={val / 2:.1f}%"
    if cluster == 0x0006 and attr == 0:
        return f"{name}={'On' if val else 'Off'}"
    if cluster == 0x0012 and attr == 0x0055:
        return f"{name}={val} ({MULTISTATE_HINT.get(val, '?')} press, Aqara/3R style)"
    if cluster == 0x0500 and attr == 0x0002:
        return f"{name}={zone_status(val)}"
    if isinstance(val, str):
        return f'{name}="{val}"'
    return f"{name}={val}"


def fmt_attr_name(cluster, attr):
    return ATTRS.get(cluster, {}).get(attr, f"0x{attr:04X}")


def zone_status(v):
    bits = [n for i, n in enumerate(ZONE_BITS) if v & (1 << i)]
    return f"0x{v:04X} [{', '.join(bits) if bits else 'clear'}]"

# --------------------------------------------------------------------------- ZCL


def decode_zcl(cluster, p, info):
    """Decode a ZCL frame. `info` (dict) collects facts for the node summary."""
    if len(p) < 3:
        return f"short ZCL {hexs(p)}"
    fc = p[0]
    i = 1
    mfr = None
    if fc & 0x04:
        mfr = u16(p, 1)
        i = 3
    seq, cmd = p[i], p[i + 1]
    d = p[i + 2:]
    specific = (fc & 0x03) == 1
    to_client = bool(fc & 0x08)
    arrow = "srv→cli" if to_client else "cli→srv"
    m = f" mfr=0x{mfr:04X}" if mfr is not None else ""

    try:
        if not specific:
            name = GLOBAL_CMDS.get(cmd, f"global 0x{cmd:02X}")
            if cmd == 0x0A:  # report
                out, j = [], 0
                while j + 3 <= len(d):
                    a, t = u16(d, j), d[j + 2]
                    v, j = parse_value(t, d, j + 3)
                    out.append(fmt_attr(cluster, a, v))
                    info.setdefault("attrs", {})[(cluster, a)] = v
                return f"Report {', '.join(out)}"
            if cmd == 0x01:  # read attr rsp
                out, j = [], 0
                while j + 3 <= len(d):
                    a, st = u16(d, j), d[j + 2]
                    j += 3
                    if st != 0:
                        out.append(f"0x{a:04X}:{ZCL_STATUS.get(st, hex(st))}")
                        continue
                    t = d[j]
                    v, j = parse_value(t, d, j + 1)
                    out.append(fmt_attr(cluster, a, v))
                    info.setdefault("attrs", {})[(cluster, a)] = v
                return f"ReadAttrRsp {', '.join(out)}"
            if cmd == 0x00:
                attrs = [ATTRS.get(cluster, {}).get(u16(d, j), f"0x{u16(d, j):04X}") for j in range(0, len(d) - 1, 2)]
                return f"ReadAttr {', '.join(attrs)}{m}"
            if cmd == 0x0D:  # discover attributes rsp
                attrs = [fmt_attr_name(cluster, u16(d, j)) for j in range(1, len(d) - 2, 3)]
                return f"DiscoverAttrRsp{' (complete)' if d and d[0] else ''}: {', '.join(attrs)}"
            if cmd in (0x0C, 0x11, 0x13):
                return f"{name} (start 0x{d[0] if cmd != 0x0C else u16(d, 0):04X})"
            if cmd in (0x12, 0x14):
                return f"{name} cmds={[hex(x) for x in d[1:]]}"
            if cmd == 0x0B:
                return f"DefaultRsp to cmd 0x{d[0]:02X}: {ZCL_STATUS.get(d[1], hex(d[1]))}"
            if cmd == 0x02:
                a, t = u16(d, 0), d[2]
                v, _ = parse_value(t, d, 3)
                return f"WriteAttr {fmt_attr(cluster, a, v)}{m}"
            if cmd in (0x04, 0x07):
                return f"{name} {ZCL_STATUS.get(d[0], hex(d[0]))}" if d else name
            if cmd == 0x06:
                a, t = u16(d, 1), d[3]
                mn, mx = u16(d, 4), u16(d, 6)
                return f"ConfigReporting {ATTRS.get(cluster, {}).get(a, hex(a))} min={mn}s max={mx}s"
            if cmd == 0x08:
                return f"ReadReportingCfg dir={d[0]} attr=0x{u16(d, 1):04X}"
            if cmd == 0x09:
                st = d[0]
                a = u16(d, 2)
                an = ATTRS.get(cluster, {}).get(a, f"0x{a:04X}")
                if st != 0:
                    return f"ReadReportingCfgRsp {an}: {ZCL_STATUS.get(st, hex(st))}"
                t = d[4]
                mn, mx = u16(d, 5), u16(d, 7)
                return f"ReadReportingCfgRsp {an} min={mn}s max={mx}s"
            return f"{name} ({arrow}) {hexs(d)}{m}"

        # ---- cluster-specific
        if cluster == 0x0006 and not to_client:
            names = {0x00: "Off", 0x01: "On", 0x02: "Toggle", 0x40: "OffWithEffect",
                     0x41: "OnWithRecall", 0x42: "OnWithTimedOff"}
            if cmd == 0xFD:
                press = TUYA_PRESS.get(d[0], f"0x{d[0]:02X}") if d else "?"
                info["presses"] = info.get("presses", 0) + 1
                return f"Tuya scene button 0xFD: {press} press"
            if cmd in names:
                info["presses"] = info.get("presses", 0) + 1
            return f"OnOff cmd {names.get(cmd, hex(cmd))}{m}"
        if cluster == 0x0500:
            if to_client and cmd == 0x00:
                st, ext, zid, dly = u16(d, 0), d[2], d[3], u16(d, 4)
                info["zone"] = st
                return f"Zone Status Change: {zone_status(st)} zoneId={zid} delay={dly}"
            if to_client and cmd == 0x01:
                return f"Zone Enroll Request type=0x{u16(d, 0):04X} mfr=0x{u16(d, 2):04X}"
            if not to_client and cmd == 0x00:
                return f"Zone Enroll Response code={d[0]} zoneId={d[1]}"
        if cluster == 0x0008 and not to_client:
            names = {0x00: "MoveToLevel", 0x01: "Move", 0x02: "Step", 0x03: "Stop",
                     0x04: "MoveToLevelOnOff", 0x05: "MoveOnOff", 0x06: "StepOnOff", 0x07: "StopOnOff"}
            return f"Level cmd {names.get(cmd, hex(cmd))} {hexs(d)}"
        if cluster == 0x0003 and not to_client and cmd == 0x00:
            return f"Identify for {u16(d, 0)}s"
        if cluster == 0x0019 and cmd == 0x01 and not to_client:
            return (f"OTA QueryNextImage mfr=0x{u16(d, 1):04X} image=0x{u16(d, 3):04X} "
                    f"fileVer=0x{struct.unpack_from('<I', bytes(d), 5)[0]:08X}")
        return f"{cname(cluster)} cmd 0x{cmd:02X} ({arrow}) {hexs(d)}{m}"
    except (IndexError, ValueError, struct.error) as e:
        return f"{'specific' if specific else 'global'} cmd 0x{cmd:02X} (undecoded: {e}) {hexs(d)}"

# --------------------------------------------------------------------------- ZDO


def decode_zdo(cluster, p, info, nodes):
    base = cluster & 0x7FFF
    name = ZDO.get(base, f"ZDO 0x{base:04X}") + ("" if cluster < 0x8000 else "")
    if cluster >= 0x8000:
        name = name.replace("_req", "_rsp")
    try:
        if cluster == 0x0013:
            n, e, cap = u16(p, 1), eui(p, 3), p[11]
            nodes[n]["ieee"] = e
            kind = "router" if cap & 0x02 else "end device"
            power = "mains" if cap & 0x04 else "battery"
            sleepy = "" if cap & 0x08 else ", sleepy"
            return f"Device_annce {node(n)} IEEE {e} ({kind}, {power}{sleepy})"
        if cluster == 0x8005:
            st, n, cnt = p[1], u16(p, 2), p[4]
            return f"Active_EP_rsp {ZDO_STATUS.get(st, hex(st))} endpoints={list(p[5:5 + cnt])}"
        if cluster == 0x8004:
            st, n = p[1], u16(p, 2)
            if st != 0:
                return f"Simple_Desc_rsp {hex(st)}"
            ep, prof, dev = p[5], u16(p, 6), u16(p, 8)
            ic = p[11]
            ins = [u16(p, 12 + 2 * k) for k in range(ic)]
            j = 12 + 2 * ic
            oc = p[j]
            outs = [u16(p, j + 1 + 2 * k) for k in range(oc)]
            nodes[n].setdefault("eps", {})[ep] = (dev, ins, outs)
            return (f"Simple_Desc_rsp ep{ep} profile=0x{prof:04X} deviceId=0x{dev:04X} "
                    f"IN[{', '.join(cname(c) for c in ins)}] OUT[{', '.join(cname(c) for c in outs)}]")
        if cluster == 0x0000:
            return f"NWK_addr_req for IEEE {eui(p, 1)}"
        if cluster == 0x0001:
            return f"IEEE_addr_req for {node(u16(p, 1))}"
        if cluster == 0x8000 and len(p) >= 12:
            return f"NWK_addr_rsp {ZDO_STATUS.get(p[1], hex(p[1]))} IEEE {eui(p, 2)} = {node(u16(p, 10))}"
        if cluster == 0x0034:
            return f"Mgmt_Leave_req {eui(p, 1)}"
        if cluster in (0x0002, 0x0003, 0x0005):
            return f"{name} for {node(u16(p, 1))}"
        if cluster == 0x0004:
            return f"Simple_Desc_req for {node(u16(p, 1))} ep{p[3]}"
        if cluster == 0x0021:
            src, sep, cl, mode = eui(p, 1), p[9], u16(p, 10), p[12]
            dst = f"{eui(p, 13)} ep{p[21]}" if mode == 3 else f"group 0x{u16(p, 13):04X}"
            return f"Bind_req {src} ep{sep} {cname(cl)} → {dst}"
        if cluster == 0x0036:
            return f"Mgmt_Permit_Joining_req duration={p[1]}s{' (CLOSE)' if p[1] == 0 else ''}"
        if cluster >= 0x8000 and len(p) > 1:
            return f"{name} status={ZDO_STATUS.get(p[1], hex(p[1]))}"
    except IndexError:
        pass
    return f"{name} {hexs(p)}"

# --------------------------------------------------------------------------- EZSP


def aps(b, i):
    """Parse an 11-byte EmberApsFrame."""
    return dict(profile=u16(b, i), cluster=u16(b, i + 2), src_ep=b[i + 4], dst_ep=b[i + 5],
                options=u16(b, i + 6), group=u16(b, i + 8), seq=b[i + 10])


def decode_payload(a, payload, nd, nodes):
    if a["profile"] == 0x0000:
        return "ZDO", decode_zdo(a["cluster"], payload, nd, nodes)
    return cname(a["cluster"]), decode_zcl(a["cluster"], payload, nd)


def decode_ezsp(direction, b, nodes, args):
    """Return (node_id or None, text) or None to skip."""
    if len(b) < 5:
        return None
    fc = u16(b, 1)
    fid = u16(b, 3)
    p = b[5:]
    is_rsp = bool(fc & 0x0080)

    if direction == "RECEIVED" and fid == 0x0045:
        mtype = p[0]
        a = aps(p, 1)
        lqi, rssi, sender = p[12], s8(p[13]), u16(p, 14)
        ln = p[18]
        payload = p[19:19 + ln]
        nd = nodes[sender]
        nd["rx"] += 1
        nd["lqi"], nd["rssi"] = lqi, rssi
        nd["clusters"].add(a["cluster"]) if a["profile"] else None
        cl, txt = decode_payload(a, payload, nd, nodes)
        extra = f"  [{hexs(payload)}]" if args.raw else ""
        bc = "" if mtype == 0 else f" {MSG_TYPE.get(mtype, mtype)}"
        return sender, (f"RX  {node(sender):>15} ep{a['src_ep']} {cl:<13} {txt}"
                        f"  (LQI {lqi}, {rssi} dBm, APS#{a['seq']:02X}{bc}){extra}")

    if fid == 0x0059 and direction == "RECEIVED":
        src, e, lqi, rssi, cnt = u16(p, 0), eui(p, 2), p[10], s8(p[11]), p[12]
        relays = [u16(p, 13 + 2 * k) for k in range(cnt)]
        nd = nodes[src]
        nd["ieee"], nd["hops"] = e, cnt
        nd["relays"] = relays
        if not args.routes:
            return None
        path = " → ".join(f"0x{r:04X}" for r in relays) or "direct"
        return src, f"RTE {node(src):>15} IEEE {e} via {path}  (last hop LQI {lqi}, {rssi} dBm)"

    if fid == 0x0024 and direction == "RECEIVED":
        n, e, st, dec, parent = u16(p, 0), eui(p, 2), p[10], p[11], u16(p, 12)
        nodes[n]["ieee"] = e
        nodes[n]["events"].append(TC_STATUS.get(st, f"status {st}"))
        return n, f"JOIN {node(n):>14} IEEE {e} {TC_STATUS.get(st, st)} (parent 0x{parent:04X})"

    if fid == 0x00C4 and direction == "RECEIVED":
        return u16(p, 1), f"NWK {node(u16(p, 1)):>15} network status 0x{p[0]:02X} (route/delivery problem reported)"

    if args.no_tx:
        return None

    if fid == 0x0034 and direction == "SENDING" and not is_rsp:
        dest = u16(p, 1)
        a = aps(p, 3)
        ln = p[15]
        payload = p[16:16 + ln]
        nd = nodes[dest]
        nd["tx"] += 1
        cl, txt = decode_payload(a, payload, nd, nodes)
        extra = f"  [{hexs(payload)}]" if args.raw else ""
        return dest, f"TX  {node(dest):>15} ep{a['dst_ep']} {cl:<13} {txt}{extra}"

    if fid == 0x0036 and direction == "SENDING" and not is_rsp:
        dest = u16(p, 0)
        a = aps(p, 2)
        ln = p[15]
        payload = p[16:16 + ln]
        cl, txt = decode_payload(a, payload, {}, nodes)
        return None if args.node is not None else (None, f"TXB {node(dest):>15}     {cl:<13} {txt}")

    if fid == 0x003F and direction == "RECEIVED":
        dest = u16(p, 1)
        a = aps(p, 3)
        st = p[15]
        if st != 0:
            nodes[dest]["fail"] += 1
            return dest, f"!!  {node(dest):>15}     {cname(a['cluster']) if a['profile'] else 'ZDO':<13} delivery FAILED: {EMBER_STATUS.get(st, hex(st))}"
        return None  # successful deliveries are noise

    return None

# --------------------------------------------------------------------------- main


def parse_node_arg(s):
    return int(s, 16) if s.lower().startswith("0x") else int(s)


def main():
    ap = argparse.ArgumentParser(description="Decode EISY/IoX Zigbee (EZSP) logs.")
    ap.add_argument("file", help="log file, or - for stdin")
    ap.add_argument("--node", type=parse_node_arg)
    ap.add_argument("--summary", action="store_true")
    ap.add_argument("--no-summary", action="store_true")
    ap.add_argument("--routes", action="store_true")
    ap.add_argument("--iox", action="store_true")
    ap.add_argument("--no-tx", action="store_true")
    ap.add_argument("--raw", action="store_true")
    args = ap.parse_args()

    nodes = defaultdict(lambda: dict(rx=0, tx=0, fail=0, clusters=set(), events=[]))
    fh = sys.stdin if args.file == "-" else open(args.file, encoding="utf-8", errors="replace")

    for line in fh:
        m = LINE_RE.search(line)
        if m:
            _, ts, direction, hx = m.groups()
            try:
                b = [int(x, 16) for x in hx.split()]
                r = decode_ezsp(direction, b, nodes, args)
            except (IndexError, ValueError, struct.error) as e:
                r = (None, f"??  undecodable EZSP frame ({e}): {hx.strip()}")
            if r is None or args.summary:
                continue
            nid, text = r
            if args.node is not None and nid != args.node:
                continue
            print(f"{ts}  {text}")
            continue
        if args.iox and not args.summary:
            mi = IOX_RE.search(line)
            if mi and any(k in mi.group(2) for k in IOX_KEEP):
                if args.node is not None and str(args.node) not in mi.group(2):
                    continue
                print(f"{mi.group(1)}  IOX {mi.group(2).strip()}")

    if args.no_summary:
        return
    print("\n=== Node summary ===")
    print(f"{'node':>15}  {'IEEE':<23} {'model':<28} {'RX':>5} {'TX':>4} {'fail':>4} "
          f"{'LQI':>4} {'RSSI':>5} {'hops':>4}  clusters / notes")
    for n in sorted(nodes):
        if n == 0 or n >= 0xFFF8:
            continue
        if args.node is not None and n != args.node:
            continue
        d = nodes[n]
        at = d.get("attrs", {})
        model = " ".join(str(x) for x in (at.get((0, 4), ""), at.get((0, 5), "")) if x) or ""
        notes = ", ".join(cname(c) for c in sorted(d["clusters"]))
        if "eps" in d:
            notes += "  eps: " + "; ".join(
                f"{ep}=dev0x{v[0]:04X}" for ep, v in sorted(d["eps"].items()))
        if "zone" in d:
            notes += f"  lastZone={zone_status(d['zone'])}"
        if d.get("presses"):
            notes += f"  presses={d['presses']}"
        if d["events"]:
            notes += f"  joins: {', '.join(d['events'])}"
        print(f"{node(n):>15}  {d.get('ieee', ''):<23} {model[:28]:<28} {d['rx']:>5} {d['tx']:>4} "
              f"{d['fail']:>4} {str(d.get('lqi', '')):>4} {str(d.get('rssi', '')):>5} "
              f"{str(d.get('hops', '')):>4}  {notes}")


if __name__ == "__main__":
    try:
        main()
    except BrokenPipeError:  # e.g. piped into `head`
        sys.stderr.close()
