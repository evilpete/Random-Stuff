#!/usr/bin/env python3
"""
eisy_zw_decode.py - Decode Z-Wave Serial API traces from a Universal Devices EISY / IoX ZWAY.LOG.

Reads the raw "SENDING: ( 01 .. )" / "RECEIVED: ( 01 .. )" Serial API frames that Z-Way logs,
decodes the Serial API function, the TX status report (route, RSSI, hops, failed link), and
the Z-Wave command class payload, and prints one readable line per event plus a per-node summary.

S2 / S0 encrypted frames cannot be decoded from the radio bytes, but Z-Way logs the clear-text
payloads ("Secure payload: ( .. )" before a send, "passing ... decrypted packet ... [ .. ]" after
a receive); the script picks those up and decodes them in place of the ciphertext.

Usage:
    python3 eisy_zw_decode.py ZWAY.LOG                # decode everything
    python3 eisy_zw_decode.py ZWAY.LOG --node 2       # one node
    python3 eisy_zw_decode.py ZWAY.LOG --summary      # per-node summary only
    python3 eisy_zw_decode.py ZWAY.LOG --mgmt --iox   # include controller housekeeping + IoX status
    cat snippet.txt | python3 eisy_zw_decode.py -     # read from stdin

Options:
    --node N      only events to/from node N
    --summary     print only the per-node summary table
    --no-summary  do not print the summary table
    --dups        show duplicate frames Z-Way discarded (hidden by default, counted in summary)
    --mgmt        show controller housekeeping (routing table reads, failed-node checks, version, ...)
    --iox         also show IoX "Update Status" lines and interview results
    --no-tx       hide frames the EISY sends and their delivery reports
    --raw         append the raw command bytes to each line
"""

import argparse
import re
import struct
import sys
from collections import defaultdict

# --------------------------------------------------------------------------- tables

FUNC = {
    0x02: "SerialApiGetInitData", 0x03: "SetApplNodeInfo", 0x04: "ApplicationCommandHandler",
    0x05: "GetControllerCapabilities", 0x06: "SerialApiSetTimeouts", 0x07: "SerialApiGetCapabilities",
    0x08: "SerialApiSoftReset", 0x09: "GetProtocolVersion", 0x0A: "SerialApiStarted",
    0x0B: "SerialApiSetup", 0x13: "SendData", 0x15: "GetVersion", 0x16: "SendDataAbort",
    0x20: "MemoryGetId", 0x41: "GetNodeProtocolInfo", 0x42: "SetDefault",
    0x46: "AssignReturnRoute", 0x47: "DeleteReturnRoute", 0x48: "RequestNodeNeighborUpdate",
    0x49: "ApplicationUpdate", 0x4A: "AddNodeToNetwork", 0x4B: "RemoveNodeFromNetwork",
    0x50: "SetLearnMode", 0x51: "AssignSucReturnRoute", 0x54: "SetSucNodeId", 0x56: "GetSucNodeId",
    0x5E: "ExploreRequestInclusion", 0x60: "RequestNodeInfo", 0x61: "RemoveFailedNode",
    0x62: "IsFailedNode", 0x63: "ReplaceFailedNode", 0x80: "GetRoutingInfo",
    0xA8: "ApplicationCommandHandler_Bridge", 0xA9: "SendData_Bridge",
}

TX_STATUS = {0: "OK", 1: "NO_ACK", 2: "FAIL", 3: "NOT_IDLE", 4: "NO_ROUTE"}
ROUTE_SPEED = {1: "9.6k", 2: "40k", 3: "100k"}
RSSI_SPECIAL = {0x7F: "n/a", 0x7E: "max", 0x7D: "below-sens"}
WAKE_REASON = {0: "reset", 1: "wakeup timer", 2: "beam", 3: "watchdog", 4: "ext interrupt",
               5: "power-up", 6: "USB suspend", 7: "software reset", 8: "emergency watchdog",
               9: "brown-out"}
APP_UPDATE = {0x84: "node info received", 0x81: "node info request FAILED", 0x40: "new node id",
              0x20: "node deleted", 0x10: "SUC id", 0x86: "include node info"}
ADD_STATUS = {1: "learn ready", 2: "node found", 3: "adding end node", 4: "adding controller",
              5: "protocol done", 6: "done", 7: "FAILED"}

BASIC_CLASS = {1: "controller", 2: "static controller", 3: "end node", 4: "routing end node"}
GENERIC_CLASS = {
    0x01: "remote controller", 0x02: "static controller", 0x03: "AV control", 0x06: "appliance",
    0x07: "notification sensor", 0x08: "thermostat", 0x09: "window covering", 0x0F: "repeater",
    0x10: "binary switch", 0x11: "multilevel switch", 0x12: "remote switch", 0x13: "toggle switch",
    0x15: "zip node", 0x16: "ventilation", 0x17: "security panel", 0x18: "wall controller",
    0x20: "binary sensor", 0x21: "multilevel sensor", 0x30: "pulse meter", 0x31: "meter",
    0x40: "entry control", 0x50: "semi-interoperable", 0xA1: "alarm sensor", 0xFF: "non-interoperable",
}

CC = {
    0x00: "NoOp", 0x20: "Basic", 0x22: "AppStatus", 0x25: "SwitchBinary", 0x26: "SwitchMultilevel",
    0x27: "SwitchAll", 0x2B: "SceneActivation", 0x2C: "SceneActuatorConf", 0x30: "SensorBinary",
    0x31: "SensorMultilevel", 0x32: "Meter", 0x33: "SwitchColor", 0x40: "ThermostatMode",
    0x42: "ThermostatOpState", 0x43: "ThermostatSetpoint", 0x44: "ThermostatFanMode",
    0x45: "ThermostatFanState", 0x4E: "ScheduleEntryLock", 0x55: "TransportService",
    0x56: "CRC16", 0x59: "AssocGroupInfo", 0x5A: "DeviceResetLocally", 0x5B: "CentralScene",
    0x5E: "ZWavePlusInfo", 0x60: "MultiChannel", 0x62: "DoorLock", 0x63: "UserCode",
    0x66: "BarrierOperator", 0x6C: "Supervision", 0x6F: "EntryControl", 0x70: "Configuration",
    0x71: "Notification", 0x72: "ManufacturerSpecific", 0x73: "Powerlevel", 0x75: "Protection",
    0x7A: "FirmwareUpdate", 0x80: "Battery", 0x84: "WakeUp", 0x85: "Association",
    0x86: "Version", 0x87: "Indicator", 0x8E: "MultiChannelAssoc", 0x8F: "MultiCmd",
    0x98: "Security0", 0x9F: "Security2",
}

METER_TYPE = {1: "Electric", 2: "Gas", 3: "Water", 4: "Heating", 5: "Cooling"}
METER_SCALE = {1: ["kWh", "kVAh", "W", "pulses", "V", "A", "PF", "kVar"],
               2: ["m³", "ft³", "?", "pulses"], 3: ["m³", "ft³", "gal", "pulses"]}
RATE_TYPE = {0: "", 1: " import", 2: " export"}
SENSOR_TYPE = {1: ("Temperature", ["°C", "°F"]), 3: ("Luminance", ["%", "lux"]),
               4: ("Power", ["W", "BTU/h"]), 5: ("Humidity", ["%", "g/m³"]),
               6: ("Velocity", ["m/s", "mph"]), 15: ("Voltage", ["V", "mV"]),
               16: ("Current", ["A", "mA"]), 17: ("CO2", ["ppm"]), 27: ("UV", [""]),
               56: ("Water flow", ["l/h"]), 65: ("Seismic", [""])}
NOTIF_TYPE = {0x01: "Smoke", 0x02: "CO", 0x03: "CO2", 0x04: "Heat", 0x05: "Water",
              0x06: "Access Control", 0x07: "Home Security", 0x08: "Power Mgmt",
              0x09: "System", 0x0A: "Emergency", 0x0B: "Clock", 0x0C: "Appliance",
              0x0E: "Siren", 0x0F: "Water Valve", 0x12: "Gas", 0x15: "Light Sensor"}
NOTIF_EVENT = {
    0x05: {0: "idle", 1: "leak detected (loc)", 2: "leak detected", 3: "level dropped"},
    0x06: {0: "idle", 1: "manual lock", 2: "manual unlock", 3: "RF lock", 4: "RF unlock",
           5: "keypad lock", 6: "keypad unlock", 0x16: "window/door OPEN", 0x17: "window/door CLOSED"},
    0x07: {0: "idle", 1: "intrusion (loc)", 2: "intrusion", 3: "tamper: cover removed",
           4: "tamper: code", 5: "glass break (loc)", 6: "glass break", 7: "motion (loc)",
           8: "motion", 9: "tamper: moved"},
    0x08: {0: "idle", 1: "power applied", 2: "AC disconnected", 3: "AC reconnected",
           4: "surge", 5: "voltage drop", 6: "over-current", 7: "over-voltage",
           8: "over-load", 9: "load error", 0x0A: "replace battery soon", 0x0B: "replace battery NOW",
           0x0C: "battery charging", 0x0D: "battery charged", 0x0E: "charge battery soon"},
    0x01: {0: "idle", 1: "smoke (loc)", 2: "smoke", 3: "smoke test"},
    0x09: {0: "idle", 1: "hardware failure", 2: "software failure", 3: "hw failure (code)",
           4: "sw failure (code)", 5: "heartbeat"},
}
SUPERVISION_STATUS = {0x00: "NO_SUPPORT", 0x01: "WORKING", 0x02: "FAIL", 0xFF: "SUCCESS"}
SCENE_KEY = {0: "pressed 1x", 1: "released", 2: "held", 3: "pressed 2x", 4: "pressed 3x",
             5: "pressed 4x", 6: "pressed 5x"}

# --------------------------------------------------------------------------- helpers

FRAME_RE = re.compile(r"^\[(\S+) (\d\d:\d\d:\d\d\.\d+)\].*?\b(SENDING|RECEIVED)(?: \(cb 0x[0-9A-Fa-f]+\))?: \( ([0-9A-Fa-f ]+)\)")
SECURE_TX_RE = re.compile(r"Secure payload: \( ([0-9A-Fa-f ]+)\)")
SECURE_RX_RE = re.compile(r"Node (\d+):(\d+) CC Security(S2|S0)?.*decrypted packet to application level: \[ ([0-9A-Fa-f ]+)\]")
DUP_RE = re.compile(r"Discarding duplicate packet from node (\d+)")
IOX_RE = re.compile(r"^\[\S+ (\d\d:\d\d:\d\d\.\d+)\].*\[iox\]\s*(.*)$")
INTERVIEW_RE = re.compile(r"^\[\S+ (\d\d:\d\d:\d\d\.\d+)\].*(Interview for Node #\d+ finished\.)")


def s8(v):
    return v - 256 if v > 127 else v


def rssi(v):
    return RSSI_SPECIAL.get(v, f"{s8(v)} dBm")


def hexs(b):
    return " ".join(f"{x:02X}" for x in b)


def cc_name(c):
    return CC.get(c, f"CC 0x{c:02X}")


def be_int(b, signed=True):
    v = int.from_bytes(bytes(b), "big", signed=signed)
    return v


def scaled(raw, precision):
    return raw / (10 ** precision) if precision else raw


def level_txt(v):
    if v == 0:
        return "Off (0)"
    if v == 0xFF:
        return "On (0xFF)"
    if v == 0xFE:
        return "unknown"
    return f"{v}%" if v <= 99 else f"0x{v:02X}"

# --------------------------------------------------------------------------- command classes


def decode_cmd(c, info):
    """Decode one Z-Wave command (list of ints). Returns text. `info` collects summary facts."""
    if not c:
        return "(empty)"
    cc = c[0]
    if len(c) < 2:
        return f"{cc_name(cc)}"
    cmd, d = c[1], c[2:]
    info.setdefault("ccs", set()).add(cc)
    try:
        if cc == 0x20:
            return {1: f"Basic Set {level_txt(d[0])}" if d else "Basic Set",
                    2: "Basic Get", 3: f"Basic Report {level_txt(d[0])}" if d else "Basic Report"
                    }.get(cmd, f"Basic cmd 0x{cmd:02X} {hexs(d)}")
        if cc == 0x25:
            if cmd == 1:
                return f"SwitchBinary Set {level_txt(d[0])}"
            if cmd == 2:
                return "SwitchBinary Get"
            if cmd == 3:
                info["state"] = level_txt(d[0])
                tgt = f" → target {level_txt(d[1])}" if len(d) >= 2 and d[1] != d[0] else ""
                return f"SwitchBinary Report {level_txt(d[0])}{tgt}"
        if cc == 0x26:
            if cmd == 1:
                dur = f" duration={d[1]}" if len(d) > 1 else ""
                return f"SwitchMultilevel Set {level_txt(d[0])}{dur}"
            if cmd == 2:
                return "SwitchMultilevel Get"
            if cmd == 3:
                info["state"] = level_txt(d[0])
                tgt = f" → target {level_txt(d[1])}" if len(d) >= 2 and d[1] != d[0] else ""
                return f"SwitchMultilevel Report {level_txt(d[0])}{tgt}"
            if cmd == 4:
                return "SwitchMultilevel StartLevelChange " + ("down" if d and d[0] & 0x40 else "up")
            if cmd == 5:
                return "SwitchMultilevel StopLevelChange"
        if cc == 0x30 and cmd == 2:
            return "SensorBinary Get"
        if cc == 0x30 and cmd == 3:
            v = "TRIGGERED" if d[0] else "idle"
            t = f" type={d[1]}" if len(d) > 1 else ""
            info["state"] = v
            return f"SensorBinary Report {v}{t}"
        if cc == 0x31:
            if cmd == 5:
                stype = d[0]
                prec, scale, size = d[1] >> 5, (d[1] >> 3) & 3, d[1] & 7
                val = scaled(be_int(d[2:2 + size]), prec)
                name, units = SENSOR_TYPE.get(stype, (f"type {stype}", []))
                unit = units[scale] if scale < len(units) else f"scale{scale}"
                info.setdefault("readings", {})[name] = f"{val:g} {unit}"
                return f"SensorMultilevel {name} = {val:g} {unit}"
            if cmd == 4:
                return f"SensorMultilevel Get type={d[0] if d else '?'}"
        if cc == 0x32:
            if cmd == 2:
                mtype = d[0] & 0x1F
                rate = (d[0] >> 5) & 3
                prec, scale_lo, size = d[1] >> 5, (d[1] >> 3) & 3, d[1] & 7
                scale = scale_lo | ((d[0] >> 5) & 0x04)  # v3+ scale bit 2 is bit 7 of byte 0
                scale = scale_lo | (4 if d[0] & 0x80 else 0)
                val = scaled(be_int(d[2:2 + size]), prec)
                units = METER_SCALE.get(mtype, [])
                unit = units[scale] if scale < len(units) else f"scale{scale}"
                extra = ""
                j = 2 + size
                if len(d) >= j + 2:
                    delta = (d[j] << 8) | d[j + 1]
                    if delta and len(d) >= j + 2 + size:
                        prev = scaled(be_int(d[j + 2:j + 2 + size]), prec)
                        extra = f" (prev {prev:g} {delta}s ago)"
                info.setdefault("readings", {})[unit] = f"{val:g} {unit}"
                return f"Meter {METER_TYPE.get(mtype, mtype)}{RATE_TYPE.get(rate, '')} = {val:g} {unit}{extra}"
            if cmd == 1:
                scale = (d[0] >> 3) & 7 if d else 0
                return f"Meter Get (scale {scale})"
            if cmd == 5:
                return "Meter Reset"
        if cc == 0x71:
            if cmd == 5:
                if len(d) >= 6:
                    ntype, ev = d[4], d[5]
                    status = "" if d[3] == 0xFF else (" (notifications OFF)" if d[3] == 0 else "")
                    tname = NOTIF_TYPE.get(ntype, f"type 0x{ntype:02X}")
                    ename = NOTIF_EVENT.get(ntype, {}).get(ev, f"event 0x{ev:02X}")
                    plen = d[6] & 0x1F if len(d) > 6 else 0
                    params = f" params=[{hexs(d[7:7 + plen])}]" if plen else ""
                    if ntype == 0x07 and ev == 0 and plen:
                        ename = f"idle (cleared: {NOTIF_EVENT[7].get(d[7], hex(d[7]))})"
                    elif ntype == 0x08 and ev == 0 and plen:
                        ename = f"idle (cleared: {NOTIF_EVENT[8].get(d[7], hex(d[7]))})"
                    info["state"] = f"{tname}: {ename}"
                    v1 = f" [v1 alarm {d[0]}/{d[1]}]" if d[0] or d[1] else ""
                    return f"Notification {tname}: {ename}{params}{status}{v1}"
                return f"Alarm (v1) type={d[0]} level={d[1]}"
            if cmd == 4:
                return f"Notification Get {hexs(d)}"
        if cc == 0x5B and cmd == 3:
            info["presses"] = info.get("presses", 0) + 1
            return f"CentralScene scene {d[2]} {SCENE_KEY.get(d[1] & 7, d[1] & 7)} (seq {d[0]})"
        if cc == 0x80:
            if cmd == 3:
                lv = "LOW" if d[0] == 0xFF else f"{d[0]}%"
                info["battery"] = lv
                return f"Battery {lv}"
            if cmd == 2:
                return "Battery Get"
        if cc == 0x84:
            names = {4: "WakeUp IntervalSet", 5: "WakeUp IntervalGet", 6: "WakeUp IntervalReport",
                     7: "WakeUp Notification (device awake)", 8: "WakeUp NoMoreInformation"}
            if cmd == 6 and len(d) >= 3:
                return f"WakeUp IntervalReport {(d[0] << 16) | (d[1] << 8) | d[2]}s"
            return names.get(cmd, f"WakeUp cmd 0x{cmd:02X}")
        if cc == 0x6C:
            if cmd == 1:
                sess, ln = d[0] & 0x3F, d[1]
                inner = decode_cmd(d[2:2 + ln], info)
                return f"Supervision Get #{sess}: {inner}"
            if cmd == 2:
                sess, st = d[0] & 0x3F, d[1]
                return f"Supervision Report #{sess}: {SUPERVISION_STATUS.get(st, hex(st))}"
        if cc == 0x60:
            if cmd == 0x0D:
                src, dst = d[0] & 0x7F, d[1] & 0x7F
                return f"[ep{src}→ep{dst}] " + decode_cmd(d[2:], info)
            if cmd == 0x08:
                return f"MultiChannel EndPointReport count={d[1] & 0x7F if len(d) > 1 else '?'}"
        if cc == 0x8F and cmd == 1:
            out, j = [], 1
            for _ in range(d[0]):
                ln = d[j]
                out.append(decode_cmd(d[j + 1:j + 1 + ln], info))
                j += 1 + ln
            return "MultiCmd { " + " | ".join(out) + " }"
        if cc == 0x56 and cmd == 1:
            return decode_cmd(d[:-2], info) + " (CRC16)"
        if cc == 0x72 and cmd == 5:
            mfr, ptype, pid = (d[0] << 8) | d[1], (d[2] << 8) | d[3], (d[4] << 8) | d[5]
            info["mfr"] = f"{mfr:04X}-{ptype:04X}-{pid:04X}"
            return f"ManufacturerSpecific mfr=0x{mfr:04X} type=0x{ptype:04X} id=0x{pid:04X}"
        if cc == 0x86:
            if cmd == 0x12:
                info["fw"] = f"{d[3]}.{d[4]:02d}"
                return f"Version Report lib={d[0]} protocol={d[1]}.{d[2]:02d} app={d[3]}.{d[4]:02d}"
            if cmd == 0x14:
                return f"Version CCReport {cc_name(d[0])} v{d[1]}"
            if cmd == 0x13:
                return f"Version CCGet {cc_name(d[0])}"
        if cc == 0x70:
            if cmd == 6:
                size = d[1] & 7
                return f"Configuration Report param {d[0]} = {be_int(d[2:2 + size])}"
            if cmd == 4:
                size = d[1] & 7
                return f"Configuration Set param {d[0]} = {be_int(d[2:2 + size])}"
            if cmd == 5:
                return f"Configuration Get param {d[0]}"
        if cc == 0x85 and cmd == 3:
            return f"Association Report group {d[0]} max={d[1]} nodes={list(d[3:])}"
        if cc == 0x5E and cmd == 2:
            return f"ZWavePlusInfo v{d[0]} role={d[1]} nodeType={d[2]}"
        if cc == 0x5A and cmd == 1:
            return "DeviceResetLocally NOTIFICATION (device was factory reset!)"
        if cc == 0x22 and cmd == 1:
            return f"ApplicationStatus Busy {['try later', 'try later (wait)', 'queued'][d[0]] if d and d[0] < 3 else hexs(d)}"
        if cc == 0x9F:
            names = {1: "NonceGet", 2: "NonceReport", 3: "MessageEncap (encrypted)", 4: "KEXGet",
                     5: "KEXReport", 6: "KEXSet", 7: "KEXFail", 8: "PublicKeyReport",
                     9: "NetworkKeyGet", 0x0A: "NetworkKeyReport", 0x0B: "NetworkKeyVerify",
                     0x0C: "TransferEnd"}
            if cmd == 2 and d:
                return "S2 NonceReport" + (" (SOS: resync)" if d[1] & 1 else "")
            return f"S2 {names.get(cmd, hex(cmd))}"
        if cc == 0x98:
            names = {0x40: "NonceGet", 0x80: "NonceReport", 0x81: "MessageEncap (encrypted)",
                     0xC1: "MessageEncapNonceGet (encrypted)"}
            return f"S0 {names.get(cmd, hex(cmd))}"
        if cc == 0x73 and cmd == 3:
            return f"Powerlevel Report {d[0]}"
        if cc == 0x00:
            return "NoOperation (ping)"
    except IndexError:
        pass
    return f"{cc_name(cc)} cmd 0x{cmd:02X} {hexs(d)}".rstrip()

# --------------------------------------------------------------------------- serial API


def tx_report(p, nd):
    """Decode a SendData callback: [cbId, txStatus, ticks(2), repeaters, ackRSSI, rep RSSI x4,
    ackCh, txCh, routeScheme, lastRoute x4, speed, attempts, failedFrom, failedTo, ...]."""
    st = p[1]
    out = TX_STATUS.get(st, f"status {st}")
    if len(p) >= 4:
        out += f" in {((p[2] << 8) | p[3]) * 10} ms"
    if len(p) >= 21:
        reps = [r for r in p[13:17] if r]
        route = ("via " + "→".join(str(r) for r in reps)) if reps else "direct"
        speed = ROUTE_SPEED.get(p[17] & 7, "")
        out += f", {route}"
        if speed:
            out += f" @{speed}"
        if st == 0 and p[5] not in RSSI_SPECIAL:
            out += f", ACK RSSI {rssi(p[5])}"
        if p[18] > 1:
            out += f", {p[18]} route attempts"
        if p[19] and p[20] and p[19] != 0x7F:
            out += f", FAILED LINK {p[19]}→{p[20]}"
        nd["route_out"] = route
    return out


def node_info(p, nd):
    st, n, ln = p[0], p[1], p[2]
    if st != 0x84 and st != 0x86:
        return n, f"ApplicationUpdate: {APP_UPDATE.get(st, hex(st))} (node {n})"
    basic, generic, specific = p[3], p[4], p[5]
    ccs = p[6:3 + ln]
    nd["devclass"] = f"{GENERIC_CLASS.get(generic, hex(generic))}/0x{specific:02X}"
    nd["nif_ccs"] = ccs
    return n, (f"Node info: {BASIC_CLASS.get(basic, basic)}, {GENERIC_CLASS.get(generic, hex(generic))} "
               f"(specific 0x{specific:02X}) CCs: {', '.join(cc_name(c) for c in ccs if c not in (0xEF, 0xF1))}")


class Decoder:
    def __init__(self, args):
        self.args = args
        self.nodes = defaultdict(lambda: dict(rx=0, tx=0, nack=0, dups=0, rssi=[], ccs=set()))
        self.pending = None          # (ts, node, text, is_encrypted) for RX awaiting dup/decrypt lines
        self.secure_tx = None        # clear-text payload for the next SendData
        self.cb_dest = {}            # callbackId -> (dest, text) for SendData delivery reports
        self.restarts = []

    # ---- output
    def emit(self, ts, n, text):
        if self.args.summary:
            return
        if self.args.node is not None and n != self.args.node:
            return
        print(f"{ts}  {text}")

    def flush(self):
        if self.pending:
            ts, n, text, _ = self.pending
            self.pending = None
            self.emit(ts, n, text)

    # ---- per line
    def line(self, line):
        m = DUP_RE.search(line)
        if m:
            n = int(m.group(1))
            self.nodes[n]["dups"] += 1
            if self.pending and self.pending[1] == n:
                if self.args.dups:
                    ts, _, text, enc = self.pending
                    self.pending = (ts, n, text + "  [DUPLICATE, discarded]", enc)
                else:
                    self.pending = None
            return
        m = SECURE_RX_RE.search(line)
        if m:
            n, ep, scheme, hx = int(m.group(1)), m.group(2), m.group(3) or "S0", m.group(4)
            cmd = [int(x, 16) for x in hx.split()]
            txt = decode_cmd(cmd, self.nodes[n])
            if self.pending and self.pending[1] == n and self.pending[3]:
                ts, _, old, _ = self.pending
                prefix = old.split("  ", 1)[0]
                tail = old[old.rfind("  ("):] if "  (" in old else ""
                self.pending = (ts, n, f"RX  node {n:>3} [{scheme}] {txt}{tail}", False)
            else:
                ts = line[12:24]
                self.flush()
                self.emit(ts, n, f"RX  node {n:>3} [{scheme}] {txt}")
            return
        m = SECURE_TX_RE.search(line)
        if m:
            self.secure_tx = [int(x, 16) for x in m.group(1).split()]
            return
        m = FRAME_RE.search(line)
        if m:
            self.flush()
            _, ts, direction, hx = m.groups()
            b = [int(x, 16) for x in hx.split()]
            try:
                self.frame(ts, direction, b)
            except (IndexError, ValueError, struct.error) as e:
                self.emit(ts, None, f"??  undecodable frame ({e}): {hx.strip()}")
            return
        if self.args.iox:
            mi = INTERVIEW_RE.search(line)
            if mi:
                self.flush()
                n = int(re.search(r"#(\d+)", mi.group(2)).group(1))
                self.emit(mi.group(1), n, f"IOX {mi.group(2)}")
                return
            mi = IOX_RE.search(line)
            if mi and "Update Status" in mi.group(2):
                self.flush()
                mm = re.search(r"ZY0*(\d+)_", mi.group(2))
                n = int(mm.group(1)) if mm else None
                self.emit(mi.group(1), n, f"IOX {mi.group(2).strip()}")

    def frame(self, ts, direction, b):
        if len(b) < 4 or b[0] != 0x01:
            return
        ftype, func, p = b[2], b[3], b[4:-1]   # strip SOF, len, type, func ... checksum
        a = self.args
        name = FUNC.get(func, f"func 0x{func:02X}")

        # ---- incoming application command
        if direction == "RECEIVED" and ftype == 0 and func in (0x04, 0xA8):
            if func == 0x04:
                rx_status, src, ln = p[0], p[1], p[2]
                cmd = p[3:3 + ln]
                tail = p[3 + ln:]
            else:
                rx_status, src, ln = p[0], p[2], p[3]
                cmd = p[4:4 + ln]
                tail = p[4 + ln + 1 + (p[4 + ln] if len(p) > 4 + ln else 0):]
            nd = self.nodes[src]
            nd["rx"] += 1
            sig = ""
            if tail:
                r = tail[0]
                if r not in RSSI_SPECIAL:
                    nd["rssi"].append(s8(r))
                sig = f"RSSI {rssi(r)}"
                if len(tail) >= 3 and tail[2] <= 4 and len(tail) >= 3 + tail[2]:
                    reps = tail[3:3 + tail[2]]
                    route = ("via " + "→".join(str(x) for x in reps)) if reps else "direct"
                    nd["route_in"] = route
                    sig += f", {route}"
            flags = []
            if rx_status & 0x02:
                flags.append("low-power")
            if rx_status & 0x0C:
                flags.append("broadcast" if rx_status & 0x04 else "multicast")
            if flags:
                sig += ", " + ", ".join(flags)
            text = decode_cmd(cmd, nd)
            raw = f"  [{hexs(cmd)}]" if a.raw else ""
            encrypted = len(cmd) > 1 and ((cmd[0] == 0x9F and cmd[1] == 0x03) or (cmd[0] == 0x98 and cmd[1] in (0x81, 0xC1)))
            self.pending = (ts, src, f"RX  node {src:>3} {text}  ({sig}){raw}", encrypted)
            return

        if direction == "RECEIVED" and ftype == 0 and func == 0x0A:
            reason = WAKE_REASON.get(p[0], p[0])
            if self.restarts and self.restarts[-1][0] == ts:
                return
            self.restarts.append((ts, reason))
            self.emit(ts, None, f"!!  Z-Wave radio (Serial API) RESTARTED - reason: {reason}")
            return

        if direction == "RECEIVED" and ftype == 0 and func == 0x49:
            n, text = node_info(p, self.nodes[p[1]])
            self.emit(ts, n, f"NIF node {n:>3} {text}")
            return

        if func == 0x4A and ftype == 0 and direction == "RECEIVED":
            st, n = p[1], p[2]
            self.emit(ts, n, f"INC node {n:>3} AddNode: {ADD_STATUS.get(st, st)}")
            return

        if func == 0x41 and direction == "SENDING":
            self.last_proto_req = p[0]
        elif func == 0x41 and ftype == 1 and getattr(self, "last_proto_req", None) and len(p) >= 6:
            nd = self.nodes[self.last_proto_req]
            listening = "listening" if p[0] & 0x80 else ("FLiRS" if p[1] & 0x60 else "sleeping")
            nd.setdefault("devclass", f"{GENERIC_CLASS.get(p[4], hex(p[4]))}/0x{p[5]:02X}")
            nd["listening"] = listening

        if a.no_tx:
            return

        # ---- outgoing SendData
        if direction == "SENDING" and func in (0x13, 0xA9):
            if func == 0x13:
                dest, ln = p[0], p[1]
                cmd = p[2:2 + ln]
                cb = p[2 + ln + 1] if len(p) > 3 + ln else None
            else:
                dest, ln = p[1], p[2]
                cmd = p[3:3 + ln]
                cb = p[-1]
            nd = self.nodes[dest]
            nd["tx"] += 1
            scheme = ""
            if self.secure_tx is not None and cmd and cmd[0] in (0x9F, 0x98):
                cmd, scheme = self.secure_tx, "[S2] " if cmd[0] == 0x9F else "[S0] "
            self.secure_tx = None
            text = decode_cmd(cmd, {})
            if cb:
                self.cb_dest[cb] = (dest, text)
            raw = f"  [{hexs(cmd)}]" if a.raw else ""
            self.emit(ts, dest, f"TX  node {dest:>3} {scheme}{text}{raw}")
            return

        # ---- SendData delivery report (callback)
        if direction == "RECEIVED" and ftype == 0 and func in (0x13, 0xA9):
            cb = p[0]
            dest, what = self.cb_dest.pop(cb, (None, "?"))
            nd = self.nodes[dest] if dest is not None else {}
            rep = tx_report(p, nd) if dest is not None else tx_report(p, {})
            if dest is not None and p[1] != 0:
                nd["nack"] += 1
            mark = "OK " if p[1] == 0 else "!! "
            who = f"node {dest:>3}" if dest is not None else "node   ?"
            self.emit(ts, dest, f"{mark} {who} delivery: {rep}  ({what})")
            return

        if not a.mgmt:
            return
        # ---- controller housekeeping
        if func == 0x80 and direction == "SENDING":
            self.emit(ts, p[0], f"MGT node {p[0]:>3} {name}")
        elif func == 0x80 and ftype == 1:
            nbrs = [i * 8 + bit + 1 for i, byte in enumerate(p[:29]) for bit in range(8) if byte >> bit & 1]
            self.emit(ts, None, f"MGT          neighbours: {nbrs}")
        elif func == 0x62 and direction == "SENDING":
            self.emit(ts, p[0], f"MGT node {p[0]:>3} IsFailedNode?")
        elif func == 0x62 and ftype == 1:
            self.emit(ts, None, f"MGT          IsFailedNode → {'FAILED' if p[0] else 'operating'}")
        elif func == 0x41 and direction == "SENDING":
            self.emit(ts, p[0], f"MGT node {p[0]:>3} GetNodeProtocolInfo")
        elif func == 0x41 and ftype == 1:
            listening = "always listening" if p[0] & 0x80 else ("FLiRS" if p[1] & 0x60 else "sleeping")
            self.emit(ts, None, f"MGT          protocol info: {listening}, basic={BASIC_CLASS.get(p[3], p[3])}, "
                                f"generic={GENERIC_CLASS.get(p[4], hex(p[4]))}, specific=0x{p[5]:02X}")
        elif func == 0x15 and ftype == 1:
            ver = bytes(p[:12]).split(b"\0")[0].decode("ascii", "replace")
            self.emit(ts, None, f"MGT          controller library: {ver}")
        elif func == 0x60 and direction == "SENDING":
            self.emit(ts, p[0], f"MGT node {p[0]:>3} RequestNodeInfo")
        else:
            arrow = "→" if direction == "SENDING" else "←"
            kind = "" if ftype == 0 else " (response)"
            self.emit(ts, None, f"MGT {arrow} {name}{kind} {hexs(p)}")

    # ---- summary
    def summary(self):
        if self.args.no_summary:
            return
        if self.restarts:
            print(f"\n!! Z-Wave radio restarted {len(self.restarts)} time(s): "
                  + ", ".join(f"{t} ({r})" for t, r in self.restarts))
        print("\n=== Node summary ===")
        print(f"{'node':>4}  {'device class':<28} {'RX':>6} {'TX':>5} {'fail':>4} {'dups':>5} "
              f"{'RSSI avg/min':>13}  {'route in':<14} last state / readings")
        for n in sorted(k for k in self.nodes if k is not None):
            if n in (0, 1, 0xFF):
                continue
            if self.args.node is not None and n != self.args.node:
                continue
            d = self.nodes[n]
            if not (d["rx"] or d["tx"] or d.get("devclass")):
                continue
            r = d["rssi"]
            rs = f"{sum(r) / len(r):.0f}/{min(r)}" if r else ""
            bits = []
            if d.get("state"):
                bits.append(d["state"])
            if d.get("readings"):
                bits.append(", ".join(d["readings"].values()))
            if d.get("battery"):
                bits.append(f"battery {d['battery']}")
            if d.get("presses"):
                bits.append(f"scene presses={d['presses']}")
            if d.get("mfr"):
                bits.append(f"mfr {d['mfr']}")
            dc = d.get("devclass", "") + (f" ({d['listening']})" if d.get("listening") == "sleeping" else "")
            print(f"{n:>4}  {dc[:28]:<28} {d['rx']:>6} {d['tx']:>5} {d['nack']:>4} "
                  f"{d['dups']:>5} {rs:>13}  {d.get('route_in', ''):<14} {'; '.join(bits)}")


def main():
    ap = argparse.ArgumentParser(description="Decode EISY/IoX Z-Wave (ZWAY.LOG) traces.")
    ap.add_argument("file", help="log file, or - for stdin")
    ap.add_argument("--node", type=int)
    ap.add_argument("--summary", action="store_true")
    ap.add_argument("--no-summary", action="store_true")
    ap.add_argument("--dups", action="store_true")
    ap.add_argument("--mgmt", action="store_true")
    ap.add_argument("--iox", action="store_true")
    ap.add_argument("--no-tx", action="store_true")
    ap.add_argument("--raw", action="store_true")
    args = ap.parse_args()

    dec = Decoder(args)
    fh = sys.stdin if args.file == "-" else open(args.file, encoding="utf-8", errors="replace")
    for line in fh:
        dec.line(line)
    dec.flush()
    dec.summary()


if __name__ == "__main__":
    try:
        main()
    except BrokenPipeError:
        sys.stderr.close()
