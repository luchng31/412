
#!/usr/bin/env python3
import os
import struct
import random
import shutil
import sys
from pathlib import Path

MAGIC = b"SC10"

OP_END = 0x00
OP_CONNECT = 0x01
OP_CLOSE = 0x02
OP_SEND = 0x03
OP_WAIT = 0x04
OP_RECV = 0x05
OP_RECONNECT = 0x06
OP_SEND_SPLIT = 0x07
OP_SHUT_WR = 0x08
OP_UFRAME = 0x09
OP_SEND_APDU = 0x0A

TYPE_C_SC_NA_1 = 45
TYPE_C_DC_NA_1 = 46
TYPE_C_RC_NA_1 = 47
TYPE_C_SE_NA_1 = 48
TYPE_C_SE_NB_1 = 49
TYPE_C_SE_NC_1 = 50
TYPE_C_BO_NA_1 = 51
TYPE_C_IC_NA_1 = 100
TYPE_C_CI_NA_1 = 101
TYPE_C_RD_NA_1 = 102
TYPE_C_CS_NA_1 = 103
TYPE_C_TS_NA_1 = 104
TYPE_C_RP_NA_1 = 105
TYPE_C_CD_NA_1 = 106
TYPE_C_TS_TA_1 = 107
TYPE_F_FR_NA_1 = 120
TYPE_F_SR_NA_1 = 121
TYPE_F_SC_NA_1 = 122
TYPE_F_LS_NA_1 = 123
TYPE_F_AF_NA_1 = 124
TYPE_F_SG_NA_1 = 125
TYPE_F_DR_TA_1 = 126
TYPE_F_SC_NB_1 = 127

COT_PERIODIC = 1
COT_BACKGROUND = 2
COT_SPONTANEOUS = 3
COT_INITIALIZED = 4
COT_REQUEST = 5
COT_ACTIVATION = 6
COT_ACTIVATION_CON = 7
COT_DEACTIVATION = 8
COT_ACTIVATION_TERMINATION = 10
COT_UNKNOWN_TYPE = 44
COT_UNKNOWN_COT = 45
COT_UNKNOWN_CA = 46
COT_UNKNOWN_IOA = 47

QOI_STATION = 20
QOI_GROUP_1 = 21
QOI_GROUP_2 = 22
QOI_GROUP_3 = 23
QOI_GROUP_4 = 24
QOI_GROUP_16 = 36

QCC_RQT_GROUP_1 = 1
QCC_RQT_GROUP_2 = 2
QCC_RQT_GROUP_3 = 3
QCC_RQT_GROUP_4 = 4
QCC_RQT_GENERAL = 5
QCC_FRZ_READ = 0x00
QCC_FRZ_FREEZE_WITHOUT_RESET = 0x40
QCC_FRZ_FREEZE_WITH_RESET = 0x80
QCC_FRZ_COUNTER_RESET = 0xC0

QRP_NOT_USED = 0
QRP_GENERAL_RESET = 1
QRP_RESET_PENDING_INFO_WITH_TIME_TAG = 2

SCQ_SELECT_FILE = 1
SCQ_REQUEST_FILE = 2
SCQ_DEACTIVATE_FILE = 3
SCQ_DELETE_FILE = 4
SCQ_SELECT_SECTION = 5
SCQ_REQUEST_SECTION = 6
SCQ_DEACTIVATE_SECTION = 7

def u16(v):
    return struct.pack("<H", v & 0xFFFF)

def i16(v):
    return struct.pack("<h", int(v))

def u24(v):
    v &= 0xFFFFFF
    return bytes((v & 0xFF, (v >> 8) & 0xFF, (v >> 16) & 0xFF))

def u32(v):
    return struct.pack("<I", v & 0xFFFFFFFF)

def f32(v):
    return struct.pack("<f", float(v))

def cp16(ms):
    return u16(ms)

def cp56_from_tuple(year, month, day, hour, minute, second, ms=0, weekday=0):
    msec = second * 1000 + ms
    b0 = msec & 0xFF
    b1 = (msec >> 8) & 0xFF
    b2 = minute & 0x3F
    b3 = hour & 0x1F
    b4 = day & 0x1F
    if weekday:
        b4 |= ((weekday & 0x07) << 5)
    b5 = month & 0x0F
    b6 = year % 100
    return bytes((b0, b1, b2, b3, b4, b5, b6))

def asdu(type_id, cot, ca, objects, oa=0, sq=False, test=False, negative=False):
    vsq = len(objects) & 0x7F
    if sq:
        vsq |= 0x80
    cot0 = cot & 0x3F
    if negative:
        cot0 |= 0x40
    if test:
        cot0 |= 0x80
    return bytes((type_id & 0xFF, vsq, cot0, oa & 0xFF)) + u16(ca) + b"".join(objects)

def i_frame(asdu_bytes, tx=0, rx=0):
    ctrl = u16((tx << 1) & 0xFFFF) + u16((rx << 1) & 0xFFFF)
    apdu = ctrl + asdu_bytes
    return bytes((0x68, len(apdu))) + apdu

def s_frame(rx=0):
    return b"\x68\x04\x01\x00" + u16((rx << 1) & 0xFFFF)

def u_frame(kind):
    table = {
        "STARTDT_ACT": b"\x68\x04\x07\x00\x00\x00",
        "STARTDT_CON": b"\x68\x04\x0B\x00\x00\x00",
        "STOPDT_ACT":  b"\x68\x04\x13\x00\x00\x00",
        "STOPDT_CON":  b"\x68\x04\x23\x00\x00\x00",
        "TESTFR_ACT":  b"\x68\x04\x43\x00\x00\x00",
        "TESTFR_CON":  b"\x68\x04\x83\x00\x00\x00",
    }
    return table[kind]

def obj_interrogation(qoi):
    return u24(0) + bytes((qoi & 0xFF,))

def obj_counter_interrogation(qcc):
    return u24(0) + bytes((qcc & 0xFF,))

def obj_read(ioa):
    return u24(ioa)

def obj_clock_sync(ts):
    return u24(0) + ts

def obj_reset_process(qrp):
    return u24(0) + bytes((qrp & 0xFF,))

def obj_delay(ms):
    return u24(0) + cp16(ms)

def obj_single_command(ioa, state, select=False, qu=0):
    sco = (1 if state else 0) | ((qu & 0x1F) << 2) | (0x80 if select else 0)
    return u24(ioa) + bytes((sco & 0xFF,))

def obj_double_command(ioa, state, select=False, qu=0):
    dco = (state & 0x03) | ((qu & 0x1F) << 2) | (0x80 if select else 0)
    return u24(ioa) + bytes((dco & 0xFF,))

def obj_step_command(ioa, state, select=False, qu=0):
    rco = (state & 0x03) | ((qu & 0x1F) << 2) | (0x80 if select else 0)
    return u24(ioa) + bytes((rco & 0xFF,))

def norm_to_i16(v):
    if v > 1.0:
        v = 1.0
    if v < -1.0:
        v = -1.0
    raw = int(round(v * 32767.0))
    if raw > 32767:
        raw = 32767
    if raw < -32768:
        raw = -32768
    return raw

def qos(select=False, ql=0):
    return ((ql & 0x7F) | (0x80 if select else 0)) & 0xFF

def obj_setpoint_norm(ioa, value, select=False, ql=0):
    return u24(ioa) + i16(norm_to_i16(value)) + bytes((qos(select, ql),))

def obj_setpoint_scaled(ioa, value, select=False, ql=0):
    if value > 32767:
        value = 32767
    if value < -32768:
        value = -32768
    return u24(ioa) + i16(value) + bytes((qos(select, ql),))

def obj_setpoint_short(ioa, value, select=False, ql=0):
    return u24(ioa) + f32(value) + bytes((qos(select, ql),))

def obj_bitstring_command(ioa, value):
    return u24(ioa) + u32(value)

def obj_test_command(valid=True):
    if valid:
        return u24(0) + b"\xAA\x55"
    return u24(0) + b"\x55\xAA"

def obj_test_command_time(counter, ts):
    return u24(0) + u16(counter) + ts

def obj_file_ready(ioa, nof, length, frq=0):
    return u24(ioa) + bytes((nof & 0xFF,)) + u24(length) + bytes((frq & 0xFF,))

def obj_section_ready(ioa, nof, name_of_section, length, srq=0):
    return u24(ioa) + bytes((nof & 0xFF, name_of_section & 0xFF)) + u24(length) + bytes((srq & 0xFF,))

def obj_file_call_select(ioa, nof, name_of_section, scq):
    return u24(ioa) + bytes((nof & 0xFF, name_of_section & 0xFF, scq & 0xFF))

def obj_last_segment(ioa, nof, name_of_section, lsq, chs=0):
    return u24(ioa) + bytes((nof & 0xFF, name_of_section & 0xFF, lsq & 0xFF)) + u16(chs)

def obj_ack_file(ioa, nof, name_of_section, afq):
    return u24(ioa) + bytes((nof & 0xFF, name_of_section & 0xFF, afq & 0xFF))

def obj_file_segment(ioa, nof, name_of_section, los, data):
    if len(data) > 220:
        data = data[:220]
    return u24(ioa) + bytes((nof & 0xFF, name_of_section & 0xFF, los & 0xFF, len(data) & 0xFF)) + data

def obj_directory(ioa, nof, length, sof=0, status=0, ts=None):
    if ts is None:
        ts = cp56_from_tuple(2025, 1, 1, 0, 0, 0)
    return u24(ioa) + bytes((nof & 0xFF,)) + u24(length) + bytes((sof & 0xFF, status & 0xFF)) + ts

def apdu_gi(ca=1, qoi=QOI_STATION, cot=COT_ACTIVATION, tx=0, oa=0):
    return i_frame(asdu(TYPE_C_IC_NA_1, cot, ca, [obj_interrogation(qoi)], oa=oa), tx=tx)

def apdu_ci(ca=1, qcc=QCC_RQT_GENERAL | QCC_FRZ_READ, cot=COT_ACTIVATION, tx=0, oa=0):
    return i_frame(asdu(TYPE_C_CI_NA_1, cot, ca, [obj_counter_interrogation(qcc)], oa=oa), tx=tx)

def apdu_read(ca=1, ioa=100, cot=COT_REQUEST, tx=0, oa=0):
    return i_frame(asdu(TYPE_C_RD_NA_1, cot, ca, [obj_read(ioa)], oa=oa), tx=tx)

def apdu_clock(ca=1, ts=None, cot=COT_ACTIVATION, tx=0, oa=0):
    if ts is None:
        ts = cp56_from_tuple(2025, 1, 1, 0, 0, 0)
    return i_frame(asdu(TYPE_C_CS_NA_1, cot, ca, [obj_clock_sync(ts)], oa=oa), tx=tx)

def apdu_reset(ca=1, qrp=QRP_GENERAL_RESET, cot=COT_ACTIVATION, tx=0, oa=0):
    return i_frame(asdu(TYPE_C_RP_NA_1, cot, ca, [obj_reset_process(qrp)], oa=oa), tx=tx)

def apdu_delay(ca=1, ms=10, cot=COT_ACTIVATION, tx=0, oa=0):
    return i_frame(asdu(TYPE_C_CD_NA_1, cot, ca, [obj_delay(ms)], oa=oa), tx=tx)

def apdu_single(ca=1, ioa=5000, state=True, select=False, qu=0, cot=COT_ACTIVATION, tx=0, oa=0):
    return i_frame(asdu(TYPE_C_SC_NA_1, cot, ca, [obj_single_command(ioa, state, select, qu)], oa=oa), tx=tx)

def apdu_double(ca=1, ioa=5100, state=2, select=False, qu=0, cot=COT_ACTIVATION, tx=0, oa=0):
    return i_frame(asdu(TYPE_C_DC_NA_1, cot, ca, [obj_double_command(ioa, state, select, qu)], oa=oa), tx=tx)

def apdu_step(ca=1, ioa=5200, state=2, select=False, qu=0, cot=COT_ACTIVATION, tx=0, oa=0):
    return i_frame(asdu(TYPE_C_RC_NA_1, cot, ca, [obj_step_command(ioa, state, select, qu)], oa=oa), tx=tx)

def apdu_sp_norm(ca=1, ioa=5300, value=0.25, select=False, ql=0, cot=COT_ACTIVATION, tx=0, oa=0):
    return i_frame(asdu(TYPE_C_SE_NA_1, cot, ca, [obj_setpoint_norm(ioa, value, select, ql)], oa=oa), tx=tx)

def apdu_sp_scaled(ca=1, ioa=5310, value=123, select=False, ql=0, cot=COT_ACTIVATION, tx=0, oa=0):
    return i_frame(asdu(TYPE_C_SE_NB_1, cot, ca, [obj_setpoint_scaled(ioa, value, select, ql)], oa=oa), tx=tx)

def apdu_sp_short(ca=1, ioa=5320, value=12.5, select=False, ql=0, cot=COT_ACTIVATION, tx=0, oa=0):
    return i_frame(asdu(TYPE_C_SE_NC_1, cot, ca, [obj_setpoint_short(ioa, value, select, ql)], oa=oa), tx=tx)

def apdu_bitstring(ca=1, ioa=5400, value=0x12345678, cot=COT_ACTIVATION, tx=0, oa=0):
    return i_frame(asdu(TYPE_C_BO_NA_1, cot, ca, [obj_bitstring_command(ioa, value)], oa=oa), tx=tx)

def apdu_test(ca=1, valid=True, cot=COT_ACTIVATION, tx=0, oa=0):
    return i_frame(asdu(TYPE_C_TS_NA_1, cot, ca, [obj_test_command(valid)], oa=oa), tx=tx)

def apdu_test_time(ca=1, counter=0x1234, ts=None, cot=COT_ACTIVATION, tx=0, oa=0):
    if ts is None:
        ts = cp56_from_tuple(2025, 2, 3, 4, 5, 6, 7)
    return i_frame(asdu(TYPE_C_TS_TA_1, cot, ca, [obj_test_command_time(counter, ts)], oa=oa), tx=tx)

def apdu_file_ready(ca=1, ioa=30001, nof=1, length=32, frq=1, tx=0, oa=0):
    return i_frame(asdu(TYPE_F_FR_NA_1, COT_ACTIVATION, ca, [obj_file_ready(ioa, nof, length, frq)], oa=oa), tx=tx)

def apdu_file_section_ready(ca=1, ioa=30001, nof=1, name_of_section=1, length=32, srq=0, tx=0, oa=0):
    return i_frame(asdu(TYPE_F_SR_NA_1, COT_ACTIVATION, ca, [obj_section_ready(ioa, nof, name_of_section, length, srq)], oa=oa), tx=tx)

def apdu_file_call_select(ca=1, ioa=30000, nof=1, name_of_section=0, scq=SCQ_SELECT_FILE, tx=0, oa=0):
    return i_frame(asdu(TYPE_F_SC_NA_1, COT_REQUEST, ca, [obj_file_call_select(ioa, nof, name_of_section, scq)], oa=oa), tx=tx)

def apdu_file_ack(ca=1, ioa=30000, nof=1, name_of_section=1, afq=0, tx=0, oa=0):
    return i_frame(asdu(TYPE_F_AF_NA_1, COT_ACTIVATION, ca, [obj_ack_file(ioa, nof, name_of_section, afq)], oa=oa), tx=tx)

def apdu_file_segment(ca=1, ioa=30001, nof=1, name_of_section=1, los=0, data=b"ABCDEF", tx=0, oa=0):
    return i_frame(asdu(TYPE_F_SG_NA_1, COT_ACTIVATION, ca, [obj_file_segment(ioa, nof, name_of_section, los, data)], oa=oa), tx=tx)

def apdu_file_last_segment(ca=1, ioa=30001, nof=1, name_of_section=1, lsq=1, chs=0, tx=0, oa=0):
    return i_frame(asdu(TYPE_F_LS_NA_1, COT_ACTIVATION, ca, [obj_last_segment(ioa, nof, name_of_section, lsq, chs)], oa=oa), tx=tx)

def apdu_file_directory(ca=1, ioa=30000, nof=1, length=1024, tx=0, oa=0):
    return i_frame(asdu(TYPE_F_DR_TA_1, COT_SPONTANEOUS, ca, [obj_directory(ioa, nof, length)], oa=oa), tx=tx)

def raw_apdu(payload):
    return payload

def op_connect():
    return bytes((OP_CONNECT,))

def op_close():
    return bytes((OP_CLOSE,))

def op_reconnect():
    return bytes((OP_RECONNECT,))

def op_wait(n):
    return bytes((OP_WAIT, n & 0xFF))

def op_recv(n):
    return bytes((OP_RECV, n & 0xFF))

def op_shutdown_wr():
    return bytes((OP_SHUT_WR,))

def op_uframe(sel):
    return bytes((OP_UFRAME, sel & 0xFF))

def op_send(data):
    return bytes((OP_SEND,)) + u16(len(data)) + data

def op_send_apdu(data):
    return bytes((OP_SEND_APDU,)) + u16(len(data)) + data

def op_send_split(stride, data):
    return bytes((OP_SEND_SPLIT, stride & 0xFF)) + u16(len(data)) + data

def script(*ops):
    return MAGIC + b"".join(ops) + bytes((OP_END,))

def raw(data):
    return data

def write_seed(out_dir, name, data):
    (out_dir / name).write_bytes(data)

def ensure_clean_dir(path):
    if path.exists():
        shutil.rmtree(path)
    path.mkdir(parents=True)

def build_dict(path):
    entries = []
    def add(name, b):
        entries.append(f'{name}="{to_escaped(b)}"')
    def to_escaped(b):
        return "".join(f"\\x{x:02x}" for x in b)

    add("magic_SC10", MAGIC)
    for op, name in [
        (OP_CONNECT, "op_connect"),
        (OP_CLOSE, "op_close"),
        (OP_SEND, "op_send"),
        (OP_WAIT, "op_wait"),
        (OP_RECV, "op_recv"),
        (OP_RECONNECT, "op_reconnect"),
        (OP_SEND_SPLIT, "op_send_split"),
        (OP_SHUT_WR, "op_shut_wr"),
        (OP_UFRAME, "op_uframe"),
        (OP_SEND_APDU, "op_send_apdu"),
        (OP_END, "op_end"),
    ]:
        add(name, bytes((op,)))

    for i, n in enumerate(["STARTDT_ACT", "STARTDT_CON", "STOPDT_ACT", "STOPDT_CON", "TESTFR_ACT", "TESTFR_CON"]):
        add("uframe_" + n.lower(), bytes((OP_UFRAME, i)))
    for n in [1,2,3,4,8,16,32,64,128]:
        add(f"wait_{n}", bytes((OP_WAIT, n)))
        add(f"recv_{n}", bytes((OP_RECV, n)))

    for name, frame in [
        ("apci_startdt_act", u_frame("STARTDT_ACT")),
        ("apci_startdt_con", u_frame("STARTDT_CON")),
        ("apci_stopdt_act", u_frame("STOPDT_ACT")),
        ("apci_stopdt_con", u_frame("STOPDT_CON")),
        ("apci_testfr_act", u_frame("TESTFR_ACT")),
        ("apci_testfr_con", u_frame("TESTFR_CON")),
        ("apci_sframe_rx0", s_frame(0)),
        ("apci_sframe_rx1", s_frame(1)),
        ("apci_sframe_rx4", s_frame(4)),
        ("apci_sframe_rx8", s_frame(8)),
    ]:
        add(name, frame)

    core_apdus = [
        ("gi_station_ca1", apdu_gi(1, QOI_STATION, tx=0)),
        ("gi_group1_ca1", apdu_gi(1, QOI_GROUP_1, tx=0)),
        ("gi_group4_ca1", apdu_gi(1, QOI_GROUP_4, tx=0)),
        ("gi_station_ca2", apdu_gi(2, QOI_STATION, tx=0)),
        ("gi_broadcast", apdu_gi(0xFFFF, QOI_STATION, tx=0)),
        ("gi_bad_ca", apdu_gi(4, QOI_STATION, tx=0)),
        ("ci_general", apdu_ci(1, QCC_RQT_GENERAL | QCC_FRZ_READ, tx=1)),
        ("ci_group1", apdu_ci(1, QCC_RQT_GROUP_1 | QCC_FRZ_READ, tx=1)),
        ("ci_group4_reset", apdu_ci(1, QCC_RQT_GROUP_4 | QCC_FRZ_COUNTER_RESET, tx=1)),
        ("read_100", apdu_read(1, 100, tx=2)),
        ("read_104", apdu_read(1, 104, tx=2)),
        ("read_500", apdu_read(1, 500, tx=2)),
        ("read_200", apdu_read(1, 200, tx=2)),
        ("read_bad_ioa", apdu_read(1, 9999, tx=2)),
        ("clock_sync", apdu_clock(1, cp56_from_tuple(2025, 1, 2, 3, 4, 5, 678), tx=3)),
        ("reset_proc", apdu_reset(1, QRP_GENERAL_RESET, tx=4)),
        ("delay_10", apdu_delay(1, 10, tx=5)),
        ("delay_60000", apdu_delay(1, 60000, tx=5)),
        ("single_on", apdu_single(1, 5000, True, False, tx=6)),
        ("single_sel", apdu_single(1, 5001, True, True, tx=7)),
        ("double_on", apdu_double(1, 5100, 2, False, tx=8)),
        ("step_high", apdu_step(1, 5200, 2, False, tx=9)),
        ("sp_norm", apdu_sp_norm(1, 5300, 0.25, False, tx=10)),
        ("sp_scaled", apdu_sp_scaled(1, 5310, 321, False, tx=11)),
        ("sp_short", apdu_sp_short(1, 5320, 1.5, False, tx=12)),
        ("bitstring", apdu_bitstring(1, 5400, 0x11223344, tx=13)),
        ("test_valid", apdu_test(1, True, tx=14)),
        ("test_invalid", apdu_test(1, False, tx=14)),
        ("test_time", apdu_test_time(1, 0x1111, cp56_from_tuple(2025, 6, 7, 8, 9, 10, 111), tx=15)),
        ("file_ready", apdu_file_ready(1, 30001, 1, 32, 1, tx=16)),
        ("file_select", apdu_file_call_select(1, 30000, 1, 0, SCQ_SELECT_FILE, tx=17)),
        ("file_request", apdu_file_call_select(1, 30000, 1, 0, SCQ_REQUEST_FILE, tx=18)),
        ("file_select_section", apdu_file_call_select(1, 30000, 1, 1, SCQ_SELECT_SECTION, tx=19)),
        ("file_request_section", apdu_file_call_select(1, 30000, 1, 1, SCQ_REQUEST_SECTION, tx=20)),
        ("file_segment", apdu_file_segment(1, 30001, 1, 1, 0, b"ABCDEF0123456789", tx=21)),
        ("file_last_segment", apdu_file_last_segment(1, 30001, 1, 1, 1, 0x1234, tx=22)),
    ]
    for n, b in core_apdus:
        add(n, b)
        if len(b) > 8:
            add(n + "_body", b[6:])
    for x in [1,2,3,20,21,22,23,24,36,45,46,47,48,49,50,51,100,101,102,103,104,105,106,107,120,121,122,123,124,125,126,127]:
        add(f"type_or_qoi_{x}", bytes((x & 0xFF,)))
    for ca in [1,2,3,4,0xFF]:
        if ca <= 0xFF:
            add(f"ca_{ca}", bytes((ca,0x00)))
    add("ca_broadcast", b"\xff\xff")
    for ioa in [0,100,101,102,104,105,106,107,110,111,112,120,130,140,150,151,152,153,200,500,501,2000,2001,2002,2003,30000,30001,30010,30011,5000,5001,5100,5200,5300,5310,5320,5400,9999]:
        add(f"ioa_{ioa}", u24(ioa))
    path.write_text("\n".join(entries) + "\n", encoding="utf-8")

def build_corpus(out_dir):
    ensure_clean_dir(out_dir)
    seeds = {}

    def add(name, data):
        if name in seeds:
            raise ValueError(name)
        seeds[name] = data

    def sess(*ops):
        return script(*ops)

    def rawsess(*parts):
        return raw(b"".join(parts))

    # Layer 1: handshake / APCI
    add("s000_handshake_startdt", sess(op_connect(), op_uframe(0), op_wait(2), op_recv(4)))
    add("s001_handshake_testfr", sess(op_connect(), op_uframe(0), op_wait(1), op_recv(2), op_uframe(4), op_wait(1), op_recv(2)))
    add("s002_handshake_stopdt", sess(op_connect(), op_uframe(0), op_wait(1), op_recv(2), op_uframe(2), op_wait(2), op_recv(2)))
    add("s003_connect_close_reconnect", sess(op_connect(), op_wait(1), op_close(), op_wait(1), op_reconnect(), op_uframe(0), op_wait(2), op_recv(2)))
    add("s004_shutdown_wr", sess(op_connect(), op_uframe(0), op_wait(1), op_shutdown_wr(), op_wait(2), op_recv(2)))
    add("s005_raw_sframe_after_start", sess(op_connect(), op_uframe(0), op_wait(1), op_send(s_frame(0)), op_wait(1), op_recv(2)))
    add("s006_raw_u_then_i_without_recv", sess(op_connect(), op_uframe(0), op_send(apdu_gi(1, QOI_STATION, tx=0)), op_send(apdu_read(1, 100, tx=1)), op_wait(8)))
    add("s007_raw_multi_u_frames", sess(op_connect(), op_send(u_frame("TESTFR_ACT")), op_send(u_frame("STARTDT_ACT")), op_wait(2), op_recv(4), op_send(u_frame("STOPDT_ACT")), op_wait(2), op_recv(2)))

    # Layer 2: GI
    for idx, (ca, qoi, split) in enumerate([
        (1, QOI_STATION, 0), (1, QOI_GROUP_1, 0), (1, QOI_GROUP_2, 0), (1, QOI_GROUP_3, 0),
        (1, QOI_GROUP_4, 1), (2, QOI_STATION, 1), (3, QOI_STATION, 2), (4, QOI_STATION, 0),
        (0xFFFF, QOI_STATION, 0), (1, 0, 0), (1, 255, 2), (1, QOI_GROUP_16, 1)
    ]):
        frame = apdu_gi(ca, qoi, tx=0)
        if split == 0:
            add(f"s010_gi_{idx:02d}", sess(op_connect(), op_uframe(0), op_wait(1), op_recv(1), op_send(frame), op_wait(8), op_recv(8), op_send(s_frame(8)), op_wait(2), op_recv(4)))
        elif split == 1:
            add(f"s010_gi_{idx:02d}", sess(op_connect(), op_uframe(0), op_wait(1), op_send_split(1, frame), op_wait(10), op_recv(10), op_send(s_frame(16)), op_wait(2), op_recv(4)))
        else:
            add(f"s010_gi_{idx:02d}", sess(op_connect(), op_uframe(0), op_wait(1), op_send_split(2, frame), op_wait(10), op_recv(10)))

    # Layer 3: CI
    ci_qccs = [
        QCC_RQT_GROUP_1 | QCC_FRZ_READ,
        QCC_RQT_GROUP_2 | QCC_FRZ_READ,
        QCC_RQT_GROUP_3 | QCC_FRZ_FREEZE_WITHOUT_RESET,
        QCC_RQT_GROUP_4 | QCC_FRZ_FREEZE_WITH_RESET,
        QCC_RQT_GENERAL | QCC_FRZ_COUNTER_RESET,
        0xFF,
    ]
    for idx, qcc in enumerate(ci_qccs):
        frame = apdu_ci(1 if idx < 5 else 4, qcc, tx=1)
        add(f"s030_ci_{idx:02d}", sess(op_connect(), op_uframe(0), op_wait(1), op_send(frame), op_wait(8), op_recv(8), op_send(s_frame(8)), op_wait(2), op_recv(4)))

    # Layer 4: read
    for idx, (ca, ioa, split) in enumerate([
        (1,100,0),(1,101,0),(1,102,1),(1,104,0),(1,105,1),(1,500,0),(1,200,1),(2,100,0),
        (3,500,1),(4,100,0),(0xFFFF,100,0),(1,9999,1),(1,5400,2)
    ]):
        frame = apdu_read(ca, ioa, tx=2)
        sender = op_send(frame) if split == 0 else op_send_split(split, frame)
        add(f"s040_read_{idx:02d}", sess(op_connect(), op_uframe(0), op_wait(1), sender, op_wait(4), op_recv(6)))

    # Layer 5: clock / reset / delay
    times = [
        cp56_from_tuple(1970,1,1,0,0,0,0),
        cp56_from_tuple(2024,2,29,23,59,59,999),
        cp56_from_tuple(2038,1,19,3,14,7,0),
        cp56_from_tuple(2099,12,31,23,59,59,999),
    ]
    for idx, ts in enumerate(times):
        add(f"s050_clock_{idx:02d}", sess(op_connect(), op_uframe(0), op_send(apdu_clock(1, ts, tx=3)), op_wait(4), op_recv(6)))
    for idx, (ca, qrp) in enumerate([(1,0),(1,1),(1,2),(1,3),(4,1),(0xFFFF,1)]):
        add(f"s060_reset_{idx:02d}", sess(op_connect(), op_uframe(0), op_send(apdu_reset(ca, qrp, tx=4)), op_wait(4), op_recv(6)))
    for idx, (ca, ms) in enumerate([(1,0),(1,1),(1,10),(1,500),(1,65535),(4,10),(0xFFFF,10)]):
        add(f"s070_delay_{idx:02d}", sess(op_connect(), op_uframe(0), op_send(apdu_delay(ca, ms, tx=5)), op_wait(4), op_recv(6)))

    # Layer 6: controls - valid / invalid / select-before-operate
    single_cases = [(1,5000,True,False,0),(1,5001,False,False,0),(1,5002,True,True,0),(1,5002,True,False,0),(1,4999,True,False,0),(1,5008,True,False,0),(4,5000,True,False,0),(0xFFFF,5000,True,False,0)]
    for idx, args in enumerate(single_cases):
        add(f"s080_single_{idx:02d}", sess(op_connect(), op_uframe(0), op_send(apdu_single(*args, tx=6)), op_wait(4), op_recv(6)))

    double_cases = [(1,5100,1,False,0),(1,5100,2,False,0),(1,5101,3,False,0),(1,5102,2,True,0),(1,5102,2,False,0),(1,5099,2,False,0),(1,5108,2,False,0)]
    for idx, args in enumerate(double_cases):
        add(f"s090_double_{idx:02d}", sess(op_connect(), op_uframe(0), op_send(apdu_double(*args, tx=7)), op_wait(4), op_recv(6)))

    step_cases = [(1,5200,1,False,0),(1,5200,2,False,0),(1,5201,3,False,0),(1,5202,2,True,0),(1,5202,2,False,0),(1,5199,2,False,0),(1,5208,2,False,0)]
    for idx, args in enumerate(step_cases):
        add(f"s100_step_{idx:02d}", sess(op_connect(), op_uframe(0), op_send(apdu_step(*args, tx=8)), op_wait(4), op_recv(6)))

    sp_norm_cases = [(1,5300,-1.0,False,0),(1,5300,0.0,False,0),(1,5300,1.0,False,0),(1,5301,0.5,True,0),(1,5301,0.5,False,0),(1,5299,0.5,False,0),(1,5302,0.5,False,0)]
    for idx, args in enumerate(sp_norm_cases):
        add(f"s110_spnorm_{idx:02d}", sess(op_connect(), op_uframe(0), op_send(apdu_sp_norm(*args, tx=9)), op_wait(4), op_recv(6)))

    sp_scaled_cases = [(1,5310,-32768,False,0),(1,5310,0,False,0),(1,5310,32767,False,0),(1,5311,123,True,0),(1,5311,123,False,0),(1,5309,123,False,0),(1,5312,123,False,0)]
    for idx, args in enumerate(sp_scaled_cases):
        add(f"s120_spscaled_{idx:02d}", sess(op_connect(), op_uframe(0), op_send(apdu_sp_scaled(*args, tx=10)), op_wait(4), op_recv(6)))

    sp_short_cases = [(1,5320,-1.0,False,0),(1,5320,0.0,False,0),(1,5320,1.5,False,0),(1,5321,123.75,True,0),(1,5321,123.75,False,0),(1,5319,1.0,False,0),(1,5322,1.0,False,0)]
    for idx, args in enumerate(sp_short_cases):
        add(f"s130_spshort_{idx:02d}", sess(op_connect(), op_uframe(0), op_send(apdu_sp_short(*args, tx=11)), op_wait(4), op_recv(6)))

    bit_cases = [(1,5400,0x0),(1,5400,0xFFFFFFFF),(1,5400,0x12345678),(1,5401,0xA5A5A5A5),(1,5399,0xCAFEBABE),(1,5402,0xDEADBEEF)]
    for idx, args in enumerate(bit_cases):
        add(f"s140_bitstring_{idx:02d}", sess(op_connect(), op_uframe(0), op_send(apdu_bitstring(*args, tx=12)), op_wait(4), op_recv(6)))

    test_cases = [
        apdu_test(1, True, tx=13),
        apdu_test(1, False, tx=13),
        apdu_test_time(1, 0x0000, cp56_from_tuple(1970,1,1,0,0,0), tx=14),
        apdu_test_time(1, 0xFFFF, cp56_from_tuple(2025,12,31,23,59,59,999), tx=14),
    ]
    for idx, frame in enumerate(test_cases):
        add(f"s150_test_{idx:02d}", sess(op_connect(), op_uframe(0), op_send(frame), op_wait(4), op_recv(6)))

    # Layer 7: multi-step stateful sequences
    add("s160_mix_gi_read_single", sess(
        op_connect(), op_uframe(0), op_wait(1),
        op_send(apdu_gi(1, QOI_STATION, tx=0)), op_wait(6), op_recv(8),
        op_send(apdu_read(1, 100, tx=1)), op_wait(2), op_recv(4),
        op_send(apdu_single(1, 5000, True, False, tx=2)), op_wait(2), op_recv(4)
    ))
    add("s161_mix_ci_delay_reset", sess(
        op_connect(), op_uframe(0), op_send(apdu_ci(1, QCC_RQT_GENERAL | QCC_FRZ_READ, tx=0)),
        op_wait(6), op_recv(8),
        op_send(apdu_delay(1, 10, tx=1)), op_wait(2), op_recv(4),
        op_send(apdu_reset(1, QRP_GENERAL_RESET, tx=2)), op_wait(2), op_recv(4)
    ))
    add("s162_mix_clock_setpoints", sess(
        op_connect(), op_uframe(0),
        op_send(apdu_clock(1, cp56_from_tuple(2025,5,5,5,5,5,5), tx=0)), op_wait(2), op_recv(4),
        op_send(apdu_sp_norm(1, 5300, 0.25, False, tx=1)), op_wait(2), op_recv(4),
        op_send(apdu_sp_scaled(1, 5310, 1234, False, tx=2)), op_wait(2), op_recv(4),
        op_send(apdu_sp_short(1, 5320, 99.5, False, tx=3)), op_wait(2), op_recv(4)
    ))
    add("s163_select_before_operate", sess(
        op_connect(), op_uframe(0),
        op_send(apdu_single(1, 5002, True, True, tx=0)), op_wait(2), op_recv(4),
        op_send(apdu_single(1, 5002, True, False, tx=1)), op_wait(2), op_recv(4),
        op_send(apdu_double(1, 5102, 2, True, tx=2)), op_wait(2), op_recv(4),
        op_send(apdu_double(1, 5102, 2, False, tx=3)), op_wait(2), op_recv(4)
    ))
    add("s164_stopdt_path", sess(
        op_connect(), op_uframe(0), op_wait(1),
        op_send(apdu_gi(1, QOI_STATION, tx=0)), op_wait(6),
        op_uframe(2), op_wait(2), op_recv(6),
        op_send(apdu_read(1, 100, tx=1)), op_wait(4), op_recv(4),
        op_reconnect(), op_uframe(0), op_wait(1),
        op_send(apdu_read(1, 100, tx=0)), op_wait(3), op_recv(4)
    ))
    add("s165_fragment_header_and_body", sess(
        op_connect(), op_uframe(0), op_wait(1),
        op_send_split(1, apdu_gi(1, QOI_STATION, tx=0)), op_wait(6), op_recv(8),
        op_send_split(2, apdu_single(1, 5000, True, False, tx=1)), op_wait(3), op_recv(4)
    ))
    add("s166_reconnect_multi_session", sess(
        op_connect(), op_uframe(0), op_send(apdu_read(1, 100, tx=0)), op_wait(2), op_recv(4),
        op_close(), op_wait(1),
        op_reconnect(), op_uframe(0), op_send(apdu_gi(1, QOI_GROUP_1, tx=0)), op_wait(6), op_recv(8),
        op_close(), op_wait(1),
        op_reconnect(), op_uframe(0), op_send(apdu_ci(1, QCC_RQT_GROUP_1 | QCC_FRZ_READ, tx=0)), op_wait(6), op_recv(8)
    ))
    add("s167_no_recv_burst_i_frames", sess(
        op_connect(), op_uframe(0),
        op_send(apdu_gi(1, QOI_STATION, tx=0)),
        op_send(apdu_read(1, 100, tx=1)),
        op_send(apdu_single(1, 5000, True, False, tx=2)),
        op_send(apdu_delay(1, 10, tx=3)),
        op_wait(16), op_recv(16)
    ))
    add("s168_with_sframe_ack", sess(
        op_connect(), op_uframe(0), op_send(apdu_gi(1, QOI_STATION, tx=0)), op_wait(6), op_recv(8),
        op_send(s_frame(4)), op_wait(2), op_recv(4),
        op_send(apdu_ci(1, QCC_RQT_GENERAL | QCC_FRZ_READ, tx=1)), op_wait(6), op_recv(8),
        op_send(s_frame(12)), op_wait(2), op_recv(4)
    ))
    add("s169_unknown_ca_and_broadcast_mix", sess(
        op_connect(), op_uframe(0),
        op_send(apdu_gi(4, QOI_STATION, tx=0)), op_wait(2), op_recv(4),
        op_send(apdu_gi(0xFFFF, QOI_STATION, tx=1)), op_wait(2), op_recv(4),
        op_send(apdu_reset(4, QRP_GENERAL_RESET, tx=2)), op_wait(2), op_recv(4),
        op_send(apdu_single(0xFFFF, 5000, True, False, tx=3)), op_wait(2), op_recv(4)
    ))

    # Layer 8: file service probes
    file_seqs = [
        [apdu_file_call_select(1, 30000, 1, 0, SCQ_SELECT_FILE, tx=0),
         apdu_file_call_select(1, 30000, 1, 0, SCQ_REQUEST_FILE, tx=1)],
        [apdu_file_call_select(1, 30000, 1, 1, SCQ_SELECT_SECTION, tx=0),
         apdu_file_call_select(1, 30000, 1, 1, SCQ_REQUEST_SECTION, tx=1)],
        [apdu_file_ready(1, 30001, 1, 16, 1, tx=0),
         apdu_file_segment(1, 30001, 1, 1, 0, b"AAAA", tx=1),
         apdu_file_last_segment(1, 30001, 1, 1, 1, 0, tx=2)],
        [apdu_file_ready(2, 30011, 1, 64, 1, tx=0),
         apdu_file_segment(2, 30011, 1, 1, 0, bytes(range(32)), tx=1),
         apdu_file_last_segment(2, 30011, 1, 1, 1, 0xBEEF, tx=2)],
        [apdu_file_call_select(1, 30000, 1, 0, SCQ_DELETE_FILE, tx=0)],
        [apdu_file_call_select(1, 30000, 1, 1, SCQ_DEACTIVATE_SECTION, tx=0)],
        [apdu_file_ack(1, 30000, 1, 1, 0, tx=0), apdu_file_directory(1, 30000, 1, 1024, tx=1)],
    ]
    for idx, seq in enumerate(file_seqs):
        ops = [op_connect(), op_uframe(0), op_wait(1)]
        for n, frame in enumerate(seq):
            if n == 1:
                ops.append(op_send_split(1, frame))
            else:
                ops.append(op_send(frame))
            ops.append(op_wait(4))
            ops.append(op_recv(4))
        add(f"s180_file_{idx:02d}", sess(*ops))

    # Layer 9: malformed / near-valid
    bad_frames = [
        b"\x68\xff" + b"A" * 16,
        b"\x68\x00",
        b"\x68\x04\x00\x00\x00\x00",
        b"\x68\x04\x03\x00\x00\x00",
        b"\x68\x04\xff\xff\xff\xff",
        apdu_gi(1, QOI_STATION, tx=0)[:-1],
        apdu_read(1, 100, tx=0)[:-2],
        apdu_single(1, 5000, True, False, tx=0) + b"\x00\x00",
    ]
    for idx, bf in enumerate(bad_frames):
        add(f"s190_bad_{idx:02d}", sess(op_connect(), op_send(bf), op_wait(4), op_recv(4)))

    # Layer 10: raw auto-mode seeds
    add("r000_auto_startdt_gi", rawsess(u_frame("STARTDT_ACT"), apdu_gi(1, QOI_STATION, tx=0)))
    add("r001_auto_startdt_ci", rawsess(u_frame("STARTDT_ACT"), apdu_ci(1, QCC_RQT_GENERAL | QCC_FRZ_READ, tx=1)))
    add("r002_auto_read_single", rawsess(u_frame("STARTDT_ACT"), apdu_read(1, 100, tx=0), apdu_single(1, 5000, True, False, tx=1)))
    add("r003_auto_mix_control", rawsess(u_frame("STARTDT_ACT"), apdu_double(1, 5100, 2, False, tx=0), apdu_step(1, 5200, 2, False, tx=1), apdu_bitstring(1, 5400, 0x11223344, tx=2)))
    add("r004_auto_time_reset", rawsess(u_frame("STARTDT_ACT"), apdu_clock(1, cp56_from_tuple(2025,7,7,7,7,7,7), tx=0), apdu_reset(1, QRP_GENERAL_RESET, tx=1), apdu_delay(1, 10, tx=2)))
    add("r005_auto_file_probe", rawsess(u_frame("STARTDT_ACT"), apdu_file_call_select(1, 30000, 1, 0, SCQ_SELECT_FILE, tx=0), apdu_file_ready(1, 30001, 1, 16, 1, tx=1)))
    add("r006_auto_bad_mix", rawsess(u_frame("STOPDT_ACT"), apdu_gi(4, QOI_STATION, tx=0), apdu_read(0xFFFF, 9999, tx=1)))
    add("r007_auto_fragmentish", rawsess(apdu_gi(1, QOI_STATION, tx=0)[:5], apdu_gi(1, QOI_STATION, tx=0)[5:], apdu_read(1, 100, tx=1)))

    # Layer 11: generated combinations for breadth
    combo_id = 0
    cas = [1,2,3,4,0xFFFF]
    qois = [QOI_STATION, QOI_GROUP_1, QOI_GROUP_4, 0, 255]
    for ca in cas:
        for qoi in qois:
            frame1 = apdu_gi(ca, qoi, tx=0)
            frame2 = apdu_read(ca if ca != 0xFFFF else 1, 100 if qoi == QOI_STATION else 9999, tx=1)
            data = sess(op_connect(), op_uframe(0), op_send_split(1 + (combo_id % 3), frame1), op_wait(4), op_recv(4), op_send(frame2), op_wait(3), op_recv(3))
            add(f"s200_combo_gi_read_{combo_id:03d}", data)
            combo_id += 1
            if combo_id >= 20:
                break
        if combo_id >= 20:
            break

    combo2_id = 0
    commands = [
        lambda tx: apdu_single(1, 5000 + (tx % 3), bool(tx & 1), bool(tx & 2), tx=tx),
        lambda tx: apdu_double(1, 5100 + (tx % 3), (tx % 4), bool(tx & 2), tx=tx),
        lambda tx: apdu_step(1, 5200 + (tx % 3), (tx % 4), bool(tx & 2), tx=tx),
        lambda tx: apdu_sp_norm(1, 5300 + (tx % 2), (tx - 2) / 3.0, bool(tx & 1), tx=tx),
        lambda tx: apdu_sp_scaled(1, 5310 + (tx % 2), tx * 1234 - 2000, bool(tx & 1), tx=tx),
        lambda tx: apdu_sp_short(1, 5320 + (tx % 2), tx * 1.25 - 3.0, bool(tx & 1), tx=tx),
        lambda tx: apdu_bitstring(1, 5400 + (tx % 2), 0x11111111 * (tx + 1), tx=tx),
    ]
    for a_idx, a in enumerate(commands):
        for b_idx, b in enumerate(commands):
            if combo2_id >= 24:
                break
            add(f"s230_combo_cmd_{combo2_id:03d}", sess(
                op_connect(), op_uframe(0),
                op_send(a(0)), op_wait(2), op_recv(3),
                op_send_split(1 + (combo2_id % 3), b(1)), op_wait(3), op_recv(4),
                op_send(apdu_read(1, 500 if b_idx == 6 else 100, tx=2)), op_wait(2), op_recv(3)
            ))
            combo2_id += 1
        if combo2_id >= 24:
            break

    for name, data in sorted(seeds.items()):
        write_seed(out_dir, name, data)

    return len(seeds)

def main():
    out_dir = Path(sys.argv[1]) if len(sys.argv) > 1 else Path("inputs")
    dict_path = Path(sys.argv[2]) if len(sys.argv) > 2 else Path("cs104_stateful.dict")
    count = build_corpus(out_dir)
    build_dict(dict_path)
    print(f"generated {count} seeds into {out_dir}")
    print(f"wrote dictionary to {dict_path}")

if __name__ == "__main__":
    main()
