#!/usr/bin/env python3
import os
import random
import itertools
from pathlib import Path

DEFAULT_OUT_DIR = "inputs"
DEFAULT_DICT_PATH = "mms_stateful.dict"
RND = random.Random(0x61850)

OP_END = 0x00
OP_OPEN = 0x01
OP_SEND = 0x02
OP_WAIT = 0x03
OP_SHUT_WR = 0x04
OP_CLOSE = 0x05
OP_REOPEN = 0x06
OP_DRAIN = 0x07

DOMAIN = "LD0"

def enc_len(n: int) -> bytes:
    if n < 0x80:
        return bytes([n])
    tmp = []
    while n:
        tmp.append(n & 0xff)
        n >>= 8
    tmp.reverse()
    return bytes([0x80 | len(tmp)]) + bytes(tmp)

def enc_uint(v: int) -> bytes:
    if v < 0:
        raise ValueError("unsigned integer must be >= 0")
    if v == 0:
        return b"\x00"
    n = (v.bit_length() + 7) // 8
    out = v.to_bytes(n, "big", signed=False)
    if out[0] & 0x80:
        out = b"\x00" + out
    return out

def enc_int(v: int) -> bytes:
    for n in range(1, 16):
        try:
            out = v.to_bytes(n, "big", signed=True)
        except OverflowError:
            continue
        if n == 1:
            return out
        if v >= 0:
            if not (out[0] == 0x00 and (out[1] & 0x80) == 0):
                return out
        else:
            if not (out[0] == 0xff and (out[1] & 0x80) == 0x80):
                return out
    raise ValueError("cannot encode integer")

def tlv(tag: bytes, value: bytes = b"") -> bytes:
    return tag + enc_len(len(value)) + value

def seq(content: bytes) -> bytes:
    return tlv(b"\x30", content)

def ctx_tag(num: int, constructed: bool) -> bytes:
    first = 0x80 | (0x20 if constructed else 0)
    if num < 31:
        return bytes([first | num])

    parts = []
    while True:
        parts.append(num & 0x7f)
        num >>= 7
        if num == 0:
            break

    out = bytearray([first | 0x1f])
    for i, part in enumerate(reversed(parts)):
        if i != len(parts) - 1:
            out.append(0x80 | part)
        else:
            out.append(part)
    return bytes(out)

def visible(s: str) -> bytes:
    return s.encode("ascii", "ignore")

def file_name(parts) -> bytes:
    if isinstance(parts, str):
        parts = [p for p in parts.split("/") if p]
    return b"".join(tlv(b"\x1a", visible(p)) for p in parts)

def obj_vmd(name: str) -> bytes:
    return tlv(b"\xa0", visible(name))

def obj_domain(domain: str, item: str) -> bytes:
    return tlv(b"\xa1", tlv(b"\x1a", visible(domain)) + tlv(b"\x1a", visible(item)))

def obj_aa(name: str) -> bytes:
    return tlv(b"\xa2", visible(name))

def var_spec_name(obj_name: bytes) -> bytes:
    return tlv(b"\xa0", obj_name)

def variable_def(obj_name: bytes) -> bytes:
    return seq(var_spec_name(obj_name))

def data_bool(v: bool) -> bytes:
    return tlv(b"\x83", b"\xff" if v else b"\x00")

def data_bitstring(raw: bytes, unused_bits: int = 0) -> bytes:
    return tlv(b"\x84", bytes([unused_bits & 0x07]) + raw)

def data_int(v: int) -> bytes:
    return tlv(b"\x85", enc_int(v))

def data_uint(v: int) -> bytes:
    return tlv(b"\x86", enc_uint(v))

def data_octets(raw: bytes) -> bytes:
    return tlv(b"\x89", raw)

def data_vstr(s: str) -> bytes:
    return tlv(b"\x8a", visible(s))

def data_utc8(raw8: bytes) -> bytes:
    if len(raw8) != 8:
        raise ValueError("utc_time requires 8 bytes")
    return tlv(b"\x91", raw8)

def pack_tpkt(mms_pdu: bytes) -> bytes:
    payload = tlv(b"\xa0", mms_pdu)
    payload = b"\x02\x01\x03" + payload
    payload = seq(payload)
    payload = tlv(b"\x61", payload)
    payload = b"\x01\x00\x01\x00" + payload
    payload = b"\x02\xf0\x80" + payload
    final_len = len(payload) + 4
    return b"\x03\x00" + bytes([final_len >> 8, final_len & 0xff]) + payload

def confirmed_request(invoke_id: int, service_num: int, service_constructed: bool, body: bytes) -> bytes:
    inv = tlv(b"\x02", enc_uint(invoke_id))
    service = ctx_tag(service_num, service_constructed) + enc_len(len(body)) + body
    return tlv(b"\xa0", inv + service)

def mms_status(invoke_id: int, logical: bool = True) -> bytes:
    return pack_tpkt(confirmed_request(invoke_id, 0, False, b"\xff" if logical else b"\x00"))

def mms_identify(invoke_id: int) -> bytes:
    return pack_tpkt(confirmed_request(invoke_id, 2, False, b""))

def mms_get_name_list(invoke_id: int, object_class: int, scope_kind: str, scope_value: str = "", continue_after: str = None) -> bytes:
    oc_inner = tlv(b"\x80", enc_uint(object_class))
    object_class_field = tlv(b"\xa0", oc_inner)

    if scope_kind == "vmd":
        scope_inner = b"\x80\x00"
    elif scope_kind == "domain":
        scope_inner = tlv(b"\x81", visible(scope_value))
    elif scope_kind == "aa":
        scope_inner = b"\x82\x00"
    else:
        raise ValueError("bad scope_kind")

    object_scope_field = tlv(b"\xa1", scope_inner)

    body = object_class_field + object_scope_field
    if continue_after is not None:
        body += tlv(b"\x82", visible(continue_after))

    return pack_tpkt(confirmed_request(invoke_id, 1, True, body))

def mms_read_by_names(invoke_id: int, names) -> bytes:
    vars_blob = b"".join(variable_def(obj_domain(DOMAIN, n)) for n in names)
    vas_choice = tlv(b"\xa0", vars_blob)
    read_body = tlv(b"\x80", b"\x00") + tlv(b"\xa1", vas_choice)
    return pack_tpkt(confirmed_request(invoke_id, 4, True, read_body))

def mms_read_by_varlist_aa(invoke_id: int, nvl_name: str) -> bytes:
    vas_choice = tlv(b"\xa1", obj_aa(nvl_name))
    read_body = tlv(b"\x80", b"\x00") + tlv(b"\xa1", vas_choice)
    return pack_tpkt(confirmed_request(invoke_id, 4, True, read_body))

def mms_read_by_varlist_domain(invoke_id: int, domain: str, nvl_name: str) -> bytes:
    vas_choice = tlv(b"\xa1", obj_domain(domain, nvl_name))
    read_body = tlv(b"\x80", b"\x00") + tlv(b"\xa1", vas_choice)
    return pack_tpkt(confirmed_request(invoke_id, 4, True, read_body))

def mms_get_var_attr(invoke_id: int, name: str) -> bytes:
    body = tlv(b"\xa0", obj_domain(DOMAIN, name))
    return pack_tpkt(confirmed_request(invoke_id, 6, True, body))

def mms_write(invoke_id: int, pairs) -> bytes:
    vars_blob = b"".join(variable_def(obj_domain(DOMAIN, name)) for name, _ in pairs)
    vas_choice = tlv(b"\xa0", vars_blob)
    data_blob = b"".join(data for _, data in pairs)
    body = vas_choice + tlv(b"\xa0", data_blob)
    return pack_tpkt(confirmed_request(invoke_id, 5, True, body))

def mms_define_nvl_aa(invoke_id: int, nvl_name: str, names) -> bytes:
    vars_blob = b"".join(variable_def(obj_domain(DOMAIN, n)) for n in names)
    body = obj_aa(nvl_name) + tlv(b"\xa0", vars_blob)
    return pack_tpkt(confirmed_request(invoke_id, 11, True, body))

def mms_define_nvl_domain(invoke_id: int, domain: str, nvl_name: str, names) -> bytes:
    vars_blob = b"".join(variable_def(obj_domain(DOMAIN, n)) for n in names)
    body = obj_domain(domain, nvl_name) + tlv(b"\xa0", vars_blob)
    return pack_tpkt(confirmed_request(invoke_id, 11, True, body))

def mms_get_nvl_attr_aa(invoke_id: int, nvl_name: str) -> bytes:
    return pack_tpkt(confirmed_request(invoke_id, 12, True, obj_aa(nvl_name)))

def mms_get_nvl_attr_domain(invoke_id: int, domain: str, nvl_name: str) -> bytes:
    return pack_tpkt(confirmed_request(invoke_id, 12, True, obj_domain(domain, nvl_name)))

def mms_delete_nvl_specific_aa(invoke_id: int, nvl_names) -> bytes:
    scope = tlv(b"\x80", enc_uint(0))
    names_blob = b"".join(obj_aa(n) for n in nvl_names)
    body = scope + tlv(b"\xa1", names_blob)
    return pack_tpkt(confirmed_request(invoke_id, 13, True, body))

def mms_delete_nvl_specific_domain(invoke_id: int, domain: str, nvl_names) -> bytes:
    scope = tlv(b"\x80", enc_uint(0))
    names_blob = b"".join(obj_domain(domain, n) for n in nvl_names)
    body = scope + tlv(b"\xa1", names_blob)
    return pack_tpkt(confirmed_request(invoke_id, 13, True, body))

def mms_file_directory(invoke_id: int, spec_parts=None, continue_parts=None) -> bytes:
    body = b""
    if spec_parts is not None:
        body += tlv(ctx_tag(0, True), file_name(spec_parts))
    if continue_parts is not None:
        body += tlv(ctx_tag(1, True), file_name(continue_parts))
    return pack_tpkt(confirmed_request(invoke_id, 77, True, body))

def mms_file_open(invoke_id: int, parts, initial_pos=0) -> bytes:
    body = tlv(ctx_tag(0, True), file_name(parts)) + tlv(ctx_tag(1, False), enc_uint(initial_pos))
    return pack_tpkt(confirmed_request(invoke_id, 72, True, body))

def mms_file_read(invoke_id: int, frsm_id: int) -> bytes:
    return pack_tpkt(confirmed_request(invoke_id, 73, False, enc_int(frsm_id)))

def mms_file_close(invoke_id: int, frsm_id: int) -> bytes:
    return pack_tpkt(confirmed_request(invoke_id, 74, False, enc_int(frsm_id)))

CR_TPDU = bytes.fromhex("0300001611e00000000100c1020000c2020001c0010a")

def act_open(idx: int) -> bytes:
    return bytes([OP_OPEN, idx & 0xff])

def act_wait(ticks: int) -> bytes:
    return bytes([OP_WAIT, ticks & 0xff])

def act_shutdown_wr(idx: int) -> bytes:
    return bytes([OP_SHUT_WR, idx & 0xff])

def act_close(idx: int) -> bytes:
    return bytes([OP_CLOSE, idx & 0xff])

def act_reopen(idx: int) -> bytes:
    return bytes([OP_REOPEN, idx & 0xff])

def act_drain(ticks: int) -> bytes:
    return bytes([OP_DRAIN, ticks & 0xff])

def act_send(idx: int, payload: bytes, segs: int = 1, trunc: int = None, inter_wait: bool = False,
             half_close: bool = False, close_after: bool = False) -> bytes:
    if segs < 1:
        segs = 1
    if segs > 8:
        segs = 8
    flags = (segs - 1) & 0x07
    aux = 0
    if trunc is not None:
        aux = max(1, min(255, trunc))
        flags |= 0x08
    if inter_wait:
        flags |= 0x10
    if half_close:
        flags |= 0x20
    if close_after:
        flags |= 0x40
    plen = len(payload)
    return bytes([OP_SEND, idx & 0xff, flags, aux]) + plen.to_bytes(2, "big") + payload

def act_end() -> bytes:
    return bytes([OP_END])

def mk_session(req_packets, conn: int = 0, cr_segs: int = 1, init_segs: int = 1, req_segs = 1,
               inter_wait: bool = False, bundle_cr_init: bool = False, final_half_close: bool = True,
               explicit_close: bool = True) -> bytes:
    out = bytearray()
    out += act_open(conn)
    out += act_wait(1)

    init_pkt = mms_initiate()

    if bundle_cr_init:
        out += act_send(conn, CR_TPDU + init_pkt, segs=max(cr_segs, init_segs), inter_wait=inter_wait)
        out += act_drain(2)
    else:
        out += act_send(conn, CR_TPDU, segs=cr_segs, inter_wait=inter_wait)
        out += act_drain(1)
        out += act_send(conn, init_pkt, segs=init_segs, inter_wait=inter_wait)
        out += act_drain(2)

    if isinstance(req_segs, int):
        req_seg_list = [req_segs] * max(1, len(req_packets))
    else:
        req_seg_list = list(req_segs)

    for i, pkt in enumerate(req_packets):
        segs = req_seg_list[i % len(req_seg_list)]
        out += act_send(conn, pkt, segs=segs, inter_wait=inter_wait and (i % 2 == 0))
        out += act_drain(2 if len(pkt) > 80 else 1)

    if final_half_close:
        out += act_shutdown_wr(conn)
        out += act_drain(1)

    if explicit_close:
        out += act_close(conn)

    out += act_end()
    return bytes(out)

def mk_trunc_after_valid(valid_packets, bad_packet, trunc_len, conn: int = 0, reopen_after: bool = False) -> bytes:
    out = bytearray()
    out += act_open(conn)
    out += act_wait(1)
    out += act_send(conn, CR_TPDU, segs=2, inter_wait=True)
    out += act_drain(1)
    out += act_send(conn, mms_initiate(), segs=3, inter_wait=True)
    out += act_drain(2)
    for pkt in valid_packets:
        out += act_send(conn, pkt, segs=2, inter_wait=True)
        out += act_drain(1)
    out += act_send(conn, bad_packet, segs=3, trunc=trunc_len, inter_wait=True, half_close=True)
    out += act_drain(2)
    if reopen_after:
        out += act_reopen(conn)
        out += act_wait(1)
        out += act_send(conn, CR_TPDU, segs=1)
        out += act_drain(1)
        out += act_send(conn, mms_initiate(), segs=2)
        out += act_drain(2)
        out += act_send(conn, mms_identify(90), segs=1)
        out += act_drain(1)
    out += act_close(conn)
    out += act_end()
    return bytes(out)

def mms_initiate() -> bytes:
    return bytes.fromhex(
        "030000d302f0800dca0506130100160102140200023302"
        "000134020001c1b43181b1a003800101"
        "a281a9810400000001820400000001a4"
        "23300f02010106045201000130040602"
        "51013010020103060528ca2202013004"
        "0602510161763074020101a06f606da1"
        "07060528ca220203a207060529018767"
        "01a30302010ca403020100a503020100"
        "a606060429018767a70302010ca80302"
        "0100a903020100be3328310602510102"
        "0103a028a826800300fde881010a8201"
        "0a830105a416800101810305f100820c"
        "03ee1c00000000000000ed18"
    )

READ_TARGETS = [
    "LLN0$SR$SrvTrk$lastSvc",
    "LLN0$OR$SrvTrk$opCnt",
    "LLN0$BL$SrvTrk$blk",
    "LLN0$CF$HiddenCfg$secret",
    "GGIO1$ST$Ind1$stVal",
    "GGIO1$ST$Ind2$stVal",
    "GGIO1$ST$Ind3$stVal",
    "GGIO1$ST$Ind4$stVal",
    "GGIO1$MX$AnIn1$mag$f",
    "GGIO1$MX$AnIn2$mag$f",
    "GGIO1$MX$AnIn3$mag$f",
    "GGIO1$MX$AnIn4$mag$f",
    "GGIO1$MX$Cnt1$actVal",
    "MMXU1$MX$Hz$mag$f",
    "GGIO1$ST$SPCSO1$stVal",
    "GGIO1$ST$SPCSO2$stVal",
    "GGIO1$ST$DPCSO1$stVal",
    "XCBR1$ST$Pos$stVal",
    "GGIO1$DC$Custom$Text255$setVal",
    "GGIO1$ST$Custom$Blob64$val",
    "GGIO1$ST$Custom$DeepNest$L1$Vector$x",
    "GGIO1$ST$Custom$DeepNest$L1$Vector$y",
    "GGIO1$ST$Custom$DeepNest$L1$Vector$z",
    "GGIO1$ST$Custom$DeepNest$L1$LongText",
    "SETG1$SG$CfgInt$setMag",
    "SETG1$SE$CfgInt$setMag",
    "SETG1$SG$CfgBool$setVal",
    "SETG1$SE$CfgBool$setVal",
    "SETG1$SG$CfgText$label",
    "SETG1$SE$CfgText$label",
    "LPHD1$DC$PhyNam$vendor",
    "LPHD1$DC$PhyNam$model",
    "LPHD1$DC$PhyNam$serNum",
    "LPHD1$DC$PhyNam$swRev",
    "LLN0$RP$EventsURCB01$RptEna",
    "LLN0$RP$EventsURCB01$GI",
    "LLN0$RP$EventsURCB01$DatSet",
    "LLN0$RP$EventsURCB01$BufTm",
    "LLN0$RP$EventsURCB01$TrgOps",
    "LLN0$RP$EventsURCB01$OptFlds",
    "LLN0$RP$EventsURCB01$Resv",
    "LLN0$RP$EventsURCB01$Owner",
    "LLN0$BR$EventsBRCB01$RptEna",
    "LLN0$BR$EventsBRCB01$DatSet",
    "LLN0$BR$EventsBRCB01$BufTm",
    "LLN0$BR$EventsBRCB01$IntgPd",
    "LLN0$BR$EventsBRCB01$PurgeBuf",
    "LLN0$BR$EventsBRCB01$ResvTms",
    "LLN0$BR$EventsBRCB01$EntryID",
    "LLN0$BR$MeasurementsBRCB01$RptEna",
    "LLN0$BR$MeasurementsBRCB01$DatSet",
    "LLN0$BR$MeasurementsBRCB01$BufTm",
    "LLN0$BR$MeasurementsBRCB01$IntgPd",
    "LLN0$RP$ControlsURCB01$RptEna",
    "LLN0$RP$ControlsURCB01$DatSet",
    "LLN0$RP$MixedURCB01$RptEna",
    "LLN0$RP$MixedURCB01$DatSet",
]

ATTR_TARGETS = [
    "GGIO1$ST$Ind1",
    "GGIO1$MX$AnIn1",
    "GGIO1$ST$SPCSO1",
    "GGIO1$ST$DPCSO1",
    "GGIO1$DC$Custom$Text255$setVal",
    "GGIO1$ST$Custom$Blob64$val",
    "GGIO1$ST$Custom$DeepNest$L1$Vector$x",
    "LLN0$SR$SrvTrk$lastSvc",
    "LLN0$OR$SrvTrk$opCnt",
    "LLN0$CF$HiddenCfg$secret",
    "SETG1$SG$CfgInt$setMag",
    "SETG1$SE$CfgText$label",
    "LLN0$RP$EventsURCB01$RptEna",
    "LLN0$RP$EventsURCB01$DatSet",
    "LLN0$BR$EventsBRCB01$BufTm",
    "LLN0$BR$MeasurementsBRCB01$IntgPd",
    "LPHD1$DC$PhyNam$model",
]

WRITE_CASES = [
    [("GGIO1$DC$Custom$Text255$setVal", data_vstr("boot"))],
    [("GGIO1$DC$Custom$Text255$setVal", data_vstr("fuzz-stateful-01"))],
    [("GGIO1$DC$Custom$Text255$setVal", data_vstr("A" * 64))],
    [("LLN0$BL$SrvTrk$blk", data_bool(True))],
    [("LLN0$BL$SrvTrk$blk", data_bool(False))],
    [("SETG1$SG$CfgInt$setMag", data_int(0))],
    [("SETG1$SG$CfgInt$setMag", data_int(42))],
    [("SETG1$SG$CfgInt$setMag", data_int(-3))],
    [("SETG1$SE$CfgInt$setMag", data_int(7))],
    [("SETG1$SE$CfgInt$setMag", data_int(-1))],
    [("SETG1$SG$CfgBool$setVal", data_bool(True))],
    [("SETG1$SG$CfgBool$setVal", data_bool(False))],
    [("SETG1$SE$CfgBool$setVal", data_bool(True))],
    [("SETG1$SE$CfgBool$setVal", data_bool(False))],
    [("SETG1$SG$CfgText$label", data_vstr("Group-1-default"))],
    [("SETG1$SG$CfgText$label", data_vstr("Group-2-limits"))],
    [("SETG1$SE$CfgText$label", data_vstr("Group-3-edge"))],
    [("LLN0$RP$EventsURCB01$RptEna", data_bool(True))],
    [("LLN0$RP$EventsURCB01$GI", data_bool(True))],
    [("LLN0$RP$EventsURCB01$DatSet", data_vstr("LD0/LLN0$Events"))],
    [("LLN0$RP$EventsURCB01$DatSet", data_vstr("LD0/LLN0$Mixed"))],
    [("LLN0$RP$EventsURCB01$BufTm", data_uint(0))],
    [("LLN0$RP$EventsURCB01$BufTm", data_uint(10))],
    [("LLN0$RP$EventsURCB01$TrgOps", data_bitstring(b"\xff", 0))],
    [("LLN0$RP$EventsURCB01$OptFlds", data_bitstring(b"\xff\xc0", 6))],
    [("LLN0$RP$EventsURCB01$Owner", data_vstr("afl"))],
    [("LLN0$BR$EventsBRCB01$RptEna", data_bool(True))],
    [("LLN0$BR$EventsBRCB01$DatSet", data_vstr("LD0/LLN0$Events"))],
    [("LLN0$BR$EventsBRCB01$BufTm", data_uint(50))],
    [("LLN0$BR$EventsBRCB01$IntgPd", data_uint(1000))],
    [("LLN0$BR$EventsBRCB01$PurgeBuf", data_bool(True))],
    [("LLN0$BR$EventsBRCB01$ResvTms", data_uint(30))],
    [("LLN0$BR$MeasurementsBRCB01$DatSet", data_vstr("LD0/LLN0$Measurements"))],
    [("LLN0$BR$MeasurementsBRCB01$BufTm", data_uint(5))],
    [("LLN0$BR$MeasurementsBRCB01$IntgPd", data_uint(500))],
    [("LLN0$RP$ControlsURCB01$DatSet", data_vstr("LD0/LLN0$Controls"))],
    [("LLN0$RP$MixedURCB01$DatSet", data_vstr("LD0/LLN0$Mixed"))],
    [("LLN0$CF$HiddenCfg$secret", data_vstr("deny"))],
    [("GGIO1$DC$Custom$Text255$setVal", data_bool(True))],
    [("SETG1$SG$CfgInt$setMag", data_vstr("7"))],
]

RCB_BATCH_CASES = [
    [
        ("LLN0$RP$EventsURCB01$RptEna", data_bool(True)),
        ("LLN0$RP$EventsURCB01$GI", data_bool(True)),
        ("LLN0$RP$EventsURCB01$DatSet", data_vstr("LD0/LLN0$Events")),
        ("LLN0$RP$EventsURCB01$BufTm", data_uint(20)),
    ],
    [
        ("LLN0$BR$EventsBRCB01$RptEna", data_bool(True)),
        ("LLN0$BR$EventsBRCB01$DatSet", data_vstr("LD0/LLN0$Events")),
        ("LLN0$BR$EventsBRCB01$BufTm", data_uint(50)),
        ("LLN0$BR$EventsBRCB01$IntgPd", data_uint(1000)),
    ],
    [
        ("LLN0$BR$MeasurementsBRCB01$RptEna", data_bool(True)),
        ("LLN0$BR$MeasurementsBRCB01$DatSet", data_vstr("LD0/LLN0$Measurements")),
        ("LLN0$BR$MeasurementsBRCB01$BufTm", data_uint(10)),
        ("LLN0$BR$MeasurementsBRCB01$IntgPd", data_uint(250)),
    ],
]

FILE_PATHS = [
    [],
    ["cfg"],
    ["files"],
    ["files", "nested"],
    ["readme.txt"],
    ["cfg", "device.cfg"],
    ["files", "alpha.bin"],
    ["files", "beta.txt"],
    ["files", "nested", "gamma.log"],
    ["missing.bin"],
]

def chunked(seq_items, n):
    for i in range(0, len(seq_items), n):
        yield seq_items[i:i+n]

def write_seed(path: Path, payload: bytes):
    with open(path, "wb") as fp:
        fp.write(payload)

def esc(bs: bytes) -> str:
    out = []
    for b in bs:
        if 0x20 <= b <= 0x7e and chr(b) not in ['\\', '"']:
            out.append(chr(b))
        else:
            out.append(f"\\x{b:02x}")
    return "".join(out)

def build_dictionary(dict_path: Path):
    entries = []
    used = set()

    def add(name: str, raw: bytes):
        if raw in used:
            return
        used.add(raw)
        entries.append((name, raw))

    add("op_open0", bytes([OP_OPEN, 0]))
    add("op_open1", bytes([OP_OPEN, 1]))
    add("op_wait1", bytes([OP_WAIT, 1]))
    add("op_wait2", bytes([OP_WAIT, 2]))
    add("op_drain1", bytes([OP_DRAIN, 1]))
    add("op_drain2", bytes([OP_DRAIN, 2]))
    add("op_shutdown0", bytes([OP_SHUT_WR, 0]))
    add("op_close0", bytes([OP_CLOSE, 0]))
    add("op_reopen0", bytes([OP_REOPEN, 0]))
    add("tpkt_hdr", b"\x03\x00")
    add("cotp_dt", b"\x02\xf0\x80")
    add("cotp_cr", CR_TPDU)
    add("mms_initiate", mms_initiate())
    add("mms_status", mms_status(3, True))
    add("mms_identify", mms_identify(3))
    add("mms_gnl_vmd_domain", mms_get_name_list(4, 9, "vmd"))
    add("mms_gnl_vmd_nvlist", mms_get_name_list(4, 2, "vmd"))
    add("mms_gnl_domain_vars", mms_get_name_list(5, 0, "domain", DOMAIN))
    add("mms_read_srvtrk", mms_read_by_names(6, ["LLN0$SR$SrvTrk$lastSvc"]))
    add("mms_read_ind1", mms_read_by_names(7, ["GGIO1$ST$Ind1$stVal"]))
    add("mms_read_an1", mms_read_by_names(8, ["GGIO1$MX$AnIn1$mag$f"]))
    add("mms_getva_text", mms_get_var_attr(9, "GGIO1$DC$Custom$Text255$setVal"))
    add("mms_write_text", mms_write(10, [("GGIO1$DC$Custom$Text255$setVal", data_vstr("afl"))]))
    add("mms_write_blk", mms_write(11, [("LLN0$BL$SrvTrk$blk", data_bool(True))]))
    add("mms_write_setint", mms_write(12, [("SETG1$SG$CfgInt$setMag", data_int(42))]))
    add("mms_write_settxt", mms_write(13, [("SETG1$SE$CfgText$label", data_vstr("Group-3-edge"))]))
    add("mms_define_nvl_aa", mms_define_nvl_aa(14, "dynAA01", ["GGIO1$ST$Ind1$stVal", "MMXU1$MX$Hz$mag$f"]))
    add("mms_get_nvl_aa", mms_get_nvl_attr_aa(15, "dynAA01"))
    add("mms_read_nvl_aa", mms_read_by_varlist_aa(16, "dynAA01"))
    add("mms_delete_nvl_aa", mms_delete_nvl_specific_aa(17, ["dynAA01"]))
    add("mms_file_dir_root", mms_file_directory(18, []))
    add("mms_file_open_alpha", mms_file_open(19, ["files", "alpha.bin"], 0))
    add("mms_file_read_1", mms_file_read(20, 1))
    add("mms_file_close_1", mms_file_close(21, 1))

    for num in [0, 1, 2, 4, 5, 6, 11, 12, 13, 72, 73, 74, 77]:
        add(f"svc_tag_{num}", ctx_tag(num, num not in (0, 2, 73, 74)))

    for text in [
        DOMAIN,
        "LLN0", "GGIO1", "MMXU1", "XCBR1", "CSWI1", "PTRC1", "SETG1", "LPHD1",
        "Events", "Measurements", "Controls", "Mixed",
        "EventsURCB01", "EventsBRCB01", "MeasurementsBRCB01", "ControlsURCB01", "MixedURCB01",
        "RptEna", "GI", "Resv", "ResvTms", "BufTm", "IntgPd", "DatSet", "Owner",
        "TrgOps", "OptFlds", "ConfRev", "EntryID", "PurgeBuf", "SqNum", "TimeOfEntry",
        "SrvTrk", "lastSvc", "opCnt", "blk",
        "HiddenCfg", "secret",
        "Ind1", "Ind2", "Ind3", "Ind4", "stVal",
        "AnIn1", "AnIn2", "AnIn3", "AnIn4", "mag", "f",
        "Cnt1", "actVal", "Hz",
        "SPCSO1", "SPCSO2", "DPCSO1", "Pos",
        "Custom", "Text255", "Blob64", "DeepNest", "L1", "Vector", "LongText",
        "CfgInt", "CfgBool", "CfgText", "setMag", "setVal", "label",
        "PhyNam", "vendor", "model", "serNum", "swRev",
        "LD0/LLN0$Events", "LD0/LLN0$Measurements", "LD0/LLN0$Controls", "LD0/LLN0$Mixed",
        "dynAA01", "dynAA02", "dynDom01", "dynDom02",
        "readme.txt", "cfg", "device.cfg", "files", "alpha.bin", "beta.txt", "nested", "gamma.log",
    ]:
        add("txt_" + text.replace("$", "_").replace("/", "_"), visible(text))
        if len(text) <= 255:
            add("id_" + text.replace("$", "_").replace("/", "_"), tlv(b"\x1a", visible(text)))

    for item in READ_TARGETS[:32]:
        add("obj_" + item.replace("$", "_"), obj_domain(DOMAIN, item))

    with open(dict_path, "w", encoding="utf-8") as fp:
        for name, raw in entries:
            safe_name = "".join(c if c.isalnum() or c == "_" else "_" for c in name)
            fp.write(f'{safe_name}="{esc(raw)}"\n')

def build_corpus(out_dir: Path):
    out_dir.mkdir(parents=True, exist_ok=True)
    seeds = []

    def add_seed(name: str, payload: bytes):
        seeds.append((name, payload))

    add_seed("000_empty_default", b"")
    add_seed("001_open_close_only", act_open(0) + act_wait(1) + act_shutdown_wr(0) + act_drain(1) + act_close(0) + act_end())
    add_seed("002_cr_only", act_open(0) + act_wait(1) + act_send(0, CR_TPDU, segs=2, inter_wait=True) + act_drain(1) + act_close(0) + act_end())

    add_seed("010_status", mk_session([mms_status(3, True)], req_segs=1))
    add_seed("011_identify", mk_session([mms_identify(3)], req_segs=1))
    add_seed("012_status_identify", mk_session([mms_status(3, True), mms_identify(4)], req_segs=[1, 2], inter_wait=True))
    add_seed("013_bundle_cr_init_identify", mk_session([mms_identify(3)], bundle_cr_init=True, req_segs=2))
    add_seed("014_identify_halfclose", mk_session([mms_identify(3)], req_segs=3, inter_wait=True, final_half_close=True))

    add_seed("020_gnl_vmd_domains", mk_session([mms_get_name_list(3, 9, "vmd")], req_segs=1))
    add_seed("021_gnl_vmd_nvlist", mk_session([mms_get_name_list(3, 2, "vmd")], req_segs=2))
    add_seed("022_gnl_domain_vars", mk_session([mms_get_name_list(3, 0, "domain", DOMAIN)], req_segs=2))
    add_seed("023_gnl_domain_nvlist", mk_session([mms_get_name_list(3, 2, "domain", DOMAIN)], req_segs=3, inter_wait=True))
    add_seed("024_gnl_continueafter", mk_session([mms_get_name_list(3, 0, "domain", DOMAIN, continue_after="GGIO1")], req_segs=2))
    add_seed("025_status_gnl_read", mk_session([
        mms_status(3, True),
        mms_get_name_list(4, 9, "vmd"),
        mms_get_name_list(5, 0, "domain", DOMAIN),
        mms_read_by_names(6, ["GGIO1$ST$Ind1$stVal", "MMXU1$MX$Hz$mag$f"]),
    ], req_segs=[1, 2, 3], inter_wait=True))

    for i, target in enumerate(READ_TARGETS[:48], start=30):
        add_seed(f"{i:03d}_read_single_{i-30:02d}", mk_session([mms_read_by_names(3, [target])], req_segs=1 + ((i - 30) % 3), inter_wait=((i - 30) % 2 == 0)))

    inv = 100
    group_sets = []
    for size in [2, 3, 4, 5, 6]:
        for grp in chunked(READ_TARGETS, size):
            if len(grp) == size:
                group_sets.append(grp)
    for i, grp in enumerate(group_sets[:30], start=80):
        add_seed(f"{i:03d}_read_group_{len(grp)}", mk_session([mms_read_by_names(inv + i, grp)], req_segs=[1, 2, 3], inter_wait=(i % 2 == 0)))

    for i, target in enumerate(ATTR_TARGETS, start=120):
        add_seed(f"{i:03d}_getva_{i-120:02d}", mk_session([mms_get_var_attr(3, target)], req_segs=1 + ((i - 120) % 3)))

    for i, pairs in enumerate(WRITE_CASES, start=140):
        add_seed(f"{i:03d}_write_{i-140:02d}", mk_session([mms_write(3, pairs)], req_segs=1 + ((i - 140) % 3), inter_wait=((i - 140) % 2 == 1)))

    for i, pairs in enumerate(RCB_BATCH_CASES, start=180):
        add_seed(f"{i:03d}_write_rcb_batch_{i-180:02d}", mk_session([
            mms_write(3, pairs),
            mms_read_by_names(4, [name for name, _ in pairs]),
        ], req_segs=[2, 3], inter_wait=True))

    nvl_targets = [
        ["GGIO1$ST$Ind1$stVal", "GGIO1$ST$Ind2$stVal"],
        ["GGIO1$MX$AnIn1$mag$f", "GGIO1$MX$AnIn2$mag$f", "MMXU1$MX$Hz$mag$f"],
        ["LLN0$SR$SrvTrk$lastSvc", "LLN0$OR$SrvTrk$opCnt", "LLN0$BL$SrvTrk$blk"],
        ["GGIO1$DC$Custom$Text255$setVal", "GGIO1$ST$Custom$DeepNest$L1$Vector$x"],
        ["SETG1$SG$CfgInt$setMag", "SETG1$SE$CfgText$label"],
    ]

    for i in range(10):
        nvl_name = f"dynAA{i:02d}"
        names = nvl_targets[i % len(nvl_targets)]
        add_seed(f"{200+i:03d}_nvl_aa_{i:02d}", mk_session([
            mms_define_nvl_aa(3, nvl_name, names),
            mms_get_nvl_attr_aa(4, nvl_name),
            mms_read_by_varlist_aa(5, nvl_name),
            mms_delete_nvl_specific_aa(6, [nvl_name]),
        ], req_segs=[2, 1, 2, 1], inter_wait=True))

    for i in range(8):
        nvl_name = f"dynDom{i:02d}"
        names = nvl_targets[(i + 1) % len(nvl_targets)]
        add_seed(f"{210+i:03d}_nvl_domain_{i:02d}", mk_session([
            mms_define_nvl_domain(3, DOMAIN, nvl_name, names),
            mms_get_nvl_attr_domain(4, DOMAIN, nvl_name),
            mms_read_by_varlist_domain(5, DOMAIN, nvl_name),
            mms_delete_nvl_specific_domain(6, DOMAIN, [nvl_name]),
        ], req_segs=[1, 2, 2, 1], inter_wait=(i % 2 == 0)))

    for i, path_parts in enumerate(FILE_PATHS[:8], start=220):
        add_seed(f"{i:03d}_file_dir_{i-220:02d}", mk_session([mms_file_directory(3, path_parts)], req_segs=2, inter_wait=(i % 2 == 0)))

    for i, path_parts in enumerate(FILE_PATHS[4:9], start=228):
        reqs = [mms_file_open(3, path_parts, 0), mms_file_read(4, (i - 228) % 3), mms_file_close(5, (i - 228) % 3)]
        add_seed(f"{i:03d}_file_open_read_close_{i-228:02d}", mk_session(reqs, req_segs=[2, 1, 1], inter_wait=True))

    add_seed("240_trunc_identify_after_valid", mk_trunc_after_valid([mms_identify(3)], mms_get_name_list(4, 0, "domain", DOMAIN), 17, reopen_after=True))
    add_seed("241_trunc_read_after_identify", mk_trunc_after_valid([mms_identify(3)], mms_read_by_names(4, ["GGIO1$ST$Ind1$stVal", "GGIO1$MX$AnIn1$mag$f"]), 21, reopen_after=False))
    add_seed("242_trunc_write_after_gnl", mk_trunc_after_valid([mms_get_name_list(3, 9, "vmd")], mms_write(4, [("SETG1$SG$CfgInt$setMag", data_int(42))]), 19, reopen_after=True))
    add_seed("243_trunc_define_nvl", mk_trunc_after_valid([mms_identify(3)], mms_define_nvl_aa(4, "dynAA99", ["GGIO1$ST$Ind1$stVal", "MMXU1$MX$Hz$mag$f"]), 33, reopen_after=False))
    add_seed("244_trunc_fileopen", mk_trunc_after_valid([mms_identify(3)], mms_file_open(4, ["files", "alpha.bin"], 0), 15, reopen_after=False))

    multi = bytearray()
    multi += act_open(0) + act_open(1) + act_wait(1)
    multi += act_send(0, CR_TPDU, segs=2, inter_wait=True) + act_send(1, CR_TPDU, segs=1)
    multi += act_drain(1)
    multi += act_send(0, mms_initiate(), segs=3, inter_wait=True)
    multi += act_send(1, mms_initiate(), segs=2)
    multi += act_drain(2)
    multi += act_send(0, mms_identify(3), segs=1)
    multi += act_send(1, mms_get_name_list(4, 0, "domain", DOMAIN), segs=2, inter_wait=True)
    multi += act_drain(2)
    multi += act_send(0, mms_read_by_names(5, ["GGIO1$ST$Ind1$stVal", "MMXU1$MX$Hz$mag$f"]), segs=2)
    multi += act_send(1, mms_write(6, [("SETG1$SG$CfgText$label", data_vstr("Group-2-limits"))]), segs=3, inter_wait=True)
    multi += act_drain(3)
    multi += act_shutdown_wr(0) + act_shutdown_wr(1) + act_drain(1)
    multi += act_close(0) + act_close(1) + act_end()
    add_seed("250_multi_conn_dual_valid", bytes(multi))

    multi2 = bytearray()
    multi2 += act_open(0) + act_open(1) + act_wait(1)
    multi2 += act_send(0, CR_TPDU + mms_initiate(), segs=3, inter_wait=True)
    multi2 += act_send(1, CR_TPDU, segs=1)
    multi2 += act_drain(2)
    multi2 += act_send(1, mms_initiate(), segs=2)
    multi2 += act_drain(2)
    multi2 += act_send(0, mms_define_nvl_aa(3, "dynAA77", ["GGIO1$ST$Ind1$stVal", "GGIO1$ST$Ind2$stVal"]), segs=2)
    multi2 += act_send(1, mms_get_var_attr(4, "GGIO1$DC$Custom$Text255$setVal"), segs=1)
    multi2 += act_drain(2)
    multi2 += act_send(0, mms_read_by_varlist_aa(5, "dynAA77"), segs=2, inter_wait=True)
    multi2 += act_send(1, mms_file_directory(6, ["files"]), segs=3, inter_wait=True)
    multi2 += act_drain(3)
    multi2 += act_send(0, mms_delete_nvl_specific_aa(7, ["dynAA77"]), segs=1)
    multi2 += act_send(1, mms_file_open(8, ["files", "beta.txt"], 0), segs=2)
    multi2 += act_drain(2)
    multi2 += act_send(1, mms_file_read(9, 1), segs=1)
    multi2 += act_send(1, mms_file_close(10, 1), segs=1)
    multi2 += act_drain(2)
    multi2 += act_close(0) + act_close(1) + act_end()
    add_seed("251_multi_conn_nvl_file_mix", bytes(multi2))

    weird_payloads = [
        CR_TPDU + CR_TPDU,
        mms_identify(3) + mms_identify(4),
        mms_get_name_list(3, 9, "vmd") + mms_get_name_list(4, 0, "domain", DOMAIN),
        mms_read_by_names(3, ["GGIO1$ST$Ind1$stVal"]) + mms_write(4, [("LLN0$BL$SrvTrk$blk", data_bool(True))]),
        mms_file_directory(3, ["files"]) + mms_file_open(4, ["files", "alpha.bin"], 0),
    ]
    for i, blob in enumerate(weird_payloads, start=252):
        add_seed(f"{i:03d}_coalesced_blob_{i-252:02d}", mk_session([blob], req_segs=4, inter_wait=True))

    for i in range(12):
        base1 = READ_TARGETS[(i * 3) % len(READ_TARGETS)]
        base2 = READ_TARGETS[(i * 3 + 1) % len(READ_TARGETS)]
        name = f"260_stateful_mix_{i:02d}"
        reqs = [
            mms_status(3, bool(i & 1)),
            mms_identify(4),
            mms_get_name_list(5, 0 if i % 3 else 2, "domain", DOMAIN),
            mms_read_by_names(6, [base1, base2]),
            mms_get_var_attr(7, base1),
        ]
        if i % 2 == 0:
            reqs.append(mms_write(8, WRITE_CASES[i % len(WRITE_CASES)]))
        add_seed(name, mk_session(reqs, req_segs=[1, 2, 3], inter_wait=True, bundle_cr_init=(i % 3 == 0)))

    for name, payload in seeds:
        write_seed(out_dir / name, payload)

    return len(seeds)

def main():
    out_dir = Path(DEFAULT_OUT_DIR)
    dict_path = Path(DEFAULT_DICT_PATH)
    count = build_corpus(out_dir)
    build_dictionary(dict_path)
    print(f"generated {count} seeds in {out_dir}")
    print(f"dictionary written to {dict_path}")

if __name__ == "__main__":
    main()
