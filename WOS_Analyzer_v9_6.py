#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
WOS Analyzer V9.6
=================

UN SEUL FICHIER D'ENTRÉE : capture.pcapng

Sortie principale :
    <capture>_WOS_players_v9_6.csv

Pipeline intégré :
    classement brut 7502
      -> Rang + Atlas ID + Puissance (moteur V7.1 validé)
    requête 7902
      -> Atlas ID demandé
    réponse individuelle 7502
      -> pseudo UTF-8 complet (moteur V8.3 validé)
      -> pseudo core sans décorations
      -> alliance/tag reconstruits

Aucun WOS ID n'est encore déclaré fiable dans cette version.
"""

from __future__ import annotations
import argparse
import csv
import difflib
import itertools
import re
import socket
import struct
import unicodedata
from pathlib import Path

PORT = 30101

ATLAS_MIN = 100_000_000
ATLAS_MAX = 300_000_000
POWER_MIN = 80_000_000
POWER_MAX = 800_000_000

ATLAS_PREFIX_BYTES = {0x7C, 0x3E, 0x1F, 0xF8, 0xF1}
ATLAS_STUFF_BYTES = {0x8F, 0xC7, 0xE3, 0x47}
POWER_STUFF_SEQUENCES = {
    b"\xff\x00", b"\x7f", b"\x3f", b"\x8f",
    b"\xc7", b"\xe3", b"\x47",
}
STRING_STUFF = {0xC7, 0xE3, 0xF1, 0x7F, 0x8F, 0x47}

KNOWN_ALLIANCES = {
    "EVL": "NoPainNoGain",
    "WAR": "TheEmpire",
    "OMG": "TheyKilledKenny",
    "ROY": "Royalty",
}

def pcapng_packets(blob: bytes):
    off = 0
    endian = "<"
    packet_no = 0
    while off + 12 <= len(blob):
        btype_le = struct.unpack_from("<I", blob, off)[0]
        if btype_le == 0x0A0D0D0A:
            bom = blob[off+8:off+12]
            endian = "<" if bom == b"\x4d\x3c\x2b\x1a" else ">"
        blen = struct.unpack_from(endian+"I", blob, off+4)[0]
        if blen < 12 or off + blen > len(blob):
            break
        if struct.unpack_from(endian+"I", blob, off)[0] == 6:
            packet_no += 1
            caplen = struct.unpack_from(endian+"I", blob, off+20)[0]
            yield packet_no, blob[off+28:off+28+caplen]
        off += blen

def tcp_payload(pkt: bytes):
    if len(pkt) < 14 or pkt[12:14] != b"\x08\x00":
        return None
    ip = pkt[14:]
    if len(ip) < 20 or ip[9] != 6:
        return None
    ihl = (ip[0] & 0x0F) * 4
    tcp = ip[ihl:]
    if len(tcp) < 20:
        return None
    doff = (tcp[12] >> 4) * 4
    sport, dport = struct.unpack("!HH", tcp[:4])
    return sport, dport, tcp[doff:]

# ---------------------------------------------------------------------------
# RANKING V7.1
# ---------------------------------------------------------------------------

def _power_structural_score(removed: bytes) -> int:
    if not removed:
        return 8
    if removed in POWER_STUFF_SEQUENCES:
        return 18
    return -100

def atlas_candidates_after_marker(buf: bytes, pos: int):
    out = []
    for skip in (0, 1):
        if pos + 1 + skip >= len(buf):
            continue
        if skip and buf[pos + 1] not in ATLAS_PREFIX_BYTES:
            continue
        start = pos + 1 + skip

        raw = buf[start:start+4]
        if len(raw) == 4:
            val = int.from_bytes(raw, "little")
            if ATLAS_MIN <= val <= ATLAS_MAX and raw[3] == 0x09:
                out.append({
                    "score": 40 + (4 if skip else 0),
                    "value": val, "decoded_hex": raw.hex(),
                    "encoded_hex": raw.hex(), "removed_hex": "",
                    "skip": skip, "value_offset": start,
                })

        enc = buf[start:start+5]
        if len(enc) == 5:
            for rem in (1,2,3):
                if enc[rem] not in ATLAS_STUFF_BYTES:
                    continue
                raw = enc[:rem] + enc[rem+1:]
                val = int.from_bytes(raw, "little")
                if ATLAS_MIN <= val <= ATLAS_MAX and raw[3] == 0x09:
                    out.append({
                        "score": 44 + (4 if skip else 0),
                        "value": val, "decoded_hex": raw.hex(),
                        "encoded_hex": enc.hex(),
                        "removed_hex": f"{enc[rem]:02x}",
                        "skip": skip, "value_offset": start,
                    })
    out.sort(key=lambda x:(-x["score"],x["skip"],x["value"]))
    return out

def power_candidates_after_marker(buf: bytes, pos: int):
    out = []
    field_start = pos + 1

    for skip in (0,2):
        skipped = buf[field_start:field_start+skip]
        if skip == 2 and skipped != b"\xff\x00":
            continue
        start = field_start + skip

        raw = buf[start:start+4]
        if len(raw) == 4:
            val = int.from_bytes(raw,"little")
            if POWER_MIN <= val <= POWER_MAX:
                out.append({
                    "score":35+(12 if skip else 0),
                    "value":val,"decoded_hex":raw.hex(),
                    "encoded_hex":(skipped+raw).hex(),
                    "removed_hex":skipped.hex(),
                    "value_offset":start,
                })

        enc5 = buf[start:start+5]
        if len(enc5)==5:
            for rem in (1,2,3):
                removed=enc5[rem:rem+1]
                if _power_structural_score(removed)<0:
                    continue
                raw=enc5[:rem]+enc5[rem+1:]
                val=int.from_bytes(raw,"little")
                if POWER_MIN<=val<=POWER_MAX:
                    out.append({
                        "score":43+_power_structural_score(removed)+(8 if skip else 0),
                        "value":val,"decoded_hex":raw.hex(),
                        "encoded_hex":(skipped+enc5).hex(),
                        "removed_hex":(skipped+removed).hex(),
                        "value_offset":start,
                    })

        enc6=buf[start:start+6]
        if len(enc6)==6:
            for rem in (1,2,3):
                removed=enc6[rem:rem+2]
                if removed not in POWER_STUFF_SEQUENCES:
                    continue
                raw=enc6[:rem]+enc6[rem+2:]
                val=int.from_bytes(raw,"little")
                if POWER_MIN<=val<=POWER_MAX:
                    out.append({
                        "score":58+(8 if skip else 0),
                        "value":val,"decoded_hex":raw.hex(),
                        "encoded_hex":(skipped+enc6).hex(),
                        "removed_hex":(skipped+removed).hex(),
                        "value_offset":start,
                    })
    out.sort(key=lambda x:(-x["score"],x["value"]))
    return out

def parse_ranking_records(buf: bytes):
    records=[]
    consumed_until=-1

    for pos in range(0,max(0,len(buf)-14)):
        if buf[pos]!=0x04 or pos<consumed_until:
            continue
        atlases=atlas_candidates_after_marker(buf,pos)
        if not atlases:
            continue
        best_record=None

        for atlas in atlases:
            atlas_end=atlas["value_offset"]+(5 if atlas["removed_hex"] else 4)
            for pm in range(atlas_end,min(atlas_end+7,len(buf))):
                if buf[pm]!=0x04:
                    continue
                for power in power_candidates_after_marker(buf,pm):
                    score=atlas["score"]+power["score"]
                    if 150_000_000<=power["value"]<=600_000_000:
                        score+=8
                    rec={
                        "score":score,
                        "atlas_id":atlas["value"],
                        "power":power["value"],
                        "atlas_marker_offset":pos,
                        "power_marker_offset":pm,
                    }
                    if best_record is None or rec["score"]>best_record["score"]:
                        best_record=rec
        if best_record:
            records.append(best_record)
            consumed_until=best_record["power_marker_offset"]+4
    return records

def normalize_ranking_records(records):
    cleaned=list(records)
    removed=[]
    if len(cleaned)<12:
        return cleaned,removed

    for i in range(5,min(10,len(cleaned)-4)):
        prev=cleaned[i-1]["power"]
        cur=cleaned[i]["power"]
        following=cleaned[i+1:i+6]
        strong_jump=cur>prev*1.25
        below=following and all(x["power"]<prev for x in following)
        desc=all(following[j]["power"]>following[j+1]["power"] for j in range(len(following)-1))
        if strong_jump and below and desc:
            bad=cleaned.pop(i)
            removed.append(bad)
            break
    return cleaned,removed

def find_ranking_payload(capture: Path):
    candidates=[]
    for packet_no,pkt in pcapng_packets(capture.read_bytes()):
        parsed=tcp_payload(pkt)
        if not parsed:
            continue
        sport,dport,payload=parsed
        if sport!=PORT or len(payload)<4 or payload[2:4]!=b"\x75\x02":
            continue
        raw=parse_ranking_records(payload)
        cleaned,removed=normalize_ranking_records(raw)
        if len(cleaned)<10:
            continue
        desc=sum(1 for a,b in zip(cleaned,cleaned[1:]) if a["power"]>b["power"])
        score=len(cleaned)*10+desc
        candidates.append((score,packet_no,payload,cleaned,removed))

    if not candidates:
        return None
    candidates.sort(key=lambda x:(-x[0],-len(x[3])))
    score,packet_no,payload,records,removed=candidates[0]

    for i,r in enumerate(records,1):
        r["rank"]=i
    return {
        "packet":packet_no,
        "payload":payload,
        "records":records,
        "removed":removed,
    }

# ---------------------------------------------------------------------------
# PROFILE REQUEST/RESPONSE CORRELATION
# ---------------------------------------------------------------------------

def decode_7902_atlas(payload: bytes):
    m=re.search(rb"\xc4\x05\x04(.)\x07(.{3})",payload,re.S)
    if not m:
        return None
    return int.from_bytes(m.group(1)+m.group(2),"little")

def atlas_present(payload: bytes, atlas: int):
    target=atlas.to_bytes(4,"little")
    if target in payload:
        return True
    for i in range(max(0,len(payload)-4)):
        w=payload[i:i+5]
        if len(w)<5:
            break
        for rem in (1,2,3):
            if w[:rem]+w[rem+1:]==target:
                return True
    return False

# ---------------------------------------------------------------------------
# UTF-8 NAME DECODER V8.3
# ---------------------------------------------------------------------------

def strip_serialization_prefix(data: bytes, declared_len: int):
    if not data:
        return data,b""
    if data.startswith((b"\xff\x00",b"\xff\x01",b"\xff\x02")):
        return data[2:],data[:2]
    if data.startswith(b"\xfc"):
        return data[1:],data[:1]
    if data.startswith(b"\x11\xfc"):
        return data[2:],data[:2]
    compact={4:0x1F,5:0x3F,6:0x7F}.get(declared_len)
    if compact is not None and data[0]==compact:
        return data[1:],data[:1]
    return data,b""

def decode_declared_utf8(encoded: bytes, declared_len: int):
    encoded,prefix=strip_serialization_prefix(encoded,declared_len)
    probe=encoded[:declared_len+6]
    positions=[i for i,b in enumerate(probe) if b in STRING_STUFF or b < 0x20]

    for remove_count in range(0,4):
        for removed in itertools.combinations(positions,remove_count):
            removed_set=set(removed)
            rebuilt=bytes(b for i,b in enumerate(probe) if i not in removed_set)
            if len(rebuilt)<declared_len:
                continue
            raw=rebuilt[:declared_len]
            try:
                text=raw.decode("utf-8")
            except UnicodeDecodeError:
                continue
            useful=0
            consumed=0
            for i,b in enumerate(probe):
                consumed=i+1
                if i in removed_set:
                    continue
                useful+=1
                if useful==declared_len:
                    break
            return {
                "text":text,
                "prefix_hex":prefix.hex(),
                "stuff_hex":bytes(probe[i] for i in removed).hex(),
                "consumed":consumed,
            }
    return None

def core_name(display_name: str):
    s="".join(ch for ch in display_name if unicodedata.category(ch)!="Cc")
    s=s.replace("\u00a0"," ").strip()
    matches=list(re.finditer(
        r"[A-Za-z0-9_@~.'?!\-]+(?: [A-Za-z0-9_@~.'?!\-]+)*", s
    ))
    if not matches:
        return s
    m=max(matches,key=lambda x:(len(x.group()),-x.start()))
    core=m.group().strip()
    alnum=sum(ch.isalnum() for ch in core)
    if alnum>=3 and len(core)>=max(3,int(len(s)*0.35)):
        return core
    return s


def decode_4109_name(encoded: bytes, declared: int):
    """
    Variant observed in some 7502 profiles:
        41 09 <declared> 11 FC <name bytes with stuffing>

    We first use the normal UTF-8 decoder. If it fails, decode a short window
    conservatively by removing validated structural/control bytes and stop
    before the next field marker 04.
    """
    d=decode_declared_utf8(encoded,declared)
    if d:
        return d

    data,prefix=strip_serialization_prefix(encoded,declared)
    # Stop at next field marker if present.
    stop=data.find(b"\x04")
    if stop>=0:
        data=data[:stop]
    else:
        data=data[:declared+12]

    cleaned=bytes(
        b for b in data
        if b not in STRING_STUFF and b>=0x20
    )
    try:
        text=cleaned.decode("utf-8")
    except UnicodeDecodeError:
        text=cleaned.decode("utf-8",errors="ignore")
    text=text.strip()

    if not text:
        return None

    return {
        "text":text,
        "prefix_hex":prefix.hex(),
        "stuff_hex":"",
        "consumed":len(data),
    }


def extract_profile_name(payload: bytes):
    """
    Deux variantes de champ pseudo sont validées dans les réponses 7502 :

      11 0B <len_octets> <prefix> <UTF-8/stuffing>
      41 09 <len_octets> FC       <UTF-8/stuffing>

    Exemples de la seconde variante:
      41 09 05 FC Henry
      41 09 08 FC TwinSn C7 ow
      41 09 0B FC ~TROUB?LE ...
    """
    markers=(b"\x11\x0b",b"\x41\x09")

    for marker in markers:
        for m in re.finditer(re.escape(marker)+rb"(.)",payload,re.S):
            declared=m.group(1)[0]
            if not (1<=declared<=60):
                continue
            decoder=decode_4109_name if marker==b"\x41\x09" else decode_declared_utf8
            d=decoder(
                payload[m.end():m.end()+declared+16],
                declared
            )
            if d:
                return {
                    "display_name":d["text"],
                    "core_name":core_name(d["text"]),
                    "name_prefix_hex":d["prefix_hex"],
                    "name_stuff_hex":d["stuff_hex"],
                    "name_marker_hex":marker.hex(),
                }

    # Third validated profile-name variant:
    #   04 10 <byte_len> C4 <encoded_len> <encoded UTF-8/stuffed name>
    # Example #25: 04 10 0D C4 0C 42 61 FF00 74 74 61 6C C2A0 47 61 C7 7A 69
    # decodes to "Battal Gazi".
    for m in re.finditer(rb"\x04\x10(.)\xc4(.)", payload, re.S):
        declared=m.group(1)[0]
        if not (1<=declared<=60):
            continue

        data=payload[m.end():m.end()+declared+16]

        # For this variant the declared field includes transport overhead.
        # Decode until the next field marker 04, removing validated stuffing.
        stop=data.find(b"\x04")
        if stop>=0:
            data=data[:stop]

        # FF00 is a structural insertion, not UTF-8 data.
        data=data.replace(b"\xff\x00",b"")
        # 0410c4 validated: C7 is stuffing, while literal 47 is the real "G"
        # in "Gazi". Do not apply the global STRING_STUFF set here because it
        # also contains 0x47 for other protocol contexts.
        local_stuff={0xC7,0xE3,0xF1,0x7F,0x8F}
        data=bytes(b for b in data if b not in local_stuff and b>=0x20)

        try:
            text=data.decode("utf-8").strip()
        except UnicodeDecodeError:
            text=data.decode("utf-8",errors="ignore").strip()

        if text:
            return {
                "display_name":text,
                "core_name":core_name(text),
                "name_prefix_hex":"",
                "name_stuff_hex":"",
                "name_marker_hex":"0410c4",
            }

    return {
        "display_name":"",
        "core_name":"",
        "name_prefix_hex":"",
        "name_stuff_hex":"",
        "name_marker_hex":"",
    }



# ---------------------------------------------------------------------------
# WOS ID DECODER V9
# ---------------------------------------------------------------------------

WOS_ID_MIN = 500_000_000
WOS_ID_MAX = 700_000_000

# Stuffing bytes validated directly on known WOS IDs:
# BAHOZ      A7 83 [C7] 47 25 -> 625443751
# MarkusDude D0 92 [47] 81 25 -> 629248720
WOS_ID_STUFF = {0xC7, 0x47, 0xE3, 0x8F, 0xF1, 0x23}


def _wos_numeric_candidates(data: bytes, pos: int):
    """
    Decode a possible 32-bit LE WOS ID beginning exactly at pos.
    Supports raw LE32 and one internally inserted structural byte.
    """
    out = []

    if pos + 4 <= len(data):
        raw = data[pos:pos+4]
        value = int.from_bytes(raw, "little")
        if WOS_ID_MIN <= value <= WOS_ID_MAX:
            out.append({
                "value": value,
                "kind": "exact_le32",
                "encoded_hex": raw.hex(),
                "removed_hex": "",
                "score": 20,
            })

    if pos + 5 <= len(data):
        enc = data[pos:pos+5]
        for rem in (1, 2, 3):
            if enc[rem] not in WOS_ID_STUFF:
                continue
            raw = enc[:rem] + enc[rem+1:]
            value = int.from_bytes(raw, "little")
            if WOS_ID_MIN <= value <= WOS_ID_MAX:
                out.append({
                    "value": value,
                    "kind": "stuffed_le32",
                    "encoded_hex": enc.hex(),
                    "removed_hex": f"{enc[rem]:02x}",
                    "score": 24,
                })

    return out


def decode_wos_id(payload: bytes):
    """
    Decode the WOS/Game ID from an individual 7502 profile response.

    Structurally validated examples:
      BAHOZ      ... C4 04 A7 83 C7 47 25 ...
      GEAH       ... 04 7C EC 01 59 25 ...
      MarkusDude ... C4 04 D0 92 47 81 25 ...

    The field is located after the alliance/language area and before the
    avatar/date/style block. V9 therefore only accepts candidates beginning
    after a short structural marker containing 0x04.

    Confidence:
      high   = validated marker family + unique best candidate
      medium = plausible marker, but more than one candidate ties
    """
    candidates = []

    # WOS ID lives in the early metadata part of an individual profile.
    # Avoid scanning avatar/equipment blobs later in the message.
    scan_end = min(len(payload), 150)

    # Marker families observed immediately before the ID:
    #   04
    #   C4 04
    #   04 7C
    # We scan every 04 and allow one optional structural byte after it.
    for marker in range(20, scan_end - 4):
        if payload[marker] != 0x04:
            continue

        starts = [(marker + 1, "04", 8)]

        if marker > 0 and payload[marker-1] == 0xC4:
            starts.append((marker + 1, "c404", 12))

        # GEAH: 04 7C <ID>
        if marker + 1 < scan_end and payload[marker+1] == 0x7C:
            starts.append((marker + 2, "047c", 14))

        # Additional compact wrappers observed in profile metadata:
        # 04 1F <ID>, 04 F8 <ID>, 04 3E <ID>.
        # These bytes are serialization metadata, not part of the ID.
        if marker + 1 < scan_end and payload[marker+1] in (0x1F,0xF8):
            wrapper=payload[marker+1]
            starts.append((marker + 2, f"04{wrapper:02x}", 14))

        # 0x3E is ambiguous: it may be a wrapper (Dark1) OR the first byte
        # of the actual WOS ID (Williamson). Treat it as a wrapper only when
        # the following four bytes already form a raw plausible WOS ID.
        if marker + 6 <= scan_end and payload[marker+1] == 0x3E:
            raw_after_3e=payload[marker+2:marker+6]
            val_after_3e=int.from_bytes(raw_after_3e,"little")
            threee_is_id=bool(_wos_numeric_candidates(payload, marker+1))
            if (
                not threee_is_id
                and WOS_ID_MIN <= val_after_3e <= WOS_ID_MAX
                and raw_after_3e[3] in (0x24,0x25)
            ):
                starts.append((marker + 2, "043e", 14))

        for pos, marker_kind, marker_score in starts:
            for cand in _wos_numeric_candidates(payload, pos):
                c = dict(cand)
                c["offset"] = pos
                c["marker"] = marker_kind
                c["score"] += marker_score

                # The real WOS ID field appears around the textual profile
                # metadata, typically offset 70..115 in current captures.
                if 65 <= pos <= 120:
                    c["score"] += 8

                # High byte of current WOS IDs is typically 0x24/0x25.
                raw = c["value"].to_bytes(4, "little")
                if raw[3] in (0x24, 0x25):
                    c["score"] += 8

                candidates.append(c)

    # Second validated family: compact wrapper directly before the WOS ID
    # in the same early metadata zone. Restrict tightly to offsets 75..115.
    for wrapper_pos in range(74, min(scan_end - 4, 116)):
        wrapper=payload[wrapper_pos]
        if wrapper not in (0x1F,0xF8):
            continue
        pos=wrapper_pos+1
        for cand in _wos_numeric_candidates(payload,pos):
            c=dict(cand)
            c["offset"]=pos
            c["marker"]=f"{wrapper:02x}"
            c["score"]+=22
            if 80<=pos<=115:
                c["score"]+=10
            raw=c["value"].to_bytes(4,"little")
            if raw[3] in (0x24,0x25):
                c["score"]+=8
            candidates.append(c)

    if not candidates:
        return {
            "wos_id": None,
            "confidence": "unresolved",
            "detail": None,
            "candidates": [],
        }

    # De-duplicate same numeric value, retain strongest structural occurrence.
    best_by_value = {}
    for c in candidates:
        prev = best_by_value.get(c["value"])
        if prev is None or c["score"] > prev["score"]:
            best_by_value[c["value"]] = c

    ranked = sorted(
        best_by_value.values(),
        key=lambda x: (-x["score"], x["offset"], x["value"])
    )

    best = ranked[0]
    second_score = ranked[1]["score"] if len(ranked) > 1 else -1

    # Require a meaningful lead when several plausible numeric fields exist.
    if best["score"] < 40:
        confidence = "unresolved"
        value = None
    elif len(ranked) == 1 or best["score"] >= second_score + 4:
        confidence = "high"
        value = best["value"]
    else:
        confidence = "medium"
        value = best["value"]

    return {
        "wos_id": value,
        "confidence": confidence,
        "detail": best,
        "candidates": ranked[:8],
    }


# ---------------------------------------------------------------------------
# ALLIANCE RECONSTRUCTION
# ---------------------------------------------------------------------------

def printable_tokens(payload: bytes):
    return [
        m.group().decode("ascii",errors="ignore")
        for m in re.finditer(rb"[\x20-\x7e]{2,}",payload)
    ]

def reconstruct_alliance(payload: bytes):
    tokens=printable_tokens(payload)
    joined="".join(re.sub(r"[^A-Za-z]","",x) for x in tokens).lower()

    best=None
    for tag,name in KNOWN_ALLIANCES.items():
        target=re.sub(r"[^A-Za-z]","",name).lower()
        # score windows, not the whole payload
        for i in range(len(tokens)):
            for width in range(1,min(5,len(tokens)-i)+1):
                chunk="".join(re.sub(r"[^A-Za-z]","",x) for x in tokens[i:i+width]).lower()
                if not chunk:
                    continue
                score=difflib.SequenceMatcher(None,chunk,target).ratio()
                if target.startswith(chunk) and len(chunk)>=5:
                    score=max(score,0.86)
                if chunk.startswith(target[:6]) and len(chunk)>=6:
                    score=max(score,0.83)
                if best is None or score>best["score"]:
                    near=" ".join(tokens[max(0,i-3):i+width]).upper()
                    detected_tag=tag if tag in near else ""
                    best={"score":score,"tag":detected_tag,"name":name}
    if best and best["score"]>=0.72:
        return best["tag"],best["name"],round(best["score"],3)
    return "","",None

def correlate_profiles(capture: Path, ranking_records):
    ranking_ids={r["atlas_id"] for r in ranking_records}
    msgs=[]

    for packet_no,pkt in pcapng_packets(capture.read_bytes()):
        parsed=tcp_payload(pkt)
        if not parsed:
            continue
        sport,dport,payload=parsed
        if len(payload)<4:
            continue
        op=payload[2:4]
        if op not in (b"\x79\x02",b"\x7d\x02",b"\x75\x02"):
            continue
        msgs.append({
            "packet":packet_no,"sport":sport,"dport":dport,
            "opcode":op,"payload":payload,
        })

    requests=[]

    for m in msgs:
        if m["dport"]!=PORT:
            continue

        if m["opcode"]==b"\x79\x02":
            atlas=decode_7902_atlas(m["payload"])
            if atlas in ranking_ids:
                requests.append((m["packet"],atlas,"7902"))

        elif m["opcode"]==b"\x7d\x02":
            # The targeted 7d02 form carries the Atlas ID directly.
            # Match only against IDs already proven by the ranking parser.
            hits=[atlas for atlas in ranking_ids if atlas_present(m["payload"],atlas)]
            if len(hits)==1:
                requests.append((m["packet"],hits[0],"7d02"))

    profiles={}
    responses=[
        m for m in msgs
        if m["opcode"]==b"\x75\x02" and m["sport"]==PORT
    ]

    for req_packet,atlas,request_opcode in requests:
        candidates=[]
        for m in responses:
            if m["packet"]<=req_packet:
                continue
            delta=m["packet"]-req_packet
            if delta>60:
                break
            if not atlas_present(m["payload"],atlas):
                continue

            score=0
            if delta<=20: score+=20
            elif delta<=40: score+=10
            if not (100<=len(m["payload"])<=700):
                continue
            score+=20

            name=extract_profile_name(m["payload"])
            if name["display_name"]:
                score+=10

            candidates.append((score,delta,m,name))

        if not candidates:
            continue

        candidates.sort(key=lambda x:(-x[0],x[1],x[2]["packet"]))
        _,delta,best,name=candidates[0]

        tag,alliance,alliance_score=reconstruct_alliance(best["payload"])
        wos_decoded=decode_wos_id(best["payload"])

        profiles[atlas]={
            "request_packet":req_packet,
            "request_opcode":request_opcode,
            "response_packet":best["packet"],
            "response_len":len(best["payload"]),
            "response_delta":delta,
            "display_name":name["display_name"],
            "core_name":name["core_name"],
            "name_prefix_hex":name["name_prefix_hex"],
            "name_stuff_hex":name["name_stuff_hex"],
            "name_marker_hex":name["name_marker_hex"],
            "alliance_tag":tag,
            "alliance_name":alliance,
            "alliance_score":alliance_score,
            "wos_id":wos_decoded["wos_id"],
            "wos_id_confidence":wos_decoded["confidence"],
            "wos_id_detail":wos_decoded["detail"],
        }

    return profiles


def main():
    ap=argparse.ArgumentParser()
    ap.add_argument("capture",type=Path)
    args=ap.parse_args()

    ranking=find_ranking_payload(args.capture)
    if not ranking:
        raise SystemExit("Aucun classement exploitable trouvé.")

    profiles=correlate_profiles(args.capture,ranking["records"])

    out=args.capture.with_name(args.capture.stem+"_WOS_players_v9_6.csv")
    fields=[
        "rank","atlas_id","wos_id","power",
        "pseudo_display","pseudo_core",
        "alliance_tag","alliance_name",
        "profile_status",
        "profile_request_packet","profile_request_opcode",
        "profile_response_packet","profile_response_len",
        "name_marker_hex","name_prefix_hex","name_stuff_hex","alliance_score",
        "wos_id_confidence","wos_id_marker","wos_id_offset",
        "wos_id_encoded_hex","wos_id_removed_hex",
    ]

    with out.open("w",newline="",encoding="utf-8-sig") as f:
        w=csv.DictWriter(f,fieldnames=fields)
        w.writeheader()
        for r in ranking["records"]:
            p=profiles.get(r["atlas_id"],{})
            w.writerow({
                "rank":r["rank"],
                "atlas_id":r["atlas_id"],
                "wos_id":p.get("wos_id",""),
                "power":r["power"],
                "pseudo_display":p.get("display_name",""),
                "pseudo_core":p.get("core_name",""),
                "alliance_tag":p.get("alliance_tag",""),
                "alliance_name":p.get("alliance_name",""),
                "profile_status":"linked" if p else "not_requested_in_capture",
                "profile_request_packet":p.get("request_packet",""),
                "profile_request_opcode":p.get("request_opcode",""),
                "profile_response_packet":p.get("response_packet",""),
                "profile_response_len":p.get("response_len",""),
                "name_marker_hex":p.get("name_marker_hex",""),
                "name_prefix_hex":p.get("name_prefix_hex",""),
                "name_stuff_hex":p.get("name_stuff_hex",""),
                "alliance_score":p.get("alliance_score",""),
                "wos_id_confidence":p.get("wos_id_confidence",""),
                "wos_id_marker":(p.get("wos_id_detail") or {}).get("marker",""),
                "wos_id_offset":(p.get("wos_id_detail") or {}).get("offset",""),
                "wos_id_encoded_hex":(p.get("wos_id_detail") or {}).get("encoded_hex",""),
                "wos_id_removed_hex":(p.get("wos_id_detail") or {}).get("removed_hex",""),
            })

    print("=== WOS Analyzer V9.6 ===")
    print(f"Classement : {len(ranking['records'])} joueurs")
    decoded_wos=sum(1 for p in profiles.values() if p.get("wos_id"))
    print(f"Profils liés : {len(profiles)}/{len(ranking['records'])}")
    print(f"WOS ID décodés : {decoded_wos}/{len(profiles)} profils liés")
    print(f"Paquet classement : {ranking['packet']}")
    print(f"Faux positifs ranking retirés : {len(ranking['removed'])}")
    print(f"CSV final : {out}")

if __name__=="__main__":
    main()
