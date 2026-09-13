#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
WOS Alliance Members Extractor V0.2
===================================
Découpe les gros 7502 d'une liste d'alliance en blocs membre et décode les
pseudos compacts (formats différents des profils individuels).

Dépendance: WOS_Analyzer_v9_6.py dans le même dossier.
"""
from pathlib import Path
import argparse, csv, re, itertools, importlib.util

NAME_STUFF = {0x1F,0x23,0x3F,0x47,0x7F,0x8F,0xC7,0xE3,0xF1}

def load_core(here):
    p=here/"WOS_Analyzer_v9_6.py"
    if not p.exists():
        raise SystemExit("WOS_Analyzer_v9_6.py doit être dans le même dossier.")
    spec=importlib.util.spec_from_file_location("woscore",p)
    m=importlib.util.module_from_spec(spec); spec.loader.exec_module(m)
    return m

def decode_exact(encoded: bytes, declared: int):
    extra=len(encoded)-declared
    if extra<0 or extra>8:
        return None

    # Structural groups (two-byte insertions).
    groups=[]
    for i in range(len(encoded)-1):
        if encoded[i]==0xFF and encoded[i+1] in (0,1,2):
            groups.append((i,i+1))

    singles=[i for i,b in enumerate(encoded) if b in NAME_STUFF]

    # Try minimum removal combinations that produce exactly declared UTF-8 bytes.
    allsets=[set()]
    for g in groups:
        allsets += [s|set(g) for s in list(allsets)]

    candidates=[]
    for base in allsets:
        need=extra-len(base)
        if need<0 or need>4:
            continue
        remaining=[i for i in singles if i not in base]
        for comb in itertools.combinations(remaining,need):
            rem=base|set(comb)
            if len(rem)!=extra:
                continue
            raw=bytes(b for i,b in enumerate(encoded) if i not in rem)
            try:
                txt=raw.decode("utf-8")
            except UnicodeDecodeError:
                continue
            if len(raw)==declared:
                # Prefer removals that do not delete ordinary ASCII 0x47 when
                # another structural solution exists.
                penalty=sum(3 if encoded[i]==0x47 else 0 for i in rem)
                candidates.append((penalty,txt,bytes(encoded[i] for i in sorted(rem)).hex()))

    if not candidates:
        return None
    candidates.sort(key=lambda x:x[0])
    return candidates[0][1],candidates[0][2]

def _early_structural_name(block: bytes, core):
    """
    Decode the compact nickname field near the start of a member block.

    This is deliberately conservative: it is used to repair an existing
    profile-decoder result only when the structural candidate is clearly
    more complete (or the old result contains protocol/control bytes).
    Validated on WAR cases Kaixun / ТЕХАС 13 Х and several previously
    truncated/stuffed names, without overriding already-clean names.
    """
    candidates=[]
    for i in range(6,min(22,len(block)-4)):
        declared=block[i]
        if not (2<=declared<=60):
            continue

        starts=[(i+1,"direct",0)]
        if i+1<len(block) and block[i+1] in (0xFC,0xF8,0xFE,0x3E):
            starts.append((i+2,f"p{block[i+1]:02x}",4))
        if i+2<len(block) and block[i+1]==0xFF and block[i+2] in (0,1,2):
            starts.append((i+3,f"ff{block[i+2]:02x}",6))
        if (
            i+3<len(block)
            and block[i+1] in (0xEA,0x63)
            and block[i+2]==0xFF
            and block[i+3] in (0,1,2)
        ):
            starts.append((i+4,"x-ff",6))

        for start,kind,bonus in starts:
            lo=start+max(1,declared-4)
            hi=min(len(block),start+declared+10)
            for end in range(lo,hi):
                if block[end]!=0x04:
                    continue
                dec=decode_exact(block[start:end],declared)
                if not dec:
                    continue
                txt,removed=dec
                txt=txt.strip()
                if not txt:
                    continue
                alnum=sum(ch.isalnum() for ch in txt)
                if alnum<2 or any(ord(ch)<32 for ch in txt):
                    continue
                score=200-i+bonus+min(20,alnum)
                if 8<=i<=12:
                    score+=10
                candidates.append((score,txt,core.core_name(txt),kind,removed))
                break

    if not candidates:
        return None
    candidates.sort(key=lambda x:-x[0])
    return candidates[0]


def compact_name(block: bytes, core):
    # Existing profile decoder covers many variants, but can occasionally
    # lock onto a later numeric field (Kaixun -> R]P) or leave stuffing in
    # the name. Compare it with the structurally located early nickname field.
    d=core.extract_profile_name(block)
    old_display=d.get("display_name") or ""
    old_core=d.get("core_name") or ""
    early=_early_structural_name(block,core)

    if early:
        _,e_display,e_core,e_kind,e_removed=early
        old_has_control=any(ord(ch)<32 for ch in old_display)
        clearly_more_complete=(
            not old_display
            or old_has_control
            or len(e_core)>=len(old_core)+2
        )
        if clearly_more_complete:
            return e_display,e_core,f"early-{e_kind}",e_removed

    if old_display and len(old_display)>=2:
        return old_display,old_core,"profile",d.get("name_stuff_hex","")

    cands=[]
    limit=min(48,len(block)-4)

    for i in range(2,limit):
        b=block[i]

        # [len] [single prefix] data
        if 1<=b<=60 and i+1<len(block) and block[i+1] in (0xFC,0xF8,0xFE,0x3E):
            cands.append((i,b,i+2,f"len-{block[i+1]:02x}"))

        # [len] FF 00/01/02 data
        if 1<=b<=60 and i+2<len(block) and block[i+1]==0xFF and block[i+2] in (0,1,2):
            cands.append((i,b,i+3,f"len-ff{block[i+2]:02x}"))

        # [len] EA FF02 data
        if 1<=b<=60 and i+3<len(block) and block[i+1]==0xEA and block[i+2]==0xFF and block[i+3]==0x02:
            cands.append((i,b,i+4,"len-eaff02"))

        # [len] 63 FF00 data
        if 1<=b<=60 and i+3<len(block) and block[i+1]==0x63 and block[i+2]==0xFF and block[i+3]==0x00:
            cands.append((i,b,i+4,"len-63ff00"))

        # [prefix] [len] data
        if b in (0xC4,0xF1,0xE2) and i+1<len(block) and 1<=block[i+1]<=60:
            cands.append((i,block[i+1],i+2,f"{b:02x}-len"))

    results=[]
    for pos,decl,start,kind in cands:
        # The next 04 is the following field. Search around the expected end.
        lo=start+max(1,decl-4)
        hi=min(len(block),start+decl+10)
        for end in range(lo,hi):
            if block[end]!=0x04:
                continue
            encoded=block[start:end]
            dec=decode_exact(encoded,decl)
            if not dec:
                continue
            txt,removed=dec
            txt=txt.strip()
            if not txt:
                continue
            if sum(ch.isprintable() for ch in txt) < max(1,int(len(txt)*0.9)):
                continue

            # Prefer candidates near the beginning of the member block.
            score=100-pos
            # Reject obvious protocol-only tiny strings.
            if len(txt)<2:
                score-=50
            results.append((score,txt,core.core_name(txt),kind,removed))
            break

    if not results:
        # Paginated decorated-name variant: 12 F8 <18 useful UTF-8 bytes>,
        # where FF01 may be inserted inside the encoded string. Validated on
        # B҉ I҉ G҉ G҉ (Atlas 156223921) across aggregate and paginated lists.
        for i in range(2,min(30,len(block)-4)):
            if block[i]==0x12 and i+1<len(block) and block[i+1]==0xF8:
                start=i+2
                for end in range(start+18,min(len(block),start+28)):
                    if block[end]!=0x04:
                        continue
                    dec=decode_exact(block[start:end],18)
                    if dec:
                        txt,removed=dec
                        txt=txt.strip()
                        if txt:
                            return txt,core.core_name(txt),"12-f8",removed
                    break

        # Specific validated compact form seen in a decorated EVL nickname:
        #   12 FF01 <18 useful UTF-8 bytes with C7 stuffing> 04
        # The generic branch below normally handles this family, but this
        # direct path avoids ambiguity caused by nearby protocol length bytes.
        for i in range(2,min(30,len(block)-4)):
            if block[i]==0x12 and block[i+1:i+3]==b"\xff\x01":
                start=i+1
                for end in range(start+18,min(len(block),start+28)):
                    if block[end]!=0x04:
                        continue
                    dec=decode_exact(block[start:end],18)
                    if dec:
                        txt,removed=dec
                        txt=txt.strip()
                        if txt:
                            return txt,core.core_name(txt),"12-ff01",removed
                    break

        # Generic compact form: [declared UTF-8 byte length] immediately
        # followed by encoded name bytes. Stuffing may occur at the beginning
        # or inside the name (e.g. FF01/FF02, 1F, C7...).
        generic=[]
        for i in range(2,min(35,len(block)-3)):
            decl=block[i]
            if not (2<=decl<=60):
                continue
            start=i+1
            lo=start+max(1,decl-4)
            hi=min(len(block),start+decl+10)

            for end in range(lo,hi):
                if block[end]!=0x04:
                    continue
                dec=decode_exact(block[start:end],decl)
                if not dec:
                    continue
                txt,removed=dec
                txt=txt.strip()
                if not txt:
                    continue
                if sum(ch.isalnum() for ch in txt)<2:
                    continue
                if sum(ch.isprintable() for ch in txt)<max(1,int(len(txt)*0.9)):
                    continue

                generic.append((
                    50-i,
                    txt,
                    core.core_name(txt),
                    "generic-len",
                    removed
                ))
                break

        if generic:
            generic.sort(key=lambda x:-x[0])
            _,disp,cname,kind,removed=generic[0]
            return disp,cname,kind,removed

        return "","","",""

    results.sort(key=lambda x:-x[0])
    _,disp,core_name,kind,removed=results[0]
    return disp,core_name,kind,removed

def reassembled_server_7502(capture: Path, core):
    """
    Reassemble WOS application frames split across consecutive TCP payloads.

    The first two bytes are the WOS declared frame length; total bytes on the
    wire for the application frame are declared_length + 2.

    EVL validation:
      packet 121 (10220) + 122 (442) = 10662
      packet 127 (7300)  + 128 (1450) = 8750
    """
    tcp_payloads=[]
    for pn,pkt in core.pcapng_packets(capture.read_bytes()):
        x=core.tcp_payload(pkt)
        if not x:
            continue
        sport,dport,payload=x
        if sport==core.PORT and payload:
            tcp_payloads.append((pn,payload))

    out=[]
    i=0
    while i<len(tcp_payloads):
        pn,payload=tcp_payloads[i]

        if len(payload)>=4 and payload[2:4]==b"\x75\x02":
            total=int.from_bytes(payload[:2],"big")+2
            buf=bytearray(payload)
            packets=[pn]
            j=i+1

            while len(buf)<total and j<len(tcp_payloads):
                pn2,p2=tcp_payloads[j]
                buf.extend(p2)
                packets.append(pn2)
                j+=1

            if len(buf)>=total:
                out.append({
                    "packets":packets,
                    "payload":bytes(buf[:total]),
                })
                i=j
                continue

        i+=1

    return out


# ---------------------------------------------------------------------------
# COMPACT ALLIANCE MEMBER ATLAS-ID DECODER
# ---------------------------------------------------------------------------

ATLAS_MEMBER_STUFF={0xC7,0xE3,0x8F}
ATLAS_MEMBER_WRAPPERS={0x1F,0xF8,0x3E,0xF1,0x7C,0xFC,0xFE,0xED}
ATLAS_MEMBER_POST_WRAPPERS={0x1F,0xF8,0x3E,0xF1,0x7C,0xFC,0xFE}

def _atlas_boundary_ok(block: bytes, end: int):
    if end < len(block) and block[end]==0x04:
        return True
    if (
        end+1 < len(block)
        and block[end] in ATLAS_MEMBER_POST_WRAPPERS
        and block[end+1]==0x04
    ):
        return True
    return False

def decode_member_atlas_id(block: bytes):
    """
    Compact alliance-member Atlas field.

    Structural shape:
       04 [optional wrapper] <4 useful LE bytes, sometimes 1 stuffing byte> 04

    Also observed:
       04 00 00 3E <Atlas LE32> 04

    Atlas IDs in this state/capture span beyond 0x09xxxxxx, so validation uses
    a broad numeric range instead of forcing the last LE byte to 09.
    """
    candidates=[]

    for marker in range(10,min(80,len(block)-7)):
        if block[marker]!=0x04:
            continue

        starts=[]

        # Multi-byte wrappers.
        if block[marker+1:marker+4]==b"\x00\x00\x3e":
            starts.append((marker+4,"00003e",70))

        # Paginated-list variant validated in EVL(2):
        #   04 00 7C <Atlas LE32> 04
        if block[marker+1:marker+3]==b"\x00\x7c":
            starts.append((marker+3,"007c",70))

        # Known one-byte wrappers.
        if block[marker+1] in ATLAS_MEMBER_WRAPPERS:
            starts.append((marker+2,f"{block[marker+1]:02x}",60))

        # Direct Atlas field.
        starts.append((marker+1,"direct",50))

        # Lower-confidence one-byte wrapper fallback. Kept only to support
        # compact variants not yet individually calibrated.
        starts.append((marker+2,f"p{block[marker+1]:02x}",35))

        for start,kind,base_score in starts:
            # Raw 4-byte LE Atlas.
            if start+4<=len(block) and _atlas_boundary_ok(block,start+4):
                raw=block[start:start+4]
                value=int.from_bytes(raw,"little")
                if 100_000_000<=value<=300_000_000:
                    candidates.append({
                        "marker_offset":marker,
                        "score":base_score,
                        "atlas_id":value,
                        "kind":kind,
                        "encoded_hex":raw.hex(),
                        "removed_hex":"",
                    })

            # 5 encoded bytes with one validated internal stuffing byte.
            if start+5<=len(block) and _atlas_boundary_ok(block,start+5):
                enc=block[start:start+5]
                for rem in (1,2,3):
                    if enc[rem] not in ATLAS_MEMBER_STUFF:
                        continue
                    raw=enc[:rem]+enc[rem+1:]
                    value=int.from_bytes(raw,"little")
                    if 100_000_000<=value<=300_000_000:
                        candidates.append({
                            "marker_offset":marker,
                            "score":base_score+5,
                            "atlas_id":value,
                            "kind":kind,
                            "encoded_hex":enc.hex(),
                            "removed_hex":f"{enc[rem]:02x}",
                        })

    if not candidates:
        return {
            "atlas_id":"",
            "confidence":"unresolved",
            "detail":None,
        }

    # The Atlas field is the earliest valid numeric field after the compact
    # nickname. At that marker, structural score resolves wrapper ambiguity.
    first_marker=min(c["marker_offset"] for c in candidates)
    same=[c for c in candidates if c["marker_offset"]==first_marker]
    same.sort(key=lambda c:(-c["score"],c["atlas_id"]))

    best=same[0]
    second=same[1] if len(same)>1 else None

    confidence=(
        "high"
        if second is None or best["score"]>=second["score"]+10
        else "medium"
    )

    return {
        "atlas_id":best["atlas_id"],
        "confidence":confidence,
        "detail":best,
    }


# ---------------------------------------------------------------------------
# STRICT COMPACT ALLIANCE-MEMBER WOS-ID DECODER
# ---------------------------------------------------------------------------

WOS_MEMBER_STUFF={0xC7,0xE3,0x8F,0x23,0x47}
WOS_MEMBER_WRAPPERS={0x1F,0x7C,0x3E,0xF8,0xF1,0xD1}
WOS_MEMBER_FOLLOW={0x20,0x21,0x54,0x70,0xC4,0x11,0xF1,0xA2,0x88,0x18,0x51}

def decode_member_wos_id(block: bytes):
    """
    Strict WOS-ID decoder for compact alliance-member records.

    Important differences from individual-profile V9.6:
    - 0x47 is NOT treated as generic stuffing here (Myszata proves it may be
      the real first byte of the WOS ID).
    - only the compact wrappers/stuffing validated on alliance-member blocks
      are accepted.
    - ambiguous candidates are returned as MEDIUM, never silently promoted.

    Calibration set currently gives 13 exact matches / 0 wrong matches;
    Chiefer's compact variant remains intentionally unresolved.
    """
    candidates=[]

    for marker in range(45,min(len(block)-6,120)):
        if block[marker]!=0x04:
            continue

        starts=[(marker+1,"direct",50)]
        if block[marker+1] in WOS_MEMBER_WRAPPERS:
            starts.append((marker+2,f"wrap{block[marker+1]:02x}",65))

        for start,kind,base_score in starts:
            # Raw LE32.
            if start+4<=len(block):
                raw=block[start:start+4]
                value=int.from_bytes(raw,"little")
                if 580_000_000<=value<=800_000_000:
                    nxt=block[start+4] if start+4<len(block) else None
                    score=base_score
                    if nxt in WOS_MEMBER_FOLLOW:
                        score+=12
                    if raw[3] in (0x24,0x25,0x2A,0x2D):
                        score+=8
                    candidates.append({
                        "score":score,
                        "wos_id":value,
                        "kind":kind,
                        "marker_offset":marker,
                        "offset":start,
                        "encoded_hex":raw.hex(),
                        "removed_hex":"",
                    })

            # One internal stuffing byte.
            if start+5<=len(block):
                enc=block[start:start+5]
                for rem in (1,2,3):
                    if enc[rem] not in WOS_MEMBER_STUFF:
                        continue
                    raw=enc[:rem]+enc[rem+1:]
                    value=int.from_bytes(raw,"little")
                    if 580_000_000<=value<=800_000_000:
                        nxt=block[start+5] if start+5<len(block) else None
                        # Stuffing priorities are calibrated:
                        # C7/E3/8F are strong; 23 is weaker; 47 is weakest
                        # because 47 can also be real data (Myszata).
                        stuffing_bonus={
                            0xC7:9,
                            0xE3:8,
                            0x8F:8,
                            0x23:4,
                            0x47:2,
                        }.get(enc[rem],0)
                        score=base_score+stuffing_bonus
                        # Structural disambiguation: in compact member fields,
                        # a byte that *can* be a wrapper (7C/3E/F1/...) may
                        # instead be the first real ID byte when a strong
                        # stuffing byte follows inside the same 5-byte field.
                        # Repeated captures validate this on Lilly (7C+E3),
                        # Williamson (3E+C7), NESSI_ (F1+8F) and KingLing
                        # (7C+8F). Prefer direct+strong-stuffing over treating
                        # byte 0 as a wrapper.
                        if (
                            kind=="direct"
                            and enc[0] in WOS_MEMBER_WRAPPERS
                            and enc[rem] in (0xC7,0xE3,0x8F)
                        ):
                            score+=20
                        if nxt in WOS_MEMBER_FOLLOW:
                            score+=12
                        if raw[3] in (0x24,0x25,0x2A,0x2D):
                            score+=8
                        candidates.append({
                            "score":score,
                            "wos_id":value,
                            "kind":kind,
                            "marker_offset":marker,
                            "offset":start,
                            "encoded_hex":enc.hex(),
                            "removed_hex":f"{enc[rem]:02x}",
                        })

    # Compact zero-omission form, validated by Chiefer:
    #   real ID 17 00 4B 25
    #   encoded 04 17 4B 25 F1 ...
    # The zero second byte is omitted and F1 terminates this compact form.
    # Keep this tightly constrained to the profile metadata zone.
    for marker in range(55,min(len(block)-5,100)):
        if block[marker]!=0x04:
            continue
        if marker+4<len(block) and block[marker+4]==0xF1:
            a,b,c=block[marker+1],block[marker+2],block[marker+3]
            raw=bytes((a,0x00,b,c))
            value=int.from_bytes(raw,"little")
            if 580_000_000<=value<=800_000_000:
                candidates.append({
                    "score":86,
                    "wos_id":value,
                    "kind":"zero_omitted_f1",
                    "marker_offset":marker,
                    "offset":marker+1,
                    "encoded_hex":block[marker+1:marker+5].hex(),
                    "removed_hex":"",
                })

    # Zero-omission + control-byte family, established from repeated Chiefer
    # captures. The useful ID bytes are [a, 00, b, c]; the omitted zero may
    # coexist with one compact control byte either after a or before a.
    # Examples:
    #   04 17 C7 4B 25 20 -> 17 00 4B 25
    #   04 74 17 4B 25 20 -> 17 00 4B 25
    zero_controls={0xC7,0x74}
    for marker in range(55,min(len(block)-6,100)):
        if block[marker]!=0x04:
            continue
        enc4=block[marker+1:marker+5]
        follow=block[marker+5] if marker+5<len(block) else None
        if len(enc4)!=4 or follow not in WOS_MEMBER_FOLLOW:
            continue

        # Control inserted after first useful byte: a X b c.
        if enc4[1] in zero_controls:
            raw=bytes((enc4[0],0x00,enc4[2],enc4[3]))
            value=int.from_bytes(raw,"little")
            if 580_000_000<=value<=800_000_000 and raw[3] in (0x24,0x25,0x28,0x2A,0x2D):
                candidates.append({
                    "score":95,
                    "wos_id":value,
                    "kind":"zero_omitted_control_internal",
                    "marker_offset":marker,
                    "offset":marker+1,
                    "encoded_hex":enc4.hex(),
                    "removed_hex":f"{enc4[1]:02x}",
                })

        # Control before three useful bytes: X a b c.
        if enc4[0] in zero_controls:
            raw=bytes((enc4[1],0x00,enc4[2],enc4[3]))
            value=int.from_bytes(raw,"little")
            if 580_000_000<=value<=800_000_000 and raw[3] in (0x24,0x25,0x28,0x2A,0x2D):
                candidates.append({
                    "score":95,
                    "wos_id":value,
                    "kind":"zero_omitted_control_leading",
                    "marker_offset":marker,
                    "offset":marker+1,
                    "encoded_hex":enc4.hex(),
                    "removed_hex":f"{enc4[0]:02x}",
                })

    if not candidates:
        return {
            "wos_id":"",
            "candidate":"",
            "confidence":"unresolved",
            "detail":None,
        }

    # Dedupe numeric values.
    best_by_value={}
    for c in candidates:
        old=best_by_value.get(c["wos_id"])
        if old is None or c["score"]>old["score"]:
            best_by_value[c["wos_id"]]=c

    ranked=sorted(
        best_by_value.values(),
        key=lambda c:(-c["score"],c["marker_offset"],c["offset"],c["wos_id"])
    )
    best=ranked[0]
    second=ranked[1] if len(ranked)>1 else None

    # C7-vs-23 ambiguity is now independently calibrated by
    # ChilliinglikeOGS: when the same 5 encoded bytes can be interpreted by
    # removing C7 or 23, C7 is the real stuffing byte.
    calibrated_c7_over_23=(
        second is not None
        and best.get("encoded_hex")==second.get("encoded_hex")
        and best.get("removed_hex")=="c7"
        and second.get("removed_hex")=="23"
    )

    # Independently validated by bahlulTzy and BabyTalonChick:
    # when the same encoded bytes allow E3 or 47 to be removed, E3 is the
    # structural stuffing byte and 47 belongs to the real WOS ID.
    calibrated_e3_over_47=(
        second is not None
        and best.get("encoded_hex")==second.get("encoded_hex")
        and best.get("removed_hex")=="e3"
        and second.get("removed_hex")=="47"
    )

    # Same structural ordering for 8F vs 47, validated by BabyTalonChick in
    # the paginated response: 88 8F 47 17 28 -> 88 47 17 28.
    calibrated_8f_over_47=(
        second is not None
        and best.get("encoded_hex")==second.get("encoded_hex")
        and best.get("removed_hex")=="8f"
        and second.get("removed_hex")=="47"
    )

    if (
        second is None
        or best["score"]>=second["score"]+8
        or calibrated_c7_over_23
        or calibrated_e3_over_47
        or calibrated_8f_over_47
    ):
        confidence="high"
        published=best["wos_id"]
    else:
        confidence="medium"
        published=""

    return {
        "wos_id":published,
        "candidate":best["wos_id"],
        "confidence":confidence,
        "detail":best,
    }


# ---------------------------------------------------------------------------
# COMPACT ALLIANCE-MEMBER POWER DECODER
# ---------------------------------------------------------------------------

POWER_MEMBER_STUFF={0xC7:10,0xE3:10,0x8F:10,0x47:9,0x23:8}
POWER_MEMBER_WRAPPERS={0x3E,0x1F,0x7C,0xF8,0xF1,0xED,0x9D}

def decode_member_power(block: bytes, atlas_detail: dict):
    """
    Power is the compact numeric field immediately following the Atlas-ID
    field. Supports direct LE32, one-byte wrappers, and one internal stuffing
    byte. Ranking rejects the common ~600M false values produced by retaining
    a stuffing byte as data.
    """
    enc_hex=atlas_detail.get("encoded_hex","")
    if not enc_hex:
        return {"power":"","confidence":"unresolved","detail":None}

    atlas_enc=bytes.fromhex(enc_hex)
    positions=[
        i for i in range(len(block)-len(atlas_enc)+1)
        if block[i:i+len(atlas_enc)]==atlas_enc
    ]
    candidates=[]

    for ap in positions:
        atlas_end=ap+len(atlas_enc)
        # V4.0.33: la fiche de ville n'emploie pas toujours le tout premier
        # champ 0x04 suivant l'Atlas ID pour la puissance. Les anciennes
        # versions s'arrêtaient au premier 0x04, ce qui laissait la puissance
        # vide alors que l'ID WOS était bien décodé. On inspecte maintenant
        # toute la petite fenêtre de métadonnées du profil, en privilégiant
        # fortement les marqueurs les plus proches de l'Atlas ID.
        for marker in range(
            atlas_end,
            min(len(block)-5,atlas_end+96)
        ):
            if block[marker]!=0x04:
                continue

            distance=marker-atlas_end
            proximity_bonus=max(0,24-(distance//4)*3)
            starts=[(marker+1,"direct",0)]
            if marker+1 < len(block) and block[marker+1] in POWER_MEMBER_WRAPPERS:
                starts.append(
                    (marker+2,f"wrap{block[marker+1]:02x}",18)
                )

            for start,kind,wrapper_bonus in starts:
                raw=block[start:start+4]
                if len(raw)==4:
                    value=int.from_bytes(raw,"little")
                    if 20_000_000<=value<=550_000_000:
                        score=wrapper_bonus+proximity_bonus
                        if 40_000_000<=value<=400_000_000:
                            score+=20
                        if 60_000_000<=value<=320_000_000:
                            score+=10
                        candidates.append({
                            "score":score,
                            "power":value,
                            "kind":kind,
                            "encoded_hex":raw.hex(),
                            "removed_hex":"",
                            "marker_offset":marker,
                            "atlas_distance":distance,
                        })

                enc=block[start:start+5]
                if len(enc)==5:
                    for rem in (1,2,3):
                        stuffing_bonus=POWER_MEMBER_STUFF.get(enc[rem])
                        if stuffing_bonus is None:
                            continue
                        raw=enc[:rem]+enc[rem+1:]
                        value=int.from_bytes(raw,"little")
                        if 20_000_000<=value<=550_000_000:
                            score=wrapper_bonus+stuffing_bonus+proximity_bonus
                            if 40_000_000<=value<=400_000_000:
                                score+=20
                            if 60_000_000<=value<=320_000_000:
                                score+=10
                            candidates.append({
                                "score":score,
                                "power":value,
                                "kind":kind,
                                "encoded_hex":enc.hex(),
                                "removed_hex":f"{enc[rem]:02x}",
                                "marker_offset":marker,
                                "atlas_distance":distance,
                            })

    if not candidates:
        return {"power":"","confidence":"unresolved","detail":None}

    candidates.sort(
        key=lambda c:(-c["score"],c["marker_offset"],c["power"])
    )
    best=candidates[0]
    second=candidates[1] if len(candidates)>1 else None

    confidence=(
        "high"
        if second is None
        or best["score"]>=second["score"]+8
        or best["power"]==second["power"]
        else "medium"
    )

    return {
        "power":best["power"] if confidence=="high" else "",
        "candidate":best["power"],
        "confidence":confidence,
        "detail":best,
    }


def main():
    ap=argparse.ArgumentParser()
    ap.add_argument("capture",type=Path)
    args=ap.parse_args()
    core=load_core(Path(__file__).resolve().parent)

    rows=[]
    summaries=[]

    for msg in reassembled_server_7502(args.capture,core):
        payload=msg["payload"]
        # V1.4 supports both transport shapes:
        # - old aggregated alliance list (many member blocks in one response)
        # - new paginated responses (often only 1-4 member blocks)
        starts=[m.start() for m in re.finditer(b"\xdc\x1c",payload)]
        if not starts:
            continue

        pn=msg["packets"][0]
        summaries.append((msg["packets"],len(payload),len(starts)))

        for idx,st in enumerate(starts,1):
            en=starts[idx] if idx<len(starts) else len(payload)
            seg=payload[st:en]
            disp,cname,nkind,nstuff=compact_name(seg,core)
            atlas=decode_member_atlas_id(seg)
            atlas_detail=atlas.get("detail") or {}
            power=decode_member_power(seg,atlas_detail)
            power_detail=power.get("detail") or {}
            wid=decode_member_wos_id(seg)
            tag,alli,ascore=core.reconstruct_alliance(seg)

            # Alliance TAG fallback (V1.9): in compact member records the TAG
            # itself may contain protocol stuffing even when the alliance name
            # is reconstructed perfectly.  When the alliance name is already
            # known, recover its canonical TAG from the same known-alliance
            # mapping instead of discarding the association.
            if not tag and alli:
                for known_tag,known_name in core.KNOWN_ALLIANCES.items():
                    if known_name == alli:
                        tag=known_tag
                        break

            detail=wid.get("detail") or {}

            rows.append({
                "source_packet":pn,
                "source_packets":"+".join(map(str,msg["packets"])),
                "member_index":idx,
                "pseudo_display":disp,
                "pseudo_core":cname,
                "name_encoding":nkind,
                "name_stuff_removed":nstuff,
                "atlas_id":atlas.get("atlas_id") or "",
                "atlas_id_confidence":atlas.get("confidence",""),
                "atlas_id_kind":atlas_detail.get("kind",""),
                "atlas_id_encoded_hex":atlas_detail.get("encoded_hex",""),
                "atlas_id_removed_hex":atlas_detail.get("removed_hex",""),
                "power":power.get("power") or "",
                "power_candidate":power.get("candidate") or "",
                "power_confidence":power.get("confidence",""),
                "power_kind":power_detail.get("kind",""),
                "power_encoded_hex":power_detail.get("encoded_hex",""),
                "power_removed_hex":power_detail.get("removed_hex",""),
                "wos_id":wid.get("wos_id") or "",
                "wos_id_candidate":wid.get("candidate") or "",
                "wos_id_confidence":wid.get("confidence",""),
                "wos_id_kind":detail.get("kind",""),
                "wos_id_encoded_hex":detail.get("encoded_hex",""),
                "wos_id_removed_hex":detail.get("removed_hex",""),
                "alliance_tag":tag,
                "alliance_name":alli,
                "block_offset":st,
                "block_len":len(seg),
                "raw_block_hex":seg.hex(),
            })

    # Deduplicate pages/reloads. Atlas ID is the stable compact-record key.
    # Keep the strongest occurrence when the same player was returned multiple times.
    def row_quality(r):
        return (
            1 if r.get("atlas_id") else 0,
            1 if r.get("wos_id_confidence")=="high" else 0,
            1 if r.get("power_confidence")=="high" else 0,
            1 if r.get("pseudo_display") else 0,
            int(r.get("block_len") or 0),
        )

    dedup={}
    anonymous=[]
    for r in rows:
        key=str(r.get("atlas_id") or "")
        if not key:
            anonymous.append(r)
            continue
        old=dedup.get(key)
        if old is None or row_quality(r)>row_quality(old):
            dedup[key]=r

    raw_count=len(rows)
    rows=list(dedup.values())+anonymous
    rows.sort(key=lambda r:(int(r["atlas_id"]) if str(r.get("atlas_id","")).isdigit() else 10**12,
                            int(r.get("source_packet") or 0)))

    out=args.capture.with_name(args.capture.stem+"_alliance_members_v2_3.csv")
    with out.open("w",newline="",encoding="utf-8-sig") as f:
        if rows:
            wr=csv.DictWriter(f,fieldnames=list(rows[0].keys()))
            wr.writeheader();wr.writerows(rows)

    print("=== WOS Alliance Members V2.3 ===")
    for packets,size,count in summaries:
        print(f"Paquets {'+'.join(map(str,packets))}: {size} octets -> {count} blocs")
    print(f"Blocs membre bruts : {raw_count}")
    print(f"Membres uniques : {len(rows)}")
    print(f"Pseudos décodés : {sum(bool(r['pseudo_display']) for r in rows)}/{len(rows)}")
    print(f"Atlas ID décodés : {sum(bool(r['atlas_id']) for r in rows)}/{len(rows)}")
    print(f"Power HIGH : {sum(bool(r['power']) for r in rows)}/{len(rows)}")
    print(f"Power MEDIUM : {sum(r['power_confidence']=='medium' for r in rows)}/{len(rows)}")
    print(f"WOS ID HIGH : {sum(bool(r['wos_id']) for r in rows)}/{len(rows)}")
    print(f"WOS ID MEDIUM : {sum(r['wos_id_confidence']=='medium' for r in rows)}/{len(rows)}")
    print(f"WOS ID unresolved : {sum(r['wos_id_confidence']=='unresolved' for r in rows)}/{len(rows)}")
    print(f"CSV : {out}")

if __name__=="__main__":
    main()
