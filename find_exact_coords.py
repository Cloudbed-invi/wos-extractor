import sqlite3
import os
import binascii
import struct

db_path = os.path.expandvars(r'%LOCALAPPDATA%\WOS_Unified_Manager\data\wos_unified.sqlite3')
conn = sqlite3.connect(db_path)
conn.row_factory = sqlite3.Row

# Get events from this session (ID > 1200)
rows = conn.execute("""
    SELECT id, opcode, payload_hex, seen_at, length(payload_hex)/2 as sz 
    FROM protocol_raw_events 
    WHERE id >= 1200
    ORDER BY id ASC
""").fetchall()

print(f"Analyzing {len(rows)} events captured between ID 1200 and {rows[-1]['id']}...")

targets = [
    (25, 493, 'นิกกี้ พิ้ม', 625804215),
    (185, 1079, 'minipopor', 744749843),
    (753, 1181, 'น้ำตกคอหมู', 628674591),
    (772, 1179, 'lord852305348', 852305348),
    (833, 1143, 'Tim Bradford', 626920887),
    (1116, 1154, 'GaMEkag12', 627804175),
    (1165, 1044, 'Ail', 621411907),
    (1160, 1019, 'Fxnn37', 625413337),
    (1167, 949, 'Jeee', 625853206),
    (1151, 835, 'lord625999966', 625999966)
]

def encode_varint(n):
    buf = bytearray()
    while n >= 0x80:
        buf.append((n & 0x7f) | 0x80)
        n >>= 7
    buf.append(n & 0x7f)
    return bytes(buf)

for x, y, name, wos_id in targets:
    print(f"\n==================================================")
    print(f"Searching for: {name} (WOS ID: {wos_id}, X: {x}, Y: {y})")
    print(f"==================================================")

    # Patterns for (X, Y)
    patterns = [
        ("uint16_LE (continuous)", struct.pack('<HH', x, y)),
        ("uint16_LE (Y then X)", struct.pack('<HH', y, x)),
        ("uint32_LE (continuous)", struct.pack('<II', x, y)),
        ("uint32_LE (Y then X)", struct.pack('<II', y, x)),
        ("uint16_BE (continuous)", struct.pack('>HH', x, y)),
        ("protobuf_varint (continuous)", encode_varint(x) + encode_varint(y)),
    ]

    found_any = False
    for r in rows:
        try:
            frame = binascii.unhexlify(r['payload_hex'])
        except Exception:
            continue

        # 1. Exact continuous pattern match
        for pat_name, pat in patterns:
            pos = 0
            while True:
                idx = frame.find(pat, pos)
                if idx == -1:
                    break
                print(f"[!] EXACT MATCH in Event {r['id']} (Opcode {r['opcode']}, sz {r['sz']}) at offset {idx}: {pat_name}")
                ctx_start = max(0, idx - 16)
                ctx_end = min(len(frame), idx + len(pat) + 24)
                print(f"    Hex context: {binascii.hexlify(frame[ctx_start:ctx_end]).decode()}")
                found_any = True
                pos = idx + 1

        # 2. Varints within 8 bytes of each other (typical protobuf fields: tag1, val1, tag2, val2)
        vx = encode_varint(x)
        vy = encode_varint(y)
        pos = 0
        while True:
            idx = frame.find(vx, pos)
            if idx == -1:
                break
            # Look for vy within 12 bytes
            sub_start = max(0, idx - 12)
            sub_end = min(len(frame), idx + len(vx) + 12)
            y_pos_sub = frame[sub_start:sub_end].find(vy)
            if y_pos_sub != -1:
                real_y = sub_start + y_pos_sub
                dist = real_y - idx
                if abs(dist) <= 10 and dist != 0:
                    print(f"[*] NEARBY VARINTS in Event {r['id']} (Opcode {r['opcode']}, sz {r['sz']})")
                    print(f"    X varint at {idx}, Y varint at {real_y} (dist: {dist})")
                    ctx_start = max(0, min(idx, real_y) - 8)
                    ctx_end = min(len(frame), max(idx, real_y) + 12)
                    print(f"    Hex: {binascii.hexlify(frame[ctx_start:ctx_end]).decode()}")
                    found_any = True
            pos = idx + 1

    if not found_any:
        print(f"[-] No direct matches for {name} ({x}, {y})")
