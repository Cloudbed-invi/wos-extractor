import sqlite3
import os
import binascii
import struct

db_path = os.path.expandvars(r'%LOCALAPPDATA%\WOS_Unified_Manager\data\wos_unified.sqlite3')
conn = sqlite3.connect(db_path)
conn.row_factory = sqlite3.Row

# Check total events captured
total_raw = conn.execute("SELECT COUNT(*) FROM protocol_raw_events").fetchone()[0]
print(f"Total protocol_raw_events in DB: {total_raw}")

# Get recent events from the last 15 minutes
rows = conn.execute("""
    SELECT id, opcode, direction, payload_hex, seen_at 
    FROM protocol_raw_events 
    ORDER BY id DESC LIMIT 500
""").fetchall()

print(f"Fetched {len(rows)} recent events.")

targets = [
    (25, 493, 'นิกกี้ พิ้ม', '625804215'),
    (185, 1079, 'minipopor', '744749843'),
    (753, 1181, 'น้ำตกคอหมู', '628674591'),
    (772, 1179, 'lord852305348', '852305348'),
    (833, 1143, 'Tim Bradford', '626920887'),
    (1116, 1154, 'GaMEkag12', '627804175'),
    (1165, 1044, 'Ail', '621411907'),
    (1160, 1019, 'Fxnn37', '625413337'),
    (1167, 949, 'Jeee', '625853206'),
    (1151, 835, 'lord625999966', '625999966')
]

def encode_varint(n):
    buf = bytearray()
    while n >= 0x80:
        buf.append((n & 0x7f) | 0x80)
        n >>= 7
    buf.append(n & 0x7f)
    return bytes(buf)

# Let's count opcodes
opcodes = {}
for r in rows:
    op = r['opcode'] or 'none'
    opcodes[op] = opcodes.get(op, 0) + 1
print("Recent opcodes breakdown:", opcodes)

# Search across all recent frames
matches = []

for r in rows:
    try:
        frame = binascii.unhexlify(r['payload_hex'])
    except Exception:
        continue

    for x, y, name, wos_id in targets:
        # Check string or ascii name / wos_id
        wos_bytes = wos_id.encode('ascii')
        wos_varint = encode_varint(int(wos_id))
        
        found_id = False
        if wos_bytes in frame:
            print(f"[Event {r['id']} | Opcode {r['opcode']}] Found WOS ID {wos_id} (ASCII) for {name}!")
            found_id = True
        if wos_varint in frame:
            print(f"[Event {r['id']} | Opcode {r['opcode']}] Found WOS ID {wos_id} (Varint) for {name}!")
            found_id = True

        # Check coordinates in different encodings
        encodings = [
            ('<H', struct.pack('<H', x), struct.pack('<H', y), 'uint16_LE'),
            ('<I', struct.pack('<I', x), struct.pack('<I', y), 'uint32_LE'),
            ('>H', struct.pack('>H', x), struct.pack('>H', y), 'uint16_BE'),
            ('>I', struct.pack('>I', x), struct.pack('>I', y), 'uint32_BE'),
            ('varint', encode_varint(x), encode_varint(y), 'protobuf_varint')
        ]

        for enc_name, xb, yb, desc in encodings:
            idx = frame.find(xb)
            while idx != -1:
                # Look for y within 30 bytes before or after
                search_start = max(0, idx - 30)
                search_end = min(len(frame), idx + 30 + len(yb))
                sub = frame[search_start:search_end]
                y_idx = sub.find(yb)
                if y_idx != -1:
                    actual_y_pos = search_start + y_idx
                    diff = actual_y_pos - idx
                    print(f"--> [MATCH in Event {r['id']} (Opcode {r['opcode']}, len {len(frame)})] {name} ({x},{y}) matched as {desc}!")
                    print(f"    X at offset {idx}, Y at offset {actual_y_pos} (relative dist = {diff} bytes)")
                    # Print context bytes around the match
                    ctx_start = max(0, min(idx, actual_y_pos) - 10)
                    ctx_end = min(len(frame), max(idx, actual_y_pos) + 15)
                    print(f"    Raw context hex: {binascii.hexlify(frame[ctx_start:ctx_end]).decode()}")
                idx = frame.find(xb, idx + 1)
