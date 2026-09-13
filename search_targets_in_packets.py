import sqlite3
import os
import binascii

db_path = os.path.expandvars(r'%LOCALAPPDATA%\WOS_Unified_Manager\data\wos_unified.sqlite3')
conn = sqlite3.connect(db_path)
conn.row_factory = sqlite3.Row

rows = conn.execute("""
    SELECT id, opcode, direction, payload_hex, seen_at 
    FROM protocol_raw_events 
    WHERE id >= 1200
    ORDER BY id ASC
""").fetchall()

print(f"Total events to scan: {len(rows)}")

targets = [b'lord625999966', b'625999966', b'vqS', b'Jeee', b'Fxnn37', b'Ail', b'GaMEkag12', b'Tim Bradford', b'lord852305348', b'minipopor']

found = 0
for r in rows:
    frame = binascii.unhexlify(r['payload_hex'])
    for t in targets:
        if t in frame:
            print(f"[FOUND '{t.decode()}'] in Event ID {r['id']} | Opcode: {r['opcode']} | Direction: {r['direction']} | Size: {len(frame)} bytes | Time: {r['seen_at']}")
            found += 1
            # Print context
            idx = frame.find(t)
            ctx_start = max(0, idx - 40)
            ctx_end = min(len(frame), idx + len(t) + 60)
            print(f"   Context: {frame[ctx_start:ctx_end]}")
            print(f"   Hex: {binascii.hexlify(frame[ctx_start:ctx_end]).decode()}\n")

if found == 0:
    print("None of the player names or alliance tags were found in the raw packets!")
