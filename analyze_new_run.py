import sqlite3
import os
import binascii
import struct

db_path = os.path.expandvars(r'%LOCALAPPDATA%\WOS_Unified_Manager\data\wos_unified.sqlite3')
conn = sqlite3.connect(db_path)
conn.row_factory = sqlite3.Row

rows = conn.execute("""
    SELECT opcode, direction, COUNT(*) as cnt, SUM(length(payload_hex)/2) as total_bytes 
    FROM protocol_raw_events 
    WHERE id >= 1800 
    GROUP BY opcode, direction
""").fetchall()

print("Opcodes summary for the 10-city run (events >= 1800):")
for r in rows:
    print(f"  {r['direction']} | Opcode: {r['opcode']} | Count: {r['cnt']} | Total: {r['total_bytes']} bytes")

# Now let's fetch all S>C events >= 1800
events = conn.execute("""
    SELECT id, opcode, payload_hex, seen_at, length(payload_hex)/2 as sz 
    FROM protocol_raw_events 
    WHERE id >= 1800 AND direction = 'S>C'
    ORDER BY id ASC
""").fetchall()

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

print("\nScanning for players and coordinates across these events:")
for x, y, name, wos_id in targets:
    found_player = False
    for ev in events:
        frame = binascii.unhexlify(ev['payload_hex'])
        
        # Search by ASCII name or WOS ID
        name_bytes = name.encode('utf-8')
        wos_bytes = wos_id.encode('ascii')
        
        name_pos = frame.find(name_bytes)
        wos_pos = frame.find(wos_bytes)
        
        if name_pos != -1 or wos_pos != -1:
            found_player = True
            matched_on = f"Name '{name}'" if name_pos != -1 else f"WOS ID {wos_id}"
            pos = name_pos if name_pos != -1 else wos_pos
            print(f"\n[FOUND {matched_on}] in Event {ev['id']} (Opcode {ev['opcode']}, {ev['sz']} bytes)")
            
            # Print 100 bytes window around match
            w_start = max(0, pos - 60)
            w_end = min(len(frame), pos + 100)
            window = frame[w_start:w_end]
            print(f"  Context hex: {binascii.hexlify(window).decode()}")
            
            # Check for coordinates inside this window or near it
            for offset in range(len(window) - 3):
                u16 = struct.unpack_from('<H', window, offset)[0]
                u32 = struct.unpack_from('<I', window, offset)[0]
                if u16 in (x, y):
                    coord_type = "X" if u16 == x else "Y"
                    print(f"    -> Matched {coord_type}={u16} (uint16 LE) at relative offset {offset - (pos - w_start)}!")
                if u32 in (x, y):
                    coord_type = "X" if u32 == x else "Y"
                    print(f"    -> Matched {coord_type}={u32} (uint32 LE) at relative offset {offset - (pos - w_start)}!")
                    
            # Check varints
            i = 0
            while i < len(window):
                start_i = i
                val = 0
                shift = 0
                while i < len(window):
                    b = window[i]
                    val |= (b & 0x7f) << shift
                    i += 1
                    if not (b & 0x80):
                        break
                    shift += 7
                if val in (x, y):
                    coord_type = "X" if val == x else "Y"
                    print(f"    -> Matched {coord_type}={val} (Varint) at relative offset {start_i - (pos - w_start)}!")

    if not found_player:
        print(f"[-] {name} not found in this batch of S>C packets.")
