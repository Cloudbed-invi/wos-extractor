import sqlite3, os, binascii, struct

db_path = os.path.expandvars(r'%LOCALAPPDATA%\WOS_Unified_Manager\data\wos_unified.sqlite3')
conn = sqlite3.connect(db_path)
conn.row_factory = sqlite3.Row

# Get events 1810 to 1825
rows = conn.execute("SELECT id, opcode, payload_hex FROM protocol_raw_events WHERE id >= 1800 ORDER BY id ASC").fetchall()

target_x = 1151
target_y = 835

print(f"Searching events 1800+ for X={target_x}, Y={target_y}")

def parse_varints(buf):
    i = 0
    results = []
    while i < len(buf):
        start_i = i
        val = 0
        shift = 0
        while i < len(buf):
            b = buf[i]
            val |= (b & 0x7f) << shift
            i += 1
            if not (b & 0x80):
                break
            shift += 7
        results.append((start_i, val, i - start_i))
    return results

for r in rows:
    frame = binascii.unhexlify(r['payload_hex'])
    
    # 1. Search uint16 LE
    for i in range(len(frame) - 1):
        v = struct.unpack_from('<H', frame, i)[0]
        if v in (target_x, target_y):
            name = "X (1151)" if v == target_x else "Y (835)"
            print(f"[Event {r['id']} | {r['opcode']}] Found {name} as uint16 LE at offset {i}")
            
    # 2. Search varints
    varints = parse_varints(frame)
    for off, val, l in varints:
        if val in (target_x, target_y):
            name = "X (1151)" if val == target_x else "Y (835)"
            print(f"[Event {r['id']} | {r['opcode']}] Found {name} as VARINT at offset {off}")
