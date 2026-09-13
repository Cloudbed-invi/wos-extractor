import sqlite3, os, binascii, struct

db_path = os.path.expandvars(r'%LOCALAPPDATA%\WOS_Unified_Manager\data\wos_unified.sqlite3')
conn = sqlite3.connect(db_path)
conn.row_factory = sqlite3.Row

row = conn.execute("SELECT payload_hex FROM protocol_raw_events WHERE id = 1239").fetchone()
frame = binascii.unhexlify(row['payload_hex'])

idx = frame.find(b'Ail')
print(f"Event 1239 (7D02) length {len(frame)}, 'Ail' at offset {idx}")

# Look at 120 bytes before and 120 bytes after
start = max(0, idx - 120)
end = min(len(frame), idx + 120)
sub = frame[start:end]
print("Context around Ail:")
print(binascii.hexlify(sub).decode())

# Ail coords: X=1165, Y=1044
target_x = 1165
target_y = 1044

# Search in the entire frame for 1165 and 1044
for i in range(len(frame) - 1):
    u16 = struct.unpack_from('<H', frame, i)[0]
    if u16 in (target_x, target_y):
        name = "X (1165)" if u16 == target_x else "Y (1044)"
        print(f"[FOUND {name} as uint16 LE] at offset {i} (distance from Ail: {i - idx})")
