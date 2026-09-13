import sqlite3, os, binascii, struct

db_path = os.path.expandvars(r'%LOCALAPPDATA%\WOS_Unified_Manager\data\wos_unified.sqlite3')
conn = sqlite3.connect(db_path)
conn.row_factory = sqlite3.Row

row = conn.execute("SELECT payload_hex FROM protocol_raw_events WHERE id = 1817").fetchone()
frame = binascii.unhexlify(row['payload_hex'])

idx = frame.find(b'lord625999966')
print(f"Frame length: {len(frame)}, 'lord625999966' at offset {idx}")

# Look at 100 bytes before and 100 bytes after
start = max(0, idx - 100)
end = min(len(frame), idx + 100)
slice_bytes = frame[start:end]

print("Slice length:", len(slice_bytes))
print("Slice hex:", binascii.hexlify(slice_bytes).decode())

# Now look for numbers 1151 and 835 in this slice!
# Target coordinates: X=1151, Y=835
target_x = 1151
target_y = 835

# Let's check every possible integer representation
for offset in range(len(slice_bytes) - 1):
    # uint16 LE
    if offset <= len(slice_bytes) - 2:
        u16 = struct.unpack_from('<H', slice_bytes, offset)[0]
        if u16 in (target_x, target_y):
            name = "X (1151)" if u16 == target_x else "Y (835)"
            print(f"[FOUND {name} as uint16 LE] at slice offset {offset} (frame offset {start + offset})")

    # uint32 LE
    if offset <= len(slice_bytes) - 4:
        u32 = struct.unpack_from('<I', slice_bytes, offset)[0]
        if u32 in (target_x, target_y):
            name = "X (1151)" if u32 == target_x else "Y (835)"
            print(f"[FOUND {name} as uint32 LE] at slice offset {offset} (frame offset {start + offset})")

# Let's decode varints in this slice
def parse_varints(buf):
    i = 0
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
        if val in (target_x, target_y):
            name = "X (1151)" if val == target_x else "Y (835)"
            print(f"[FOUND {name} as VARINT] at slice offset {start_i} (frame offset {start + start_i})")

parse_varints(slice_bytes)
