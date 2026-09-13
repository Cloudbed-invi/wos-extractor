import sqlite3, os, binascii, struct

db_path = os.path.expandvars(r'%LOCALAPPDATA%\WOS_Unified_Manager\data\wos_unified.sqlite3')
conn = sqlite3.connect(db_path)
conn.row_factory = sqlite3.Row

# Get Event 1239
row = conn.execute("SELECT payload_hex FROM protocol_raw_events WHERE id = 1239").fetchone()
frame = binascii.unhexlify(row['payload_hex'])

print(f"Event 1239 (7D02): Total {len(frame)} bytes")

# Find all 'da1c' and 'dc1c' blocks in this 7D02 frame
import re
tags = [m.start() for m in re.finditer(b'(\xda\x1c|\xdc\x1c)', frame)]
print(f"Found {len(tags)} player/entity tags (da1c/dc1c) at offsets: {tags}")

# For each tag, look at the block
for i, pos in enumerate(tags):
    next_pos = tags[i+1] if i+1 < len(tags) else len(frame)
    block = frame[pos:min(next_pos, pos + 120)]
    print(f"\n--- Entity {i+1} at offset {pos} (len {len(block)}) ---")
    print("Hex:", binascii.hexlify(block[:60]).decode())
    
    # Try to find string (Name)
    # Names usually appear as printable ASCII of length >= 3
    ascii_matches = re.findall(b'[A-Za-z0-9_]{3,20}', block)
    print("Extracted strings:", [s.decode() for s in ascii_matches])
