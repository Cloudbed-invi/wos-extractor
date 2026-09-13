import sqlite3, os, binascii

db_path = os.path.expandvars(r'%LOCALAPPDATA%\WOS_Unified_Manager\data\wos_unified.sqlite3')
conn = sqlite3.connect(db_path)
conn.row_factory = sqlite3.Row

# Get events between 1810 and 1818
rows = conn.execute("""
    SELECT id, opcode, direction, payload_hex, seen_at, length(payload_hex)/2 as sz 
    FROM protocol_raw_events 
    WHERE id BETWEEN 1805 AND 1820
    ORDER BY id ASC
""").fetchall()

for r in rows:
    print(f"ID {r['id']} | {r['direction']} | Opcode: {r['opcode']} | Size: {r['sz']} bytes | Time: {r['seen_at']}")
    hex_str = r['payload_hex']
    print(f"   Hex: {hex_str[:120]}")
    if r['direction'] == 'C>S':
        print(f"   FULL C>S: {hex_str}")
