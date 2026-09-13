import sqlite3
import blackboxprotobuf
import pprint
import os
import binascii

db_path = os.path.expandvars(r'%LOCALAPPDATA%\WOS_Unified_Manager\data\wos_unified.sqlite3')
conn = sqlite3.connect(db_path)
conn.row_factory = sqlite3.Row

row = conn.execute("""
    SELECT payload_hex FROM protocol_raw_events
    WHERE opcode = '7d02' AND direction = 'S>C' AND length(payload_hex) > 1000
    ORDER BY id DESC LIMIT 1
""").fetchone()

if not row:
    print('No raw frames found')
    exit()

frame = binascii.unhexlify(row['payload_hex'])
print('Frame size:', len(frame))

try:
    msg, _ = blackboxprotobuf.decode_message(frame)
    
    # 7D02 packets usually have a structure like:
    # { 1: [ ... blocks ... ] }
    print('Top level keys:', msg.keys())
    
    for k, v in msg.items():
        if isinstance(v, list) and len(v) > 0 and isinstance(v[0], dict):
            print(f'Found list field {k} with {len(v)} items!')
            item = v[0]
            print("First item dump:")
            pprint.pprint(item, depth=4)
            
            print("\nSearching for X, Y in ALL items...")
            for idx, obj in enumerate(v):
                # Search for X/Y in this object
                for ik, iv in obj.items():
                    if isinstance(iv, int) and 1 <= iv <= 800:
                        print(f'Item {idx} has {ik} = {iv}')
                    elif isinstance(iv, dict):
                        for sub_k, sub_v in iv.items():
                            if isinstance(sub_v, int) and 1 <= sub_v <= 800:
                                print(f'Item {idx}[{ik}][{sub_k}] = {sub_v}')
            break
except Exception as e:
    print('blackboxprotobuf failed to decode entire frame:', e)
