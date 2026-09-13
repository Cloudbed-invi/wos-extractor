import binascii, struct

hx = "040679020988066e44181240035402030257da1c020201d5020902ba0b150201021402041f101750090dff016c6f72643632353939393936360800001e69730fdce203767153f10434ca166900000b5d01f02c04263404da1c0000087502014401010102001c1d01d05d03100417e1cd24041f4d315109105103162af1044d315109"
b = binascii.unhexlify(hx)

print("Total bytes:", len(b))

# Let's decode as protobuf fields
i = 0
def decode_varint(buf, off):
    val = 0
    shift = 0
    idx = off
    while idx < len(buf):
        byte = buf[idx]
        val |= (byte & 0x7f) << shift
        idx += 1
        shift += 7
        if not (byte & 0x80):
            break
    return val, idx - off

# Print all integers in the slice
print("\n--- Scanning all possible integers in this block ---")
for off in range(len(b) - 3):
    u16 = struct.unpack_from('<H', b, off)[0]
    u32 = struct.unpack_from('<I', b, off)[0]
    # Check if either u16 or u32 relates to X:1151, Y:835
    print(f"offset {off:02d} (0x{off:02x}): byte=0x{b[off]:02x} | u16={u16} | u32={u32}")
