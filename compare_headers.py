import binascii, struct

samples = [
    {
        "name": "lord625999966",
        "x": 1151, "y": 835,
        "hex": "da1c020201d5020902ba0b150201021402041f101750090dff016c6f7264363235393939393636"
    },
    {
        "name": "น้ำตกคอหมู",
        "x": 753, "y": 1181,
        "hex": "da1c020201d5020902ba0b150201021402041f5d0754091eff03e0b899e0b989e0b8b3e0b895e0b881e0b884e0b8ade0b8abe0b8a1e0b8b9"
    },
    {
        "name": "Fxnn37",
        "x": 1160, "y": 1019,
        "hex": "da1c020201d5020902224e150201021402041fa2365309067f46786e6e3337"
    },
    {
        "name": "Jeee",
        "x": 1167, "y": 949,
        "hex": "da1c020201d5020902a20f150201021402041fcec55009041f4a656565"
    }
]

print("Comparing the bytes before name for each player:\n")
for s in samples:
    b = binascii.unhexlify(s['hex'])
    print(f"=== {s['name']} (X={s['x']}, Y={s['y']}) ===")
    print("Hex:", s['hex'])
    print("Length:", len(b))
    # Print bytes index by index
    print("Bytes: " + " ".join(f"{x:02x}" for x in b[:25]))

print("\nNotice:")
print("Common prefix:")
print("da 1c 02 02 01 d5 02 09 02 [VARIABLE 2 BYTES] 15 02 01 02 14 02 04 1f [ATLAS ID 4 BYTES] [NAME LEN] [NAME]")
