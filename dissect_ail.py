import binascii

hx = "da1c0255020102095d02224e0201410202f1044e904f09f10341696c087865750fdc880377c77a550447c0031569441c04144819d10602"
b = binascii.unhexlify(hx)

print("Decoded bytes:")
for i, byte in enumerate(b):
    ch = chr(byte) if 32 <= byte <= 126 else '.'
    print(f"{i:02d} (0x{i:02x}): 0x{byte:02x} ({byte:3d}) '{ch}'")
