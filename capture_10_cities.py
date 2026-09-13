import time
import subprocess
import re

ADB_PATH = "adb"

def setup_adb_connection():
    configured_serial = "127.0.0.1:7555"
    for port in ['127.0.0.1:7555', '127.0.0.1:16384', '127.0.0.1:5555']:
        try:
            subprocess.run([ADB_PATH, 'connect', port], capture_output=True, timeout=3)
        except subprocess.TimeoutExpired:
            pass
    try:
        res = subprocess.run([ADB_PATH, 'devices'], capture_output=True, text=True)
        lines = [l.strip() for l in res.stdout.strip().split('\n')[1:] if '\tdevice' in l]
        if lines:
            serials = [l.split('\t')[0] for l in lines]
            if configured_serial in serials:
                serial = configured_serial
            else:
                serial = serials[0]
            print(f"[+] Connected to ADB device: {serial}")
            return serial
    except Exception as e:
        print(f"[!] ADB detection failed: {e}")
    return configured_serial

ADB_SERIAL = setup_adb_connection()

# Known from config.json dump earlier
taps = {
    "search_map_icon": [472, 1605],
    "x_input_box": [366, 941],
    "x_ok_button": [977, 1852],
    "y_input_box": [774, 933],
    "y_ok_button": [997, 1861],
    "go_button": [536, 1124]
}

TARGET_W, TARGET_H = 1080, 1920

def get_device_resolution():
    res = subprocess.run([ADB_PATH, '-s', ADB_SERIAL, 'shell', 'wm', 'size'], capture_output=True, text=True)
    match = re.search(r'(\d+)x(\d+)', res.stdout)
    if match:
        return int(match.group(1)), int(match.group(2))
    return 1080, 1920

DEVICE_W, DEVICE_H = get_device_resolution()
SCALE_X = DEVICE_W / float(TARGET_W)
SCALE_Y = DEVICE_H / float(TARGET_H)

def scale_coords(x, y):
    return int(round(x * SCALE_X)), int(round(y * SCALE_Y))

def jump_to_coordinates(x, y, prev_x=None, prev_y=None):
    del_keys = "input keyevent 67 67 67 67 67"

    search_x, search_y = scale_coords(*taps['search_map_icon'])
    x_box_x, x_box_y = scale_coords(*taps['x_input_box'])
    x_ok_x, x_ok_y = scale_coords(*taps['x_ok_button'])
    y_box_x, y_box_y = scale_coords(*taps['y_input_box'])
    y_ok_x, y_ok_y = scale_coords(*taps['y_ok_button'])
    go_x, go_y = scale_coords(*taps['go_button'])

    parts = [f"input tap {search_x} {search_y}", "sleep 0.7"]

    if str(prev_x) != str(x):
        parts += [
            f"input tap {x_box_x} {x_box_y}", "sleep 0.2", del_keys,
            f"input text {x}", f"input tap {x_ok_x} {x_ok_y}", "sleep 0.1"
        ]

    if str(prev_y) != str(y):
        parts += [
            f"input tap {y_box_x} {y_box_y}", "sleep 0.2", del_keys,
            f"input text {y}", f"input tap {y_ok_x} {y_ok_y}", "sleep 0.1"
        ]

    parts.append(f"input tap {go_x} {go_y}")
    full_cmd = [ADB_PATH, '-s', ADB_SERIAL, 'shell', " && ".join(parts)]
    subprocess.run(full_cmd, capture_output=True)
    time.sleep(4)

cities = [
    ("นิกกี้ พิ้ม", 25, 493),
    ("minipopor", 185, 1079),
    ("น้ำตกคอหมู", 753, 1181),
    ("lord852305348", 772, 1179),
    ("Tim Bradford", 833, 1143),
    ("GaMEkag12", 1116, 1154),
    ("Ail", 1165, 1044),
    ("Fxnn37", 1160, 1019),
    ("Jeee", 1167, 949),
    ("lord625999966", 1151, 835)
]

print("[*] Starting isolated city capture...")
prev_x, prev_y = None, None

for name, x, y in cities:
    print(f"Jumping to {name} at X:{x} Y:{y}...")
    jump_to_coordinates(x, y, prev_x, prev_y)
    print("Waiting 5 seconds for map packets to stream...")
    time.sleep(5)
    prev_x, prev_y = x, y

print("[+] Done! The sniffer should now have the exact 7D02 map packets for these locations.")
