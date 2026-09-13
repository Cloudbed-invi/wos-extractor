import re

code = open('wos_collector_engine.py', 'r', encoding='utf-8').read()
match = re.search(r'def _decode_map_frame\(self, frame: bytes\):.*?(?=\n    def |\Z)', code, re.DOTALL)
if match:
    print(match.group(0)[:3000])
