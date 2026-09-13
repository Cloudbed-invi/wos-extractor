import re

with open('WOS_Unified_Manager_V4_0_49.py', encoding='utf-8') as f:
    content = f.read()

strings = re.findall(r'["\'](.*?)["\']', content)
french = [s for s in strings if re.search(r'[éèàçêûîôâ]', s)]
print(list(set(french))[:50])
