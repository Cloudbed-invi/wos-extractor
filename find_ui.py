import re

with open('WOS_Unified_Manager_V4_0_49.py', encoding='utf-8') as f:
    content = f.read()

strings = re.findall(r'(?:text|label)=["\'](.*?)["\']', content)
print(list(set(strings)))
