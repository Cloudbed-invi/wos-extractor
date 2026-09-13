import browser_cookie3
try:
    cj = browser_cookie3.chrome(domain_name='wos-atlas.com')
    for c in cj:
        print(c.name, c.value)
except Exception as e:
    print("Chrome failed:", e)

try:
    cj = browser_cookie3.edge(domain_name='wos-atlas.com')
    for c in cj:
        print(c.name, c.value)
except Exception as e:
    print("Edge failed:", e)
