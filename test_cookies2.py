import browser_cookie3
try:
    cj = browser_cookie3.load(domain_name='wos-atlas.com')
    for c in cj:
        print(c.name, c.value)
except Exception as e:
    print("Failed:", e)
