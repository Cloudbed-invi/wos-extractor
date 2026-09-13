import urllib.request, json, time

def patch_atlas_client():
    with open('WOS_Unified_Manager_V4_0_49.py', 'r', encoding='utf-8') as f:
        code = f.read()

    # 1. Add _refresh_token method to AtlasClient
    refresh_method = '''
    def _refresh_token(self):
        try:
            req = urllib.request.Request(
                'https://api.wosatlas.com/v1/auth/refresh',
                method='POST',
                headers={'Cookie': self.cookie, 'Origin': 'https://wosatlas.com', 'Content-Type': 'application/json'},
                data=b'{}'
            )
            with urllib.request.urlopen(req, timeout=self.timeout, context=SSL_CONTEXT) as r:
                cookies = r.info().get_all('Set-Cookie')
                if not cookies: return False
                new_at = new_rt = None
                for c in cookies:
                    if c.startswith('wos_at='): new_at = c.split(';')[0]
                    elif c.startswith('wos_rt='): new_rt = c.split(';')[0]
                if new_at and new_rt:
                    self.cookie = f"{new_at}; {new_rt}"
                    (BASE_DIR / 'atlas_cookies.txt').write_text(self.cookie, encoding='utf-8')
                    self.log('WOS Atlas Auth: successfully auto-refreshed expired tokens.')
                    return True
        except Exception as e:
            self.log(f'WOS Atlas Auth: failed to auto-refresh token: {e}')
        return False

'''
    # Find where to inject _refresh_token (before get)
    code = code.replace("    def get(self,url,retries=2):", refresh_method + "    def get(self,url,retries=2):")

    # 2. Patch get() to handle 401
    old_get_catch = '''            except urllib.error.HTTPError as e:
                if e.code==429:'''
    new_get_catch = '''            except urllib.error.HTTPError as e:
                if e.code == 401 and attempt == 0:
                    self.log('Atlas Auth: 401 Unauthorized. Attempting auto-refresh...')
                    if self._refresh_token():
                        continue
                if e.code==429:'''
    code = code.replace(old_get_catch, new_get_catch)

    # 3. Patch members() to handle ANONYMOUS
    old_members_tier = '''            got_count=payload.get('memberCount')
            keys=','.join(sorted(map(str,payload.keys())))
            tier=payload.get('viewerTier')
            self.log(f'Atlas /members AID {aid}: 200 response but members empty (memberCount={got_count}, expected≈{expected_count}, viewerTier={tier}, clés={keys}) ; tentative {attempt+1}/3...')'''
    new_members_tier = '''            tier=str(payload.get('viewerTier') or '').upper()
            if tier == 'ANONYMOUS' and attempt == 0:
                self.log('Atlas Auth: Session expired (ANONYMOUS). Attempting auto-refresh...')
                if self._refresh_token():
                    continue

            got_count=payload.get('memberCount')
            keys=','.join(sorted(map(str,payload.keys())))
            self.log(f'Atlas /members AID {aid}: 200 response but members empty (memberCount={got_count}, expected≈{expected_count}, viewerTier={tier}, keys={keys}) ; attempt {attempt+1}/3...')'''
    code = code.replace(old_members_tier, new_members_tier)

    with open('WOS_Unified_Manager_V4_0_49.py', 'w', encoding='utf-8') as f:
        f.write(code)
    print("Patched AtlasClient auth refresh logic.")

if __name__ == '__main__':
    patch_atlas_client()
