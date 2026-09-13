#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import sys,json,re,unicodedata,traceback

# Windows lance parfois ce helper avec stdout en CP1252. RapidOCR peut
# reconnaître des pseudos chinois/cyrilliques : on force donc UTF-8 avant
# d'émettre le JSON, sinon un simple caractère non occidental faisait échouer
# toute l'analyse avec UnicodeEncodeError.
try:
    sys.stdout.reconfigure(encoding='utf-8', errors='replace')
    sys.stderr.reconfigure(encoding='utf-8', errors='replace')
except Exception:
    pass
from difflib import SequenceMatcher

def norm(s):
    s=unicodedata.normalize('NFKC',str(s or '')).replace('\xa0',' ')
    return ''.join(ch for ch in s.casefold() if ch.isalnum())

def safe_int(v,default=-1):
    try:return int(v)
    except:return default

def main():
    try:
        image=sys.argv[1]; expected=sys.argv[2] if len(sys.argv)>2 else ''
        ex=safe_int(sys.argv[3] if len(sys.argv)>3 else -1); ey=safe_int(sys.argv[4] if len(sys.argv)>4 else -1)
        wos=safe_int(sys.argv[5] if len(sys.argv)>5 else 0,0); atlas=safe_int(sys.argv[6] if len(sys.argv)>6 else 0,0)
        from rapidocr_onnxruntime import RapidOCR
        result,_=RapidOCR()(image)
        rows=[]
        for item in (result or []):
            try:
                box,text,score=item[0],str(item[1]).strip(),float(item[2])
                if not text: continue
                xs=[float(p[0]) for p in box]; ys=[float(p[1]) for p in box]
                rows.append({'text':text,'score':score,'x':sum(xs)/len(xs),'y':sum(ys)/len(ys),
                             'xmin':min(xs),'xmax':max(xs),'ymin':min(ys),'ymax':max(ys)})
            except Exception: pass
        rows.sort(key=lambda r:(r['y'],r['x']))
        alltext=' | '.join(r['text'] for r in rows)
        ne=norm(expected); best_text=''; best_score=0.0; best_conf=0.0

        # Le pseudo se trouve normalement dans la moitié haute de la pancarte.
        # On évite les libellés/boutons connus qui peuvent sinon devenir le
        # "meilleur" mauvais candidat.
        bad_tokens=('puissance','power','alliance','visiter','espionner','ralliement','attaquer','coord','deepl','tradu','window')
        maxy=max((r['ymax'] for r in rows),default=1.0)
        cand=[]
        for i,r in enumerate(rows):
            nr=norm(r['text'])
            if any(norm(k) in nr for k in bad_tokens): continue
            # privilégier la moitié supérieure mais ne pas l'imposer totalement
            pos_bonus=1.0 if r['y'] <= maxy*0.62 else 0.88
            cand.append((r['text'],r['score'],pos_bonus))
            for j in range(i+1,min(i+4,len(rows))):
                q=rows[j]
                if abs(q['y']-r['y'])<=35:
                    txt=r['text']+' '+q['text']; nt=norm(txt)
                    if not any(norm(k) in nt for k in bad_tokens):
                        cand.append((txt,min(r['score'],q['score']),pos_bonus))
        for text,conf,pos_bonus in cand:
            nt=norm(text)
            if not ne or not nt: continue
            ratio=SequenceMatcher(None,ne,nt).ratio()
            if ne in nt or nt in ne:
                ratio=max(ratio,min(len(ne),len(nt))/max(len(ne),len(nt)))
            score=ratio*(0.72+0.28*max(0.0,min(1.0,conf)))*pos_bonus
            if score>best_score:
                best_score,best_text,best_conf=score,text,conf
        pseudo_ok=bool(ne and best_score>=0.72)

        def first_num(pattern,text):
            m=re.search(pattern,text,re.I)
            return int(m.group(1)) if m else None
        # OCR peut séparer X et Y dans des lignes différentes. On recherche
        # donc chaque coordonnée indépendamment dans le texte global.
        clean=alltext.replace('：',':').replace('；',':').replace('＝','=')
        ox=first_num(r'(?<![A-Za-z])[Xx]\s*[:=]?\s*(\d{1,4})\b',clean)
        oy=first_num(r'(?<![A-Za-z])[Yy]\s*[:=]?\s*(\d{1,4})\b',clean)
        location_seen=(ox is not None and oy is not None)
        location_ok=bool(location_seen and ex>=0 and ey>=0 and abs(ox-ex)<=1 and abs(oy-ey)<=1)

        labels=[r for r in rows if any(k in norm(r['text']) for k in
                ('puissance','power','macht','potenza','мощность','poder','guc','forca','sila'))]
        pcs=[]
        for r in rows:
            digits=re.sub(r'\D','',r['text'])
            if 7<=len(digits)<=9:
                n=int(digits)
                if 10_000_000<=n<=550_000_000 and n not in (wos,atlas):
                    prox=min((abs(r['y']-l['y'])+(0 if r['x']>=l['x'] else 180) for l in labels),default=999999.0)
                    pcs.append((prox,-r['score'],n,r['text']))
        # déduplication par valeur
        ded={}
        for c in pcs:
            if c[2] not in ded or c[:2]<ded[c[2]][:2]: ded[c[2]]=c
        pcs=sorted(ded.values())
        power=None
        if pcs:
            if labels and pcs[0][0]<=180:
                power=pcs[0][2]
            elif len(pcs)==1:
                # Sur le crop serré, une seule valeur 10M..550M est très
                # probablement la puissance, même si le mot "Puissance" a été
                # raté par l'OCR.
                power=pcs[0][2]

        out={'pseudo':best_text or None,'pseudo_score':round(best_score,4),'pseudo_ocr_conf':round(best_conf,4),
             'pseudo_ok':pseudo_ok,'x':ox,'y':oy,'location_seen':location_seen,'location_ok':location_ok,
             'power':power,'text':alltext,'power_candidates':[c[2] for c in pcs[:12]],
             'expected':{'pseudo':expected,'x':ex,'y':ey}}
        print(json.dumps(out,ensure_ascii=False))
    except Exception as e:
        # Ne jamais faire tomber le Manager : le helper retourne toujours un
        # JSON exploitable, avec une erreur détaillée pour le log.
        print(json.dumps({'_error':f'{type(e).__name__}: {e}','trace':traceback.format_exc()[-2000:]},ensure_ascii=False))

if __name__=='__main__': main()
