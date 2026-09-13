#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from __future__ import annotations
import csv, json, queue, ssl, threading, time, urllib.error, urllib.request, re, shutil, zipfile, platform, sys, subprocess
from datetime import datetime, timezone
from pathlib import Path
import tkinter as tk
from tkinter import ttk, filedialog, messagebox
import wos_collector_engine as core

try:
    import pyautogui
except Exception:
    pyautogui=None

APP_VERSION='4.0.49-cleanvision'
BASE_DIR=Path(__file__).resolve().parent
# V4.0.10: persistent data is no longer stored inside the version folder.
# This prevents WOS identities/history disappearing when a new ZIP is extracted.
import os
PERSIST_ROOT=Path(os.environ.get('LOCALAPPDATA') or Path.home())/'WOS_Unified_Manager'
DATA_DIR=PERSIST_ROOT/'data'; DATA_DIR.mkdir(parents=True,exist_ok=True)
DB_PATH=DATA_DIR/'wos_unified.sqlite3'

def _db_score(path):
    try:
        import sqlite3
        c=sqlite3.connect(str(path));
        try:
            players=c.execute('SELECT COUNT(*) FROM players').fetchone()[0]
            wos=c.execute('SELECT COUNT(*) FROM players WHERE wos_id IS NOT NULL').fetchone()[0]
            pw=c.execute('SELECT COUNT(*) FROM players WHERE power IS NOT NULL').fetchone()[0]
            return int(wos)*1000000+int(pw)*10000+int(players)
        finally: c.close()
    except Exception: return -1

def _migrate_legacy_db_once():
    if DB_PATH.exists(): return
    candidates=[]
    local=BASE_DIR/'WOS_Unified_Data'/'wos_unified.sqlite3'
    if local.exists(): candidates.append(local)
    try:
        for d in BASE_DIR.parent.glob('WOS_Unified_Manager_V4_0_*'):
            q=d/'WOS_Unified_Data'/'wos_unified.sqlite3'
            if q.exists(): candidates.append(q)
    except Exception: pass
    if candidates:
        best=max(candidates,key=_db_score)
        if _db_score(best)>=0:
            import shutil
            shutil.copy2(best,DB_PATH)
_migrate_legacy_db_once()
SESSIONS_DIR=DATA_DIR/'sessions'; SESSIONS_DIR.mkdir(exist_ok=True)
EXPORT_DIR=DATA_DIR/'exports'; EXPORT_DIR.mkdir(exist_ok=True)
DIAG_DIR=DATA_DIR/'diagnostics'; DIAG_DIR.mkdir(exist_ok=True)
NAV_CONFIG_PATH=DATA_DIR/'pc_navigation.json'
LEADERBOARD_URL='https://api.wosatlas.com/v1/alliances/leaderboard?limit={limit}&kid={kid}'
MEMBERS_URL='https://api.wosatlas.com/v1/alliances/{aid}/members'
POWER_URL='https://api.wosatlas.com/v1/players/{uid}/power'
HISTORY_URL='https://api.wosatlas.com/v1/players/{uid}/history?limit=200'
SSL_CONTEXT=ssl._create_unverified_context()

def now(): return datetime.now(timezone.utc).astimezone().isoformat(timespec='seconds')

def sql_scalar(value):
    # Atlas history can return structured objects in old/new fields.
    # SQLite only accepts scalar bind values, so preserve structures as JSON text.
    if value is None or isinstance(value, (str, int, float, bytes)):
        return value
    if isinstance(value, bool):
        return int(value)
    if isinstance(value, (dict, list, tuple)):
        return json.dumps(value, ensure_ascii=False, separators=(",", ":"), sort_keys=True)
    return str(value)

class UnifiedDB(core.StateDB):
    def __init__(self,path):
        super().__init__(path); self._init_atlas_schema()
    def upsert_player(self,row,session_id,source_kind):
        # V4.0.17: the base engine writes atlas_id/wos_id/power/etc but has no
        # notion of "kid" (Atlas-layer column, added below via ALTER TABLE).
        # A player discovered ONLY through live capture -- never touched by
        # an Atlas API import -- was therefore left with kid=NULL: correctly
        # identified in the DB, but invisible to every kid-scoped view
        # (report counts, on-screen table, CSV export). Backfill it from the
        # État active when this capture session was started. COALESCE means
        # an already-known kid (from a real Atlas import) is never touched.
        changed=super().upsert_player(row,session_id,source_kind)
        kid=getattr(self,'active_kid',None)
        if kid is not None:
            atlas=self._to_int(row.get('atlas_id'))
            if atlas is not None:
                with self.lock,self.conn:
                    self.conn.execute('UPDATE players SET kid=COALESCE(kid,?) WHERE atlas_id=?',(int(kid),atlas))
        return changed
    def _cols(self,table): return {r[1] for r in self.conn.execute(f'PRAGMA table_info({table})')}
    def _add_col(self,table,col,decl):
        if col not in self._cols(table): self.conn.execute(f'ALTER TABLE {table} ADD COLUMN {col} {decl}')
    def _init_atlas_schema(self):
        with self.lock,self.conn:
            for c,d in [('kid','INTEGER'),('atlas_aid','INTEGER'),('atlas_x','INTEGER'),('atlas_y','INTEGER'),('atlas_level','INTEGER'),('atlas_office','INTEGER'),('atlas_power','INTEGER'),('atlas_power_recorded_at','TEXT'),('atlas_last_sync','TEXT'),('atlas_observed_since','TEXT'),('atlas_last_checked','TEXT')]: self._add_col('players',c,d)
            # V4.0.21: upsert_player has withheld Power-without-WOS-ID writes
            # since V4.0.17, but that gate only guards NEW writes going
            # forward -- rows already written by older sessions (V4.0.15/16,
            # before the gate existed) keep sitting in the DB forever
            # otherwise, since nothing ever revisits a settled row. Run the
            # same rule once at every startup so old orphans (e.g. Przemo851:
            # Power WOS set, WOS ID blank) get cleaned up automatically. Pure
            # cleanup of a state the gate itself defines as invalid, so it's
            # safe to run every time the app opens, and does nothing once
            # the database is already clean.
            self.conn.execute('UPDATE players SET power=NULL WHERE power IS NOT NULL AND wos_id IS NULL')
            self.conn.executescript("""
            CREATE TABLE IF NOT EXISTS atlas_alliances(aid INTEGER PRIMARY KEY,kid INTEGER NOT NULL,abbr TEXT,member_count INTEGER,total_power INTEGER,max_power INTEGER,median_power INTEGER,first_seen TEXT NOT NULL,last_seen TEXT NOT NULL,recorded_at TEXT);
            CREATE INDEX IF NOT EXISTS idx_atlas_alliances_kid ON atlas_alliances(kid);
            CREATE TABLE IF NOT EXISTS atlas_changes(uid INTEGER NOT NULL,change_type TEXT NOT NULL,changed_at TEXT NOT NULL,pass_id INTEGER,kid INTEGER,old_value TEXT,new_value TEXT,PRIMARY KEY(uid,change_type,changed_at,old_value,new_value));
            CREATE TABLE IF NOT EXISTS atlas_power_history(uid INTEGER NOT NULL,recorded_at TEXT NOT NULL,power INTEGER NOT NULL,prev_power INTEGER,pct REAL,stove_lv INTEGER,kid INTEGER,PRIMARY KEY(uid,recorded_at));
            CREATE TABLE IF NOT EXISTS atlas_location_history(uid INTEGER NOT NULL,seen_at TEXT NOT NULL,kid INTEGER,x INTEGER,y INTEGER,aid INTEGER,abbr TEXT,PRIMARY KEY(uid,seen_at));
            CREATE TABLE IF NOT EXISTS atlas_sync_runs(id INTEGER PRIMARY KEY AUTOINCREMENT,kid INTEGER NOT NULL,started_at TEXT NOT NULL,finished_at TEXT,alliances INTEGER DEFAULT 0,players INTEGER DEFAULT 0,histories INTEGER DEFAULT 0,powers INTEGER DEFAULT 0,status TEXT);
            CREATE TABLE IF NOT EXISTS map_observations(
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                session_id TEXT NOT NULL,
                seen_at TEXT NOT NULL,
                atlas_id INTEGER NOT NULL,
                pseudo_display TEXT,
                alliance_tag TEXT,
                atlas_x INTEGER,
                atlas_y INTEGER,
                anchor_kind TEXT,
                decoded_atlas_id INTEGER,
                decoded_wos_id INTEGER,
                decoded_power INTEGER,
                wos_confidence TEXT,
                pair_valid INTEGER DEFAULT 0,
                frame_len INTEGER,
                byte_offset INTEGER,
                block_hex TEXT
            );
            CREATE INDEX IF NOT EXISTS idx_map_obs_session ON map_observations(session_id,atlas_id);
            CREATE INDEX IF NOT EXISTS idx_map_obs_atlas ON map_observations(atlas_id,seen_at);
            CREATE TABLE IF NOT EXISTS verification_runs(
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                session_id TEXT UNIQUE NOT NULL,
                kid INTEGER NOT NULL,
                alliance_tag TEXT NOT NULL,
                started_at TEXT NOT NULL,
                finished_at TEXT,
                total_members INTEGER DEFAULT 0,
                visited INTEGER DEFAULT 0,
                seen INTEGER DEFAULT 0,
                ok INTEGER DEFAULT 0,
                missing INTEGER DEFAULT 0,
                conflicts INTEGER DEFAULT 0,
                status TEXT
            );
            CREATE TABLE IF NOT EXISTS visit_protocol_windows(
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                session_id TEXT NOT NULL,
                atlas_id INTEGER NOT NULL,
                pseudo_display TEXT,
                alliance_tag TEXT,
                x INTEGER,y INTEGER,
                started_at TEXT NOT NULL,
                finished_at TEXT,
                raw_id_start INTEGER DEFAULT 0,
                raw_id_end INTEGER DEFAULT 0,
                frame_count INTEGER DEFAULT 0,
                opcode_summary TEXT,
                trace_file TEXT
            );
            CREATE INDEX IF NOT EXISTS idx_visit_windows_session ON visit_protocol_windows(session_id,atlas_id);
            CREATE TABLE IF NOT EXISTS vision_observations(
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                session_id TEXT, seen_at TEXT NOT NULL, atlas_id INTEGER NOT NULL,
                expected_pseudo TEXT, observed_pseudo TEXT, pseudo_score REAL, pseudo_ok INTEGER DEFAULT 0,
                expected_x INTEGER, expected_y INTEGER, observed_x INTEGER, observed_y INTEGER, location_ok INTEGER DEFAULT 0,
                observed_power INTEGER, power_ok INTEGER DEFAULT 0, alliance_tag TEXT, screenshot_file TEXT,
                raw_text TEXT, status TEXT
            );
            CREATE INDEX IF NOT EXISTS idx_vision_obs_session ON vision_observations(session_id,atlas_id);
            CREATE TABLE IF NOT EXISTS verification_results(
                run_id INTEGER NOT NULL,
                atlas_id INTEGER NOT NULL,
                pseudo_display TEXT,
                x INTEGER,y INTEGER,
                before_wos_id INTEGER,before_power INTEGER,
                after_wos_id INTEGER,after_power INTEGER,
                live_seen INTEGER DEFAULT 0,
                conflict_seen INTEGER DEFAULT 0,
                result TEXT,
                detail TEXT,
                PRIMARY KEY(run_id,atlas_id)
            );
            """)
    def raw_protocol_max_id(self,session_id):
        with self.lock:
            r=self.conn.execute("SELECT COALESCE(MAX(id),0) FROM protocol_raw_events WHERE session_id=?",(session_id,)).fetchone()
            return int(r[0] or 0)
    def visit_trace_finish(self,session_id,row,started_at,raw_start,trace_dir):
        raw_end=self.raw_protocol_max_id(session_id)
        with self.lock:
            frames=[dict(r) for r in self.conn.execute("SELECT id,seen_at,direction,opcode,frame_len,payload_hex FROM protocol_raw_events WHERE session_id=? AND id>? AND id<=? ORDER BY id",(session_id,int(raw_start),int(raw_end))).fetchall()]
        from collections import Counter
        c=Counter((f.get('direction') or '?', (f.get('opcode') or '????').lower()) for f in frames)
        summary=', '.join(f'{d} {op}:{n}' for (d,op),n in sorted(c.items()))
        aid=int(row['atlas_id']); safe=re.sub(r'[^A-Za-z0-9_.-]+','_',str(row.get('pseudo_display') or aid))[:60]
        trace_dir=Path(trace_dir); trace_dir.mkdir(parents=True,exist_ok=True)
        out=trace_dir/f'VISIT_{aid}_{safe}.txt'
        lines=[f'WOS V{APP_VERSION} - fenetre protocole visite',f'Session: {session_id}',f'Atlas ID: {aid}',f'Pseudo: {row.get("pseudo_display") or ""}',f'Alliance: {row.get("alliance_tag") or ""}',f'Coordonnees: X{row.get("atlas_x")} Y{row.get("atlas_y")}',f'Debut: {started_at}',f'Fin: {now()}',f'Raw IDs: >{raw_start} .. {raw_end}',f'Frames: {len(frames)}',f'Opcode summary: {summary}','', '=== TRAMES COMPLETES PENDANT LES 5s ===']
        for f in frames:
            lines += [f'--- raw#{f["id"]} {f["seen_at"]} {f["direction"]} {f["opcode"]} len={f["frame_len"]} ---',f['payload_hex'],'']
        out.write_text('\n'.join(lines),encoding='utf-8')
        with self.lock,self.conn:
            self.conn.execute("INSERT INTO visit_protocol_windows(session_id,atlas_id,pseudo_display,alliance_tag,x,y,started_at,finished_at,raw_id_start,raw_id_end,frame_count,opcode_summary,trace_file) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)",(session_id,aid,row.get('pseudo_display'),row.get('alliance_tag'),row.get('atlas_x'),row.get('atlas_y'),started_at,now(),int(raw_start),int(raw_end),len(frames),summary,str(out)))
        return out,len(frames),summary

    def atlas_upsert_alliance(self,kid,a):
        stamp=now(); aid=int(a['aid'])
        with self.lock,self.conn:
            self.conn.execute("""INSERT INTO atlas_alliances(aid,kid,abbr,member_count,total_power,max_power,median_power,first_seen,last_seen,recorded_at) VALUES(?,?,?,?,?,?,?,?,?,?) ON CONFLICT(aid) DO UPDATE SET kid=excluded.kid,abbr=excluded.abbr,member_count=excluded.member_count,total_power=excluded.total_power,max_power=excluded.max_power,median_power=excluded.median_power,last_seen=excluded.last_seen,recorded_at=excluded.recorded_at""",(aid,kid,a.get('abbr'),a.get('members'),a.get('totalPower'),a.get('maxPower'),a.get('medianPower'),stamp,stamp,a.get('recordedAt')))
    def atlas_upsert_member(self,kid,aid,abbr,m):
        uid=int(m['uid']); stamp=now(); pseudo=m.get('nick_name') or f'Atlas {uid}'; mkid=int(m.get('kid') or kid)
        with self.lock,self.conn:
            old=self.conn.execute('SELECT atlas_id FROM players WHERE atlas_id=?',(uid,)).fetchone()
            if old is None:
                self.conn.execute("""INSERT INTO players(atlas_id,pseudo_display,alliance_tag,first_seen,last_seen,source_kind,kid,atlas_aid,atlas_x,atlas_y,atlas_level,atlas_office,atlas_last_sync) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)""",(uid,pseudo,m.get('abbr') or abbr,stamp,stamp,'wos-atlas',mkid,aid,m.get('x'),m.get('y'),m.get('lv'),m.get('office'),stamp))
            else:
                self.conn.execute("""UPDATE players SET pseudo_display=?,alliance_tag=?,last_seen=?,kid=?,atlas_aid=?,atlas_x=?,atlas_y=?,atlas_level=?,atlas_office=?,atlas_last_sync=? WHERE atlas_id=?""",(pseudo,m.get('abbr') or abbr,stamp,mkid,aid,m.get('x'),m.get('y'),m.get('lv'),m.get('office'),stamp,uid))
            self.conn.execute('INSERT OR IGNORE INTO atlas_location_history(uid,seen_at,kid,x,y,aid,abbr) VALUES(?,?,?,?,?,?,?)',(uid,stamp,mkid,m.get('x'),m.get('y'),aid,m.get('abbr') or abbr))
        return uid
    def atlas_store_history(self,uid,payload):
        if not isinstance(payload,dict): return 0
        n=0
        with self.lock,self.conn:
            for c in payload.get('changes') or []:
                cur=self.conn.execute('INSERT OR IGNORE INTO atlas_changes(uid,change_type,changed_at,pass_id,kid,old_value,new_value) VALUES(?,?,?,?,?,?,?)',(uid,sql_scalar(c.get('changeType') or '?'),sql_scalar(c.get('changedAt') or now()),sql_scalar(c.get('passId')),sql_scalar(c.get('kid')),sql_scalar(c.get('old')),sql_scalar(c.get('new')))); n+=max(0,cur.rowcount)
            self.conn.execute('UPDATE players SET atlas_observed_since=COALESCE(?,atlas_observed_since),atlas_last_checked=COALESCE(?,atlas_last_checked) WHERE atlas_id=?',(payload.get('observedSince'),payload.get('lastCheckedAt'),uid))
        return n
    def atlas_store_power(self,uid,payload):
        if not isinstance(payload,dict) or not isinstance(payload.get('series'),list): return 0
        pts=[]; n=0
        with self.lock,self.conn:
            for p in payload['series']:
                if p.get('recordedAt') is None or p.get('power') is None: continue
                pts.append(p); cur=self.conn.execute('INSERT OR IGNORE INTO atlas_power_history(uid,recorded_at,power,prev_power,pct,stove_lv,kid) VALUES(?,?,?,?,?,?,?)',(uid,p['recordedAt'],p['power'],p.get('prevPower'),p.get('pct'),p.get('stoveLv'),p.get('kid'))); n+=max(0,cur.rowcount)
            if pts:
                latest=max(pts,key=lambda p:p['recordedAt']); self.conn.execute('UPDATE players SET atlas_power=?,atlas_power_recorded_at=? WHERE atlas_id=?',(latest.get('power'),latest.get('recordedAt'),uid))
        return n
    def atlas_stats(self,kid):
        with self.lock:
            r=self.conn.execute("SELECT COUNT(*) total,SUM(CASE WHEN wos_id IS NOT NULL THEN 1 ELSE 0 END) wos,SUM(CASE WHEN power IS NOT NULL THEN 1 ELSE 0 END) wos_power,SUM(CASE WHEN atlas_power IS NOT NULL THEN 1 ELSE 0 END) atlas_power FROM players WHERE kid=?",(kid,)).fetchone(); a=self.conn.execute('SELECT COUNT(*) FROM atlas_alliances WHERE kid=?',(kid,)).fetchone()[0]
        return {'players':r['total'] or 0,'wos':r['wos'] or 0,'wos_power':r['wos_power'] or 0,'atlas_power':r['atlas_power'] or 0,'alliances':a}
    def atlas_rows(self,kid,query=''):
        with self.lock:
            sql="SELECT atlas_id,pseudo_display,alliance_tag,atlas_x,atlas_y,atlas_level,atlas_power,wos_id,power,atlas_last_sync FROM players WHERE kid=?"; args=[kid]
            if query:
                sql += " AND (LOWER(COALESCE(pseudo_display,'')) LIKE ? OR LOWER(COALESCE(alliance_tag,'')) LIKE ? OR CAST(atlas_id AS TEXT) LIKE ? OR CAST(COALESCE(wos_id,'') AS TEXT) LIKE ?)"; q='%'+query.lower()+'%'; args += [q,q,q,q]
            sql += ' ORDER BY COALESCE(atlas_power,power,0) DESC,pseudo_display LIMIT 10000'; return list(self.conn.execute(sql,args))
    def queue_state(self,kid):
        stamp=now(); n=0
        with self.lock,self.conn:
            rows=self.conn.execute('SELECT atlas_id,wos_id,pseudo_display,alliance_tag FROM players WHERE kid=? AND (wos_id IS NULL OR power IS NULL)',(kid,)).fetchall()
            for r in rows:
                self.conn.execute("""INSERT INTO refresh_queue(atlas_id,wos_id,pseudo_display,alliance_tag,reason,status,first_queued,last_queued,last_session) VALUES(?,?,?,?,?,'pending',?,?,?) ON CONFLICT(atlas_id) DO UPDATE SET status='pending',reason=excluded.reason,last_queued=excluded.last_queued""",(r['atlas_id'],r['wos_id'],r['pseudo_display'],r['alliance_tag'],'atlas-live-consolidation',stamp,stamp,'atlas-live')); n+=1
        return n
    def pending_count(self,kid):
        with self.lock:return self.conn.execute("SELECT COUNT(*) FROM refresh_queue rq JOIN players p ON p.atlas_id=rq.atlas_id WHERE rq.status='pending' AND p.kid=?",(kid,)).fetchone()[0]
    def navigation_targets(self,kid,alliance_tag=None,only_missing=True):
        with self.lock:
            sql="SELECT atlas_id,pseudo_display,alliance_tag,atlas_x,atlas_y,wos_id,power FROM players WHERE kid=? AND atlas_x IS NOT NULL AND atlas_y IS NOT NULL"
            args=[int(kid)]
            if alliance_tag:
                sql += " AND alliance_tag=?"; args.append(alliance_tag)
            if only_missing:
                sql += " AND (wos_id IS NULL OR power IS NULL)"
            sql += " ORDER BY COALESCE(atlas_power,power,0) DESC,pseudo_display"
            return [dict(r) for r in self.conn.execute(sql,args)]
    def alliance_tags(self,kid):
        with self.lock:
            return [r[0] for r in self.conn.execute("SELECT DISTINCT alliance_tag FROM players WHERE kid=? AND alliance_tag IS NOT NULL AND alliance_tag<>'' ORDER BY alliance_tag",(int(kid),))]
    def player_state(self,atlas_id):
        with self.lock:
            r=self.conn.execute("SELECT atlas_id,pseudo_display,alliance_tag,atlas_x,atlas_y,wos_id,power FROM players WHERE atlas_id=?",(int(atlas_id),)).fetchone()
            return dict(r) if r else None
    def store_vision_observation(self,row,session_id,data,screenshot_file='',promote=True):
        """Persist the local vision-agent verdict; WOS ID still comes only from network capture."""
        aid=self._to_int(row.get('atlas_id')); stamp=now()
        if aid is None: return {'stored':False,'power_promoted':False}
        pseudo=str(data.get('pseudo') or '')[:300]
        pscore=float(data.get('pseudo_score') or 0.0)
        pok=1 if data.get('pseudo_ok') else 0
        ox=self._to_int(data.get('x')); oy=self._to_int(data.get('y'))
        lok=1 if data.get('location_ok') else 0
        pwr=self._to_int(data.get('power'))
        power_ok=1 if pwr is not None and 10_000_000 <= pwr <= 550_000_000 else 0
        # Une lecture OCR incomplète n'est PAS un conflit. On ne déclare
        # VISION_CONFLICT que lorsque les coordonnées ont réellement été lues
        # et contredisent la cible Atlas. Cela évite les faux conflits dus à
        # des textes parasites (barre DeepL, UI Windows, boutons du jeu, etc.).
        location_seen = (ox is not None and oy is not None)
        if pok and lok and power_ok:
            status='VISION_VERIFIED'
        elif pok and lok:
            status='VISION_ID_OK'
        elif location_seen and not lok:
            status='VISION_CONFLICT'
        else:
            status='VISION_PARTIAL'
        raw=str(data.get('text') or '')[:12000]
        promoted=False
        with self.lock,self.conn:
            self.conn.execute("INSERT INTO vision_observations(session_id,seen_at,atlas_id,expected_pseudo,observed_pseudo,pseudo_score,pseudo_ok,expected_x,expected_y,observed_x,observed_y,location_ok,observed_power,power_ok,alliance_tag,screenshot_file,raw_text,status) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (session_id,stamp,aid,row.get('pseudo_display'),pseudo,pscore,pok,row.get('atlas_x'),row.get('atlas_y'),ox,oy,lok,pwr,power_ok,row.get('alliance_tag'),str(screenshot_file or ''),raw,status))
            cur=self.conn.execute('SELECT wos_id,power FROM players WHERE atlas_id=?',(aid,)).fetchone()
            if promote and cur and cur[0] is not None and pok and lok and power_ok:
                self.conn.execute("INSERT INTO power_observations(session_id,seen_at,atlas_id,candidate_power,source_kind,confidence) VALUES(?,?,?,?,?,?)",(session_id,stamp,aid,pwr,'vision-agent','high'))
                self.conn.execute("UPDATE players SET power=?, power_confidence='vision-agent', last_seen=? WHERE atlas_id=?",(pwr,stamp,aid))
                promoted=True
        return {'stored':True,'power_promoted':promoted,'status':status}

    def store_ocr_power(self,atlas_id,power,session_id,ocr_text='',screenshot_file=''):
        row=self.player_state(atlas_id)
        if not row:return False
        data={'power':power,'text':ocr_text,'pseudo':row.get('pseudo_display'),'pseudo_score':1.0,'pseudo_ok':True,'x':row.get('atlas_x'),'y':row.get('atlas_y'),'location_ok':True}
        return bool(self.store_vision_observation(row,session_id,data,screenshot_file).get('power_promoted'))

    def verification_create(self,session_id,kid,tag,total):
        with self.lock,self.conn:
            cur=self.conn.execute("INSERT INTO verification_runs(session_id,kid,alliance_tag,started_at,total_members,status) VALUES(?,?,?,?,?,'RUNNING')",(session_id,int(kid),tag,now(),int(total)))
            return int(cur.lastrowid)
    def verification_finish(self,run_id,visited,seen,ok,missing,conflicts,status='DONE'):
        with self.lock,self.conn:
            self.conn.execute("UPDATE verification_runs SET finished_at=?,visited=?,seen=?,ok=?,missing=?,conflicts=?,status=? WHERE id=?",(now(),visited,seen,ok,missing,conflicts,status,int(run_id)))
    def verification_store_result(self,run_id,row,before,after,session_id):
        aid=int(row['atlas_id'])
        with self.lock,self.conn:
            ev=self.conn.execute("SELECT COUNT(*) FROM identity_observations WHERE session_id=? AND atlas_id=?",(session_id,aid)).fetchone()[0]
            mev=self.conn.execute("SELECT COUNT(*) FROM map_observations WHERE session_id=? AND atlas_id=?",(session_id,aid)).fetchone()[0]
            vv=self.conn.execute("SELECT COUNT(*) FROM vision_observations WHERE session_id=? AND atlas_id=? AND status IN ('VISION_VERIFIED','VISION_ID_OK')",(session_id,aid)).fetchone()[0]
            vcf=self.conn.execute("SELECT COUNT(*) FROM vision_observations WHERE session_id=? AND atlas_id=? AND status='VISION_CONFLICT'",(session_id,aid)).fetchone()[0]
            # Une valeur Power déjà présente dans players ne prouve pas qu'elle a
            # été revérifiée pendant CETTE visite. C'est ce qui faisait afficher
            # Mori SEEN_OK avec une ancienne puissance de 37 M alors que la fiche
            # courante affichait 217 M. On exige désormais une observation de
            # puissance de la session courante pour déclarer SEEN_OK.
            pvev=self.conn.execute("SELECT COUNT(*) FROM power_observations WHERE session_id=? AND atlas_id=?",(session_id,aid)).fetchone()[0]
            cf=self.conn.execute("SELECT COUNT(*) FROM identity_observations WHERE session_id=? AND atlas_id=? AND status='CONFLICT'",(session_id,aid)).fetchone()[0]
            seen=1 if (ev or mev or vv) else 0
            bw=(before or {}).get('wos_id'); bp=(before or {}).get('power'); aw=(after or {}).get('wos_id'); ap=(after or {}).get('power')
            if cf or vcf: result='CONFLICT'; detail='Conflit réseau ou visuel : pseudo / localisation différents de la cible Atlas.'
            elif aw is None or ap is None:
                result='MISSING'
                v=self.conn.execute("SELECT observed_pseudo,pseudo_score,observed_x,observed_y,observed_power,pseudo_ok,location_ok FROM vision_observations WHERE session_id=? AND atlas_id=? ORDER BY id DESC LIMIT 1",(session_id,aid)).fetchone()
                if v and v['pseudo_ok'] and v['location_ok'] and v['observed_power']:
                    detail='Vision OK (pseudo, X/Y, puissance) ; WOS ID réseau encore manquant.' if aw is None else 'Vision OK mais puissance non promue.'
                elif v:
                    bits=[]
                    if v['observed_pseudo']: bits.append(f"pseudo lu={v['observed_pseudo']}")
                    if v['observed_x'] is not None or v['observed_y'] is not None: bits.append(f"XY lu=X{v['observed_x']} Y{v['observed_y']}")
                    if v['observed_power']: bits.append(f"power lu={v['observed_power']}")
                    detail='Vision partielle ('+', '.join(bits)+') ; WOS ID ou puissance encore manquant.' if bits else 'Vision inexploitable ; WOS ID ou puissance toujours manquant après visite.'
                else: detail='WOS ID ou puissance toujours manquant après visite.'
            elif seen and pvev:
                result='SEEN_OK'
                if bp is not None and ap is not None and int(bp) != int(ap):
                    detail=f'Joueur revu; puissance revérifiée et mise à jour {int(bp):,} -> {int(ap):,}.'
                else:
                    detail='Joueur revu; WOS ID présent et puissance revérifiée pendant cette session.'
            elif seen:
                result='NOT_SEEN'; detail='Joueur revu, mais puissance NON revérifiée pendant cette visite : ancienne valeur conservée, pas de SEEN_OK.'
            else:
                result='NOT_SEEN'; detail='Données complètes en base mais aucun record Atlas ancré revu pendant cette visite.'
            self.conn.execute("INSERT OR REPLACE INTO verification_results(run_id,atlas_id,pseudo_display,x,y,before_wos_id,before_power,after_wos_id,after_power,live_seen,conflict_seen,result,detail) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)",(run_id,aid,row.get('pseudo_display'),row.get('atlas_x'),row.get('atlas_y'),bw,bp,aw,ap,seen,1 if cf else 0,result,detail))
            return result,seen
    def verification_results_for_run(self,run_id):
        with self.lock: return [dict(r) for r in self.conn.execute("SELECT * FROM verification_results WHERE run_id=? ORDER BY CASE result WHEN 'CONFLICT' THEN 0 WHEN 'MISSING' THEN 1 WHEN 'NOT_SEEN' THEN 2 ELSE 3 END,pseudo_display",(int(run_id),))]
    def export_unified_csv(self,kid,path):
        with Path(path).open('w',newline='',encoding='utf-8-sig') as f:
            w=csv.writer(f); w.writerow(['Etat','Atlas ID','Pseudo','Alliance','X','Y','Niveau','Power Atlas','WOS ID','Power WOS','Derniere synchro Atlas'])
            for r in self.atlas_rows(kid): w.writerow([kid,r['atlas_id'],r['pseudo_display'],r['alliance_tag'],r['atlas_x'],r['atlas_y'],r['atlas_level'],r['atlas_power'],r['wos_id'],r['power'],r['atlas_last_sync']])
    def atlas_roster_consensus(self, atlas_ids):
        """Infer the alliance of a ranking roster from Atlas memberships.

        Atlas is used only to identify the alliance context. It never validates
        a WOS ID or WOS power. A strong majority is required so stale Atlas
        membership cannot silently relabel a roster.
        """
        ids=[]
        for x in atlas_ids or []:
            try: ids.append(int(x))
            except Exception: pass
        ids=list(dict.fromkeys(ids))
        if not ids: return None
        ph=','.join('?' for _ in ids)
        with self.lock:
            rows=self.conn.execute(
                f"SELECT atlas_id,alliance_tag,atlas_aid FROM players WHERE atlas_id IN ({ph}) AND alliance_tag IS NOT NULL AND alliance_tag<>''",
                ids).fetchall()
        votes={}
        aids={}
        for r in rows:
            tag=str(r['alliance_tag'] or '').strip()
            if not tag: continue
            votes[tag]=votes.get(tag,0)+1
            if r['atlas_aid'] is not None: aids.setdefault(tag,int(r['atlas_aid']))
        if not votes: return None
        ordered=sorted(votes.items(),key=lambda kv:(-kv[1],kv[0]))
        tag,hits=ordered[0]; mapped=sum(votes.values()); runner=ordered[1][1] if len(ordered)>1 else 0
        total=len(ids); ratio=hits/max(1,mapped); coverage=mapped/max(1,total)
        # V4.0.23 small-alliance fix. The old hard minimum of 3 made Atlas
        # consensus impossible for 1-2 member rosters. For those tiny rosters,
        # accept only a unanimous mapped result; normal rosters keep the same
        # conservative 3-hit / majority / coverage thresholds.
        tiny_ok = (total <= 2 and mapped == total and hits == total and runner == 0)
        normal_ok = (hits >= 3 and ratio >= 0.60 and coverage >= 0.20 and hits > runner)
        if not (tiny_ok or normal_ok):
            return {'accepted':False,'tag':tag,'hits':hits,'mapped':mapped,'total':total,'ratio':ratio,'coverage':coverage,'runner':runner}
        return {'accepted':True,'tag':tag,'aid':aids.get(tag),'hits':hits,'mapped':mapped,'total':total,'ratio':ratio,'coverage':coverage,'runner':runner}

    def atlas_anchor_for_player(self,atlas_id):
        """Return the current Atlas membership already imported for this player.

        The live decoder can use this as a membership anchor while the ranking
        screen is generating 7902/7502 traffic. This avoids requiring the user
        to open every alliance merely to re-discover a roster Atlas already
        provided through /alliances/{aid}/members.
        """
        with self.lock:
            r=self.conn.execute("SELECT alliance_tag,atlas_aid,kid,pseudo_display FROM players WHERE atlas_id=?",(int(atlas_id),)).fetchone()
        if not r: return None
        return {'alliance_tag':r['alliance_tag'],'atlas_aid':r['atlas_aid'],'kid':r['kid'],'pseudo_display':r['pseudo_display']}

    @staticmethod
    def _map_norm(value):
        import unicodedata
        s=unicodedata.normalize('NFKC',str(value or '')).replace('\xa0',' ')
        return ' '.join(s.casefold().split())

    def map_resolve_anchor(self,row):
        """Resolve a decoded world-map record against the Atlas census.

        Priority is strict decoded Atlas ID + compatible name.  If the numeric
        Atlas field is absent, allow a unique normalized nickname, or a duplicate
        nickname disambiguated by alliance tag.  Fallback anchors are diagnostic
        only; the collector will not use them to validate WOS identity.
        """
        dname=self._map_norm(row.get('pseudo_display') or row.get('pseudo_core') or '')
        dtag=str(row.get('alliance_tag') or '').strip().casefold()
        datlas=None
        try: datlas=int(row.get('atlas_id')) if row.get('atlas_id') not in (None,'') else None
        except Exception: datlas=None
        with self.lock:
            if datlas is not None:
                r=self.conn.execute("SELECT atlas_id,pseudo_display,alliance_tag,atlas_x,atlas_y,kid FROM players WHERE atlas_id=?",(datlas,)).fetchone()
                if r:
                    aname=self._map_norm(r['pseudo_display'])
                    if not dname or not aname or dname==aname:
                        return dict(r)|{'anchor_kind':'atlas-id'}
                    # Numeric mismatch with name is unsafe: do not reinterpret it.
                    return None
            if not dname or len(dname)<3:
                return None
            rows=self.conn.execute("SELECT atlas_id,pseudo_display,alliance_tag,atlas_x,atlas_y,kid FROM players WHERE pseudo_display IS NOT NULL").fetchall()
        cand=[dict(r) for r in rows if self._map_norm(r['pseudo_display'])==dname]
        if len(cand)==1:
            cand[0]['anchor_kind']='unique-name'; return cand[0]
        if len(cand)>1 and dtag:
            tagged=[r for r in cand if str(r.get('alliance_tag') or '').strip().casefold()==dtag]
            if len(tagged)==1:
                tagged[0]['anchor_kind']='name+alliance'; return tagged[0]
        return None

    def map_record_observation(self,session_id,atlas_id,anchor,row,frame_len,byte_offset,block):
        def iv(v):
            try:return int(v) if v not in (None,'') else None
            except Exception:return None
        with self.lock,self.conn:
            self.conn.execute("""INSERT INTO map_observations(
                session_id,seen_at,atlas_id,pseudo_display,alliance_tag,atlas_x,atlas_y,
                anchor_kind,decoded_atlas_id,decoded_wos_id,decoded_power,wos_confidence,
                pair_valid,frame_len,byte_offset,block_hex)
                VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                (session_id,now(),int(atlas_id),anchor.get('pseudo_display'),anchor.get('alliance_tag'),
                 anchor.get('atlas_x'),anchor.get('atlas_y'),anchor.get('anchor_kind'),
                 iv(row.get('atlas_id')),iv(row.get('wos_id') or row.get('wos_id_candidate')),
                 iv(row.get('power') or row.get('power_candidate')),row.get('wos_confidence'),
                 1 if row.get('identity_pair_valid') else 0,int(frame_len),int(byte_offset),block.hex()))

    def map_session_stats(self,session_id):
        with self.lock:
            r=self.conn.execute("""SELECT COUNT(*) n,COUNT(DISTINCT atlas_id) players,
                   SUM(CASE WHEN anchor_kind='atlas-id' THEN 1 ELSE 0 END) atlas_id_anchors,
                   SUM(CASE WHEN decoded_wos_id IS NOT NULL THEN 1 ELSE 0 END) wos_candidates,
                   SUM(CASE WHEN pair_valid=1 THEN 1 ELSE 0 END) pair_valid
                   FROM map_observations WHERE session_id=?""",(session_id,)).fetchone()
            rows=self.conn.execute("""SELECT atlas_id,pseudo_display,alliance_tag,atlas_x,atlas_y,
                   anchor_kind,decoded_atlas_id,decoded_wos_id,decoded_power,wos_confidence,pair_valid,
                   COUNT(*) sightings
                   FROM map_observations WHERE session_id=?
                   GROUP BY atlas_id,pseudo_display,alliance_tag,atlas_x,atlas_y,anchor_kind,
                            decoded_atlas_id,decoded_wos_id,decoded_power,wos_confidence,pair_valid
                   ORDER BY pair_valid DESC,sightings DESC,pseudo_display LIMIT 80""",(session_id,)).fetchall()
        return dict(r or {}) if r else {'n':0,'players':0,'atlas_id_anchors':0,'wos_candidates':0,'pair_valid':0}, [dict(x) for x in rows]

class AtlasClient:
    def __init__(self,log,cookie=''):
        self.log=log; self.timeout=20; self.delay=.50; self.kid=None; self.cookie=(cookie or '').strip()

    def _headers(self):
        # IMPORTANT: reuse the exact request profile from the user's old Atlas
        # manager, which already worked with /alliances/{aid}/members.
        # Do not impersonate a full Chrome request here: Atlas can return a 200
        # envelope with memberCount populated but members=[] for that profile.
        state=self.kid if self.kid is not None else 0
        h={
            'User-Agent':f'Mozilla/5.0 WOSMultiServerManager/2.0 State/{state}',
            'Accept':'application/json,text/plain,*/*',
            'Origin':'https://wosatlas.com',
            'Referer':'https://wosatlas.com/',
        }
        if self.cookie:
            h['Cookie']=self.cookie
        return h

    def get(self,url,retries=2):
        for attempt in range(retries+1):
            req=urllib.request.Request(url,headers=self._headers())
            try:
                with urllib.request.urlopen(req,timeout=self.timeout,context=SSL_CONTEXT) as r:
                    raw=r.read().decode(r.headers.get_content_charset() or 'utf-8',errors='replace')
                    return json.loads(raw)
            except urllib.error.HTTPError as e:
                if e.code==429:
                    wait=30 if attempt<retries else 60
                    self.log(f'WOS Atlas : rate-limit 429, pause {wait} s...'); time.sleep(wait)
                else:
                    self.log(f'WOS Atlas HTTP {e.code}: {url}')
                    break
            except Exception as e:
                self.log(f'WOS Atlas erreur ({attempt+1}/{retries+1}): {e}')
            finally:
                time.sleep(self.delay)
        return None

    def leaderboard(self,kid):
        self.kid=int(kid)
        return self.get(LEADERBOARD_URL.format(limit=100,kid=kid))

    def members(self,aid,expected_count=0):
        url=MEMBERS_URL.format(aid=aid)
        last=None
        for attempt in range(3):
            payload=self.get(url,retries=1); last=payload
            if not isinstance(payload,dict):
                continue
            members=payload.get('members')
            if isinstance(members,list) and (members or int(expected_count or 0)==0):
                return payload
            got_count=payload.get('memberCount')
            keys=','.join(sorted(map(str,payload.keys())))
            tier=payload.get('viewerTier')
            self.log(f'Atlas /members AID {aid}: réponse 200 mais members vide (memberCount={got_count}, attendu≈{expected_count}, viewerTier={tier}, clés={keys}) ; tentative {attempt+1}/3...')
            time.sleep(1.0 + attempt)
        return last

    def history(self,uid): return self.get(HISTORY_URL.format(uid=uid))
    def power(self,uid): return self.get(POWER_URL.format(uid=uid))

class App:
    def __init__(self):
        self.root=tk.Tk(); self.root.title(f'WOS Unified Manager V{APP_VERSION}'); self.root.geometry('1250x800')
        self.db=UnifiedDB(DB_PATH); self.decoder=core.DecoderBundle(BASE_DIR); self.events=queue.Queue(); self.engine=core.CollectorEngine(self.decoder,self.db,self.log,self.stats_event); self.live=core.LiveCapture(self.engine,self.log)
        self.capture_path=None; self.session_id=''; self.atlas_busy=False; self.atlas_cookie=''; self.nav_stop=threading.Event(); self.nav_thread=None; self.nav_config=self._load_nav_config(); self._build(); self.root.after(120,self._poll); self.root.protocol('WM_DELETE_WINDOW',self.close)
    def log(self,msg): self.events.put(('log',str(msg)))
    def stats_event(self,d): self.events.put(('stats',d))
    def _build(self):
        top=ttk.Frame(self.root,padding=10); top.pack(fill='x'); ttk.Label(top,text='État :').pack(side='left'); self.kid=tk.StringVar(value='3693'); ttk.Entry(top,textvariable=self.kid,width=9).pack(side='left',padx=(5,15))
        ttk.Button(top,text='Session WOS Atlas',command=self.configure_atlas_session).pack(side='left',padx=4); ttk.Button(top,text='Importer WOS Atlas',command=self.start_atlas_sync).pack(side='left',padx=4); ttk.Button(top,text='Consolider WOS LIVE',command=self.start_consolidation).pack(side='left',padx=4); ttk.Button(top,text='Découverte CARTE',command=self.start_map_discovery).pack(side='left',padx=4); self.btn_stop=ttk.Button(top,text='Arrêter capture',command=self.stop_live,state='disabled'); self.btn_stop.pack(side='left',padx=4); ttk.Button(top,text='Exporter CSV',command=self.export_csv).pack(side='left',padx=4); ttk.Button(top,text='Rapport diagnostic',command=self.show_diagnostic_report).pack(side='left',padx=4); ttk.Button(top,text='Export diagnostic',command=self.export_diagnostic).pack(side='left',padx=4)
        self.atlas_session_status=tk.StringVar(value='Atlas: non connecté'); ttk.Label(top,textvariable=self.atlas_session_status).pack(side='left',padx=(10,4)); self.status=tk.StringVar(value='Prêt'); ttk.Label(top,textvariable=self.status).pack(side='right')
        cards=ttk.LabelFrame(self.root,text='État sélectionné',padding=8); cards.pack(fill='x',padx=10,pady=(0,8)); self.svars={k:tk.StringVar(value='0') for k in ['alliances','players','atlas_power','wos','wos_power','pending']}
        for i,(lab,key) in enumerate([('Alliances Atlas','alliances'),('Joueurs Atlas','players'),('Power Atlas','atlas_power'),('WOS ID','wos'),('Power WOS','wos_power'),('À consolider','pending')]):
            f=ttk.Frame(cards); f.grid(row=0,column=i,padx=18,sticky='w'); ttk.Label(f,text=lab).pack(); ttk.Label(f,textvariable=self.svars[key],font=('Segoe UI',14,'bold')).pack()
        book=ttk.Notebook(self.root); book.pack(fill='both',expand=True,padx=10,pady=4); data=ttk.Frame(book,padding=6); logtab=ttk.Frame(book,padding=6); autotab=ttk.Frame(book,padding=6); book.add(data,text='Base joueurs'); book.add(logtab,text='Journal / Live'); book.add(autotab,text='Scan MAP / Vérification')
        filt=ttk.Frame(data); filt.pack(fill='x'); ttk.Label(filt,text='Recherche :').pack(side='left'); self.query=tk.StringVar(); ttk.Entry(filt,textvariable=self.query,width=35).pack(side='left',padx=6); ttk.Button(filt,text='Actualiser',command=self.refresh).pack(side='left')
        cols=('pseudo','alliance','atlas','xy','lv','apat','wos','pwos'); self.tree=ttk.Treeview(data,columns=cols,show='headings')
        for c,l,w in [('pseudo','Pseudo',230),('alliance','Alliance',75),('atlas','Atlas ID',110),('xy','X / Y',85),('lv','Niv.',55),('apat','Power Atlas',125),('wos','WOS ID',110),('pwos','Power WOS',125)]: self.tree.heading(c,text=l); self.tree.column(c,width=w,anchor='w' if c=='pseudo' else 'center')
        sy=ttk.Scrollbar(data,orient='vertical',command=self.tree.yview); self.tree.configure(yscrollcommand=sy.set); sy.pack(side='right',fill='y'); self.tree.pack(fill='both',expand=True,pady=6)
        self.logbox=tk.Text(logtab,wrap='none',font=('Consolas',9)); self.logbox.pack(fill='both',expand=True); self._build_automation_tab(autotab); self.query.trace_add('write',lambda *_: self.refresh()); self.refresh()

    # ---------- Fenêtre WOS / bureau multi-écrans ----------
    def _win32_root_from_point(self, x, y):
        """Retourne la fenêtre top-level située sous un point du bureau virtuel."""
        if os.name != 'nt': return None
        try:
            import ctypes
            from ctypes import wintypes
            user32=ctypes.windll.user32
            class POINT(ctypes.Structure): _fields_=[('x',wintypes.LONG),('y',wintypes.LONG)]
            hwnd=user32.WindowFromPoint(POINT(int(x),int(y)))
            if not hwnd: return None
            GA_ROOT=2
            root=user32.GetAncestor(hwnd,GA_ROOT) or hwnd
            return int(root)
        except Exception:
            return None

    def _win32_window_info(self, hwnd):
        if os.name!='nt' or not hwnd: return None
        try:
            import ctypes
            from ctypes import wintypes
            user32=ctypes.windll.user32
            if not user32.IsWindow(wintypes.HWND(hwnd)): return None
            r=wintypes.RECT()
            if not user32.GetWindowRect(wintypes.HWND(hwnd),ctypes.byref(r)): return None
            ln=user32.GetWindowTextLengthW(wintypes.HWND(hwnd))
            title=ctypes.create_unicode_buffer(max(ln+1,2)); user32.GetWindowTextW(wintypes.HWND(hwnd),title,len(title))
            cls=ctypes.create_unicode_buffer(256); user32.GetClassNameW(wintypes.HWND(hwnd),cls,256)
            return {'hwnd':int(hwnd),'title':title.value,'class':cls.value,'left':int(r.left),'top':int(r.top),'right':int(r.right),'bottom':int(r.bottom),'width':int(r.right-r.left),'height':int(r.bottom-r.top),'minimized':bool(user32.IsIconic(wintypes.HWND(hwnd))),'visible':bool(user32.IsWindowVisible(wintypes.HWND(hwnd)))}
        except Exception:
            return None

    def _resolve_wos_window(self, quiet=False):
        """Retrouve la fenêtre calibrée même après redémarrage / déplacement d'écran."""
        if os.name!='nt': return None
        cfg=self.nav_config.get('window') or {}
        wanted_title=str(cfg.get('title') or '')
        wanted_class=str(cfg.get('class') or '')
        cached=getattr(self,'_wos_hwnd',None)
        inf=self._win32_window_info(cached) if cached else None
        if inf and ((not wanted_class or inf['class']==wanted_class) and (not wanted_title or inf['title']==wanted_title)):
            return inf
        try:
            import ctypes
            from ctypes import wintypes
            user32=ctypes.windll.user32
            matches=[]
            CB=ctypes.WINFUNCTYPE(wintypes.BOOL,wintypes.HWND,wintypes.LPARAM)
            def cb(hwnd,lparam):
                ii=self._win32_window_info(int(hwnd))
                if not ii or not ii['visible']: return True
                cls_ok=(not wanted_class or ii['class']==wanted_class)
                title_ok=(not wanted_title or ii['title']==wanted_title)
                if cls_ok and title_ok: matches.append(ii)
                return True
            user32.EnumWindows(CB(cb),0)
            if matches:
                # Si plusieurs fenêtres ont la même classe, privilégie le titre exact puis la plus grande.
                matches.sort(key=lambda x:((x['title']==wanted_title),x['width']*x['height']),reverse=True)
                self._wos_hwnd=matches[0]['hwnd']; return matches[0]
        except Exception:
            pass
        if not quiet:
            self.log('Navigation PC: fenêtre WOS calibrée introuvable. Recalibre un point dans la fenêtre WOS.')
        return None

    def _focus_wos_window(self):
        inf=self._resolve_wos_window()
        if not inf: return None
        if inf.get('minimized'):
            raise RuntimeError('La fenêtre WOS est minimisée.')
        try:
            import ctypes
            ctypes.windll.user32.SetForegroundWindow(int(inf['hwnd']))
            time.sleep(.12)
        except Exception: pass
        return inf

    def _abs_nav_point(self,key):
        """Convertit un point calibré relatif à WOS vers le bureau virtuel courant."""
        pts=self.nav_config.get('points',{})
        p=pts.get(key)
        if not (isinstance(p,list) and len(p)==2): raise RuntimeError(f'Point {key} non calibré')
        if self.nav_config.get('coordinate_mode')!='window-relative':
            raise RuntimeError('Ancienne calibration absolue détectée : refais les 5 points de calibration.')
        inf=self._resolve_wos_window()
        if not inf: raise RuntimeError('Fenêtre WOS introuvable')
        return [int(inf['left']+p[0]),int(inf['top']+p[1])]

    def _capture_wos_window_image(self):
        """Capture uniquement la fenêtre WOS, y compris si elle est sur un écran à coordonnées négatives."""
        inf=self._resolve_wos_window()
        if not inf: raise RuntimeError('Fenêtre WOS introuvable pour la capture')
        if inf.get('minimized'): raise RuntimeError('Fenêtre WOS minimisée')
        from PIL import ImageGrab
        bbox=(int(inf['left']),int(inf['top']),int(inf['right']),int(inf['bottom']))
        try:
            img=ImageGrab.grab(bbox=bbox,all_screens=True)
        except TypeError:
            img=ImageGrab.grab(bbox=bbox)
        return img,inf

    def _load_nav_config(self):
        try:
            if NAV_CONFIG_PATH.exists(): return json.loads(NAV_CONFIG_PATH.read_text(encoding='utf-8'))
        except Exception: pass
        return {'points':{},'vision_zones':{},'dwell':2.5,'settle':0.4,'coordinate_mode':'window-relative','window':{}}
    def _save_nav_config(self):
        NAV_CONFIG_PATH.write_text(json.dumps(self.nav_config,ensure_ascii=False,indent=2),encoding='utf-8')
    def _build_automation_tab(self,parent):
        info=ttk.LabelFrame(parent,text='Navigation PC (souris/clavier)',padding=8); info.pack(fill='x',pady=(0,8))
        ttk.Label(info,text="Calibration V4.0.49 : navigation + zones visuelles sont enregistrées RELATIVEMENT à la fenêtre WOS. Tu peux déplacer WOS sur l’autre écran sans recalibrer.").grid(row=0,column=0,columnspan=6,sticky='w',pady=(0,2)); self.nav_window_var=tk.StringVar(value='Fenêtre WOS : non liée'); ttk.Label(info,textvariable=self.nav_window_var).grid(row=3,column=0,columnspan=5,sticky='w',pady=(0,5))
        self.nav_point_vars={k:tk.StringVar() for k in ('coord','x','y','go','city')}
        labels=[('coord','Bouton coordonnées'),('x','Champ X'),('y','Champ Y'),('go','Bouton Aller'),('city','Ville ciblée')]
        for i,(key,label) in enumerate(labels):
            ttk.Button(info,text='Calibrer '+label,command=lambda k=key,l=label:self._capture_nav_point(k,l)).grid(row=1,column=i,padx=3,pady=3,sticky='ew')
            ttk.Label(info,textvariable=self.nav_point_vars[key]).grid(row=2,column=i,padx=3,sticky='ew')
        self._refresh_nav_labels()

        # V4.0.47 : calibration déterministe des 3 zones de la pancarte joueur.
        # Chaque rectangle est défini par deux coins, eux-mêmes relatifs à la fenêtre WOS.
        vision=ttk.LabelFrame(info,text='Calibration visuelle de la plaque joueur (profil standard)',padding=6)
        vision.grid(row=4,column=0,columnspan=5,sticky='ew',pady=(8,4))
        ttk.Label(vision,text='Ouvre manuellement une plaque joueur standard puis calibre les coins HG/BD de chaque zone. L’agent ne lira ensuite QUE ces rectangles.').grid(row=0,column=0,columnspan=7,sticky='w',pady=(0,4))
        self.vision_zone_vars={k:tk.StringVar(value='non calibrée') for k in ('pseudo','coords','power')}
        vlabels=[('pseudo','Pseudo'),('coords','Coordonnées X/Y'),('power','Puissance')]
        for i,(key,label) in enumerate(vlabels,1):
            ttk.Label(vision,text=label,width=16).grid(row=i,column=0,sticky='w',padx=(0,4))
            ttk.Button(vision,text='Coin HG',command=lambda k=key,l=label:self._capture_vision_corner(k,'tl',l+' — coin haut-gauche')).grid(row=i,column=1,padx=2,pady=2)
            ttk.Button(vision,text='Coin BD',command=lambda k=key,l=label:self._capture_vision_corner(k,'br',l+' — coin bas-droit')).grid(row=i,column=2,padx=2,pady=2)
            ttk.Label(vision,textvariable=self.vision_zone_vars[key],width=36).grid(row=i,column=3,columnspan=3,sticky='w',padx=6)
        ttk.Button(vision,text='Effacer zones visuelles',command=self._clear_vision_zones).grid(row=1,column=6,rowspan=3,padx=8,sticky='ns')
        self._refresh_vision_labels()

        cfg=ttk.Frame(info); cfg.grid(row=5,column=0,columnspan=5,sticky='w',pady=(8,2))
        ttk.Label(cfg,text='Temps ville ouverte (s) :').pack(side='left'); self.nav_dwell=tk.DoubleVar(value=5.0); ttk.Spinbox(cfg,from_=2,to=15,increment=.5,textvariable=self.nav_dwell,width=6).pack(side='left',padx=4)
        self.screen_ocr_enabled=tk.BooleanVar(value=True); ttk.Checkbutton(cfg,text='Agent visuel : pseudo + puissance + X/Y',variable=self.screen_ocr_enabled).pack(side='left',padx=8)
        ttk.Button(cfg,text='Tester une coordonnée',command=self._test_navigation).pack(side='left',padx=10)
        scan=ttk.LabelFrame(parent,text='Scan ciblé des comptes manquants',padding=8); scan.pack(fill='x',pady=(0,8))
        self.nav_alliance=tk.StringVar(value='TOUTES'); self.nav_missing=tk.BooleanVar(value=True)
        ttk.Label(scan,text='Alliance :').grid(row=0,column=0,sticky='w'); self.nav_combo=ttk.Combobox(scan,textvariable=self.nav_alliance,state='readonly',width=15); self.nav_combo.grid(row=0,column=1,padx=5,sticky='w')
        ttk.Checkbutton(scan,text='Seulement WOS ID / puissance manquants',variable=self.nav_missing).grid(row=0,column=2,padx=8,sticky='w')
        ttk.Button(scan,text='Actualiser alliances',command=self._refresh_alliance_combo).grid(row=0,column=3,padx=4)
        ttk.Button(scan,text='Démarrer scan automatique',command=self.start_pc_map_scan).grid(row=1,column=0,columnspan=2,padx=4,pady=6,sticky='ew')
        ttk.Button(scan,text='ARRÊTER navigation',command=self.stop_pc_navigation).grid(row=1,column=2,padx=4,pady=6,sticky='ew')
        self.nav_progress=tk.StringVar(value='Inactif'); ttk.Label(scan,textvariable=self.nav_progress).grid(row=1,column=3,padx=8,sticky='w')
        verify=ttk.LabelFrame(parent,text='Vérification d’une alliance',padding=8); verify.pack(fill='both',expand=True)
        ttk.Label(verify,text="Le module visite chaque ville. L’agent visuel vérifie pseudo + puissance + X/Y ; le réseau conserve la récupération du WOS ID.").pack(anchor='w')
        bar=ttk.Frame(verify); bar.pack(fill='x',pady=5); ttk.Label(bar,text='Alliance :').pack(side='left'); self.verify_alliance=tk.StringVar(value='ROY'); self.verify_combo=ttk.Combobox(bar,textvariable=self.verify_alliance,state='readonly',width=15); self.verify_combo.pack(side='left',padx=5); ttk.Button(bar,text='Lancer vérification',command=self.start_alliance_verification).pack(side='left',padx=5)
        ttk.Button(bar,text='VISION PROPRE (base vierge)',command=self.start_clean_vision_benchmark).pack(side='left',padx=5)
        ttk.Button(bar,text='Ouvrir résultats Vision',command=self.open_clean_vision_results).pack(side='left',padx=5)
        self.verify_status=tk.StringVar(value='Aucune vérification lancée'); ttk.Label(bar,textvariable=self.verify_status).pack(side='left',padx=10)
        cols=('pseudo','atlas','result','wos','power','detail'); self.verify_tree=ttk.Treeview(verify,columns=cols,show='headings',height=8)
        for c,l,w in [('pseudo','Pseudo',200),('atlas','Atlas ID',100),('result','Résultat',100),('wos','WOS ID',105),('power','Power WOS',115),('detail','Détail',430)]: self.verify_tree.heading(c,text=l); self.verify_tree.column(c,width=w,anchor='w' if c in ('pseudo','detail') else 'center')
        self.verify_tree.pack(fill='both',expand=True,pady=4)
        self._refresh_alliance_combo()
    def _refresh_nav_labels(self):
        pts=self.nav_config.get('points',{})
        rel=self.nav_config.get('coordinate_mode')=='window-relative'
        for k,v in getattr(self,'nav_point_vars',{}).items():
            p=pts.get(k); v.set((f"rel {p[0]},{p[1]}" if rel else f"ABS {p[0]},{p[1]}") if isinstance(p,list) and len(p)==2 else 'non calibré')
        if hasattr(self,'nav_window_var'):
            w=self.nav_config.get('window') or {}; title=w.get('title') or '?'; cls=w.get('class') or '?'
            self.nav_window_var.set(f"Fenêtre WOS : {title}  [{cls}]" if w else 'Fenêtre WOS : non liée')
    def _refresh_vision_labels(self):
        zones=self.nav_config.get('vision_zones',{}) or {}
        for key,var in getattr(self,'vision_zone_vars',{}).items():
            z=zones.get(key) or {}
            tl=z.get('tl'); br=z.get('br')
            if isinstance(tl,list) and len(tl)==2 and isinstance(br,list) and len(br)==2:
                x1,y1=tl; x2,y2=br
                var.set(f'rel ({x1},{y1}) → ({x2},{y2})  {abs(x2-x1)}×{abs(y2-y1)}')
            elif isinstance(tl,list) and len(tl)==2:
                var.set(f'HG rel {tl[0]},{tl[1]} — BD manquant')
            elif isinstance(br,list) and len(br)==2:
                var.set(f'HG manquant — BD rel {br[0]},{br[1]}')
            else:
                var.set('non calibrée')

    def _clear_vision_zones(self):
        self.nav_config['vision_zones']={}
        self._save_nav_config(); self._refresh_vision_labels()
        self.log('Calibration visuelle : zones pseudo / X-Y / puissance effacées.')

    def _capture_vision_corner(self,zone,corner,label):
        if pyautogui is None:
            messagebox.showerror('Dépendance manquante','pyautogui n’est pas installé. Lance INSTALL_DEPENDENCIES.bat puis redémarre.'); return
        if not self.nav_config.get('window'):
            messagebox.showwarning('Fenêtre WOS non liée','Calibre d’abord au moins un des 5 points de navigation dans la fenêtre WOS.'); return
        messagebox.showinfo('Calibration visuelle',f'Après OK tu as 3 secondes pour placer la souris sur :\n{label}\n\nLa plaque joueur doit être ouverte. Ne clique pas.')
        def worker():
            time.sleep(3)
            p=pyautogui.position(); hwnd=self._win32_root_from_point(p.x,p.y); inf=self._win32_window_info(hwnd)
            if not inf:
                self.root.after(0,lambda:messagebox.showerror('Calibration visuelle','Impossible d’identifier la fenêtre sous le curseur.')); return
            existing=self.nav_config.get('window') or {}
            if existing and (existing.get('class')!=inf['class'] or existing.get('title')!=inf['title']):
                msg=f"Le point visuel est sur une autre fenêtre : {inf['title'] or inf['class']}\nFenêtre liée : {existing.get('title') or existing.get('class')}\n\nRecommence dans WOS."
                self.root.after(0,lambda m=msg:messagebox.showerror('Calibration visuelle WOS',m)); return
            relx=int(p.x-inf['left']); rely=int(p.y-inf['top'])
            zones=self.nav_config.setdefault('vision_zones',{})
            z=zones.setdefault(zone,{})
            z[corner]=[relx,rely]
            # Si les deux coins existent mais sont inversés, on normalise immédiatement.
            if isinstance(z.get('tl'),list) and isinstance(z.get('br'),list):
                a,b=z['tl'],z['br']; z['tl']=[min(a[0],b[0]),min(a[1],b[1])]; z['br']=[max(a[0],b[0]),max(a[1],b[1])]
            self._save_nav_config()
            self.root.after(0,self._refresh_vision_labels)
            self.log(f'Calibration visuelle: {zone}/{corner} = rel {relx},{rely}')
        threading.Thread(target=worker,daemon=True).start()

    def _vision_zones_ready(self,show=False):
        if not getattr(self,'screen_ocr_enabled',None) or not self.screen_ocr_enabled.get():
            return True
        zones=self.nav_config.get('vision_zones',{}) or {}; missing=[]
        for k in ('pseudo','coords','power'):
            z=zones.get(k) or {}; tl=z.get('tl'); br=z.get('br')
            if not (isinstance(tl,list) and len(tl)==2 and isinstance(br,list) and len(br)==2 and br[0]-tl[0]>=20 and br[1]-tl[1]>=12):
                missing.append(k)
        if missing and show:
            messagebox.showwarning('Calibration visuelle incomplète','Calibre les zones de plaque avant le scan : '+', '.join(missing)+'\n\nOuvre une plaque joueur STANDARD et calibre le coin HG puis BD de chaque zone.')
        return not missing

    def _capture_nav_point(self,key,label):
        if pyautogui is None:
            messagebox.showerror('Dépendance manquante','pyautogui n’est pas installé. Lance INSTALL_DEPENDENCIES.bat puis redémarre.'); return
        messagebox.showinfo('Calibration',f'Après OK tu as 3 secondes pour placer la souris sur :\n{label}\n\nPlace bien le curseur DANS la fenêtre WOS. Ne clique pas.')
        def worker():
            time.sleep(3)
            p=pyautogui.position(); hwnd=self._win32_root_from_point(p.x,p.y); inf=self._win32_window_info(hwnd)
            if not inf:
                self.root.after(0,lambda:messagebox.showerror('Calibration','Impossible d’identifier la fenêtre sous le curseur.'))
                return
            existing=self.nav_config.get('window') or {}
            # Le premier point lie la fenêtre. Les suivants doivent appartenir à la même fenêtre.
            if existing and (existing.get('class')!=inf['class'] or existing.get('title')!=inf['title']):
                msg=f"Le point est sur une autre fenêtre : {inf['title'] or inf['class']}\nFenêtre liée : {existing.get('title') or existing.get('class')}\n\nRecommence la calibration dans WOS."
                self.root.after(0,lambda m=msg:messagebox.showerror('Calibration WOS',m)); return
            self.nav_config['window']={'title':inf['title'],'class':inf['class']}
            self.nav_config['coordinate_mode']='window-relative'; self._wos_hwnd=inf['hwnd']
            relx=int(p.x-inf['left']); rely=int(p.y-inf['top'])
            self.nav_config.setdefault('points',{})[key]=[relx,rely]; self._save_nav_config()
            self.root.after(0,self._refresh_nav_labels)
            self.log(f"Calibration WOS: {label} = rel {relx},{rely} | fenêtre={inf['title']!r} rect=({inf['left']},{inf['top']},{inf['right']},{inf['bottom']})")
        threading.Thread(target=worker,daemon=True).start()

    def _refresh_alliance_combo(self):
        try:
            kid=int(self.kid.get().strip()); tags=self.db.alliance_tags(kid)
        except Exception: tags=[]
        vals=['TOUTES']+tags
        if hasattr(self,'nav_combo'): self.nav_combo['values']=vals
        if hasattr(self,'verify_combo'): self.verify_combo['values']=tags
        if getattr(self,'nav_alliance',None) and self.nav_alliance.get() not in vals:self.nav_alliance.set('TOUTES')
        if tags and getattr(self,'verify_alliance',None) and self.verify_alliance.get() not in tags:self.verify_alliance.set(tags[0])
    def _nav_ready(self):
        if pyautogui is None:
            messagebox.showerror('Navigation PC','pyautogui est absent. Lance INSTALL_DEPENDENCIES.bat.'); return False
        pts=self.nav_config.get('points',{})
        miss=[k for k in ('coord','x','y','go','city') if k not in pts]
        if miss:
            messagebox.showwarning('Calibration incomplète','Calibre d’abord : '+', '.join(miss)); return False
        if self.nav_config.get('coordinate_mode')!='window-relative' or not self.nav_config.get('window'):
            messagebox.showwarning('Nouvelle calibration requise','Cette version utilise une calibration relative à la fenêtre WOS. Refais les 5 points une fois.'); return False
        inf=self._resolve_wos_window(quiet=True)
        if not inf:
            messagebox.showerror('Fenêtre WOS introuvable','La fenêtre WOS liée à la calibration est introuvable. Ouvre WOS puis recalibre un point.'); return False
        if inf.get('minimized'):
            messagebox.showerror('Fenêtre WOS minimisée','Restaure la fenêtre WOS avant de lancer la navigation.'); return False
        return True
    def _clipboard_set_text(self,text):
        # WOS PC n'accepte pas toujours correctement pyautogui.write() dans ses champs
        # personnalisés. On passe donc par le presse-papiers Windows + Ctrl+V.
        if os.name!='nt':
            return False
        try:
            import ctypes
            from ctypes import wintypes
            CF_UNICODETEXT=13; GMEM_MOVEABLE=0x0002
            user32=ctypes.windll.user32; kernel32=ctypes.windll.kernel32
            data=(str(text)+'\0').encode('utf-16-le')
            h=kernel32.GlobalAlloc(GMEM_MOVEABLE,len(data))
            if not h:return False
            p=kernel32.GlobalLock(h)
            ctypes.memmove(p,data,len(data)); kernel32.GlobalUnlock(h)
            if not user32.OpenClipboard(None):
                kernel32.GlobalFree(h); return False
            try:
                user32.EmptyClipboard(); user32.SetClipboardData(CF_UNICODETEXT,h)
            finally:user32.CloseClipboard()
            return True
        except Exception:
            return False
    def _direct_key_sequence(self, keys):
        """Envoie des frappes Windows en scan-codes (SendInput).

        Le client PC WOS utilise des contrôles DirectX/custom qui peuvent ignorer
        pyautogui.write(), Ctrl+V et les messages clavier classiques. Les scan-codes
        sont injectés au niveau entrée Windows, comme un vrai clavier.
        """
        if os.name != 'nt':
            return False
        try:
            import ctypes
            from ctypes import wintypes

            ULONG_PTR = wintypes.WPARAM
            class KEYBDINPUT(ctypes.Structure):
                _fields_ = [('wVk', wintypes.WORD), ('wScan', wintypes.WORD),
                            ('dwFlags', wintypes.DWORD), ('time', wintypes.DWORD),
                            ('dwExtraInfo', ULONG_PTR)]
            class MOUSEINPUT(ctypes.Structure):
                _fields_ = [('dx', wintypes.LONG), ('dy', wintypes.LONG),
                            ('mouseData', wintypes.DWORD), ('dwFlags', wintypes.DWORD),
                            ('time', wintypes.DWORD), ('dwExtraInfo', ULONG_PTR)]
            class HARDWAREINPUT(ctypes.Structure):
                _fields_ = [('uMsg', wintypes.DWORD), ('wParamL', wintypes.WORD), ('wParamH', wintypes.WORD)]
            class _U(ctypes.Union):
                _fields_ = [('ki', KEYBDINPUT), ('mi', MOUSEINPUT), ('hi', HARDWAREINPUT)]
            class INPUT(ctypes.Structure):
                _anonymous_ = ('u',)
                _fields_ = [('type', wintypes.DWORD), ('u', _U)]

            KEYEVENTF_KEYUP = 0x0002
            KEYEVENTF_SCANCODE = 0x0008
            scan = {
                'ctrl':0x1D, 'a':0x1E, 'backspace':0x0E, 'esc':0x01,
                '0':0x0B, '1':0x02, '2':0x03, '3':0x04, '4':0x05,
                '5':0x06, '6':0x07, '7':0x08, '8':0x09, '9':0x0A,
            }
            send = ctypes.windll.user32.SendInput
            send.argtypes = (wintypes.UINT, ctypes.POINTER(INPUT), ctypes.c_int)
            send.restype = wintypes.UINT

            def key(sc, up=False):
                flags = KEYEVENTF_SCANCODE | (KEYEVENTF_KEYUP if up else 0)
                inp = INPUT(type=1, ki=KEYBDINPUT(0, sc, flags, 0, 0))
                return send(1, ctypes.byref(inp), ctypes.sizeof(INPUT)) == 1

            for item in keys:
                if isinstance(item, tuple) and item and item[0] == 'chord':
                    names=item[1]
                    for name in names: key(scan[name], False); time.sleep(.025)
                    for name in reversed(names): key(scan[name], True); time.sleep(.025)
                else:
                    sc=scan[str(item)]
                    key(sc, False); time.sleep(.035); key(sc, True); time.sleep(.035)
            return True
        except Exception as exc:
            try:self.log(f'Navigation PC: SendInput indisponible ({exc})')
            except Exception:pass
            return False

    def _replace_game_field(self,point,value):
        # V4.0.28 : Google Play Games/WOS ne reconnait pas Ctrl+A dans ces champs.
        # Les coordonnees WOS tiennent sur 4 chiffres maximum : on efface donc
        # explicitement l'ancienne valeur avec 4 Backspace, puis on saisit les chiffres.
        # Les frappes passent toujours par SendInput scan-codes ; fallback pyautogui.
        pyautogui.click(*point,clicks=2,interval=0.10); time.sleep(.22)
        text=str(int(value))
        seq=['backspace'] * 4 + list(text)
        if not self._direct_key_sequence(seq):
            pyautogui.press('backspace', presses=4, interval=.08); time.sleep(.08)
            pyautogui.write(text,interval=0.10)
        time.sleep(.30)
    def _goto_xy(self,x,y):
        self._focus_wos_window(); pyautogui.FAILSAFE=True; pyautogui.PAUSE=float(self.nav_config.get('settle',0.4))
        pyautogui.click(*self._abs_nav_point('coord')); time.sleep(.65)
        self._replace_game_field(self._abs_nav_point('x'),x)
        self._replace_game_field(self._abs_nav_point('y'),y)
        # Retire le focus du champ avant validation : certains clients WOS
        # n'appliquent la valeur qu'après perte de focus.
        pyautogui.press('tab'); time.sleep(.12)
        pyautogui.click(*self._abs_nav_point('go')); time.sleep(.25)

    def _open_target_city(self):
        """Clique réellement la ville après le déplacement de carte.

        Se déplacer aux X/Y ne force pas toujours le client à demander la fiche du
        joueur. Le clic sur la ville déclenche les réponses profil/ville dont le
        collecteur a besoin pour WOS ID et puissance.
        """
        # Laisse le temps à la carte de recentrer et d'afficher la ville.
        self._focus_wos_window(); time.sleep(1.15)
        pyautogui.click(*self._abs_nav_point('city'))
        time.sleep(.45)

    def _visit_xy(self,x,y):
        self._goto_xy(x,y)
        self._open_target_city()

    def _close_city_panel(self):
        # V4.0.33 : Echap est envoye par SendInput avec le scan-code materiel 0x01.
        # On n'utilise plus de point de calibration de fermeture : cela évite
        # de cliquer accidentellement sur une autre ville selon la position de la carte.
        try:
            self._focus_wos_window()
            if not self._direct_key_sequence(['esc']):
                pyautogui.press('esc')
            time.sleep(.35)
        except Exception:
            try:
                pyautogui.press('esc'); time.sleep(.35)
            except Exception:
                pass
    def _screen_power_fallback(self,row):
        """Agent visuel V4.0.47 — lecture par zones calibrées.

        Plus de crop global autour de la ville : pseudo, X/Y et puissance sont lus
        dans trois rectangles fixes calibrés relativement à la fenêtre WOS.
        Cela évite de confondre bâtiments, boutons ou autres textes de l'interface.
        """
        try:
            if not getattr(self,'screen_ocr_enabled',None) or not self.screen_ocr_enabled.get(): return None
            if not self._vision_zones_ready(False):
                self.log(f'VISION A{row["atlas_id"]}: zones visuelles non calibrées; aucune donnée visuelle promue.')
                return None
            full_img,win=self._capture_wos_window_image(); sw,sh=full_img.size
            odir=SESSIONS_DIR/(self.session_id or 'manual')/'vision'; odir.mkdir(parents=True,exist_ok=True)
            state=self.db.player_state(row['atlas_id']) or {}; helper=BASE_DIR/'wos_ocr_helper.py'
            zones=self.nav_config.get('vision_zones',{}) or {}

            def crop_zone(key):
                z=zones[key]; x1,y1=[int(v) for v in z['tl']]; x2,y2=[int(v) for v in z['br']]
                x1=max(0,min(sw-1,x1)); y1=max(0,min(sh-1,y1)); x2=max(x1+1,min(sw,x2)); y2=max(y1+1,min(sh,y2))
                shot=odir/f"A{int(row['atlas_id'])}_{datetime.now().strftime('%H%M%S_%f')}_{key}.png"
                full_img.crop((x1,y1,x2,y2)).save(shot)
                cmd=[sys.executable,str(helper),str(shot),str(row.get('pseudo_display') or ''),str(int(row.get('atlas_x') or -1)),str(int(row.get('atlas_y') or -1)),str(int(state.get('wos_id') or 0)),str(int(row['atlas_id']))]
                cp=subprocess.run(cmd,capture_output=True,text=True,encoding='utf-8',errors='replace',timeout=35,creationflags=(0x08000000 if os.name=='nt' else 0))
                if cp.returncode!=0:
                    raise RuntimeError(f'{key}: helper erreur {cp.returncode}: {(cp.stderr or "").strip()[:350]}')
                data=json.loads((cp.stdout or '').strip() or '{}')
                if data.get('_error'): raise RuntimeError(f'{key}: {data.get("_error")}')
                return data,shot

            pd,pshot=crop_zone('pseudo'); cd,cshot=crop_zone('coords'); wd,wshot=crop_zone('power')
            data={
                'pseudo':pd.get('pseudo'),
                'pseudo_score':pd.get('pseudo_score') or 0.0,
                'pseudo_ocr_conf':pd.get('pseudo_ocr_conf') or 0.0,
                'pseudo_ok':bool(pd.get('pseudo_ok')),
                'x':cd.get('x'),'y':cd.get('y'),
                'location_seen':bool(cd.get('location_seen')),
                'location_ok':bool(cd.get('location_ok')),
                'power':wd.get('power'),
                'power_candidates':wd.get('power_candidates') or [],
                'text':f"PSEUDO[{pd.get('text') or ''}] | XY[{cd.get('text') or ''}] | POWER[{wd.get('text') or ''}]"
            }
            # On ne promeut une puissance visuelle que si l'identité ET la localisation
            # ont été confirmées dans leurs zones dédiées. store_vision_observation
            # applique cette règle et conserve la trace des lectures partielles.
            verdict=self.db.store_vision_observation(row,self.session_id,data,str(wshot),promote=not getattr(self,'clean_vision_mode',False))
            obs=data.get('pseudo') or '?'; score=float(data.get('pseudo_score') or 0.0); p=data.get('power')
            xy=f"X{data.get('x')} Y{data.get('y')}"
            self.log(f'VISION A{row["atlas_id"]} [zones]: pseudo={obs!r} score={score:.2f} ok={bool(data.get("pseudo_ok"))} | {xy} ok={bool(data.get("location_ok"))} | power={p or "?"} | {verdict.get("status")} | shots={pshot.name},{cshot.name},{wshot.name}')
            return data
        except Exception as e:
            self.log(f'Agent vision A{row.get("atlas_id")}: {type(e).__name__}: {e} — le manager continue.')
        return None

    def _test_navigation(self):
        if not self._nav_ready(): return
        kid=self.get_kid();
        if kid is None:return
        tag=None if self.nav_alliance.get()=='TOUTES' else self.nav_alliance.get(); rows=self.db.navigation_targets(kid,tag,False)
        if not rows: messagebox.showinfo('Test','Aucune coordonnée Atlas disponible.'); return
        r=rows[0]
        try:
            self._visit_xy(r['atlas_x'],r['atlas_y'])
            time.sleep(float(self.nav_dwell.get()))
            self._close_city_panel()
            self.log(f"Test navigation + ouverture/fermeture ville -> {r['pseudo_display']} X{r['atlas_x']} Y{r['atlas_y']}")
        except Exception as e: messagebox.showerror('Navigation PC',str(e))
    def _ensure_nav_capture(self,kid,mode):
        if self.live.running:return
        sid=f"{mode}_{kid}_{datetime.now().strftime('%Y%m%d_%H%M%S')}"; self.engine.reset(sid); self.engine.set_protocol_discovery(True); self.session_id=sid; self.capture_path=SESSIONS_DIR/f'{sid}.pcap'; self.db.start_session(sid,mode,str(self.capture_path)); self.live.start('AUTO',self.capture_path); self.btn_stop.config(state='normal')
    def start_pc_map_scan(self):
        if self.nav_thread and self.nav_thread.is_alive(): messagebox.showwarning('Navigation PC','Une navigation est déjà active.'); return
        if not self._nav_ready(): return
        if not self._vision_zones_ready(True): return
        kid=self.get_kid();
        if kid is None:return
        tag=None if self.nav_alliance.get()=='TOUTES' else self.nav_alliance.get(); rows=self.db.navigation_targets(kid,tag,bool(self.nav_missing.get()))
        if not rows: messagebox.showinfo('Scan MAP','Aucun joueur correspondant avec coordonnées Atlas.'); return
        self.nav_config['dwell']=float(self.nav_dwell.get()); self._save_nav_config(); self.nav_stop.clear()
        try:self._ensure_nav_capture(kid,'pc-map-scan')
        except Exception as e: messagebox.showerror('Capture WOS',str(e)); return
        self.nav_thread=threading.Thread(target=self._scan_worker,args=(rows,),daemon=True); self.nav_thread.start()
    def _scan_worker(self,rows):
        total=len(rows); resolved=0
        self.log(f'Scan MAP automatique : {total} position(s) à visiter. Déplace la souris dans le coin haut-gauche pour arrêt d’urgence PyAutoGUI.')
        try:
            for i,r in enumerate(rows,1):
                if self.nav_stop.is_set():break
                before=self.db.player_state(r['atlas_id']); trace_start=now(); raw_start=self.db.raw_protocol_max_id(self.session_id); self._visit_xy(r['atlas_x'],r['atlas_y']); self.events.put(('navprogress',f"{i}/{total} — {r['pseudo_display']} [{r['alliance_tag']}] X{r['atlas_x']} Y{r['atlas_y']} — ville ouverte")); time.sleep(float(self.nav_dwell.get()))
                self._screen_power_fallback(r)
                after=self.db.player_state(r['atlas_id'])
                if before and (before.get('wos_id') is None or before.get('power') is None) and after and after.get('wos_id') is not None and after.get('power') is not None: resolved+=1
                self._close_city_panel()
                trace_file,nframes,ops=self.db.visit_trace_finish(self.session_id,r,trace_start,raw_start,SESSIONS_DIR/self.session_id/'visits')
                self.log(f'Trace visite A{r["atlas_id"]}: {nframes} trame(s) | {ops} | {trace_file}')
                if i%5==0:self.events.put(('refresh','Scan MAP en cours'))
        except Exception as e:self.log(f'Scan MAP interrompu: {e}')
        finally:
            self.events.put(('navprogress',f'Terminé / arrêté — {resolved} compte(s) devenus complets'))
            self.events.put(('refresh','Scan MAP terminé'))
    def stop_pc_navigation(self):
        self.nav_stop.set(); self.nav_progress.set('Arrêt demandé…'); self.log('Arrêt navigation PC demandé.')

    def _clean_db_path(self):
        return DATA_DIR/'clean_vision.sqlite3'

    def _clean_init(self, kid, tag, rows):
        import sqlite3
        path=self._clean_db_path()
        if path.exists():
            backup=DATA_DIR/f"clean_vision_backup_{datetime.now().strftime('%Y%m%d_%H%M%S')}.sqlite3"
            shutil.copy2(path,backup)
            path.unlink()
        c=sqlite3.connect(str(path))
        c.executescript("""
        CREATE TABLE atlas_targets(atlas_id INTEGER PRIMARY KEY, aid INTEGER, alliance_tag TEXT, pseudo_atlas TEXT, x INTEGER, y INTEGER);
        CREATE TABLE vision_results(atlas_id INTEGER PRIMARY KEY, seen_at TEXT, pseudo_atlas TEXT, pseudo_vision TEXT, pseudo_score REAL, x_atlas INTEGER,y_atlas INTEGER,x_vision INTEGER,y_vision INTEGER,power_vision INTEGER,status TEXT, screenshot TEXT, raw_text TEXT);
        CREATE TABLE meta(key TEXT PRIMARY KEY,value TEXT);
        """)
        c.execute('INSERT INTO meta VALUES(?,?)',('created_at',now())); c.execute('INSERT INTO meta VALUES(?,?)',('kid',str(kid))); c.execute('INSERT INTO meta VALUES(?,?)',('alliance',tag))
        for r in rows:
            c.execute('INSERT INTO atlas_targets VALUES(?,?,?,?,?,?)',(int(r['atlas_id']),None,r.get('alliance_tag'),r.get('pseudo_display'),r.get('atlas_x'),r.get('atlas_y')))
        c.commit(); c.close(); return path

    def _clean_store_latest(self, sid, row):
        import sqlite3
        with self.db.lock:
            v=self.db.conn.execute("SELECT seen_at,observed_pseudo,pseudo_score,observed_x,observed_y,observed_power,status,screenshot_file,raw_text FROM vision_observations WHERE session_id=? AND atlas_id=? ORDER BY id DESC LIMIT 1",(sid,int(row['atlas_id']))).fetchone()
        if not v: return 'NO_VISION'
        v=dict(v); status=v.get('status') or 'VISION_PARTIAL'
        c=sqlite3.connect(str(self._clean_db_path()))
        c.execute("INSERT OR REPLACE INTO vision_results VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)",(int(row['atlas_id']),v.get('seen_at'),row.get('pseudo_display'),v.get('observed_pseudo'),v.get('pseudo_score'),row.get('atlas_x'),row.get('atlas_y'),v.get('observed_x'),v.get('observed_y'),v.get('observed_power'),status,v.get('screenshot_file'),v.get('raw_text')))
        c.commit(); c.close(); return status

    def start_clean_vision_benchmark(self):
        if self.nav_thread and self.nav_thread.is_alive(): messagebox.showwarning('Vision propre','Une navigation est déjà active.'); return
        if not self._nav_ready() or not self._vision_zones_ready(True): return
        kid=self.get_kid(); tag=self.verify_alliance.get().strip()
        if kid is None or not tag: return
        rows=self.db.navigation_targets(kid,tag,False)
        if not rows: messagebox.showwarning('Vision propre',f'Aucun membre [{tag}] avec coordonnées Atlas.'); return
        if not messagebox.askyesno('VISION PROPRE',f'Créer une BASE VIERGE pour [{tag}] avec uniquement Atlas ID + pseudo + localisation, puis visiter {len(rows)} villes ?\n\nAucune ancienne puissance/WOS ID ne sera copiée dans cette base.'): return
        path=self._clean_init(kid,tag,rows); self.clean_vision_mode=True; self.nav_stop.clear()
        try:
            if self.live.running:self.stop_live()
            self._ensure_nav_capture(kid,'clean-vision')
        except Exception as e:
            self.clean_vision_mode=False; messagebox.showerror('Capture WOS',str(e)); return
        sid=self.session_id; self.verify_status.set(f'[VISION PROPRE {tag}] 0/{len(rows)} — {path.name}')
        self.nav_thread=threading.Thread(target=self._clean_vision_worker,args=(sid,tag,rows),daemon=True); self.nav_thread.start()

    def _clean_vision_worker(self,sid,tag,rows):
        ok=partial=0
        try:
            for i,r in enumerate(rows,1):
                if self.nav_stop.is_set(): break
                self._visit_xy(r['atlas_x'],r['atlas_y']); time.sleep(float(self.nav_dwell.get())); self._screen_power_fallback(r); self._close_city_panel()
                st=self._clean_store_latest(sid,r)
                if st=='VISION_VERIFIED': ok+=1
                else: partial+=1
                self.events.put(('verifystatus',f'[VISION PROPRE {tag}] {i}/{len(rows)} | complets {ok} | partiels {partial}'))
        except Exception as e:
            self.log(f'VISION PROPRE [{tag}] interrompue: {type(e).__name__}: {e}')
        finally:
            self.clean_vision_mode=False
            self.events.put(('verifystatus',f'[VISION PROPRE {tag}] terminé | complets {ok} | partiels {partial} | DB: {self._clean_db_path()}'))

    def open_clean_vision_results(self):
        """Affiche directement le contenu de clean_vision.sqlite3 dans l'application.

        La base Clean Vision reste isolée de la base principale. Cette fenêtre est
        uniquement une vue SQL + outils de contrôle/export ; elle ne promeut rien.
        """
        path=self._clean_db_path()
        if not path.exists():
            messagebox.showinfo('Vision propre','Aucune base Vision propre créée.')
            return

        win=tk.Toplevel(self)
        win.title(f'Résultats Clean Vision — SQL — V{APP_VERSION}')
        win.geometry('1500x760')
        win.minsize(1050,520)

        top=ttk.Frame(win,padding=8); top.pack(fill='x')
        summary=tk.StringVar(value='Chargement…')
        ttk.Label(top,textvariable=summary,font=('TkDefaultFont',10,'bold')).pack(side='left',padx=(0,14))
        filter_var=tk.StringVar(value='TOUS')
        ttk.Label(top,text='Filtre :').pack(side='left')
        filter_box=ttk.Combobox(top,textvariable=filter_var,state='readonly',width=18,
                                values=('TOUS','VISION_VERIFIED','VISION_PARTIAL','VISION_CONFLICT','NO_VISION'))
        filter_box.pack(side='left',padx=4)

        cols=('atlas','alliance','pseudo_atlas','loc_atlas','pseudo_vision','score','loc_vision','power','status','seen')
        tree=ttk.Treeview(win,columns=cols,show='headings')
        spec=[
            ('atlas','Atlas ID',105,'center'),('alliance','Alliance',75,'center'),
            ('pseudo_atlas','Pseudo Atlas',190,'w'),('loc_atlas','LOC Atlas',105,'center'),
            ('pseudo_vision','Pseudo Vision',190,'w'),('score','Score',70,'center'),
            ('loc_vision','LOC Vision',105,'center'),('power','Puissance Vision',130,'e'),
            ('status','Statut Vision',145,'center'),('seen','Vu le',165,'center')
        ]
        for key,label,width,anchor in spec:
            tree.heading(key,text=label); tree.column(key,width=width,anchor=anchor,stretch=(key in ('pseudo_atlas','pseudo_vision')))
        y=ttk.Scrollbar(win,orient='vertical',command=tree.yview); x=ttk.Scrollbar(win,orient='horizontal',command=tree.xview)
        tree.configure(yscrollcommand=y.set,xscrollcommand=x.set)
        tree.pack(side='left',fill='both',expand=True,padx=(8,0),pady=(0,8)); y.pack(side='right',fill='y',pady=(0,8)); x.pack(side='bottom',fill='x',padx=8)

        cache=[]
        def load_rows(*_):
            import sqlite3
            cache.clear()
            try:
                c=sqlite3.connect(str(path)); c.row_factory=sqlite3.Row
                rows=c.execute("""
                    SELECT t.atlas_id,t.alliance_tag,t.pseudo_atlas,t.x,t.y,
                           v.seen_at,v.pseudo_vision,v.pseudo_score,v.x_vision,v.y_vision,
                           v.power_vision,v.status,v.screenshot,v.raw_text
                    FROM atlas_targets t LEFT JOIN vision_results v ON v.atlas_id=t.atlas_id
                    ORDER BY COALESCE(t.alliance_tag,''), LOWER(COALESCE(t.pseudo_atlas,'')), t.atlas_id
                """).fetchall(); c.close()
            except Exception as e:
                messagebox.showerror('Vision SQL',f'Lecture impossible : {e}',parent=win); return
            for iid in tree.get_children(): tree.delete(iid)
            f=filter_var.get(); total=len(rows); verified=partial=conflict=novision=0
            for r0 in rows:
                r=dict(r0); st=r.get('status') or 'NO_VISION'
                if st=='VISION_VERIFIED': verified+=1
                elif st=='VISION_CONFLICT': conflict+=1
                elif st=='NO_VISION': novision+=1
                else: partial+=1
                if f!='TOUS' and st!=f: continue
                p=r.get('power_vision'); ptxt=f'{int(p):,}'.replace(',', ' ') if p is not None else ''
                score=r.get('pseudo_score'); stxt=f'{float(score):.2f}' if score is not None else ''
                loc_a='' if r.get('x') is None or r.get('y') is None else f"{r['x']},{r['y']}"
                loc_v='' if r.get('x_vision') is None or r.get('y_vision') is None else f"{r['x_vision']},{r['y_vision']}"
                vals=(r.get('atlas_id'),r.get('alliance_tag') or '',r.get('pseudo_atlas') or '',loc_a,
                      r.get('pseudo_vision') or '',stxt,loc_v,ptxt,st,r.get('seen_at') or '')
                iid=tree.insert('', 'end', values=vals); r['_iid']=iid; cache.append(r)
            summary.set(f'Total {total}  |  Vérifiés {verified}  |  Partiels {partial}  |  Conflits {conflict}  |  Non vus {novision}')

        def selected_row():
            sel=tree.selection()
            if not sel: return None
            iid=sel[0]
            return next((r for r in cache if r.get('_iid')==iid),None)

        def open_shot(event=None):
            r=selected_row()
            if not r: return
            shot=r.get('screenshot')
            if not shot:
                messagebox.showinfo('Capture Vision','Aucune capture enregistrée pour cette ligne.',parent=win); return
            q=Path(shot)
            if not q.exists():
                messagebox.showwarning('Capture Vision',f'Capture introuvable :\n{q}',parent=win); return
            try: os.startfile(str(q))
            except Exception as e: messagebox.showerror('Capture Vision',str(e),parent=win)

        def export_csv():
            import sqlite3
            dest=filedialog.asksaveasfilename(parent=win,title='Exporter résultats Vision',defaultextension='.csv',
                                              filetypes=[('CSV','*.csv')],initialfile='clean_vision_results.csv')
            if not dest: return
            c=sqlite3.connect(str(path)); c.row_factory=sqlite3.Row
            rows=c.execute("""SELECT t.atlas_id,t.alliance_tag,t.pseudo_atlas,t.x AS x_atlas,t.y AS y_atlas,
                v.seen_at,v.pseudo_vision,v.pseudo_score,v.x_vision,v.y_vision,v.power_vision,v.status,v.screenshot,v.raw_text
                FROM atlas_targets t LEFT JOIN vision_results v ON v.atlas_id=t.atlas_id
                ORDER BY t.alliance_tag,t.pseudo_atlas""").fetchall(); c.close()
            names=list(rows[0].keys()) if rows else ['atlas_id','alliance_tag','pseudo_atlas','x_atlas','y_atlas','seen_at','pseudo_vision','pseudo_score','x_vision','y_vision','power_vision','status','screenshot','raw_text']
            with open(dest,'w',newline='',encoding='utf-8-sig') as fh:
                w=csv.writer(fh,delimiter=';'); w.writerow(names); [w.writerow([r[n] for n in names]) for r in rows]
            messagebox.showinfo('Export Vision',f'Export créé :\n{dest}',parent=win)

        btns=ttk.Frame(top); btns.pack(side='right')
        ttk.Button(btns,text='Actualiser',command=load_rows).pack(side='left',padx=3)
        ttk.Button(btns,text='Ouvrir capture',command=open_shot).pack(side='left',padx=3)
        ttk.Button(btns,text='Exporter CSV',command=export_csv).pack(side='left',padx=3)
        ttk.Button(btns,text='Ouvrir dossier DB',command=lambda: os.startfile(str(path.parent))).pack(side='left',padx=3)
        filter_box.bind('<<ComboboxSelected>>',load_rows)
        tree.bind('<Double-1>',open_shot)
        load_rows()

    def start_alliance_verification(self):
        if self.nav_thread and self.nav_thread.is_alive(): messagebox.showwarning('Vérification','Une navigation est déjà active.'); return
        if not self._nav_ready():return
        if not self._vision_zones_ready(True):return
        kid=self.get_kid(); tag=self.verify_alliance.get().strip()
        if kid is None or not tag:return
        rows=self.db.navigation_targets(kid,tag,False)
        if not rows: messagebox.showwarning('Vérification',f'Aucun membre [{tag}] avec coordonnées Atlas.'); return
        if not messagebox.askyesno('Vérifier alliance',f'Visiter automatiquement {len(rows)} membre(s) de [{tag}] ?\n\nWOS doit être ouvert et la carte accessible.'):return
        self.nav_config['dwell']=float(self.nav_dwell.get()); self._save_nav_config(); self.nav_stop.clear()
        try:
            if self.live.running:self.stop_live()
            self._ensure_nav_capture(kid,'alliance-verify')
        except Exception as e:messagebox.showerror('Capture WOS',str(e));return
        sid=self.session_id; before={r['atlas_id']:self.db.player_state(r['atlas_id']) for r in rows}; run_id=self.db.verification_create(sid,kid,tag,len(rows)); self.verify_status.set(f'[{tag}] 0/{len(rows)}')
        self.nav_thread=threading.Thread(target=self._verify_worker,args=(run_id,sid,tag,rows,before),daemon=True); self.nav_thread.start()
    def _verify_worker(self,run_id,sid,tag,rows,before):
        visited=seen=ok=missing=conflicts=0
        try:
            for i,r in enumerate(rows,1):
                if self.nav_stop.is_set():break
                trace_start=now(); raw_start=self.db.raw_protocol_max_id(sid)
                self._visit_xy(r['atlas_x'],r['atlas_y']); time.sleep(float(self.nav_dwell.get())); self._screen_power_fallback(r); visited+=1; self.events.put(('verifystatus',f'[{tag}] {i}/{len(rows)} — {r["pseudo_display"]} — ville ouverte')); self._close_city_panel()
                trace_file,nframes,ops=self.db.visit_trace_finish(sid,r,trace_start,raw_start,SESSIONS_DIR/sid/'visits')
                self.log(f'Trace visite A{r["atlas_id"]}: {nframes} trame(s) | {ops} | {trace_file}')
            # allow last response to arrive
            if not self.nav_stop.is_set():time.sleep(1.0)
            for r in rows[:visited]:
                after=self.db.player_state(r['atlas_id']); result,was_seen=self.db.verification_store_result(run_id,r,before.get(r['atlas_id']),after,sid); seen+=was_seen
                if result=='SEEN_OK':ok+=1
                elif result=='MISSING':missing+=1
                elif result=='CONFLICT':conflicts+=1
            self.db.verification_finish(run_id,visited,seen,ok,missing,conflicts,'STOPPED' if self.nav_stop.is_set() else 'DONE')
            self.events.put(('verifydone',(run_id,tag,visited,seen,ok,missing,conflicts)))
        except Exception as e:
            self.db.verification_finish(run_id,visited,seen,ok,missing,conflicts,'ERROR'); self.log(f'Verification [{tag}] interrompue: {e}'); self.events.put(('verifystatus',f'[{tag}] ERREUR: {e}'))
    def _show_verification_results(self,run_id):
        for x in self.verify_tree.get_children():self.verify_tree.delete(x)
        for r in self.db.verification_results_for_run(run_id):
            pw=f"{r['after_power']:,}" if r.get('after_power') else ''
            self.verify_tree.insert('', 'end', values=(r.get('pseudo_display') or '?',r['atlas_id'],r['result'],r.get('after_wos_id') or '',pw,r.get('detail') or ''))
    def _extract_atlas_cookie(self,text):
        text=(text or '').strip()
        if not text:
            return ''
        # Accepte soit la valeur Cookie brute, soit "Copy as cURL" (CMD/PowerShell).
        candidates=[]
        for pat in [r'-b\s+\^?"([^"\r\n]+)\^?"', r'--cookie\s+\^?"([^"\r\n]+)\^?"', r'cookie:\s*([^\r\n]+)']:
            m=re.search(pat,text,re.I)
            if m: candidates.append(m.group(1))
        candidates.append(text)
        for c in candidates:
            c=c.replace('^','').strip().strip('"').strip()
            if 'wos_at=' in c and 'wos_rt=' in c:
                # Ne conserve que les deux cookies WOS Atlas utiles.
                parts=[]
                for item in c.split(';'):
                    item=item.strip()
                    if item.startswith('wos_at=') or item.startswith('wos_rt='):
                        parts.append(item)
                if any(x.startswith('wos_at=') for x in parts) and any(x.startswith('wos_rt=') for x in parts):
                    return '; '.join(parts)
        return ''

    def configure_atlas_session(self):
        win=tk.Toplevel(self.root); win.title('Session WOS Atlas'); win.geometry('760x360'); win.transient(self.root); win.grab_set()
        ttk.Label(win,text='Colle ici Copy as cURL de WOS Atlas, ou uniquement les cookies wos_at + wos_rt.').pack(anchor='w',padx=12,pady=(12,4))
        ttk.Label(win,text='La session reste uniquement en mémoire pendant cette exécution et n’est pas enregistrée dans le ZIP ou la base.').pack(anchor='w',padx=12,pady=(0,8))
        txt=tk.Text(win,wrap='word',font=('Consolas',9),height=11); txt.pack(fill='both',expand=True,padx=12,pady=4)
        if self.atlas_cookie:
            txt.insert('1.0','wos_at=••••••; wos_rt=••••••')
        msg=tk.StringVar(value='')
        ttk.Label(win,textvariable=msg).pack(anchor='w',padx=12,pady=4)
        bar=ttk.Frame(win); bar.pack(fill='x',padx=12,pady=(2,12))
        def save():
            raw=txt.get('1.0','end').strip()
            if raw=='wos_at=••••••; wos_rt=••••••' and self.atlas_cookie:
                win.destroy(); return
            cookie=self._extract_atlas_cookie(raw)
            if not cookie:
                msg.set('Impossible de trouver wos_at et wos_rt dans ce texte.'); return
            self.atlas_cookie=cookie; self.atlas_session_status.set('Atlas: session configurée'); self.log('Session WOS Atlas configurée (cookies chargés en mémoire, valeurs masquées).'); win.destroy()
        def clear():
            self.atlas_cookie=''; self.atlas_session_status.set('Atlas: non connecté'); self.log('Session WOS Atlas effacée de la mémoire.'); win.destroy()
        ttk.Button(bar,text='Valider',command=save).pack(side='left'); ttk.Button(bar,text='Effacer session',command=clear).pack(side='left',padx=6); ttk.Button(bar,text='Annuler',command=win.destroy).pack(side='right')

    def get_kid(self):
        try:k=int(self.kid.get().strip()); assert k>0; return k
        except Exception: messagebox.showerror('État invalide','Saisis un numéro d’État WOS valide.'); return None
    def _poll(self):
        try:
            while True:
                kind,data=self.events.get_nowait()
                if kind=='log': self.logbox.insert('end',f'[{datetime.now().strftime("%H:%M:%S")}] {data}\n'); self.logbox.see('end')
                elif kind=='refresh': self.refresh(); self.status.set(data or 'Prêt')
                elif kind=='navprogress': self.nav_progress.set(str(data))
                elif kind=='verifystatus': self.verify_status.set(str(data))
                elif kind=='verifydone':
                    run_id,tag,visited,seen,ok,missing,conflicts=data; self.verify_status.set(f'[{tag}] visités {visited} | revus {seen} | OK {ok} | manquants {missing} | conflits {conflicts}'); self._show_verification_results(run_id); self.refresh()
        except queue.Empty: pass
        self.root.after(120,self._poll)
    def start_atlas_sync(self):
        kid=self.get_kid()
        if kid is None or self.atlas_busy:return
        if not self.atlas_cookie:
            messagebox.showwarning('Session WOS Atlas','Configure d’abord la session WOS Atlas avec le bouton « Session WOS Atlas » puis colle Copy as cURL de ton navigateur.'); self.configure_atlas_session(); return
        self.atlas_busy=True; self.status.set(f'Import Atlas État {kid}...'); threading.Thread(target=self._atlas_worker,args=(kid,),daemon=True).start()
    def _atlas_worker(self,kid):
        client=AtlasClient(self.log,self.atlas_cookie); run_id=None
        try:
            with self.db.lock,self.db.conn: run_id=self.db.conn.execute('INSERT INTO atlas_sync_runs(kid,started_at,status) VALUES(?,?,?)',(kid,now(),'RUNNING')).lastrowid
            lead=client.leaderboard(kid)
            if not isinstance(lead,dict):
                raise RuntimeError(f'ÉCHEC API ATLAS : impossible de récupérer la liste des alliances de l’État {kid}. Import annulé.')
            entries=lead.get('entries')
            if not isinstance(entries,list):
                raise RuntimeError(f'ÉCHEC API ATLAS : réponse leaderboard invalide pour l’État {kid} (champ entries absent/invalide). Import annulé.')
            self.log(f'Atlas État {kid}: {len(entries)} alliances trouvées.')
            uids=[]
            for idx,a in enumerate(entries,1):
                self.db.atlas_upsert_alliance(kid,a); payload=client.members(int(a['aid']), int(a.get('members') or 0))
                if not isinstance(payload,dict):
                    raise RuntimeError(f'ÉCHEC API ATLAS : impossible de récupérer les membres de {a.get("abbr") or a.get("aid")} (AID {a.get("aid")}).')
                abbr=payload.get('abbr') or a.get('abbr') or '?'
                if str(payload.get('viewerTier') or '').upper()=='ANONYMOUS':
                    raise RuntimeError('AUTH WOS ATLAS : la session est absente ou expirée (viewerTier=ANONYMOUS). Recopie un nouveau « Copy as cURL » depuis ton navigateur connecté à WOS Atlas.')
                members=payload.get('members')
                if not isinstance(members,list):
                    raise RuntimeError(f'ÉCHEC API ATLAS : réponse /members invalide pour {abbr} (AID {a.get("aid")}).')
                expected=int(a.get('members') or payload.get('memberCount') or 0)
                if expected>0 and not members:
                    raise RuntimeError(f"ÉCHEC API ATLAS : {abbr} annonce {expected} membre(s), mais /members renvoie une liste vide après 3 tentatives. Import arrêté au lieu d'enregistrer 0 membre.")
                for m in members:
                    if m.get('uid') is None or (m.get('kid') is not None and int(m.get('kid'))!=kid): continue
                    uids.append(self.db.atlas_upsert_member(kid,int(a['aid']),abbr,m))
                self.log(f'[{idx}/{len(entries)}] {abbr}: {len(members)} membres')
            uids=sorted(set(uids)); self.log(f'Atlas: {len(uids)} joueurs uniques. Historique + puissance...'); h_ok=p_ok=0
            enrich_errors=0
            for i,uid in enumerate(uids,1):
                try:
                    h=client.history(uid)
                    if isinstance(h,dict):
                        self.db.atlas_store_history(uid,h); h_ok+=1
                except Exception as e:
                    enrich_errors+=1
                    self.log(f'Atlas history UID {uid}: erreur non bloquante: {e}')
                try:
                    p=client.power(uid)
                    if isinstance(p,dict):
                        self.db.atlas_store_power(uid,p); p_ok+=1
                except Exception as e:
                    enrich_errors+=1
                    self.log(f'Atlas power UID {uid}: erreur non bloquante: {e}')
                if i%25==0:self.log(f'Joueurs enrichis {i}/{len(uids)} (erreurs non bloquantes: {enrich_errors})')
            if enrich_errors:
                self.log(f'Atlas: enrichissement terminé avec {enrich_errors} erreur(s) non bloquante(s); les joueurs valides ont été conservés.')
            with self.db.lock,self.db.conn:self.db.conn.execute('UPDATE atlas_sync_runs SET finished_at=?,alliances=?,players=?,histories=?,powers=?,status=? WHERE id=?',(now(),len(entries),len(uids),h_ok,p_ok,'OK',run_id))
            self.events.put(('refresh',f'Atlas {kid} terminé : {len(uids)} joueurs'))
        except Exception as e:
            self.log(f'Import Atlas interrompu: {e}')
            if run_id:
                with self.db.lock,self.db.conn:self.db.conn.execute('UPDATE atlas_sync_runs SET finished_at=?,status=? WHERE id=?',(now(),'ERROR',run_id))
        finally:self.atlas_busy=False
    def start_consolidation(self):
        kid=self.get_kid()
        if kid is None:return
        self.db.active_kid=kid
        n=self.db.queue_state(kid)
        if not self.live.running:
            sid=f'live_{kid}_{datetime.now().strftime("%Y%m%d_%H%M%S")}'; self.engine.reset(sid); self.engine.set_protocol_discovery(False); self.session_id=sid; self.capture_path=SESSIONS_DIR/f'{sid}.pcap'; self.db.start_session(sid,'live',str(self.capture_path))
            try:self.live.start('AUTO',self.capture_path)
            except Exception as e:messagebox.showerror('Capture WOS',str(e));return
        self.btn_stop.config(state='normal'); self.status.set(f'Consolidation LIVE active — {n} joueurs à enrichir'); self.log(f'Consolidation LIVE État {kid}: {n} joueurs en attente. Ouvre simplement le classement WOS. V4.0.10 utilise les affiliations Atlas déjà importées comme ancrage et ne doit plus exiger l’ouverture alliance par alliance.')
    def start_map_discovery(self):
        kid=self.get_kid()
        if kid is None:return
        self.db.active_kid=kid
        if self.live.running:
            messagebox.showwarning('Découverte CARTE','Arrête d’abord la capture en cours avant de lancer un test carte.'); return
        sid=f'map_{kid}_{datetime.now().strftime("%Y%m%d_%H%M%S")}'
        self.engine.reset(sid); self.engine.set_protocol_discovery(True); self.session_id=sid
        self.capture_path=SESSIONS_DIR/f'{sid}.pcap'; self.db.start_session(sid,'map-discovery',str(self.capture_path))
        try:self.live.start('AUTO',self.capture_path)
        except Exception as e:
            self.engine.set_protocol_discovery(False); messagebox.showerror('Capture WOS',str(e)); return
        self.btn_stop.config(state='normal'); self.status.set('Découverte CARTE active — capture exhaustive des opcodes WOS')
        self.log('Découverte CARTE : reste 5–10 s immobile, déplace la carte plusieurs fois, fais un zoom/dézoom, sans ouvrir ville/profil/alliance/classement, puis Arrêter capture.')

    def stop_live(self):
        if self.live.running:self.live.stop(); self.engine.finalize_session(); self.db.stop_session(self.session_id,self.engine.stats_data)
        self.engine.set_protocol_discovery(False)
        self.btn_stop.config(state='disabled'); self.status.set('Capture WOS arrêtée'); self.refresh()
    def refresh(self):
        kid=self.get_kid()
        if kid is None:return
        st=self.db.atlas_stats(kid)
        for k in ['alliances','players','atlas_power','wos','wos_power']: self.svars[k].set(str(st[k]))
        self.svars['pending'].set(str(self.db.pending_count(kid))); q=self.query.get().strip() if hasattr(self,'query') else ''
        if not hasattr(self,'tree'):return
        for x in self.tree.get_children(): self.tree.delete(x)
        for r in self.db.atlas_rows(kid,q):
            xy=f"{r['atlas_x'] if r['atlas_x'] is not None else '?'} / {r['atlas_y'] if r['atlas_y'] is not None else '?'}"; ap=f"{r['atlas_power']:,}" if r['atlas_power'] else ''; pw=f"{r['power']:,}" if r['power'] else ''
            self.tree.insert('', 'end', values=(r['pseudo_display'] or '?',r['alliance_tag'] or '?',r['atlas_id'],xy,r['atlas_level'] if r['atlas_level'] is not None else '?',ap,r['wos_id'] or '',pw))
    def export_csv(self):
        kid=self.get_kid()
        if kid is None:return
        f=filedialog.asksaveasfilename(initialdir=str(EXPORT_DIR),initialfile=f'WOS_Unified_{kid}_{datetime.now().strftime("%Y%m%d_%H%M%S")}.csv',defaultextension='.csv',filetypes=[('CSV','*.csv')])
        if f:self.db.export_unified_csv(kid,Path(f)); self.status.set(f'CSV exporté : {f}')
    def build_diagnostic_report(self):
        kid=self.get_kid()
        if kid is None:return 'État invalide.'
        st=self.db.atlas_stats(kid); pending=self.db.pending_count(kid)
        lines=[f'WOS Unified Manager V{APP_VERSION} — Rapport diagnostic',f'État: {kid}',f'Base persistante: {DB_PATH}','',
               '=== ATLAS ===',f"Alliances: {st['alliances']}",f"Joueurs: {st['players']}",f"Power Atlas: {st['atlas_power']}",'',
               '=== WOS ===',f"WOS ID vérifiés/connus: {st['wos']}",f"Power WOS: {st['wos_power']}",f"En attente consolidation: {pending}",'']
        with self.db.lock:
            # V4.0.20: re-opening the SAME alliance roster shows the decoder
            # the exact same bytes it already saw -- past the 2-confirmation
            # threshold, that adds zero new VERIFIED players, which is why
            # progress can plateau even during an active capture session.
            # Surface which alliances are least covered so the next play
            # session targets NEW ground instead of repeating old ground.
            cov=self.db.conn.execute("""
                SELECT a.abbr AS tag, a.member_count AS official,
                       COUNT(p.atlas_id) AS known,
                       SUM(CASE WHEN p.wos_id IS NOT NULL THEN 1 ELSE 0 END) AS verified
                FROM atlas_alliances a
                LEFT JOIN players p ON p.alliance_tag=a.abbr AND p.kid=a.kid
                WHERE a.kid=?
                GROUP BY a.abbr,a.member_count
                ORDER BY verified ASC, official DESC
                LIMIT 15
            """,(kid,)).fetchall()
            if cov:
                lines += ['=== ALLIANCES LES MOINS COUVERTES (ouvre celles-ci en priorité) ===']
                for r in cov:
                    lines.append(f"[{r['tag'] or '?'}] {r['verified']}/{r['official'] if r['official'] is not None else '?'} membres officiels vérifiés (connus en base: {r['known']})")
                lines += ['']
            sr=self.db.conn.execute("SELECT session_id,started_at,stopped_at,frames_7502,req_7902,req_7d02,member_blocks,roster_count FROM sessions ORDER BY rowid DESC LIMIT 1").fetchone()
            if sr:
                lines += ['=== DERNIÈRE SESSION LIVE ===']
                live_stats=dict(getattr(self.engine,'stats_data',{}) or {}) if self.live.running and sr['session_id']==self.session_id else {}
                for k in sr.keys():
                    v=live_stats.get(k,sr[k]) if k in ('frames_7502','req_7902','req_7d02','member_blocks','roster_count') else sr[k]
                    lines.append(f'{k}: {v}')
                if self.live.running: lines.append('capture_active: True (compteurs LIVE, sans attendre Arrêter capture)')
                lines += ['']
            rows=self.db.conn.execute("""SELECT p.atlas_id,p.pseudo_display,p.alliance_tag,p.wos_id,p.power,p.atlas_power
                FROM players p WHERE p.kid=? AND (p.wos_id IS NULL OR p.power IS NULL)
                ORDER BY COALESCE(p.atlas_power,0) DESC LIMIT 50""",(kid,)).fetchall()
            lines += [f'=== 50 PREMIERS NON CONSOLIDÉS ({len(rows)} affichés) ===']
            for r in rows:
                lines.append(f"A:{r['atlas_id']} | {r['pseudo_display'] or '?'} | [{r['alliance_tag'] or '?'}] | W:{r['wos_id'] or '?'} | PWOS:{r['power'] or '?'} | PATLAS:{r['atlas_power'] or '?'}")
            lines += ['']
            try:
                # V4.0.19: V4.0.17 grouped by "most recent logged status per
                # atlas_id", but that log records the outcome of ONE event --
                # not the player's current state. _identity_decision can log
                # "CONFLICT" or "UNRESOLVED"/"no-wos-candidate" for a given
                # frame while deliberately RETURNING the untouched, already-
                # correct established wos_id (see wos-identity-conflicts
                # quarantine, and the plain no-candidate branch). So a fully
                # verified player can show a non-VERIFIED "latest status"
                # simply because a later frame carried no candidate, or a
                # bogus one that was correctly rejected -- nothing was wrong
                # with their identity, only with reading the log as if it
                # were a live status field. This version reads the actual
                # current truth instead: players.wos_id itself, plus the
                # dedicated wos_identity_conflicts table for genuinely open
                # disputes, so it can never again disagree with the WOS
                # section above for the wrong reason.
                verified=int(st['wos'])
                not_verified=int(st['players'])-verified
                conflicted=self.db.conn.execute("""
                    SELECT COUNT(DISTINCT c.atlas_id) FROM wos_identity_conflicts c
                    JOIN players p ON p.atlas_id=c.atlas_id
                    WHERE p.kid=? AND p.wos_id IS NULL
                """,(kid,)).fetchone()[0]
                awaiting=max(0,not_verified-conflicted)
                lines += ['=== IDENTITÉ (état actuel, pas un historique d\'événements) ===',
                          f'VERIFIED (WOS ID confirmé): {verified}',
                          f'EN CONFLIT (candidature contestée, pas encore tranchée): {conflicted}',
                          f'EN ATTENTE (pas encore assez d\'observations): {awaiting}','']
            except Exception as e: lines += [f'Identité: indisponible ({e})','']
            try:
                sid = sr['session_id'] if sr else self.session_id
                raw_total=self.db.conn.execute("SELECT COUNT(*) FROM protocol_raw_events WHERE session_id=?",(sid,)).fetchone()[0]
                if raw_total:
                    lines += ['=== DÉCOUVERTE PROTOCOLE EXHAUSTIVE ===',f'Trames WOS réassemblées sauvegardées: {raw_total}']
                    hist=self.db.conn.execute("SELECT direction,opcode,COUNT(*) n,MIN(frame_len) min_len,MAX(frame_len) max_len,CAST(AVG(frame_len) AS INT) avg_len FROM protocol_raw_events WHERE session_id=? GROUP BY direction,opcode ORDER BY n DESC,direction,opcode",(sid,)).fetchall()
                    known={'7d02','5d02','7502','5502','7902','5902'}
                    for r in hist:
                        flag='CONNU' if (r['opcode'] or '').lower() in known else 'NOUVEAU'
                        lines.append(f"{r['direction']} | opcode={r['opcode']} | n={r['n']} | len={r['min_len']}..{r['max_len']} avg={r['avg_len']} | {flag}")
                    lines.append('--- ÉCHANTILLONS OPCODES NON CONNUS ---')
                    unknown=self.db.conn.execute("SELECT opcode,direction,COUNT(*) n FROM protocol_raw_events WHERE session_id=? AND LOWER(opcode) NOT IN ('7d02','5d02','7502','5502','7902','5902') GROUP BY opcode,direction ORDER BY n DESC LIMIT 30",(sid,)).fetchall()
                    if not unknown:
                        lines.append('Aucun opcode inconnu dans cette session.')
                    for u in unknown:
                        samples=self.db.conn.execute("SELECT seen_at,frame_len,payload_hex FROM protocol_raw_events WHERE session_id=? AND opcode=? AND direction=? ORDER BY id LIMIT 3",(sid,u['opcode'],u['direction'])).fetchall()
                        lines.append(f"OPCODE {u['opcode']} {u['direction']} n={u['n']}")
                        for x in samples:
                            hx=x['payload_hex'] or ''
                            shown=hx if len(hx)<=500 else hx[:500]+'...<tronqué>'
                            lines.append(f"  {x['seen_at']} len={x['frame_len']} hex={shown}")
                    lines.append('--- ÉCHANTILLONS BRUTS CARTE (S>C 7D02 / 7902) ---')
                    map_rows=self.db.conn.execute("""SELECT id,seen_at,opcode,frame_len,payload_hex
                        FROM protocol_raw_events WHERE session_id=? AND direction='S>C' AND LOWER(opcode) IN ('7d02','5d02','7902','5902')
                        ORDER BY frame_len DESC,id LIMIT 20""",(sid,)).fetchall()
                    if not map_rows:
                        lines.append('Aucune grosse réponse carte sauvegardée dans cette session.')
                    for x in map_rows:
                        hx=x['payload_hex'] or ''
                        # V4.0.14: deliberately keep the FULL hex. This diagnostic is for reverse engineering,
                        # not for compact human reading; truncating it destroyed the useful evidence in V4.0.13.
                        lines.append(f"MAPRSP id={x['id']} {x['seen_at']} opcode={x['opcode']} len={x['frame_len']} hex={hx}")
                        # Context: show the closest preceding client request and following server frames.
                        prev=self.db.conn.execute("""SELECT id,seen_at,direction,opcode,frame_len,payload_hex FROM protocol_raw_events
                            WHERE session_id=? AND id<? AND direction='C>S' ORDER BY id DESC LIMIT 1""",(sid,x['id'])).fetchone()
                        if prev:
                            lines.append(f"  PREVREQ id={prev['id']} {prev['seen_at']} opcode={prev['opcode']} len={prev['frame_len']} hex={prev['payload_hex'] or ''}")
                        foll=self.db.conn.execute("""SELECT id,seen_at,direction,opcode,frame_len,payload_hex FROM protocol_raw_events
                            WHERE session_id=? AND id>? ORDER BY id LIMIT 2""",(sid,x['id'])).fetchall()
                        for y in foll:
                            lines.append(f"  NEXT id={y['id']} {y['seen_at']} {y['direction']} opcode={y['opcode']} len={y['frame_len']} hex={y['payload_hex'] or ''}")
                    lines += ['']
            except Exception as e:
                lines += [f'Découverte protocole: indisponible ({e})','']
            try:
                ms,mrows=self.db.map_session_stats(sid)
                lines += ['=== DÉCODEUR MAP V4.0.15 ===',
                          f"Blocs ancrés Atlas: {ms.get('n',0)} | joueurs uniques: {ms.get('players',0)} | ancres Atlas-ID strictes: {ms.get('atlas_id_anchors',0)} | candidats WOS: {ms.get('wos_candidates',0)} | paires structurelles valides: {ms.get('pair_valid',0)}"]
                if not mrows:
                    lines.append('Aucun bloc MAP ancré dans cette session.')
                else:
                    for r in mrows:
                        lines.append(f"MAP A:{r.get('atlas_id')} | {r.get('pseudo_display') or '?'} [{r.get('alliance_tag') or '?'}] | XY:{r.get('atlas_x')},{r.get('atlas_y')} | anchor={r.get('anchor_kind')} | decA={r.get('decoded_atlas_id') or '?'} Wcand={r.get('decoded_wos_id') or '?'} Pcand={r.get('decoded_power') or '?'} conf={r.get('wos_confidence') or '?'} pair={r.get('pair_valid')} | x{r.get('sightings')}")
                lines.append('')
            except Exception as e:
                lines += [f'Décodeur MAP: indisponible ({e})','']
            try:
                sid = sr['session_id'] if sr else self.session_id
                txrows=self.db.conn.execute("SELECT rowid,seen_at,direction,opcode,payload_hex,note FROM protocol_events WHERE session_id=? AND opcode IN ('7d02','5d02','7502','5502') ORDER BY rowid",(sid,)).fetchall()
                req_total=req_targets=resp_total=resp_counters=0
                req_by_ctr={}
                resp_by_ctr={}
                raw_responses=[]
                for r in txrows:
                    try: raw=bytes.fromhex(r['payload_hex'] or '')
                    except Exception: raw=b''
                    op=(r['opcode'] or '').lower()
                    if op in ('7d02','5d02') and r['direction']=='C>S':
                        req_total+=1
                        target=self.engine._request_7d_single_target(raw)
                        counter=self.engine._request_7d_counter(raw)
                        if target is not None: req_targets+=1
                        if counter is not None:
                            req_by_ctr.setdefault(counter.hex(),[]).append((r,target,raw))
                    elif op in ('7502','5502') and r['direction']=='S>C':
                        resp_total+=1
                        counter=self.engine._response_7502_counter(raw)
                        if counter is not None:
                            resp_counters+=1
                            resp_by_ctr.setdefault(counter.hex(),[]).append((r,raw))
                        raw_responses.append((r,counter,raw))
                lines += ['=== DIAGNOSTIC TRANSACTIONS 7D02/7502 ===',
                          f'7D02 session: {req_total} | cibles Atlas décodées: {req_targets}',
                          f'7502 sauvegardées: {resp_total} | compteurs décodés: {resp_counters}']
                targeted=[]
                for ctr,items in req_by_ctr.items():
                    for rr,target,reqraw in items:
                        if target is None: continue
                        responses=resp_by_ctr.get(ctr,[])
                        lines.append(f"TARGET A:{target} ctr={ctr} req={rr['seen_at']} len={len(reqraw)} responses={len(responses)} reqhex={reqraw.hex()}")
                        for rsp,raw in responses[:4]:
                            lines.append(f"  RSP {rsp['seen_at']} len={len(raw)} note={rsp['note'] or ''} hex={raw.hex()}")
                        targeted.append((target,ctr))
                if not targeted:
                    lines.append('Aucune paire ciblée complète dans cette session.')
                # V4.0.11: expose raw request/response pairs even when the Atlas target decoder
                # does not understand this 7D02 variant. The transaction counter itself is
                # authoritative for pairing and lets us reverse-engineer the target encoding.
                lines.append('--- PAIRES BRUTES 7D02 -> 7502 (même compteur) ---')
                pair_count=0
                for ctr,items in req_by_ctr.items():
                    responses=resp_by_ctr.get(ctr,[])
                    if not responses:
                        continue
                    for rr,target,reqraw in items:
                        pair_count += 1
                        lines.append(f"PAIR ctr={ctr} target={target if target is not None else '?'} req={rr['seen_at']} reqlen={len(reqraw)} responses={len(responses)}")
                        lines.append(f"  REQ hex={reqraw.hex()}")
                        for rsp,raw in responses[:2]:
                            lines.append(f"  RSP {rsp['seen_at']} len={len(raw)} note={rsp['note'] or ''} hex={raw.hex()}")
                        if pair_count >= 80:
                            break
                    if pair_count >= 80:
                        break
                lines.append(f'Paires compteur exact affichées: {pair_count}')
                if pair_count == 0:
                    lines.append('Aucune paire par compteur dans cette session.')
                # Always expose a few raw responses too, even if the counter decoder fails.
                lines.append('--- ÉCHANTILLON 7502 BRUTES ---')
                for r,counter,raw in raw_responses[-12:]:
                    lines.append(f"RSP {r['seen_at']} len={len(raw)} ctr={counter.hex() if counter else '?'} note={r['note'] or ''} hex={raw.hex()}")
                lines += ['']
            except Exception as e: lines += [f'Transactions: indisponibles ({e})','']
            try:
                ev=self.db.conn.execute("SELECT seen_at,direction,opcode,note FROM protocol_events ORDER BY rowid DESC LIMIT 120").fetchall()
                lines += ['=== 120 DERNIERS ÉVÉNEMENTS PROTOCOLE ===']
                for r in reversed(ev): lines.append(f"{r['seen_at']} | {r['direction']} | {r['opcode']} | {r['note'] or ''}")
            except Exception as e: lines += [f'Événements: indisponibles ({e})']
        return '\n'.join(lines)
    def show_diagnostic_report(self):
        report=self.build_diagnostic_report()
        win=tk.Toplevel(self.root); win.title('Rapport diagnostic copiable'); win.geometry('1050x750')
        txt=tk.Text(win,wrap='none'); txt.pack(fill='both',expand=True,padx=8,pady=8); txt.insert('1.0',report)
        bar=ttk.Frame(win); bar.pack(fill='x',padx=8,pady=(0,8))
        def copy_all():
            self.root.clipboard_clear(); self.root.clipboard_append(report); self.log('Rapport diagnostic copié dans le presse-papiers.')
        ttk.Button(bar,text='Copier tout',command=copy_all).pack(side='left')
        ttk.Button(bar,text='Fermer',command=win.destroy).pack(side='right')

    def export_diagnostic(self):
        kid=self.get_kid()
        if kid is None:return
        stamp=datetime.now().strftime('%Y%m%d_%H%M%S')
        default=f'WOS_Diagnostic_{kid}_{stamp}.zip'
        target=filedialog.asksaveasfilename(initialdir=str(DIAG_DIR),initialfile=default,defaultextension='.zip',filetypes=[('ZIP diagnostic','*.zip')])
        if not target:return
        target=Path(target)
        tmp=DIAG_DIR/f'_build_{kid}_{stamp}'
        try:
            if tmp.exists(): shutil.rmtree(tmp)
            tmp.mkdir(parents=True)
            # Snapshot SQLite cohérent, même si l'application continue à tourner.
            snap=tmp/'wos_unified.sqlite3'
            import sqlite3
            with self.db.lock:
                dst=sqlite3.connect(str(snap)); self.db.conn.backup(dst); dst.close()
            # Export joueurs de l'État sans dialogue supplémentaire.
            self.db.export_unified_csv(kid,tmp/f'WOS_Unified_{kid}.csv')
            # Journal visible: utile même si le PCAP n'est pas transférable.
            (tmp/'journal.txt').write_text(self.logbox.get('1.0','end-1c'),encoding='utf-8')
            # Résumé machine + session + compteurs, sans cookies/token Atlas.
            st=self.db.atlas_stats(kid)
            with self.db.lock:
                sessions=[dict(r) for r in self.db.conn.execute('SELECT * FROM sessions ORDER BY started_at DESC LIMIT 10')]
                syncs=[dict(r) for r in self.db.conn.execute('SELECT * FROM atlas_sync_runs WHERE kid=? ORDER BY id DESC LIMIT 10',(kid,))]
                pending=self.db.pending_count(kid)
                conflicts=[]
                try: conflicts=[dict(r) for r in self.db.conn.execute('SELECT * FROM wos_identity_conflicts ORDER BY id DESC LIMIT 200')]
                except Exception: pass
            summary={'app_version':APP_VERSION,'created_at':now(),'kid':kid,'stats':st,'pending':pending,'active_session_id':self.session_id or None,'capture_path':str(self.capture_path) if self.capture_path else None,'live_running':bool(self.live.running),'engine_stats':dict(getattr(self.engine,'stats_data',{}) or {}),'sessions':sessions,'atlas_sync_runs':syncs,'identity_conflicts':conflicts,'python':sys.version,'platform':platform.platform()}
            (tmp/'diagnostic.json').write_text(json.dumps(summary,ensure_ascii=False,indent=2,default=str),encoding='utf-8')
            # Inclure le PCAP de la session active/dernière s'il existe réellement.
            pcap=None
            if self.capture_path and Path(self.capture_path).exists(): pcap=Path(self.capture_path)
            elif sessions:
                cp=sessions[0].get('capture_path')
                if cp and Path(cp).exists(): pcap=Path(cp)
            if pcap: shutil.copy2(pcap,tmp/pcap.name)
            # Petit manifeste lisible.
            files_note=['diagnostic.json','journal.txt','wos_unified.sqlite3',f'WOS_Unified_{kid}.csv'] + ([pcap.name] if pcap else [])
            (tmp/'README_DIAGNOSTIC.txt').write_text('WOS Unified Manager diagnostic V'+APP_VERSION+'\nEtat: '+str(kid)+'\n\nFichiers:\n- '+'\n- '.join(files_note)+'\n\nSécurité: les cookies wos_at / wos_rt ne sont jamais inclus dans cet export.\n',encoding='utf-8')
            with zipfile.ZipFile(target,'w',zipfile.ZIP_DEFLATED) as z:
                for f in tmp.iterdir(): z.write(f,arcname=f.name)
            self.status.set(f'Diagnostic exporté : {target}')
            self.log(f'Export diagnostic créé: {target.name}'+(' (PCAP inclus)' if pcap else ' (aucun PCAP disponible)'))
            messagebox.showinfo('Diagnostic créé',f'Archive créée :\n{target}\n\nTu peux me transmettre uniquement ce ZIP.')
        except Exception as e:
            self.log(f'Erreur export diagnostic: {e}'); messagebox.showerror('Export diagnostic',str(e))
        finally:
            try:
                if tmp.exists(): shutil.rmtree(tmp)
            except Exception: pass

    def close(self):
        self.nav_stop.set()
        try:
            if self.live.running:self.stop_live()
        finally:self.root.destroy()
    def run(self):self.root.mainloop()

def main(): App().run()
if __name__=='__main__': main()
