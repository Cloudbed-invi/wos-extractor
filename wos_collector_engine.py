#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
WOS State Collector V3.34.6 Structural Roster Identity PCAP Fix (Historical players + authoritative current roster)
===================================

But:
- capture en direct le trafic WOS TCP/30101 (Npcap + Scapy sous Windows)
- reassemble les trames applicatives WOS
- detecte roster / 7902 / 7D02 / 7502
- decodes member records with the validated V2.1 engine
- stocke l'etat courant + historique dans SQLite
- exporte un CSV a la demande
- conserve un PCAP brut de session

IMPORTANT : V3.1 observe et decode automatiquement. L'emission active de
requests to WOS servers are intentionally disabled as long as the
structure de session / sequence / cache n'est pas totalement validee.

Fichiers requis dans le meme dossier :
  WOS_Alliance_Members_v2_3.py
  WOS_Analyzer_v9_6.py

Live Windows :
  pip install scapy
  Npcap installe (WinPcap API compatible recommande)
  lancer le .bat en administrateur si la capture ne demarre pas.
"""

from __future__ import annotations

import argparse
import csv
import importlib.util
import json
import itertools
import math
import os
import queue
import re
import sqlite3
import struct
import sys
import threading
import time
import traceback
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional, Tuple

APP_VERSION = '4.0.47'
GAME_PORT = 30101
BASE_DIR = Path(__file__).resolve().parent
DATA_DIR = BASE_DIR / "WOS_State_Collector_Data"
DB_PATH = DATA_DIR / "wos_state.sqlite3"
SESSIONS_DIR = DATA_DIR / "sessions"
EXPORT_DIR = DATA_DIR / "exports"

# Guard against known compact-power false positives (typically ~600M when a
# stuffing byte is retained as data). Override if needed with WOS_POWER_MAX.
POWER_HARD_CEILING = int(os.environ.get("WOS_POWER_MAX", "550000000"))


def utc_now() -> str:
    return datetime.now(timezone.utc).astimezone().isoformat(timespec="seconds")


def safe_name(s: str) -> str:
    s = re.sub(r"[^A-Za-z0-9_.-]+", "_", s.strip())
    return s[:80] or "session"


def load_module(path: Path, name: str):
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"Impossible de charger {path.name}")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


class DecoderBundle:
    def __init__(self, base_dir: Path):
        member_path = base_dir / "WOS_Alliance_Members_v2_3.py"
        core_path = base_dir / "WOS_Analyzer_v9_6.py"
        if not member_path.exists():
            raise FileNotFoundError(f"Fichier manquant : {member_path.name}")
        if not core_path.exists():
            raise FileNotFoundError(f"Fichier manquant : {core_path.name}")
        self.members = load_module(member_path, "wos_members_v23")
        self.core = load_module(core_path, "wos_core_v96")

    @staticmethod
    def decode_direct_alliance(block: bytes):
        """Decode the roster alliance TAG from the real 7502 member structure.

        V3.34.6 is grounded on live_20260831_232637.pcap.  The stable local
        marker is B5 1E DC (the byte immediately before it varies).  Just after
        this marker, the first declared length-03 field is the roster alliance
        TAG.  A second length-03 field may follow (observed SEA behind KOR) and
        MUST NOT be treated as the player's roster alliance.

        Protocol stuffing bytes may occur between printable characters, so we
        accept up to a few non-printable bytes while reconstructing exactly
        three uppercase/digit characters.  We intentionally inspect only the
        FIRST nearby length-03 field; this is what prevents KOR/SEA inversion.
        """
        marker=b"\xb5\x1e\xdc"
        pos=block.find(marker)
        if pos < 0:
            return "", "", None
        tail=block[pos+len(marker):pos+len(marker)+20]

        # In the captured member blocks the first 0x03 sits immediately after
        # the marker or behind 1-2 stuffing/control bytes.  Do not search later
        # fields: the following 0x03 is commonly SEA and is not the roster TAG.
        decl=None
        for i in range(min(4,len(tail))):
            if tail[i] == 0x03:
                decl=i
                break
        if decl is None:
            return "", "", None

        chars=[]
        for b in tail[decl+1:decl+8]:
            if (65 <= b <= 90) or (48 <= b <= 57):
                chars.append(chr(b))
                if len(chars) == 3:
                    break
        if len(chars) != 3:
            return "", "", None
        tag="".join(chars)
        if not re.fullmatch(r"[A-Z0-9]{3}", tag):
            return "", "", None
        return tag, "", 1.0

    def decode_member_block(self, block: bytes) -> dict:
        disp, cname, nkind, nstuff = self.members.compact_name(block, self.core)
        atlas = self.members.decode_member_atlas_id(block)
        atlas_detail = atlas.get("detail") or {}
        power = self.members.decode_member_power(block, atlas_detail)
        power_detail = power.get("detail") or {}
        # V3.1 power guard: keep the raw candidate for diagnostics but do not
        # publish obviously implausible values as HIGH. This specifically
        # prevents the 600M+ stuffing artefacts observed during the first live
        # state-wide capture. The ceiling is configurable via WOS_POWER_MAX.
        pval = power.get("power") or power.get("candidate") or ""
        try:
            pnum = int(pval) if pval not in (None, "") else None
        except Exception:
            pnum = None
        if pnum is not None and pnum > POWER_HARD_CEILING:
            power = dict(power)
            power["power"] = ""
            power["confidence"] = "suspect"
        wid = self.members.decode_member_wos_id(block)
        wid_detail = wid.get("detail") or {}

        # V3.34.6 AID<->WOS Structural Pair Guard.
        # The two IDs are accepted as an identity pair only when BOTH strict
        # decoders are HIGH and the WOS field is physically after the Atlas
        # field in the same compact member block, inside the observed metadata
        # window. This is stronger than validating each number independently.
        pair_valid=False
        pair_distance=None
        try:
            am_raw=atlas_detail.get("marker_offset")
            wm_raw=wid_detail.get("marker_offset")
            if am_raw in (None,"") or wm_raw in (None,""):
                raise ValueError("missing marker offset")
            am=int(am_raw)
            wm=int(wm_raw)
            pair_distance=wm-am
            pair_valid=(
                atlas.get("confidence")=="high"
                and wid.get("confidence")=="high"
                and 1 <= pair_distance <= 90
            )
        except Exception:
            pair_valid=False

        tag, alliance, alliance_score = self.core.reconstruct_alliance(block)
        # V3.23: generic direct decoder. The old analyzer only knew a small
        # hard-coded alliance dictionary; this reads the tag/name carried by
        # the player's own 7502/5502 block (e.g. WET / WARxEVL).
        direct_tag,direct_name,direct_score = self.decode_direct_alliance(block)
        if direct_tag:
            tag,alliance,alliance_score=direct_tag,direct_name,direct_score
        return {
            "pseudo_display": disp or "",
            "pseudo_core": cname or "",
            "name_encoding": nkind or "",
            "atlas_id": atlas.get("atlas_id") or "",
            "atlas_confidence": atlas.get("confidence") or "",
            "wos_id": wid.get("wos_id") or "",
            "wos_id_candidate": wid.get("candidate") or "",
            "wos_confidence": wid.get("confidence") or "",
            "identity_pair_valid": pair_valid,
            "identity_pair_distance": pair_distance if pair_distance is not None else "",
            "power": power.get("power") or "",
            "power_candidate": power.get("candidate") or "",
            "power_confidence": power.get("confidence") or "",
            "alliance_tag": tag or "",
            "alliance_name": alliance or "",
            "alliance_score": alliance_score if alliance_score is not None else "",
            "atlas_encoded_hex": atlas_detail.get("encoded_hex", ""),
            "wos_encoded_hex": wid_detail.get("encoded_hex", ""),
            "power_encoded_hex": power_detail.get("encoded_hex", ""),
            "raw_block_hex": block.hex(),
            "block_len": len(block),
        }


class StateDB:
    def __init__(self, path: Path):
        path.parent.mkdir(parents=True, exist_ok=True)
        self.path = path
        self.lock = threading.RLock()
        self.conn = sqlite3.connect(str(path), check_same_thread=False)
        self.conn.row_factory = sqlite3.Row
        self._init_schema()
        self._sanitize_existing_power()
        self._sanitize_legacy_map_power()
        self._merge_existing_wos_duplicates()

    def _init_schema(self):
        with self.lock, self.conn:
            self.conn.executescript(
                """
                PRAGMA journal_mode=WAL;
                CREATE TABLE IF NOT EXISTS players (
                    atlas_id INTEGER PRIMARY KEY,
                    wos_id INTEGER,
                    pseudo_display TEXT,
                    pseudo_core TEXT,
                    power INTEGER,
                    alliance_tag TEXT,
                    alliance_name TEXT,
                    first_seen TEXT NOT NULL,
                    last_seen TEXT NOT NULL,
                    last_session TEXT,
                    source_kind TEXT,
                    wos_confidence TEXT,
                    power_confidence TEXT
                );
                DROP INDEX IF EXISTS idx_players_wos_id;
                CREATE INDEX IF NOT EXISTS idx_players_wos_id
                    ON players(wos_id) WHERE wos_id IS NOT NULL;
                CREATE INDEX IF NOT EXISTS idx_players_alliance
                    ON players(alliance_tag);

                CREATE TABLE IF NOT EXISTS wos_identity_conflicts (
                    atlas_id INTEGER NOT NULL,
                    candidate_wos_id INTEGER NOT NULL,
                    first_seen TEXT NOT NULL,
                    last_seen TEXT NOT NULL,
                    confirmations INTEGER NOT NULL DEFAULT 1,
                    last_session TEXT,
                    last_source TEXT,
                    PRIMARY KEY(atlas_id,candidate_wos_id)
                );

                CREATE TABLE IF NOT EXISTS identity_observations (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    session_id TEXT,
                    seen_at TEXT NOT NULL,
                    atlas_id INTEGER NOT NULL,
                    candidate_wos_id INTEGER,
                    accepted_wos_id INTEGER,
                    status TEXT NOT NULL,
                    reason TEXT,
                    source_kind TEXT,
                    alliance_tag TEXT,
                    pseudo_display TEXT,
                    power INTEGER,
                    wos_confidence TEXT,
                    pair_valid INTEGER DEFAULT 0
                );
                CREATE INDEX IF NOT EXISTS idx_identity_obs_atlas
                    ON identity_observations(atlas_id,seen_at);
                CREATE INDEX IF NOT EXISTS idx_identity_obs_wos
                    ON identity_observations(candidate_wos_id,seen_at);

                CREATE TABLE IF NOT EXISTS power_observations (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    session_id TEXT,
                    seen_at TEXT NOT NULL,
                    atlas_id INTEGER NOT NULL,
                    candidate_power INTEGER NOT NULL,
                    source_kind TEXT,
                    confidence TEXT
                );
                CREATE INDEX IF NOT EXISTS idx_power_obs_atlas
                    ON power_observations(atlas_id,seen_at);

                CREATE TABLE IF NOT EXISTS atlas_aliases (
                    atlas_id INTEGER PRIMARY KEY,
                    canonical_atlas_id INTEGER NOT NULL,
                    wos_id INTEGER,
                    first_seen TEXT NOT NULL,
                    last_seen TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_alias_wos ON atlas_aliases(wos_id);

                CREATE TABLE IF NOT EXISTS history (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    atlas_id INTEGER NOT NULL,
                    seen_at TEXT NOT NULL,
                    session_id TEXT,
                    pseudo_display TEXT,
                    pseudo_core TEXT,
                    wos_id INTEGER,
                    power INTEGER,
                    alliance_tag TEXT,
                    alliance_name TEXT,
                    source_kind TEXT,
                    UNIQUE(atlas_id, seen_at, session_id)
                );

                CREATE TABLE IF NOT EXISTS sessions (
                    session_id TEXT PRIMARY KEY,
                    started_at TEXT NOT NULL,
                    stopped_at TEXT,
                    mode TEXT,
                    capture_path TEXT,
                    frames_7502 INTEGER DEFAULT 0,
                    req_7902 INTEGER DEFAULT 0,
                    req_7d02 INTEGER DEFAULT 0,
                    member_blocks INTEGER DEFAULT 0,
                    roster_count INTEGER DEFAULT 0
                );

                CREATE TABLE IF NOT EXISTS protocol_events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    session_id TEXT,
                    seen_at TEXT NOT NULL,
                    direction TEXT,
                    opcode TEXT,
                    seq INTEGER,
                    payload_hex TEXT,
                    note TEXT
                );

                CREATE TABLE IF NOT EXISTS protocol_raw_events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    session_id TEXT NOT NULL,
                    seen_at TEXT NOT NULL,
                    direction TEXT NOT NULL,
                    opcode TEXT,
                    frame_len INTEGER NOT NULL,
                    payload_hex TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_protocol_raw_session_opcode
                    ON protocol_raw_events(session_id,opcode,direction);

                CREATE TABLE IF NOT EXISTS refresh_queue (
                    atlas_id INTEGER PRIMARY KEY,
                    wos_id INTEGER,
                    pseudo_display TEXT,
                    alliance_tag TEXT,
                    reason TEXT NOT NULL,
                    status TEXT NOT NULL DEFAULT 'pending',
                    first_queued TEXT NOT NULL,
                    last_queued TEXT NOT NULL,
                    resolved_at TEXT,
                    last_session TEXT
                );
                CREATE INDEX IF NOT EXISTS idx_refresh_status ON refresh_queue(status);

                CREATE TABLE IF NOT EXISTS alliance_memberships (
                    session_id TEXT NOT NULL,
                    alliance_tag TEXT NOT NULL,
                    alliance_name TEXT,
                    atlas_id INTEGER NOT NULL,
                    source TEXT NOT NULL,
                    confidence TEXT NOT NULL,
                    seen_at TEXT NOT NULL,
                    PRIMARY KEY(session_id,alliance_tag,atlas_id)
                );
                CREATE INDEX IF NOT EXISTS idx_membership_session_tag
                    ON alliance_memberships(session_id,alliance_tag);

                CREATE TABLE IF NOT EXISTS current_roster (
                    alliance_tag TEXT NOT NULL,
                    alliance_name TEXT,
                    atlas_id INTEGER NOT NULL,
                    verified_session TEXT NOT NULL,
                    verified_at TEXT NOT NULL,
                    PRIMARY KEY(alliance_tag,atlas_id)
                );
                CREATE INDEX IF NOT EXISTS idx_current_roster_atlas
                    ON current_roster(atlas_id);

                CREATE TABLE IF NOT EXISTS state_discovery (
                    atlas_id INTEGER PRIMARY KEY,
                    wos_id INTEGER,
                    pseudo_display TEXT,
                    power INTEGER,
                    alliance_tag TEXT,
                    first_seen TEXT NOT NULL,
                    last_seen TEXT NOT NULL,
                    sightings INTEGER NOT NULL DEFAULT 1,
                    last_session TEXT,
                    last_source TEXT,
                    last_opcode TEXT,
                    profile_resolved INTEGER NOT NULL DEFAULT 0,
                    discovered_via TEXT
                );
                CREATE INDEX IF NOT EXISTS idx_state_discovery_wos ON state_discovery(wos_id);
                CREATE INDEX IF NOT EXISTS idx_state_discovery_alliance ON state_discovery(alliance_tag);

                CREATE TABLE IF NOT EXISTS alliance_discovery (
                    alliance_id INTEGER PRIMARY KEY,
                    alliance_tag TEXT,
                    alliance_name TEXT,
                    first_seen TEXT NOT NULL,
                    last_seen TEXT NOT NULL,
                    sightings INTEGER NOT NULL DEFAULT 1,
                    last_session TEXT,
                    last_opcode TEXT,
                    discovered_via TEXT
                );
                CREATE INDEX IF NOT EXISTS idx_alliance_discovery_tag ON alliance_discovery(alliance_tag);

                CREATE TABLE IF NOT EXISTS alliance_roster_coverage (
                    alliance_tag TEXT PRIMARY KEY,
                    alliance_id INTEGER,
                    alliance_name TEXT,
                    announced_members INTEGER,
                    last_roster_session TEXT,
                    last_roster_seen TEXT,
                    roster_sightings INTEGER NOT NULL DEFAULT 0
                );
                CREATE INDEX IF NOT EXISTS idx_alliance_roster_coverage_id
                    ON alliance_roster_coverage(alliance_id);

                CREATE TABLE IF NOT EXISTS raw_diag_runs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT, session_id TEXT,
                    target_atlas_id INTEGER, target_pseudo TEXT, alliance_tag TEXT,
                    started_at TEXT NOT NULL, stopped_at TEXT, packet_count INTEGER DEFAULT 0,
                    client_bytes INTEGER DEFAULT 0, server_bytes INTEGER DEFAULT 0, note TEXT
                );
                CREATE TABLE IF NOT EXISTS raw_diag_packets (
                    id INTEGER PRIMARY KEY AUTOINCREMENT, run_id INTEGER NOT NULL,
                    seen_at TEXT NOT NULL, direction TEXT NOT NULL, src_port INTEGER,
                    dst_port INTEGER, tcp_seq INTEGER, payload_len INTEGER NOT NULL,
                    payload_hex TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_raw_diag_run ON raw_diag_packets(run_id,id);

                CREATE TABLE IF NOT EXISTS request_builder_tests (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    session_id TEXT,
                    atlas_id INTEGER,
                    wos_id INTEGER,
                    pseudo_display TEXT,
                    alliance_tag TEXT,
                    armed_at TEXT NOT NULL,
                    last_counter INTEGER,
                    predicted_counter INTEGER,
                    predicted_hex TEXT,
                    actual_counter INTEGER,
                    actual_hex TEXT,
                    result TEXT DEFAULT 'armed',
                    checked_at TEXT,
                    note TEXT
                );
                CREATE INDEX IF NOT EXISTS idx_request_builder_session
                    ON request_builder_tests(session_id,id);

                CREATE TABLE IF NOT EXISTS counter_lab_runs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    session_id TEXT,
                    target_atlas_id INTEGER,
                    target_wos_id INTEGER,
                    target_pseudo TEXT,
                    alliance_tag TEXT,
                    started_at TEXT NOT NULL,
                    stopped_at TEXT,
                    expected_count INTEGER DEFAULT 5,
                    captured_count INTEGER DEFAULT 0,
                    note TEXT
                );
                CREATE TABLE IF NOT EXISTS counter_lab_events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    run_id INTEGER NOT NULL,
                    seq_index INTEGER NOT NULL,
                    seen_at TEXT NOT NULL,
                    kind TEXT NOT NULL,
                    direction TEXT,
                    opcode TEXT,
                    frame_hex TEXT,
                    dynamic_hex TEXT,
                    dynamic_value INTEGER,
                    target_hex TEXT
                );
                CREATE INDEX IF NOT EXISTS idx_counter_lab_run
                    ON counter_lab_events(run_id,id);

                CREATE TABLE IF NOT EXISTS sequence_lab_runs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    session_id TEXT,
                    started_at TEXT NOT NULL,
                    stopped_at TEXT,
                    expected_count INTEGER DEFAULT 0,
                    captured_count INTEGER DEFAULT 0,
                    note TEXT
                );
                CREATE TABLE IF NOT EXISTS sequence_lab_events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    run_id INTEGER NOT NULL,
                    seq_index INTEGER NOT NULL,
                    seen_at TEXT NOT NULL,
                    atlas_id INTEGER,
                    wos_id INTEGER,
                    pseudo_display TEXT,
                    alliance_tag TEXT,
                    request_hex TEXT NOT NULL,
                    dynamic_hex TEXT,
                    target_hex TEXT,
                    FOREIGN KEY(run_id) REFERENCES sequence_lab_runs(id)
                );
                CREATE INDEX IF NOT EXISTS idx_sequence_lab_run
                    ON sequence_lab_events(run_id,seq_index);

                CREATE TABLE IF NOT EXISTS active_lab_attempts (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    session_id TEXT,
                    target_atlas_id INTEGER,
                    target_wos_id INTEGER,
                    target_pseudo TEXT,
                    alliance_tag TEXT,
                    armed_at TEXT NOT NULL,
                    request_seen_at TEXT,
                    request_hex TEXT,
                    response_seen_at TEXT,
                    response_atlas_id INTEGER,
                    response_wos_id INTEGER,
                    response_power INTEGER,
                    result TEXT NOT NULL DEFAULT 'armed',
                    note TEXT
                );
                CREATE INDEX IF NOT EXISTS idx_active_lab_session ON active_lab_attempts(session_id,id);
                CREATE TABLE IF NOT EXISTS active_lab_candidates (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    attempt_id INTEGER NOT NULL,
                    seen_at TEXT NOT NULL,
                    atlas_id INTEGER,
                    wos_id INTEGER,
                    pseudo_display TEXT,
                    power INTEGER,
                    source_kind TEXT,
                    atlas_match INTEGER NOT NULL DEFAULT 0,
                    wos_match INTEGER NOT NULL DEFAULT 0,
                    pseudo_match INTEGER NOT NULL DEFAULT 0,
                    score INTEGER NOT NULL DEFAULT 0,
                    note TEXT
                );
                CREATE INDEX IF NOT EXISTS idx_active_lab_candidates_attempt
                    ON active_lab_candidates(attempt_id,id);
                """
            )

    def _sanitize_existing_power(self):
        """Downgrade already-stored power values above the configured ceiling.

        V3.0 may have persisted compact-field false positives around 600M+.
        We keep the player/history but clear that current Power so a future
        fresh observation can repopulate it safely.
        """
        with self.lock, self.conn:
            self.conn.execute(
                """UPDATE players SET power=NULL, power_confidence='suspect'
                   WHERE power IS NOT NULL AND power>?""",
                (POWER_HARD_CEILING,),
            )

    def _sanitize_legacy_map_power(self):
        """V4.0.24: MAP Pcand is not a decoded total-power field.

        V4.0.15-4.0.23 could persist the first plausible compact integer after
        an Atlas marker as player Power.  Captures proved values such as
        Lambda=35,425,144 and Maverik=37,391,194 are secondary fields, not
        total power.  Clear only current values whose winning source is MAP;
        raw observations remain available for diagnostics/history.
        """
        with self.lock, self.conn:
            self.conn.execute(
                """UPDATE players SET power=NULL, power_confidence='map-field-unverified'
                   WHERE power IS NOT NULL AND source_kind LIKE 'map-%'"""
            )

    def _merge_existing_wos_duplicates(self):
        """Collapse legacy duplicate player rows that share the same WOS ID.

        WOS ID is the stable player identity when it was decoded HIGH. Atlas
        representations can vary with compact stuffing. The oldest Atlas row
        is retained as canonical and the others are recorded as aliases.
        """
        now=utc_now()
        with self.lock, self.conn:
            groups=self.conn.execute(
                "SELECT wos_id, GROUP_CONCAT(atlas_id), COUNT(*) FROM players "
                "WHERE wos_id IS NOT NULL GROUP BY wos_id HAVING COUNT(*)>1"
            ).fetchall()
            for wos_id, ids_csv, _ in groups:
                ids=[int(x) for x in str(ids_csv).split(',') if x]
                rows=[self.conn.execute("SELECT * FROM players WHERE atlas_id=?",(a,)).fetchone() for a in ids]
                rows=[r for r in rows if r is not None]
                if len(rows)<2: continue
                # Prefer richer row, then oldest first_seen as stable canonical.
                def quality(r):
                    return (
                        1 if r['pseudo_display'] else 0,
                        1 if r['power'] is not None else 0,
                        1 if r['alliance_tag'] else 0,
                        1 if r['wos_confidence']=='high' else 0,
                    )
                canonical=sorted(rows,key=lambda r:(quality(r), str(r['first_seen'])),reverse=True)[0]
                cid=int(canonical['atlas_id'])
                for r in rows:
                    aid=int(r['atlas_id'])
                    if aid==cid: continue
                    self.conn.execute(
                        "INSERT OR REPLACE INTO atlas_aliases(atlas_id,canonical_atlas_id,wos_id,first_seen,last_seen) VALUES(?,?,?,?,?)",
                        (aid,cid,wos_id,r['first_seen'] or now,r['last_seen'] or now)
                    )
                    # Fill missing canonical values before deleting duplicate.
                    self.conn.execute(
                        """UPDATE players SET
                        pseudo_display=COALESCE(pseudo_display,?), pseudo_core=COALESCE(pseudo_core,?),
                        power=COALESCE(power,?), alliance_tag=COALESCE(alliance_tag,?),
                        alliance_name=COALESCE(alliance_name,?), last_seen=MAX(last_seen,?)
                        WHERE atlas_id=?""",
                        (r['pseudo_display'],r['pseudo_core'],r['power'],r['alliance_tag'],r['alliance_name'],r['last_seen'],cid)
                    )
                    self.conn.execute("DELETE FROM players WHERE atlas_id=?",(aid,))

    def start_session(self, session_id: str, mode: str, capture_path: str):
        with self.lock, self.conn:
            self.conn.execute(
                "INSERT OR REPLACE INTO sessions(session_id,started_at,mode,capture_path) VALUES(?,?,?,?)",
                (session_id, utc_now(), mode, capture_path),
            )

    def stop_session(self, session_id: str, stats: dict):
        with self.lock, self.conn:
            self.conn.execute(
                """UPDATE sessions SET stopped_at=?, frames_7502=?, req_7902=?, req_7d02=?,
                   member_blocks=?, roster_count=? WHERE session_id=?""",
                (
                    utc_now(), stats.get("frames_7502", 0), stats.get("req_7902", 0),
                    stats.get("req_7d02", 0), stats.get("member_blocks", 0),
                    stats.get("roster_count", 0), session_id,
                ),
            )

    def add_event(self, session_id: str, direction: str, opcode: str, seq, payload: bytes, note=""):
        with self.lock, self.conn:
            self.conn.execute(
                "INSERT INTO protocol_events(session_id,seen_at,direction,opcode,seq,payload_hex,note) VALUES(?,?,?,?,?,?,?)",
                (session_id, utc_now(), direction, opcode, seq, payload.hex(), note),
            )

    def add_raw_protocol_event(self, session_id: str, direction: str, opcode: str, payload: bytes):
        with self.lock, self.conn:
            self.conn.execute(
                "INSERT INTO protocol_raw_events(session_id,seen_at,direction,opcode,frame_len,payload_hex) VALUES(?,?,?,?,?,?)",
                (session_id, utc_now(), direction, opcode or "????", len(payload), payload.hex()),
            )
            # V3.19 migration: preserve existing Data folder/DB and extend discovery in place.
            cols={r[1] for r in self.conn.execute("PRAGMA table_info(state_discovery)").fetchall()}
            if "profile_resolved" not in cols:
                self.conn.execute("ALTER TABLE state_discovery ADD COLUMN profile_resolved INTEGER NOT NULL DEFAULT 0")
            if "discovered_via" not in cols:
                self.conn.execute("ALTER TABLE state_discovery ADD COLUMN discovered_via TEXT")
            self.conn.execute("""UPDATE state_discovery SET profile_resolved=1
                               WHERE wos_id IS NOT NULL OR pseudo_display IS NOT NULL OR power IS NOT NULL""")

    @staticmethod
    def _to_int(v):
        try:
            if v in (None, ""): return None
            return int(v)
        except Exception:
            return None

    @staticmethod
    def _is_explicit_source(source_kind: str) -> bool:
        return source_kind in {"profile-explicit","7502-profile-explicit","profile-correlated-primary"}

    def _record_identity_observation(self, session_id, row, source_kind,
                                     candidate_wos, accepted_wos, status, reason):
        atlas=self._to_int(row.get("atlas_id"))
        if atlas is None:
            return
        with self.lock, self.conn:
            self.conn.execute(
                """INSERT INTO identity_observations
                   (session_id,seen_at,atlas_id,candidate_wos_id,accepted_wos_id,
                    status,reason,source_kind,alliance_tag,pseudo_display,power,
                    wos_confidence,pair_valid)
                   VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                (session_id,utc_now(),atlas,self._to_int(candidate_wos),
                 self._to_int(accepted_wos),status,reason,source_kind,
                 row.get("alliance_tag") or None,row.get("pseudo_display") or None,
                 self._to_int(row.get("power")),row.get("wos_confidence") or None,
                 1 if row.get("identity_pair_valid") else 0)
            )

    def _identity_decision(self, row: dict, session_id: str, source_kind: str):
        """V3.34 generic pre-write identity validation.

        Decoder output is evidence, not truth. Existing Atlas identity is checked
        BEFORE any WOS-based aliasing. Passive contradictory rows are quarantined
        unless independently repeated. A WOS already owned by another established
        Atlas is never silently reassigned.
        """
        atlas=self._to_int(row.get("atlas_id"))
        candidate=self._to_int(row.get("wos_id") or row.get("wos_id_candidate"))
        conf=(row.get("wos_confidence") or "").lower()
        explicit=self._is_explicit_source(source_kind)
        pair=bool(row.get("identity_pair_valid"))

        if atlas is None:
            return None,"UNRESOLVED","missing-atlas"

        old=self.conn.execute("SELECT * FROM players WHERE atlas_id=?",(atlas,)).fetchone()
        established=self._to_int(old["wos_id"]) if old is not None else None

        if candidate is None:
            return established,"UNRESOLVED","no-wos-candidate"

        # Cross-Atlas uniqueness guard comes before alias/canonicalization.
        owner=self.conn.execute(
            "SELECT atlas_id FROM players WHERE wos_id=? AND atlas_id<>? LIMIT 1",
            (candidate,atlas)
        ).fetchone()
        if owner is not None:
            return established,"CONFLICT",f"wos-owned-by-atlas-{int(owner['atlas_id'])}"

        if established is None:
            # V3.34.6: one passive structural co-location is evidence, not proof.
            # Explicit profiles and exact default lord######### names remain
            # independently authoritative. Other passive HIGH pairs need two
            # identical observations before becoming VERIFIED.
            name_valid=(row.get("wos_validation")=="default-name")
            if explicit and conf=="high":
                return candidate,"VERIFIED","new-explicit-high"
            if name_valid and conf=="high":
                return candidate,"VERIFIED","new-default-name-high"
            if conf=="high" and pair:
                seen=self.conn.execute(
                    """SELECT COUNT(*) FROM identity_observations
                       WHERE atlas_id=? AND candidate_wos_id=? AND wos_confidence='high'""",
                    (atlas,candidate)
                ).fetchone()
                confirmations=(int(seen[0]) if seen else 0)+1
                if confirmations>=2:
                    return candidate,"VERIFIED",f"new-passive-confirmed-{confirmations}"
                return None,"PROVISIONAL","new-passive-high-1/2"
            return None,"PROVISIONAL",f"new-{conf or 'unresolved'}"

        if candidate==established:
            return established,"VERIFIED","matches-established"

        if explicit and conf=="high":
            return candidate,"VERIFIED","explicit-high-replacement"
        if row.get("wos_validation")=="default-name" and conf=="high":
            return candidate,"VERIFIED","default-name-high-replacement"

        # Contradiction: count evidence, but do not corrupt the established map.
        c=self.conn.execute(
            "SELECT confirmations FROM wos_identity_conflicts WHERE atlas_id=? AND candidate_wos_id=?",
            (atlas,candidate)
        ).fetchone()
        confirmations=(int(c[0])+1) if c else 1
        now=utc_now()
        self.conn.execute(
            """INSERT INTO wos_identity_conflicts
               (atlas_id,candidate_wos_id,first_seen,last_seen,confirmations,last_session,last_source)
               VALUES(?,?,?,?,?,?,?)
               ON CONFLICT(atlas_id,candidate_wos_id) DO UPDATE SET
                 last_seen=excluded.last_seen,
                 confirmations=excluded.confirmations,
                 last_session=excluded.last_session,
                 last_source=excluded.last_source""",
            (atlas,candidate,now,now,confirmations,session_id,source_kind)
        )
        required=5
        # A compact decoder error can repeat deterministically, so passive
        # repetition alone is not enough to rewrite an established WOS.
        return established,"CONFLICT",f"contradicts-established-{confirmations}/{required}-quarantined"

    def _power_decision(self, row: dict, session_id: str, source_kind: str, old):
        """V3.34.6 power validation independent from the compact decoder."""
        atlas=self._to_int(row.get("atlas_id"))
        candidate=self._to_int(row.get("power"))
        conf=(row.get("power_confidence") or "").lower()
        explicit=self._is_explicit_source(source_kind)
        if atlas is None or candidate is None:
            return None
        if conf not in ("","high"):
            return None

        established=self._to_int(old["power"]) if old is not None else None
        self.conn.execute(
            """INSERT INTO power_observations
               (session_id,seen_at,atlas_id,candidate_power,source_kind,confidence)
               VALUES(?,?,?,?,?,?)""",
            (session_id,utc_now(),atlas,candidate,source_kind,conf or "high")
        )

        if explicit:
            return candidate

        recent=self.conn.execute(
            """SELECT candidate_power FROM power_observations
               WHERE atlas_id=? ORDER BY id DESC LIMIT 6""",(atlas,)
        ).fetchall()
        close=sum(
            1 for r in recent
            if abs(int(r[0])-candidate) <= max(2_000_000,int(candidate*0.02))
        )

        if established is None:
            # Do not seed a player's stored power from one lone compact value.
            return candidate if close>=2 else None

        # Normal progression/noise can update immediately.
        if abs(candidate-established) <= max(5_000_000,int(established*0.15)):
            return candidate

        # Large jumps (e.g. 134M -> 285M artefact) need three corroborations.
        return candidate if close>=3 else established

    def upsert_player(self, row: dict, session_id: str, source_kind: str) -> bool:
        atlas = self._to_int(row.get("atlas_id"))
        if atlas is None:
            return False
        now = utc_now()
        incoming_wos_conf=(row.get("wos_confidence") or "").lower()
        candidate_wos=self._to_int(row.get("wos_id") or row.get("wos_id_candidate"))
        raw_power = self._to_int(row.get("power"))
        power = raw_power
        changed = False

        with self.lock, self.conn:
            accepted_wos,status,reason=self._identity_decision(row,session_id,source_kind)
            wos=self._to_int(accepted_wos)
            old = self.conn.execute("SELECT * FROM players WHERE atlas_id=?", (atlas,)).fetchone()
            power=self._power_decision(row,session_id,source_kind,old)

            # V4.0.17: a corroborated Power reading is still an orphan datum
            # if this Atlas has no accepted WOS ID at all yet -- neither from
            # this decision (wos) nor a prior session (old["wos_id"]). Writing
            # Power ahead of identity is exactly how "Power WOS" can outnumber
            # "WOS ID verifies/connus" in the diagnostic report (e.g. Chiefer:
            # PWOS set, W still "?"). Withhold it here; nothing is lost --
            # power_observations already logged every raw reading above, so
            # the value reappears on the very next decision once the WOS ID
            # itself clears its own confirmation threshold.
            established_wos=self._to_int(old["wos_id"]) if old is not None else None
            if power is not None and wos is None and established_wos is None:
                pass # power=None # V4.0.17 bypassed by Antigravity to allow Power-only updates!

            incoming = {
                "atlas_id": atlas,
                "wos_id": wos,
                "pseudo_display": row.get("pseudo_display") or None,
                "pseudo_core": row.get("pseudo_core") or None,
                "power": power,
                "alliance_tag": row.get("alliance_tag") or None,
                "alliance_name": row.get("alliance_name") or None,
            }

            # Record every identity decision for audit/quarantine diagnostics.
            self.conn.execute(
                """INSERT INTO identity_observations
                   (session_id,seen_at,atlas_id,candidate_wos_id,accepted_wos_id,
                    status,reason,source_kind,alliance_tag,pseudo_display,power,
                    wos_confidence,pair_valid)
                   VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                (session_id,now,atlas,candidate_wos,wos,status,reason,source_kind,
                 row.get("alliance_tag") or None,row.get("pseudo_display") or None,
                 raw_power,row.get("wos_confidence") or None,
                 1 if row.get("identity_pair_valid") else 0)
            )

            # A matching accepted observation clears stale alternatives.
            if old is not None and wos is not None and old["wos_id"] is not None and int(old["wos_id"])==int(wos):
                self.conn.execute(
                    "DELETE FROM wos_identity_conflicts WHERE atlas_id=? AND candidate_wos_id<>?",
                    (atlas,wos)
                )

            if old is None:
                self.conn.execute(
                    """INSERT INTO players(atlas_id,wos_id,pseudo_display,pseudo_core,power,alliance_tag,
                       alliance_name,first_seen,last_seen,last_session,source_kind,wos_confidence,power_confidence)
                       VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                    (
                        atlas, wos, incoming["pseudo_display"], incoming["pseudo_core"], power,
                        incoming["alliance_tag"], incoming["alliance_name"], now, now,
                        session_id, source_kind, row.get("wos_confidence"), row.get("power_confidence"),
                    ),
                )
                changed = True
            else:
                for k in ("wos_id", "pseudo_display", "pseudo_core", "power", "alliance_tag", "alliance_name"):
                    nv = incoming[k]
                    if nv is not None and nv != old[k]:
                        changed = True
                        break
                self.conn.execute(
                    """UPDATE players SET
                       wos_id=COALESCE(?,wos_id), pseudo_display=COALESCE(?,pseudo_display),
                       pseudo_core=COALESCE(?,pseudo_core), power=COALESCE(?,power),
                       alliance_tag=COALESCE(?,alliance_tag), alliance_name=COALESCE(?,alliance_name),
                       last_seen=?, last_session=?, source_kind=?,
                       wos_confidence=COALESCE(?,wos_confidence), power_confidence=COALESCE(?,power_confidence)
                       WHERE atlas_id=?""",
                    (
                        wos, incoming["pseudo_display"], incoming["pseudo_core"], power,
                        incoming["alliance_tag"], incoming["alliance_name"], now, session_id, source_kind,
                        row.get("wos_confidence"), row.get("power_confidence"), atlas,
                    ),
                )
            if changed:
                self.conn.execute(
                    """INSERT OR IGNORE INTO history(atlas_id,seen_at,session_id,pseudo_display,pseudo_core,
                       wos_id,power,alliance_tag,alliance_name,source_kind) VALUES(?,?,?,?,?,?,?,?,?,?)""",
                    (
                        atlas, now, session_id, incoming["pseudo_display"], incoming["pseudo_core"],
                        wos, power, incoming["alliance_tag"], incoming["alliance_name"], source_kind,
                    ),
                )
        return changed

    def queue_refresh(self, row: dict, session_id: str, reason: str):
        atlas=self._to_int(row.get("atlas_id"))
        if atlas is None:
            return
        now=utc_now()
        with self.lock, self.conn:
            self.conn.execute(
                """INSERT INTO refresh_queue(atlas_id,wos_id,pseudo_display,alliance_tag,reason,status,first_queued,last_queued,last_session)
                   VALUES(?,?,?,?,?,'pending',?,?,?)
                   ON CONFLICT(atlas_id) DO UPDATE SET
                     wos_id=COALESCE(excluded.wos_id,refresh_queue.wos_id),
                     pseudo_display=COALESCE(excluded.pseudo_display,refresh_queue.pseudo_display),
                     alliance_tag=COALESCE(excluded.alliance_tag,refresh_queue.alliance_tag),
                     reason=excluded.reason,status='pending',last_queued=excluded.last_queued,
                     resolved_at=NULL,last_session=excluded.last_session""",
                (atlas,self._to_int(row.get("wos_id")),row.get("pseudo_display") or None,
                 row.get("alliance_tag") or None,reason,now,now,session_id),
            )

    def resolve_refresh(self, atlas_id, session_id: str):
        atlas=self._to_int(atlas_id)
        if atlas is None:
            return
        with self.lock, self.conn:
            self.conn.execute(
                """UPDATE refresh_queue SET status='resolved',resolved_at=?,last_session=?
                   WHERE atlas_id=?""", (utc_now(),session_id,atlas)
            )

    def canonical_atlas(self, atlas_id):
        atlas=self._to_int(atlas_id)
        if atlas is None:
            return None
        with self.lock:
            row=self.conn.execute(
                "SELECT canonical_atlas_id FROM atlas_aliases WHERE atlas_id=?",(atlas,)
            ).fetchone()
        return int(row[0]) if row else atlas

    def record_membership(self, session_id: str, tag: str, name: str, atlas_ids, source="7902", confidence="verified"):
        tag=(tag or "").strip(); name=(name or "").strip()
        if not tag:
            return
        now=utc_now()
        ids=[]
        for aid in atlas_ids:
            ca=self.canonical_atlas(aid)
            if ca is not None:
                ids.append(ca)
        ids=set(ids)
        with self.lock, self.conn:
            for aid in ids:
                self.conn.execute(
                    """INSERT OR REPLACE INTO alliance_memberships
                       (session_id,alliance_tag,alliance_name,atlas_id,source,confidence,seen_at)
                       VALUES(?,?,?,?,?,?,?)""",
                    (session_id,tag,name or None,aid,source,confidence,now)
                )
                # Any verified membership observed in the CURRENT session is safe
                # to publish provisionally. A later complete roster atomically
                # replaces this alliance and removes stale entries.
                if confidence=="verified":
                    self.conn.execute(
                        "DELETE FROM current_roster WHERE atlas_id=? AND alliance_tag<>?",
                        (aid,tag)
                    )
                    self.conn.execute(
                        """INSERT OR REPLACE INTO current_roster
                           (alliance_tag,alliance_name,atlas_id,verified_session,verified_at)
                           VALUES(?,?,?,?,?)""",
                        (tag,name or None,aid,session_id,now)
                    )

    def reconcile_alliance_membership(self, session_id: str, tag: str, name: str, atlas_ids):
        """Publish a COMPLETE roster as the current authoritative membership.

        V3.5 deliberately separates historical player observations from current
        alliance membership. The players table keeps the last observed alliance
        for history/debugging, while current_roster is replaced atomically when
        a complete roster is verified.
        """
        tag=(tag or "").strip(); name=(name or "").strip()
        if not tag or not atlas_ids:
            return
        canon={self.canonical_atlas(a) for a in atlas_ids}
        canon={a for a in canon if a is not None}
        if not canon:
            return
        self.record_membership(session_id,tag,name,canon,"complete-roster","verified")
        now=utc_now()
        with self.lock, self.conn:
            # Replace only this alliance's CURRENT roster. Historical rows in
            # players/history are never deleted.
            self.conn.execute("DELETE FROM current_roster WHERE alliance_tag=?",(tag,))

            # A canonical player cannot be current member of two alliances at
            # once. Remove these Atlas IDs from any previously-current roster.
            placeholders=','.join('?' for _ in canon)
            canon_sorted=sorted(canon)
            if canon_sorted:
                self.conn.execute(
                    f"DELETE FROM current_roster WHERE atlas_id IN ({placeholders})",
                    canon_sorted
                )

            for aid in canon_sorted:
                self.conn.execute(
                    """INSERT OR REPLACE INTO current_roster
                       (alliance_tag,alliance_name,atlas_id,verified_session,verified_at)
                       VALUES(?,?,?,?,?)""",
                    (tag,name or None,aid,session_id,now)
                )

            # Refresh queue is current-roster only. Keep history elsewhere.
            params=[tag,*canon_sorted]
            self.conn.execute(
                f"""DELETE FROM refresh_queue
                    WHERE alliance_tag=? AND atlas_id NOT IN ({placeholders})""",
                params
            )

    def current_roster_count(self):
        with self.lock:
            return self.conn.execute("SELECT COUNT(*) FROM current_roster").fetchone()[0]

    def refresh_pending_count(self):
        with self.lock:
            return self.conn.execute(
                """SELECT COUNT(*) FROM refresh_queue q
                   JOIN current_roster cr ON cr.atlas_id=q.atlas_id
                                          AND cr.alliance_tag=q.alliance_tag
                   WHERE q.status='pending'"""
            ).fetchone()[0]

    def export_refresh_csv(self, path: Path):
        path.parent.mkdir(parents=True,exist_ok=True)
        with self.lock:
            rows=self.conn.execute(
                """SELECT q.atlas_id,q.wos_id,q.pseudo_display,q.alliance_tag,q.reason,q.status,
                          q.first_queued,q.last_queued,q.resolved_at,q.last_session
                   FROM refresh_queue q
                   JOIN current_roster cr ON cr.atlas_id=q.atlas_id
                                          AND cr.alliance_tag=q.alliance_tag
                   ORDER BY q.status,q.alliance_tag,q.pseudo_display,q.atlas_id"""
            ).fetchall()
        fields=rows[0].keys() if rows else ["atlas_id","wos_id","pseudo_display","alliance_tag","reason","status"]
        with path.open("w",newline="",encoding="utf-8-sig") as f:
            wr=csv.DictWriter(f,fieldnames=fields); wr.writeheader()
            for r in rows: wr.writerow(dict(r))

    def current_roster_rows(self):
        """Rows available for graphical Sequence-Lab selection."""
        with self.lock:
            return self.conn.execute(
                """SELECT cr.atlas_id,
                          p.wos_id,
                          p.pseudo_display,
                          cr.alliance_tag,
                          cr.alliance_name
                   FROM current_roster cr
                   LEFT JOIN players p ON p.atlas_id=cr.atlas_id
                   ORDER BY COALESCE(cr.alliance_tag,''), COALESCE(p.pseudo_display,''), cr.atlas_id"""
            ).fetchall()

    def pending_refresh_rows(self):
        with self.lock:
            return self.conn.execute(
                """SELECT q.atlas_id,q.wos_id,q.pseudo_display,q.alliance_tag,q.reason
                   FROM refresh_queue q JOIN current_roster cr ON cr.atlas_id=q.atlas_id
                   WHERE q.status='pending'
                   ORDER BY q.alliance_tag,q.pseudo_display,q.atlas_id"""
            ).fetchall()

    def active_lab_arm(self, session_id: str, atlas_id: int):
        with self.lock, self.conn:
            r=self.conn.execute(
                """SELECT q.atlas_id,q.wos_id,q.pseudo_display,q.alliance_tag
                   FROM refresh_queue q JOIN current_roster cr ON cr.atlas_id=q.atlas_id
                   WHERE q.status='pending' AND q.atlas_id=? LIMIT 1""",(atlas_id,)
            ).fetchone()
            if r is None: return None
            cur=self.conn.execute(
                """INSERT INTO active_lab_attempts
                   (session_id,target_atlas_id,target_wos_id,target_pseudo,alliance_tag,armed_at,result)
                   VALUES(?,?,?,?,?,?,'armed')""",
                (session_id,r['atlas_id'],r['wos_id'],r['pseudo_display'],r['alliance_tag'],utc_now())
            )
            d=dict(r); d["id"]=cur.lastrowid
            return d

    def active_lab_request(self, attempt_id: int, frame: bytes):
        with self.lock, self.conn:
            self.conn.execute(
                "UPDATE active_lab_attempts SET request_seen_at=?,request_hex=?,result='request-captured' WHERE id=?",
                (utc_now(),frame.hex(),attempt_id)
            )

    def active_lab_response(self, attempt_id: int, row: dict, ok: bool, note=""):
        with self.lock, self.conn:
            self.conn.execute(
                """UPDATE active_lab_attempts SET response_seen_at=?,response_atlas_id=?,
                   response_wos_id=?,response_power=?,result=?,note=? WHERE id=?""",
                (utc_now(),self._to_int(row.get('atlas_id')),
                 self._to_int(row.get('wos_id') or row.get('wos_id_candidate')),
                 self._to_int(row.get('power')),
                 'validated' if ok else 'mismatch',note,attempt_id)
            )

    def active_lab_candidate(self, attempt_id: int, row: dict, source_kind: str,
                             atlas_match: bool, wos_match: bool, pseudo_match: bool, score: int, note: str=""):
        with self.lock, self.conn:
            self.conn.execute(
                """INSERT INTO active_lab_candidates
                   (attempt_id,seen_at,atlas_id,wos_id,pseudo_display,power,source_kind,
                    atlas_match,wos_match,pseudo_match,score,note)
                   VALUES(?,?,?,?,?,?,?,?,?,?,?,?)""",
                (attempt_id,utc_now(),self._to_int(row.get('atlas_id')),
                 self._to_int(row.get('wos_id') or row.get('wos_id_candidate')),
                 row.get('pseudo_display') or row.get('pseudo_core') or None,
                 self._to_int(row.get('power')),source_kind,
                 1 if atlas_match else 0,1 if wos_match else 0,1 if pseudo_match else 0,
                 int(score),note)
            )

    def active_lab_timeout(self, attempt_id: int, note: str):
        with self.lock, self.conn:
            self.conn.execute(
                """UPDATE active_lab_attempts SET result='timeout',note=?
                   WHERE id=? AND result IN ('armed','request-captured','searching')""",
                (note,attempt_id)
            )

    def export_active_lab_csv(self, path: Path):
        path.parent.mkdir(parents=True,exist_ok=True)
        with self.lock:
            rows=self.conn.execute(
                """SELECT a.id,a.session_id,a.target_atlas_id,a.target_wos_id,a.target_pseudo,a.alliance_tag,
                          a.armed_at,a.request_seen_at,a.response_seen_at,a.response_atlas_id,a.response_wos_id,
                          a.response_power,a.result,a.note,a.request_hex,
                          (SELECT COUNT(*) FROM active_lab_candidates c WHERE c.attempt_id=a.id) AS candidates_seen,
                          (SELECT MAX(score) FROM active_lab_candidates c WHERE c.attempt_id=a.id) AS best_candidate_score
                   FROM active_lab_attempts a ORDER BY a.id"""
            ).fetchall()
        fields=rows[0].keys() if rows else ['id','session_id','target_atlas_id','target_wos_id',
            'target_pseudo','alliance_tag','armed_at','request_seen_at','response_seen_at',
            'response_atlas_id','response_wos_id','response_power','result','note','request_hex','candidates_seen','best_candidate_score']
        with path.open('w',newline='',encoding='utf-8-sig') as f:
            w=csv.writer(f); w.writerow(fields)
            for r in rows: w.writerow([r[k] for k in fields])

    def sequence_lab_start(self, session_id: str, expected_count: int):
        with self.lock, self.conn:
            cur=self.conn.execute(
                "INSERT INTO sequence_lab_runs(session_id,started_at,expected_count) VALUES(?,?,?)",
                (session_id,utc_now(),int(expected_count))
            )
            return cur.lastrowid

    def sequence_lab_add(self, run_id: int, seq_index: int, row: dict, frame: bytes):
        atlas=self._to_int(row.get("atlas_id")); wos=self._to_int(row.get("wos_id"))
        dynamic_hex=frame[6:9].hex() if len(frame)>=9 else ""
        target_hex=frame[11:].hex() if len(frame)>=12 else ""
        with self.lock, self.conn:
            self.conn.execute(
                """INSERT INTO sequence_lab_events
                   (run_id,seq_index,seen_at,atlas_id,wos_id,pseudo_display,alliance_tag,request_hex,dynamic_hex,target_hex)
                   VALUES(?,?,?,?,?,?,?,?,?,?)""",
                (run_id,seq_index,utc_now(),atlas,wos,row.get("pseudo_display"),row.get("alliance_tag"),frame.hex(),dynamic_hex,target_hex)
            )
            self.conn.execute("UPDATE sequence_lab_runs SET captured_count=? WHERE id=?",(seq_index,run_id))

    def sequence_lab_stop(self, run_id: int, note=""):
        with self.lock, self.conn:
            self.conn.execute("UPDATE sequence_lab_runs SET stopped_at=?,note=? WHERE id=?",(utc_now(),note,run_id))

    def export_sequence_lab_csv(self, path: Path):
        path.parent.mkdir(parents=True,exist_ok=True)
        with self.lock:
            rows=self.conn.execute(
                """SELECT r.id AS run_id,r.session_id,r.started_at,r.stopped_at,r.expected_count,r.captured_count,r.note,
                          e.seq_index,e.seen_at,e.atlas_id,e.wos_id,e.pseudo_display,e.alliance_tag,e.dynamic_hex,e.target_hex,e.request_hex
                   FROM sequence_lab_runs r LEFT JOIN sequence_lab_events e ON e.run_id=r.id
                   ORDER BY r.id,e.seq_index"""
            ).fetchall()
        fields=rows[0].keys() if rows else ["run_id","session_id","started_at","stopped_at","expected_count","captured_count","note","seq_index","seen_at","atlas_id","wos_id","pseudo_display","alliance_tag","dynamic_hex","target_hex","request_hex"]
        with path.open("w",newline="",encoding="utf-8-sig") as f:
            w=csv.writer(f); w.writerow(fields)
            for r in rows: w.writerow([r[k] for k in fields])

    def counter_lab_start(self, session_id: str, target: dict, expected_count: int=5):
        with self.lock, self.conn:
            cur=self.conn.execute(
                """INSERT INTO counter_lab_runs
                   (session_id,target_atlas_id,target_wos_id,target_pseudo,alliance_tag,
                    started_at,expected_count)
                   VALUES(?,?,?,?,?,?,?)""",
                (session_id,int(target["atlas_id"]),self._to_int(target.get("wos_id")),
                 target.get("pseudo_display"),target.get("alliance_tag"),utc_now(),int(expected_count))
            )
            return cur.lastrowid

    def counter_lab_event(self, run_id:int, seq_index:int, kind:str, direction:str,
                          opcode:str, frame:bytes, dynamic_hex="", dynamic_value=None,
                          target_hex=""):
        with self.lock, self.conn:
            self.conn.execute(
                """INSERT INTO counter_lab_events
                   (run_id,seq_index,seen_at,kind,direction,opcode,frame_hex,
                    dynamic_hex,dynamic_value,target_hex)
                   VALUES(?,?,?,?,?,?,?,?,?,?)""",
                (run_id,seq_index,utc_now(),kind,direction,opcode,frame.hex(),
                 dynamic_hex,dynamic_value,target_hex)
            )

    def counter_lab_progress(self, run_id:int, captured_count:int):
        with self.lock, self.conn:
            self.conn.execute("UPDATE counter_lab_runs SET captured_count=? WHERE id=?",
                              (int(captured_count),run_id))

    def counter_lab_stop(self, run_id:int, note=""):
        with self.lock, self.conn:
            self.conn.execute("UPDATE counter_lab_runs SET stopped_at=?,note=? WHERE id=?",
                              (utc_now(),note,run_id))

    def export_counter_lab_csv(self,path:Path):
        path.parent.mkdir(parents=True,exist_ok=True)
        with self.lock:
            rows=self.conn.execute(
                """SELECT r.id AS run_id,r.session_id,r.target_atlas_id,r.target_wos_id,
                          r.target_pseudo,r.alliance_tag,r.started_at,r.stopped_at,
                          r.expected_count,r.captured_count,r.note,
                          e.id AS event_id,e.seq_index,e.seen_at,e.kind,e.direction,
                          e.opcode,e.dynamic_hex,e.dynamic_value,e.target_hex,e.frame_hex
                   FROM counter_lab_runs r
                   LEFT JOIN counter_lab_events e ON e.run_id=r.id
                   ORDER BY r.id,e.id"""
            ).fetchall()
        fields=rows[0].keys() if rows else ["run_id","session_id","target_atlas_id","target_wos_id",
            "target_pseudo","alliance_tag","started_at","stopped_at","expected_count","captured_count",
            "note","event_id","seq_index","seen_at","kind","direction","opcode","dynamic_hex",
            "dynamic_value","target_hex","frame_hex"]
        with path.open("w",newline="",encoding="utf-8-sig") as f:
            w=csv.writer(f); w.writerow(fields)
            for r in rows: w.writerow([r[k] for k in fields])

    def request_builder_arm(self,session_id,target,last_counter,predicted_counter,predicted_hex):
        with self.lock,self.conn:
            cur=self.conn.execute(
                """INSERT INTO request_builder_tests
                   (session_id,atlas_id,wos_id,pseudo_display,alliance_tag,armed_at,
                    last_counter,predicted_counter,predicted_hex)
                   VALUES(?,?,?,?,?,?,?,?,?)""",
                (session_id,int(target["atlas_id"]),self._to_int(target.get("wos_id")),
                 target.get("pseudo_display"),target.get("alliance_tag"),utc_now(),
                 last_counter,predicted_counter,predicted_hex)
            )
            return cur.lastrowid

    def request_builder_update_prediction(self,test_id,last_counter,predicted_counter,predicted_hex):
        with self.lock,self.conn:
            self.conn.execute(
                """UPDATE request_builder_tests SET last_counter=?,predicted_counter=?,predicted_hex=?
                   WHERE id=?""",
                (last_counter,predicted_counter,predicted_hex,test_id)
            )

    def request_builder_result(self,test_id,actual_counter,actual_hex,result,note=""):
        with self.lock,self.conn:
            self.conn.execute(
                """UPDATE request_builder_tests SET actual_counter=?,actual_hex=?,
                   result=?,checked_at=?,note=? WHERE id=?""",
                (actual_counter,actual_hex,result,utc_now(),note,test_id)
            )

    def export_request_builder_csv(self,path:Path):
        path.parent.mkdir(parents=True,exist_ok=True)
        with self.lock:
            rows=self.conn.execute(
                """SELECT id,session_id,atlas_id,wos_id,pseudo_display,alliance_tag,armed_at,
                          last_counter,predicted_counter,predicted_hex,actual_counter,
                          actual_hex,result,checked_at,note
                   FROM request_builder_tests ORDER BY id"""
            ).fetchall()
        fields=rows[0].keys() if rows else ["id","session_id","atlas_id","wos_id","pseudo_display",
            "alliance_tag","armed_at","last_counter","predicted_counter","predicted_hex",
            "actual_counter","actual_hex","result","checked_at","note"]
        with path.open("w",newline="",encoding="utf-8-sig") as f:
            w=csv.writer(f);w.writerow(fields)
            for r in rows:w.writerow([r[k] for k in fields])

    def raw_diag_start(self,session_id,target):
        with self.lock,self.conn:
            cur=self.conn.execute("""INSERT INTO raw_diag_runs
                (session_id,target_atlas_id,target_pseudo,alliance_tag,started_at)
                VALUES(?,?,?,?,?)""",(session_id,int(target["atlas_id"]),
                target.get("pseudo_display"),target.get("alliance_tag"),utc_now()))
            return cur.lastrowid

    def raw_diag_packet(self,run_id,seen_at,direction,src_port,dst_port,tcp_seq,payload):
        with self.lock,self.conn:
            self.conn.execute("""INSERT INTO raw_diag_packets
                (run_id,seen_at,direction,src_port,dst_port,tcp_seq,payload_len,payload_hex)
                VALUES(?,?,?,?,?,?,?,?)""",(run_id,seen_at,direction,src_port,dst_port,
                int(tcp_seq),len(payload),payload.hex()))
            col="client_bytes" if direction=="C>S" else "server_bytes"
            self.conn.execute(f"UPDATE raw_diag_runs SET packet_count=packet_count+1,{col}={col}+? WHERE id=?",
                              (len(payload),run_id))

    def raw_diag_stop(self,run_id,note=""):
        with self.lock,self.conn:
            self.conn.execute("UPDATE raw_diag_runs SET stopped_at=?,note=? WHERE id=?",(utc_now(),note,run_id))

    def export_raw_diag_csv(self,path):
        with self.lock:
            rows=self.conn.execute("""SELECT r.id run_id,r.session_id,r.target_atlas_id,r.target_pseudo,
                r.alliance_tag,r.started_at,r.stopped_at,r.packet_count,r.client_bytes,r.server_bytes,r.note,
                p.id packet_id,p.seen_at,p.direction,p.src_port,p.dst_port,p.tcp_seq,p.payload_len,p.payload_hex
                FROM raw_diag_runs r LEFT JOIN raw_diag_packets p ON p.run_id=r.id ORDER BY r.id,p.id""").fetchall()
        fields=rows[0].keys() if rows else ["run_id","session_id","target_atlas_id","target_pseudo","alliance_tag",
            "started_at","stopped_at","packet_count","client_bytes","server_bytes","note","packet_id","seen_at",
            "direction","src_port","dst_port","tcp_seq","payload_len","payload_hex"]
        with Path(path).open("w",newline="",encoding="utf-8-sig") as f:
            w=csv.writer(f);w.writerow(fields)
            for r in rows:w.writerow([r[k] for k in fields])

    def cleanup_v320_false_aids(self):
        """Remove only the 19 false unresolved AIDs produced by the known V3.20 parser bug.

        The IDs are intentionally explicit: no heuristic deletion is used, so valid
        historical/discovery rows cannot be removed accidentally. Rows that have
        subsequently been resolved are preserved.
        """
        false_aids = (
            156238719,156244607,156246399,156252287,156256639,156261759,
            156263551,156267903,156280191,156283655,156291455,156293759,
            156570239,168551295,172732799,173693823,182151039,184647039,
            191240063,
        )
        placeholders=",".join("?" for _ in false_aids)
        with self.lock, self.conn:
            cur=self.conn.execute(
                f"""DELETE FROM state_discovery
                    WHERE atlas_id IN ({placeholders})
                      AND COALESCE(profile_resolved,0)=0
                      AND COALESCE(discovered_via,'')='7902-aid-list'""",
                false_aids,
            )
            return cur.rowcount if cur.rowcount is not None and cur.rowcount >= 0 else 0

    def cleanup_oversized_roster_sessions(self):
        """Repair roster contamination from older collectors.

        If one session/tag contains more verified memberships than the roster size
        observed in that same session, keep only the earliest N membership rows
        (N = roster_count) and remove later overflow rows.  Current-roster and
        last-observation alliance labels are cleared only for those overflow IDs
        when they still point to the same contaminated session/tag.
        """
        repaired=[]
        with self.lock, self.conn:
            bad=self.conn.execute(
                """SELECT am.session_id,am.alliance_tag,COUNT(*) AS n,s.roster_count
                   FROM alliance_memberships am
                   JOIN sessions s ON s.session_id=am.session_id
                   WHERE COALESCE(s.roster_count,0)>0
                   GROUP BY am.session_id,am.alliance_tag
                   HAVING COUNT(*) > s.roster_count"""
            ).fetchall()
            for r in bad:
                sid,tag,n,limit=r[0],r[1],int(r[2]),int(r[3])
                rows=self.conn.execute(
                    """SELECT rowid,atlas_id FROM alliance_memberships
                       WHERE session_id=? AND alliance_tag=?
                       ORDER BY rowid""",(sid,tag)
                ).fetchall()
                overflow=rows[limit:]
                if not overflow:
                    continue
                aids=[int(x[1]) for x in overflow]
                rowids=[int(x[0]) for x in overflow]
                ph=','.join('?' for _ in rowids)
                self.conn.execute(f"DELETE FROM alliance_memberships WHERE rowid IN ({ph})",rowids)
                ph2=','.join('?' for _ in aids)
                self.conn.execute(
                    f"DELETE FROM current_roster WHERE verified_session=? AND alliance_tag=? AND atlas_id IN ({ph2})",
                    [sid,tag,*aids]
                )
                self.conn.execute(
                    f"UPDATE players SET alliance_tag=NULL,alliance_name=NULL WHERE last_session=? AND alliance_tag=? AND atlas_id IN ({ph2})",
                    [sid,tag,*aids]
                )
                self.conn.execute(
                    f"UPDATE state_discovery SET alliance_tag=NULL WHERE last_session=? AND alliance_tag=? AND atlas_id IN ({ph2})",
                    [sid,tag,*aids]
                )
                repaired.append((sid,tag,n,limit,len(aids)))
        return repaired

    def discovery_observe(self,row,session_id,source_kind,opcode):
        """Atomically observe an Atlas ID in the discovery table.

        V3.34.6: SELECT-then-INSERT was vulnerable when packet processing paths
        observed the same Atlas almost simultaneously. SQLite now performs the
        uniqueness decision atomically with ON CONFLICT.
        """
        atlas=self._to_int(row.get("atlas_id"))
        if not atlas:return False
        wos=self._to_int(row.get("wos_id") or row.get("wos_id_candidate"))
        power=self._to_int(row.get("power") or row.get("power_candidate"))
        pseudo=row.get("pseudo_display") or row.get("pseudo_core") or None
        tag=row.get("alliance_tag") or None
        resolved=1 if (wos is not None or pseudo or power is not None) else 0
        now=utc_now()
        with self.lock,self.conn:
            existed=self.conn.execute("SELECT 1 FROM state_discovery WHERE atlas_id=?",(atlas,)).fetchone() is not None
            self.conn.execute("""INSERT INTO state_discovery
                (atlas_id,wos_id,pseudo_display,power,alliance_tag,first_seen,last_seen,
                 sightings,last_session,last_source,last_opcode,profile_resolved,discovered_via)
                VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)
                ON CONFLICT(atlas_id) DO UPDATE SET
                  wos_id=COALESCE(excluded.wos_id,state_discovery.wos_id),
                  pseudo_display=COALESCE(excluded.pseudo_display,state_discovery.pseudo_display),
                  power=COALESCE(excluded.power,state_discovery.power),
                  alliance_tag=COALESCE(excluded.alliance_tag,state_discovery.alliance_tag),
                  last_seen=excluded.last_seen,
                  sightings=state_discovery.sightings+1,
                  last_session=excluded.last_session,
                  last_source=excluded.last_source,
                  last_opcode=excluded.last_opcode,
                  profile_resolved=MAX(state_discovery.profile_resolved,excluded.profile_resolved),
                  discovered_via=COALESCE(state_discovery.discovered_via,excluded.discovered_via)""",
                (atlas,wos,pseudo,power,tag,now,now,1,session_id,source_kind,opcode,resolved,source_kind))
            return not existed

    def discovery_observe_aids(self,atlas_ids,session_id,source_kind,opcode):
        added=0
        for atlas in atlas_ids:
            if self.discovery_observe({"atlas_id":atlas},session_id,source_kind,opcode):
                added+=1
        return added

    def discovery_count(self):
        with self.lock:
            return self.conn.execute("SELECT COUNT(*) FROM state_discovery").fetchone()[0]

    def discovery_resolved_count(self):
        with self.lock:
            return self.conn.execute("SELECT COUNT(*) FROM state_discovery WHERE profile_resolved=1").fetchone()[0]

    def alliance_discovery_observe(self, alliance_ids, session_id: str, opcode: str, via="alliance-list"):
        now=utc_now(); added=0
        ids=[]
        for x in alliance_ids or []:
            try: x=int(x)
            except Exception: continue
            # State 3693 alliance IDs observed as 3693xxxxxx. Keep the
            # conservative 100k namespace to reject unrelated 32-bit fields.
            if not (3693000000 <= x < 3693100000):
                continue
            if x not in ids: ids.append(x)
        with self.lock, self.conn:
            for aid in ids:
                old=self.conn.execute("SELECT alliance_id FROM alliance_discovery WHERE alliance_id=?",(aid,)).fetchone()
                if old is None: added += 1
                self.conn.execute("""INSERT INTO alliance_discovery
                    (alliance_id,first_seen,last_seen,sightings,last_session,last_opcode,discovered_via)
                    VALUES(?,?,?,1,?,?,?)
                    ON CONFLICT(alliance_id) DO UPDATE SET
                      last_seen=excluded.last_seen, sightings=alliance_discovery.sightings+1,
                      last_session=excluded.last_session,last_opcode=excluded.last_opcode,
                      discovered_via=COALESCE(alliance_discovery.discovered_via,excluded.discovered_via)""",
                    (aid,now,now,session_id,opcode,via))
        return added

    def alliance_discovery_enrich(self, alliance_id: int, tag: str="", name: str=""):
        try: alliance_id=int(alliance_id)
        except Exception: return
        with self.lock, self.conn:
            self.conn.execute("""UPDATE alliance_discovery SET
                alliance_tag=COALESCE(NULLIF(?,''),alliance_tag),
                alliance_name=COALESCE(NULLIF(?,''),alliance_name) WHERE alliance_id=?""",
                (tag or '',name or '',alliance_id))

    def alliance_discovery_count(self):
        with self.lock:
            return self.conn.execute("SELECT COUNT(*) FROM alliance_discovery").fetchone()[0]

    def known_alliance_tags(self):
        """Canonical TAGs learned from Alliance Discovery."""
        with self.lock:
            rows=self.conn.execute(
                """SELECT alliance_tag,alliance_name,alliance_id
                   FROM alliance_discovery
                   WHERE alliance_tag IS NOT NULL AND LENGTH(TRIM(alliance_tag)) BETWEEN 2 AND 3
                   ORDER BY last_seen DESC"""
            ).fetchall()
        out=[]; seen=set()
        for r in rows:
            tag=(r["alliance_tag"] or "").strip()
            if tag and tag not in seen:
                seen.add(tag); out.append((tag,r["alliance_name"] or "",r["alliance_id"]))
        return out

    def export_alliance_discovery_csv(self,path):
        path.parent.mkdir(parents=True,exist_ok=True)
        with self.lock:
            rows=self.conn.execute("""SELECT alliance_id,alliance_tag,alliance_name,first_seen,last_seen,
                       sightings,last_session,last_opcode,discovered_via
                       FROM alliance_discovery ORDER BY alliance_id""").fetchall()
        fields=rows[0].keys() if rows else ["alliance_id","alliance_tag","alliance_name","first_seen","last_seen","sightings","last_session","last_opcode","discovered_via"]
        with path.open('w',newline='',encoding='utf-8-sig') as f:
            w=csv.writer(f); w.writerow(fields)
            for r in rows: w.writerow([r[k] for k in fields])

    def observe_alliance_roster(self, alliance_tag: str, alliance_name: str, announced_members: int,
                                session_id: str):
        tag=(alliance_tag or "").strip()
        if not tag:
            return
        name=(alliance_name or "").strip()
        try:
            announced=int(announced_members or 0)
        except Exception:
            announced=0
        now=utc_now()
        with self.lock, self.conn:
            aidrow=self.conn.execute(
                "SELECT alliance_id FROM alliance_discovery WHERE alliance_tag=? ORDER BY last_seen DESC LIMIT 1",
                (tag,)
            ).fetchone()
            aid=int(aidrow[0]) if aidrow and aidrow[0] is not None else None
            self.conn.execute("""INSERT INTO alliance_roster_coverage
                (alliance_tag,alliance_id,alliance_name,announced_members,last_roster_session,last_roster_seen,roster_sightings)
                VALUES(?,?,?,?,?,?,1)
                ON CONFLICT(alliance_tag) DO UPDATE SET
                    alliance_id=COALESCE(excluded.alliance_id,alliance_roster_coverage.alliance_id),
                    alliance_name=COALESCE(NULLIF(excluded.alliance_name,''),alliance_roster_coverage.alliance_name),
                    announced_members=CASE WHEN excluded.announced_members>0
                                           THEN excluded.announced_members
                                           ELSE alliance_roster_coverage.announced_members END,
                    last_roster_session=excluded.last_roster_session,
                    last_roster_seen=excluded.last_roster_seen,
                    roster_sightings=alliance_roster_coverage.roster_sightings+1""",
                (tag,aid,name,announced,session_id,now))

    def alliance_coverage_rows(self):
        """One row per discovered alliance, enriched with passive roster/profile coverage."""
        with self.lock:
            return self.conn.execute("""
                SELECT
                    ad.alliance_id,
                    ad.alliance_tag,
                    ad.alliance_name,
                    CASE WHEN arc.alliance_tag IS NULL THEN 0 ELSE 1 END AS roster_seen,
                    arc.announced_members,
                    COUNT(DISTINCT cr.atlas_id) AS captured_members,
                    COUNT(DISTINCT CASE WHEN sd.profile_resolved=1 THEN cr.atlas_id END) AS profiles_resolved,
                    arc.last_roster_session,
                    arc.last_roster_seen,
                    COALESCE(arc.roster_sightings,0) AS roster_sightings,
                    ad.last_session AS ranking_last_session,
                    CASE
                      WHEN arc.alliance_tag IS NULL THEN 'NO_ROSTER'
                      WHEN COALESCE(arc.announced_members,0)<=0 THEN 'ROSTER_SEEN'
                      WHEN COUNT(DISTINCT cr.atlas_id) >= arc.announced_members THEN 'ROSTER_COMPLETE'
                      ELSE 'ROSTER_PARTIAL'
                    END AS roster_status
                FROM alliance_discovery ad
                LEFT JOIN alliance_roster_coverage arc
                  ON arc.alliance_tag=ad.alliance_tag
                LEFT JOIN current_roster cr
                  ON cr.alliance_tag=ad.alliance_tag
                LEFT JOIN state_discovery sd
                  ON sd.atlas_id=cr.atlas_id
                WHERE ad.alliance_tag IS NOT NULL AND TRIM(ad.alliance_tag)<>''
                GROUP BY ad.alliance_id,ad.alliance_tag,ad.alliance_name,
                         arc.alliance_tag,arc.announced_members,arc.last_roster_session,
                         arc.last_roster_seen,arc.roster_sightings,ad.last_session
                ORDER BY
                    CASE
                      WHEN arc.alliance_tag IS NULL THEN 0
                      WHEN COALESCE(arc.announced_members,0)>COUNT(DISTINCT cr.atlas_id) THEN 1
                      ELSE 2
                    END,
                    ad.alliance_tag
            """).fetchall()

    def alliance_coverage_stats(self):
        rows=self.alliance_coverage_rows()
        total=len(rows)
        seen=sum(1 for r in rows if int(r["roster_seen"] or 0))
        complete=sum(1 for r in rows if r["roster_status"]=="ROSTER_COMPLETE")
        captured=sum(int(r["captured_members"] or 0) for r in rows)
        resolved=sum(int(r["profiles_resolved"] or 0) for r in rows)
        return {"total":total,"roster_seen":seen,"roster_complete":complete,
                "captured_members":captured,"profiles_resolved":resolved}

    def export_alliance_coverage_csv(self,path):
        path=Path(path); path.parent.mkdir(parents=True,exist_ok=True)
        rows=self.alliance_coverage_rows()
        fields=["alliance_id","alliance_tag","alliance_name","roster_seen","announced_members",
                "captured_members","profiles_resolved","profile_coverage_pct","roster_status",
                "roster_sightings","last_roster_session","last_roster_seen","ranking_last_session"]
        with path.open("w",newline="",encoding="utf-8-sig") as f:
            w=csv.writer(f); w.writerow(fields)
            for r in rows:
                captured=int(r["captured_members"] or 0)
                resolved=int(r["profiles_resolved"] or 0)
                pct=round((resolved*100.0/captured),1) if captured else 0.0
                w.writerow([r["alliance_id"],r["alliance_tag"],r["alliance_name"],r["roster_seen"],
                            r["announced_members"],captured,resolved,pct,r["roster_status"],
                            r["roster_sightings"],r["last_roster_session"],r["last_roster_seen"],
                            r["ranking_last_session"]])

    def export_state_discovery_csv(self,path):
        path=Path(path);path.parent.mkdir(parents=True,exist_ok=True)
        with self.lock:
            rows=self.conn.execute("""SELECT atlas_id,wos_id,pseudo_display,power,alliance_tag,profile_resolved,discovered_via,
                first_seen,last_seen,sightings,last_session,last_source,last_opcode
                FROM state_discovery ORDER BY COALESCE(alliance_tag,''),power DESC,pseudo_display""").fetchall()
        fields=rows[0].keys() if rows else ["atlas_id","wos_id","pseudo_display","power","alliance_tag","profile_resolved","discovered_via",
            "first_seen","last_seen","sightings","last_session","last_source","last_opcode"]
        with path.open("w",newline="",encoding="utf-8-sig") as f:
            w=csv.writer(f);w.writerow(fields)
            for r in rows:w.writerow([r[k] for k in fields])

    def stats(self) -> dict:
        with self.lock:
            historical = self.conn.execute("SELECT COUNT(*) FROM players").fetchone()[0]
            current = self.conn.execute("SELECT COUNT(*) FROM current_roster").fetchone()[0]
            alliances = self.conn.execute("SELECT COUNT(DISTINCT alliance_tag) FROM current_roster").fetchone()[0]
            complete = self.conn.execute(
                """SELECT COUNT(*) FROM current_roster cr
                   JOIN players p ON p.atlas_id=cr.atlas_id
                   WHERE p.wos_id IS NOT NULL AND p.power IS NOT NULL
                         AND p.pseudo_display IS NOT NULL"""
            ).fetchone()[0]
            power_suspect = self.conn.execute(
                """SELECT COUNT(*) FROM current_roster cr
                   JOIN players p ON p.atlas_id=cr.atlas_id
                   WHERE p.power_confidence='suspect'"""
            ).fetchone()[0]
        refresh_pending = self.refresh_pending_count()
        discovered=self.discovery_count()
        resolved=self.discovery_resolved_count()
        return {"players": current, "historical_players": historical, "current_members": current,
                "alliances": alliances, "complete": complete, "power_suspect": power_suspect,
                "refresh_pending": refresh_pending, "discovered": discovered, "resolved": resolved, "alliance_discovered": self.alliance_discovery_count()}

    def export_csv(self, path: Path):
        """Export CURRENT roster members only.

        Historical players remain in SQLite/history and are not lost. The CSV
        intentionally represents current verified membership, not every player
        ever observed by the collector.
        """
        path.parent.mkdir(parents=True, exist_ok=True)
        with self.lock:
            rows = self.conn.execute(
                """SELECT p.atlas_id,p.wos_id,p.pseudo_display,p.pseudo_core,p.power,
                   cr.alliance_tag AS alliance_tag,cr.alliance_name AS alliance_name,
                   p.alliance_tag AS last_observed_alliance_tag,
                   p.first_seen,p.last_seen,p.last_session,p.source_kind,p.wos_confidence,p.power_confidence,
                   cr.verified_session AS roster_session,cr.verified_at AS roster_verified_at,
                   (SELECT COUNT(*) FROM atlas_aliases a WHERE a.canonical_atlas_id=p.atlas_id) AS atlas_alias_count
                   FROM current_roster cr
                   JOIN players p ON p.atlas_id=cr.atlas_id
                   ORDER BY cr.alliance_tag,p.power DESC,p.pseudo_display"""
            ).fetchall()
        fields = rows[0].keys() if rows else ["atlas_id","wos_id","pseudo_display","pseudo_core","power","alliance_tag","alliance_name"]
        with path.open("w", newline="", encoding="utf-8-sig") as f:
            w = csv.writer(f)
            w.writerow(fields)
            for r in rows:
                w.writerow([r[k] for k in fields])

    def export_history_csv(self, path: Path):
        path.parent.mkdir(parents=True, exist_ok=True)
        with self.lock:
            rows=self.conn.execute(
                """SELECT atlas_id,seen_at,session_id,pseudo_display,pseudo_core,wos_id,power,
                          alliance_tag,alliance_name,source_kind
                   FROM history ORDER BY seen_at,atlas_id"""
            ).fetchall()
        fields=rows[0].keys() if rows else ["atlas_id","seen_at","session_id"]
        with path.open("w",newline="",encoding="utf-8-sig") as f:
            w=csv.writer(f); w.writerow(fields)
            for r in rows: w.writerow([r[k] for k in fields])


@dataclass
class StreamState:
    next_seq: Optional[int] = None
    pending: Dict[int, bytes] = field(default_factory=dict)
    appbuf: bytearray = field(default_factory=bytearray)


class TcpWosReassembler:
    """TCP sequence-aware reassembly + WOS application framing."""
    def __init__(self, on_frame):
        self.streams: Dict[Tuple[str, int, str, int], StreamState] = {}
        self.on_frame = on_frame

    def feed(self, src_ip: str, src_port: int, dst_ip: str, dst_port: int, seq: int, payload: bytes, ts: float):
        if not payload:
            return
        key = (src_ip, src_port, dst_ip, dst_port)
        st = self.streams.setdefault(key, StreamState())
        if st.next_seq is None:
            st.next_seq = seq
        # Ignore entirely retransmitted payload.
        if seq + len(payload) <= st.next_seq:
            return
        if seq < st.next_seq:
            payload = payload[st.next_seq - seq:]
            seq = st.next_seq
        st.pending[seq] = payload
        while st.next_seq in st.pending:
            chunk = st.pending.pop(st.next_seq)
            st.appbuf.extend(chunk)
            st.next_seq += len(chunk)
            self._drain_frames(key, st, ts)

    def _drain_frames(self, key, st: StreamState, ts: float):
        # The TCP stream also carries short opaque/ack payloads that are not
        # length-prefixed WOS frames. We therefore synchronize only on the
        # opcodes the collector actually needs.
        # V4.0.16: the game session can negotiate a XOR-0x20 "shifted" opcode
        # family (55 02 / 59 02 / 5D 02) instead of the normal one
        # (75 02 / 79 02 / 7D 02) -- see _extract_raw_counter and the
        # opcode_norm mapping in _on_frame, which already expect both. The
        # reassembler must recognize BOTH families as valid sync points, or
        # every frame in a "shifted" session is silently dropped before it
        # ever reaches decoding (no error, no roster, no map, no members).
        tracked = {
            b"\x75\x02", b"\x79\x02", b"\x7d\x02",
            b"\x55\x02", b"\x59\x02", b"\x5d\x02",
        }
        while True:
            if len(st.appbuf) < 4:
                return
            if bytes(st.appbuf[2:4]) not in tracked:
                # Find the next plausible tracked frame start.
                found = None
                for i in range(1, max(1, len(st.appbuf)-3)):
                    if bytes(st.appbuf[i+2:i+4]) in tracked:
                        found = i
                        break
                if found is None:
                    # Keep only a tiny suffix so a split header can complete.
                    if len(st.appbuf) > 3:
                        del st.appbuf[:-3]
                    return
                del st.appbuf[:found]
                continue
            declared = int.from_bytes(st.appbuf[:2], "big")
            total = declared + 2
            if total < 6 or total > 2_000_000:
                del st.appbuf[0]
                continue
            if len(st.appbuf) < total:
                return
            frame = bytes(st.appbuf[:total])
            del st.appbuf[:total]
            self.on_frame(key, frame, ts)


class RosterDecoder:
    """Compact roster detector/count + strict Atlas hints for epoch correlation."""
    PREFIX = {0x1F,0x7C,0xF1,0xF8,0x3E,0x3C}
    STUFF = {0x47,0xC7,0xE3,0x8F,0x23}
    ATLAS_MIN = 100_000_000
    ATLAS_MAX = 300_000_000

    @staticmethod
    def looks_like_roster(frame: bytes) -> bool:
        return len(frame) > 500 and frame[2:4] == b"\x75\x02" and b"\xdc\x1c" not in frame and frame.count(b"\x0e") >= 30

    @classmethod
    def _decode_entry_atlas(cls, enc: bytes):
        """Strict roster-entry Atlas hint.

        Used ONLY to correlate a roster epoch with later 7902 batches. It is not
        written as player identity on its own.
        """
        if len(enc) != 5:
            return None
        candidates=[]

        def add(raw, score, kind):
            if len(raw)!=4:
                return
            v=int.from_bytes(raw,"little")
            if cls.ATLAS_MIN <= v <= cls.ATLAS_MAX:
                candidates.append((score,v,kind))

        if enc[0] in cls.PREFIX:
            add(enc[1:],30,"prefix")
        for i in range(1,4):
            if enc[i] in cls.STUFF:
                add(enc[:i]+enc[i+1:],20,"stuff")
        if enc[4] == 0x11:
            add(enc[:4],10,"tail11")

        if not candidates:
            return None
        candidates.sort(reverse=True)
        top_score=candidates[0][0]
        top={v for score,v,kind in candidates if score==top_score}
        return next(iter(top)) if len(top)==1 else None

    def decode(self, frame: bytes) -> dict:
        encoded = []
        # Classic entries: 04 + 5 encoded bytes + 0e.
        for j, b in enumerate(frame):
            if b == 0x0E and j >= 6 and frame[j-6] == 0x04:
                encoded.append(frame[j-5:j])
        # Last entry can be unterminated; observed roster tail ends in 04 + 5 bytes.
        if len(frame) >= 6 and frame[-6] == 0x04:
            tail = frame[-5:]
            if tail not in encoded:
                encoded.append(tail)
        hints=[]
        for enc in encoded:
            aid=self._decode_entry_atlas(enc)
            if aid is not None:
                hints.append(aid)
        return {
            "count": len(encoded),
            "encoded_hex": [e.hex() for e in encoded],
            "atlas_ids_hint": list(dict.fromkeys(hints)),
            "hint_count": len(set(hints)),
        }


def decode_7902_atlas_ids(frame: bytes):
    """Decode Atlas IDs from canonical 7902 or shifted-session 5902 requests.

    V3.21 separates two observed wire formats:
    - large ranking/list batches (>=100 bytes): coherent flat uint32-LE Atlas IDs;
    - short wrapped batches: compact IDs containing wrapper/stuffing bytes such as 7F.

    V3.20 incorrectly tried the flat decoder on short wrapped frames, which
    created false Atlas IDs by treating stuffing bytes as part of the ID.
    """
    if len(frame) < 12 or frame[2:4] not in (b"\x79\x02", b"\x59\x02"):
        return []

    # 1) Large flat ranking/list variant. This is intentionally restricted to
    # genuinely large frames so short wrapped batches can never hit it.
    if len(frame) >= 100:
        best=[]
        for start_off in range(11,17):
            for trailer in range(0,5):
                stop=len(frame)-trailer
                if stop<=start_off or (stop-start_off)%4:
                    continue
                vals=[]
                for i in range(start_off,stop,4):
                    v=int.from_bytes(frame[i:i+4],"little")
                    if not (100_000_000<=v<=300_000_000):
                        vals=[]
                        break
                    vals.append(v)
                if len(vals)>=10 and len(vals)>len(best):
                    best=vals
        if best:
            return best

    # 2) Short/legacy wrapped member-batch format.
    data=frame[11:]
    if data.endswith(b"\x00"):
        data=data[:-1]
    wrappers={0x1F,0x7C,0xF1,0xF8,0x3E,0x7F}
    stuffing={0x47,0xC7,0xE3,0x8F,0x23,0x7F}

    def token_options(enc):
        n=len(enc); out=[]
        if n==4:
            v=int.from_bytes(enc,"little")
            if 100_000_000<=v<=300_000_000:
                out.append((v,10))
        elif n==5:
            for rem in range(5):
                if rem==0 and enc[0] not in wrappers: continue
                if rem==4 and enc[4]!=0x11: continue
                if rem in (1,2,3) and enc[rem] not in stuffing: continue
                raw=enc[:rem]+enc[rem+1:]
                v=int.from_bytes(raw,"little")
                if 100_000_000<=v<=300_000_000:
                    out.append((v,8))
        elif n==6:
            for i in range(5):
                if enc[i]==0xFF:
                    raw=enc[:i]+enc[i+2:]
                    if len(raw)==4:
                        v=int.from_bytes(raw,"little")
                        if 100_000_000<=v<=300_000_000:
                            out.append((v,9))
        return out

    memo={}
    def parse(i):
        if i==len(data): return (0,[])
        if i in memo: return memo[i]
        best_parse=None
        for n in (4,5,6):
            if i+n>len(data): continue
            for value,score in token_options(data[i:i+n]):
                rest=parse(i+n)
                if rest is None: continue
                cand=(score+rest[0],[value]+rest[1])
                if best_parse is None or cand[0]>best_parse[0]:
                    best_parse=cand
        memo[i]=best_parse
        return best_parse

    ans=parse(0)
    return ans[1] if ans and len(ans[1])>=2 else []


class CollectorEngine:
    def __init__(self, decoder: DecoderBundle, db: StateDB, log_cb=None, stats_cb=None):
        self.decoder = decoder
        self.db = db
        self.log_cb = log_cb or (lambda s: None)
        self.stats_cb = stats_cb or (lambda d: None)
        self.session_id = ""
        self.stats_data = {"frames_7502":0,"req_7902":0,"req_7d02":0,"member_blocks":0,"roster_count":0,"decoded_players":0,"changed_players":0,"profile_refreshes":0,"map_frames":0,"map_blocks":0,"map_anchors":0,"map_rows":0}
        self.roster = RosterDecoder()
        self.reassembler = TcpWosReassembler(self._on_frame)
        self._seen_blocks = set()
        self._best_rows = {}
        self._session_wos_confirmations = {}
        self._alliance_name_to_tag = {}
        self._alliance_tag_to_name = {}
        self._roster_epoch = 0
        self._roster_tag_votes = {}
        self._roster_tag_frames = {}
        self._roster_tag_names = {}
        self._roster_vote_candidate = ""
        self._roster_vote_streak = 0
        self._roster_identity_locked = False
        self._roster_active = False
        self._context_tag = ""
        self._context_name = ""
        self._pending_context_rows = []
        self._explicit_profile_frames = 0
        self._current_roster_count = 0
        self._current_requested_ids = set()
        self._recent_bulk_7902 = []  # [(timestamp,[Atlas IDs])], rolling 60s
        # V3.34.6 exact application transaction correlation.
        # 7D02 requests carry a transaction counter that is echoed by their
        # 7502 response; this is stronger than "the next 7502 frame".
        self._recent_7d_transactions = {}  # counter(bytes2) -> dict(ts,target,primary)
        self._current_roster_hint_ids = set()
        self._roster_request_correlated = False
        self._roster_reconciled = False
        # V3.34.6: keep a protected tail context after roster reconciliation.
        # Late 7502 member responses may arrive after the 90/90 request set is
        # complete. Only Atlas IDs from that locked roster are allowed to
        # inherit membership during this tail window.
        self._completed_roster_tag = ""
        self._completed_roster_name = ""
        self._completed_roster_ids = set()
        self._roster_tail_guard = False
        self._active_lab = None
        self._active_lab_request_captured = False
        self._active_lab_request_ts = None
        self._active_lab_candidates_seen = 0
        self._active_lab_window_seconds = 60.0
        self._raw_diag = None
        self._rb_last_7d02_counter = None
        self._rb_last_client_counter = None
        self._rb_raw_counter = None
        self._rb_raw_opcode = ""
        self._rb_raw_seen = []
        self._session_opcode_mask = None
        self._rb_last_client_opcode = ""
        self._rb_counter_history = []
        self._rb_last_7d02_hex = ""
        self._rb_test = None
        self._counter_lab = None
        self._counter_lab_open_count = 0
        self._sequence_lab = None
        self._sequence_targets = []
        self._sequence_index = 0
        self.protocol_discovery = False
        self._discovery_saved = 0
        self._discovery_limit = int(os.environ.get("WOS_DISCOVERY_MAX_FRAMES", "20000"))

    def reset(self, session_id: str):
        self.session_id = session_id
        self.stats_data = {"frames_7502":0,"req_7902":0,"req_7d02":0,"member_blocks":0,"roster_count":0,"decoded_players":0,"changed_players":0,"profile_refreshes":0,"map_frames":0,"map_blocks":0,"map_anchors":0,"map_rows":0}
        self.reassembler = TcpWosReassembler(self._on_frame)
        self._seen_blocks = set()
        self._best_rows = {}
        self._session_wos_confirmations = {}
        self._explicit_profile_frames = 0
        self._alliance_name_to_tag = {}
        self._alliance_tag_to_name = {}
        self._roster_epoch = 0
        self._roster_tag_votes = {}
        self._roster_tag_frames = {}
        self._roster_tag_names = {}
        self._roster_vote_candidate = ""
        self._roster_vote_streak = 0
        self._roster_identity_locked = False
        self._roster_active = False
        self._context_tag = ""
        self._context_name = ""
        self._pending_context_rows = []
        self._current_roster_count = 0
        self._current_requested_ids = set()
        self._recent_bulk_7902 = []  # [(timestamp,[Atlas IDs])], rolling 60s
        # V3.34.6 exact application transaction correlation.
        # 7D02 requests carry a transaction counter that is echoed by their
        # 7502 response; this is stronger than "the next 7502 frame".
        self._recent_7d_transactions = {}  # counter(bytes2) -> dict(ts,target,primary)
        self._current_roster_hint_ids = set()
        self._roster_request_correlated = False
        self._roster_reconciled = False
        # V3.34.6: keep a protected tail context after roster reconciliation.
        # Late 7502 member responses may arrive after the 90/90 request set is
        # complete. Only Atlas IDs from that locked roster are allowed to
        # inherit membership during this tail window.
        self._completed_roster_tag = ""
        self._completed_roster_name = ""
        self._completed_roster_ids = set()
        self._roster_tail_guard = False
        self._active_lab = None
        self._active_lab_request_captured = False
        self._active_lab_request_ts = None
        self._active_lab_candidates_seen = 0
        self._rb_last_7d02_counter = None
        self._rb_last_7d02_hex = ""
        self._rb_test = None
        self._sequence_lab = None
        self._sequence_targets = []
        self._sequence_index = 0
        self.protocol_discovery = False
        self._discovery_saved = 0
        self._discovery_limit = int(os.environ.get("WOS_DISCOVERY_MAX_FRAMES", "20000"))

    def set_protocol_discovery(self, enabled: bool):
        self.protocol_discovery = bool(enabled)
        self._discovery_saved = 0
        if self.protocol_discovery:
            self.log(f"PROTOCOL DISCOVERY MODE active: all reassembled WOS frames will be saved (limit {self._discovery_limit}).")
        else:
            self.log("Protocol discovery mode disabled.")

    def arm_active_lab(self, atlas_id: int):
        if not self.session_id:
            raise ValueError("Demarre d'abord une capture live.")
        info=self.db.active_lab_arm(self.session_id,int(atlas_id))
        if not info:
            raise ValueError("This target is not pending in the current roster.")
        self._active_lab=info
        self._active_lab_request_captured=False
        self._active_lab_request_ts=None
        self._active_lab_candidates_seen=0
        self.log(f"ACTIVE-LAB armed : {info.get('pseudo_display') or atlas_id} | Atlas {atlas_id} [{info.get('alliance_tag') or '?'}]")
        self.log("Open this profile EXACTLY ONCE in WOS now. V3.7 ignores auxiliary 7D02s and waits for the 6C7D primary profile request.")
        return info

    def start_sequence_lab(self, targets):
        if not self.session_id:
            raise ValueError("Demarre d'abord une capture live.")
        if self._sequence_lab:
            raise ValueError("Un Sequence Lab est deja actif.")
        clean=[]
        for r in targets:
            try: aid=int(r.get("atlas_id"))
            except Exception: continue
            clean.append({"atlas_id":aid,"wos_id":r.get("wos_id"),"pseudo_display":r.get("pseudo_display") or "?","alliance_tag":r.get("alliance_tag") or "?"})
        if not clean: raise ValueError("No valid target.")
        run_id=self.db.sequence_lab_start(self.session_id,len(clean))
        self._sequence_lab={"id":run_id,"expected":len(clean)}
        self._sequence_targets=clean; self._sequence_index=0
        first=clean[0]
        self.log(f"SEQUENCE-LAB started : {len(clean)} targets.")
        self.log(f"[1/{len(clean)}] Open now: [{first['alliance_tag']}] {first['pseudo_display']} | Atlas {first['atlas_id']}")
        return first

    def stop_sequence_lab(self, note="manual stop"):
        if not self._sequence_lab: return
        self.db.sequence_lab_stop(self._sequence_lab["id"],note)
        self.log(f"SEQUENCE-LAB stop : {self._sequence_index}/{len(self._sequence_targets)} requests captured.")
        self._sequence_lab=None; self._sequence_targets=[]; self._sequence_index=0

    def sequence_lab_primary_7d02(self, frame: bytes):
        if not self._sequence_lab or not self._is_primary_profile_7d02(frame): return False
        if self._sequence_index>=len(self._sequence_targets): return False
        target=self._sequence_targets[self._sequence_index]
        self._sequence_index+=1
        self.db.sequence_lab_add(self._sequence_lab["id"],self._sequence_index,target,frame)
        self.log(f"SEQUENCE-LAB capture [{self._sequence_index}/{len(self._sequence_targets)}] {target['pseudo_display']} | dynamic={frame[6:9].hex()} | target={frame[11:].hex()}")
        if self._sequence_index<len(self._sequence_targets):
            nxt=self._sequence_targets[self._sequence_index]
            self.log(f"[{self._sequence_index+1}/{len(self._sequence_targets)}] Open now: [{nxt['alliance_tag']}] {nxt['pseudo_display']} | Atlas {nxt['atlas_id']}")
        else:
            self.db.sequence_lab_stop(self._sequence_lab["id"],"completed")
            self.log("SEQUENCE-LAB FINISHED. Click Export Sequence.")
            self._sequence_lab=None; self._sequence_targets=[]
        return True

    def start_counter_lab(self,target:dict,expected_count:int=5):
        if not self.session_id: raise ValueError("Demarre d'abord une capture live.")
        if self._counter_lab: raise ValueError("Un Counter Lab est deja actif.")
        run_id=self.db.counter_lab_start(self.session_id,target,expected_count)
        self._counter_lab={"id":run_id,"target":dict(target),"expected":int(expected_count)}
        self._counter_lab_open_count=0
        self.log(f"COUNTER-LAB : open then close {target.get('pseudo_display') or target.get('atlas_id')} five times.")
        return self._counter_lab

    def stop_counter_lab(self,note="manual stop"):
        if not self._counter_lab:return
        self.db.counter_lab_stop(self._counter_lab["id"],note)
        self.log(f"COUNTER-LAB stop : {self._counter_lab_open_count}/{self._counter_lab['expected']}.")
        self._counter_lab=None
        self._counter_lab_open_count=0

    def counter_lab_frame(self,frame:bytes,direction:str):
        if not self._counter_lab or len(frame)<4:return
        opcode=frame[2:4].hex()
        if direction=="C>S":
            self.db.counter_lab_event(self._counter_lab["id"],self._counter_lab_open_count,
                                      "client-frame",direction,opcode,frame)
        if direction=="C>S" and self._is_primary_profile_7d02(frame):
            self._counter_lab_open_count+=1
            dyn_hex=frame[6:9].hex()
            dyn_val=int.from_bytes(frame[6:8],"little")
            target_hex=frame[11:].hex()
            self.db.counter_lab_event(self._counter_lab["id"],self._counter_lab_open_count,
                                      "primary-7d02",direction,opcode,frame,dyn_hex,dyn_val,target_hex)
            self.db.counter_lab_progress(self._counter_lab["id"],self._counter_lab_open_count)
            self.log(f"COUNTER-LAB [{self._counter_lab_open_count}/{self._counter_lab['expected']}] dyn={dyn_hex} value={dyn_val}")
            if self._counter_lab_open_count < self._counter_lab["expected"]:
                self.log("Close the profile then reopen THE SAME player.")
            else:
                self.db.counter_lab_stop(self._counter_lab["id"],"completed")
                self.log("COUNTER-LAB FINISHED. Click Export Counter.")
                self._counter_lab=None

    @staticmethod
    def _encode_aid_target(atlas_id:int)->bytes:
        raw=int(atlas_id).to_bytes(4,"little",signed=False)
        return raw[:2]+b"\x03"+raw[2:]

    def build_profile_7d02(self,atlas_id:int,counter:int)->bytes:
        raw=self._encode_aid_target(atlas_id)
        mask=self._session_opcode_mask or 0
        if mask==0x20:
            # Observed 5D family: total 15 bytes, no standalone 01 before C404.
            return (b"\x00\x0d\x5d\x02\x6c\x7d"
                    +int(counter).to_bytes(2,"little",signed=False)
                    +b"\xc4\x04"+raw)
        return (b"\x00\x0e\x7d\x02\x6c\x7d"
                +int(counter).to_bytes(2,"little",signed=False)
                +b"\x01\xc4\x04"+raw)

    def arm_request_builder(self,target:dict):
        if not self.session_id:
            raise ValueError("Demarre d'abord une capture live.")
        if self._rb_raw_counter is None:
            raise ValueError("Aucun compteur BRUT observe. Laisse WOS actif quelques secondes puis reessaie.")
        if self._rb_test:
            raise ValueError("Un test Request Builder est deja arme.")
        last_counter=self._rb_raw_counter
        predicted=(last_counter+2)&0xffff
        frame=self.build_profile_7d02(int(target["atlas_id"]),predicted)
        test_id=self.db.request_builder_arm(
            self.session_id,target,last_counter,predicted,frame.hex()
        )
        self._rb_test={"id":test_id,"target":dict(target),"predicted_counter":predicted,
                       "predicted_hex":frame.hex(),"last_client_counter":last_counter}
        self.log(f"RAW-BUILDER ARMED : {target.get('pseudo_display') or target['atlas_id']}")
        self.log(f"Current raw counter={last_counter} ({self._rb_raw_opcode}) -> provisional prediction={predicted}")
        self.log("Open THIS profile now. The prediction will be adjusted in real-time on each intermediate request.")
        return dict(self._rb_test)

    def request_builder_observe(self,frame:bytes,direction:str):
        # V3.15 compares on the RAW client stream before reassembly.
        # Keep only legacy 7D02 visibility for the rest of the collector.
        if direction!="C>S" or len(frame)<8:
            return
        if frame[2:4] in (b"\x7d\x02",b"\x5d\x02"):
            self._rb_last_7d02_counter=int.from_bytes(frame[6:8],"little")
            self._rb_last_7d02_hex=frame.hex()

    @staticmethod
    def _split_raw_wos_frames(payload:bytes):
        """Best-effort split of one TCP payload into WOS length-prefixed frames."""
        out=[]; i=0
        while i+4<=len(payload):
            declared=int.from_bytes(payload[i:i+2],"big")
            total=declared+2
            if 6<=total<=65535 and i+total<=len(payload):
                out.append(payload[i:i+total]); i+=total
            else:
                # Most observed client payloads are exactly one complete frame.
                if i==0:
                    out.append(payload)
                break
        return out

    def _extract_raw_counter(self,frame:bytes):
        if len(frame)<6:return None
        op=frame[2:4]
        prev=self._rb_raw_counter

        # Long client requests: counter at bytes 6..7.
        # Both session families are supported (e.g. 7D02 and XOR-20 => 5D02).
        if len(frame)>=8 and frame[3]==0x02 and frame[2] in (
            0x1d,0x3d,0x5d,0x7d,0x59,0x79
        ):
            return int.from_bytes(frame[6:8],"little")
        if op==b"\x35\x02" and len(frame)>=7:
            return int.from_bytes(frame[5:7],"little")
        if prev is None:return None

        ranked=[]
        for pos in range(4,min(len(frame)-1,14)):
            v=int.from_bytes(frame[pos:pos+2],"little")
            d=(v-prev)&0xffff
            if 0<d<=64 and d%2==0:
                ranked.append((0 if d==2 else 1,d,pos,v))
        if not ranked:return None
        ranked.sort()
        return ranked[0][-1]

    def raw_counter_packet(self,src_port,dst_port,payload,ts):
        if dst_port!=GAME_PORT or not payload:
            return
        frames=self._split_raw_wos_frames(payload)
        if not frames:
            frames=[payload]

        changed=False
        for frame in frames:
            if len(frame)<4:
                continue
            op=frame[2:4].hex()

            # Learn current opcode family from a primary profile request.
            if len(frame)>=6 and frame[3]==0x02 and frame[4:6]==b"\x6c\x7d":
                if frame[2]==0x7d:self._session_opcode_mask=0x00
                elif frame[2]==0x5d:self._session_opcode_mask=0x20

            counter=self._extract_raw_counter(frame)
            if counter is None:
                continue

            # Reject obvious backwards/stale duplicates, but allow 16-bit wrap.
            prev=self._rb_raw_counter
            if prev is not None:
                delta=(counter-prev)&0xffff
                if delta==0:
                    continue
                if delta>256 and not (prev>65000 and counter<256):
                    continue

            primary=self._is_primary_profile_7d02(frame)
            if primary and self._rb_test:
                predicted=self._rb_test["predicted_hex"]
                actual=frame.hex()
                target=int(self._rb_test["target"]["atlas_id"])
                target_ok=(frame[11:].hex()==self._encode_aid_target(target).hex())
                exact=(actual==predicted)
                result="MATCH" if exact else "MISMATCH"
                note=(f"RAW tracker V3.16; target={'OK' if target_ok else 'BAD'}; "
                      f"previous_raw_counter={self._rb_raw_counter}; "
                      f"predicted={self._rb_test['predicted_counter']}; actual={counter}")
                self.db.request_builder_result(self._rb_test["id"],counter,actual,result,note)
                self.log(f"RAW-BUILDER {result} | previous={self._rb_raw_counter} | predicted={self._rb_test['predicted_counter']} | actual={counter}")
                if not exact:
                    self.log(f"PREDICTED : {predicted}")
                    self.log(f"ACTUAL   : {actual}")
                self._rb_test=None

            self._rb_raw_counter=counter
            self._rb_raw_opcode=op
            stamp=datetime.fromtimestamp(ts,timezone.utc).astimezone().isoformat(timespec="milliseconds")
            self._rb_raw_seen.append((stamp,op,counter,frame.hex()))
            if len(self._rb_raw_seen)>500:
                self._rb_raw_seen=self._rb_raw_seen[-500:]
            changed=True

            if self._rb_test and not primary:
                predicted=(counter+2)&0xffff
                pframe=self.build_profile_7d02(int(self._rb_test["target"]["atlas_id"]),predicted)
                self._rb_test["predicted_counter"]=predicted
                self._rb_test["predicted_hex"]=pframe.hex()
                self._rb_test["last_client_counter"]=counter
                self.db.request_builder_update_prediction(
                    self._rb_test["id"],counter,predicted,pframe.hex()
                )

        if changed:
            try:
                self.stats_cb(self.db.stats())
            except Exception:
                pass

    def start_raw_diag(self,target):
        if not self.session_id: raise ValueError("Demarre d'abord une capture live.")
        if self._raw_diag: raise ValueError("Un diagnostic brut est deja actif.")
        rid=self.db.raw_diag_start(self.session_id,target)
        self._raw_diag={"id":rid,"target":dict(target),"packets":0}
        self.log(f"RAW-DIAG ARMED : {target.get('pseudo_display') or target['atlas_id']}")
        self.log("Open THIS profile once, wait 5 seconds, then Stop Raw.")
        return self._raw_diag

    def stop_raw_diag(self,note="manual stop"):
        if not self._raw_diag:return None
        d=self._raw_diag;self.db.raw_diag_stop(d["id"],note)
        self.log(f"RAW-DIAG STOP : {d['packets']} raw TCP payloads.")
        self._raw_diag=None;return d

    def raw_diag_packet(self,src_port,dst_port,seq,payload,ts):
        if not self._raw_diag or not payload:return
        direction="C>S" if dst_port==GAME_PORT else "S>C"
        seen=datetime.fromtimestamp(ts,timezone.utc).astimezone().isoformat(timespec="milliseconds")
        self.db.raw_diag_packet(self._raw_diag["id"],seen,direction,src_port,dst_port,seq,payload)
        self._raw_diag["packets"]+=1

    @staticmethod
    def _lab_norm_name(value):
        if not value:
            return ""
        import unicodedata
        t=unicodedata.normalize("NFKC",str(value)).casefold()
        return "".join(ch for ch in t if ch.isalnum())

    @staticmethod
    def _request_7d_counter(frame: bytes):
        # Observed on live_20260901_005433.pcap: C>S 7D02 counter is bytes
        # [6:8], echoed by S>C 7502 bytes [5:7].
        if len(frame) < 8 or frame[2:4] not in (b"\x7d\x02",b"\x5d\x02"):
            return None
        return bytes(frame[6:8])

    def _request_7d_single_target(self, frame: bytes):
        """Return an Atlas ID only when the request is structurally single-target.

        Two observed families are accepted:
        - primary 6C7D profile request (15/16 bytes), encoded target after C4 04;
        - short auxiliary request (<=30 bytes), raw uint32-LE target after 04.
        Larger 7D02 frames are deliberately excluded: they are multi-target
        batches even when a naive scan happens to find only one readable ID.
        """
        if len(frame) < 12 or frame[2:4] not in (b"\x7d\x02",b"\x5d\x02"):
            return None
        if self._is_primary_profile_7d02(frame):
            pos=frame.find(b"\xc4\x04",8)
            if pos >= 0:
                enc=frame[pos+2:]
                if len(enc)==5 and enc[2]==0x03:
                    raw=enc[:2]+enc[3:]
                    aid=int.from_bytes(raw,"little")
                    if 100_000_000 <= aid <= 300_000_000:
                        return aid
            return None
        if len(frame) > 30:
            return None
        vals=[]
        for i in range(10,len(frame)-4):
            if frame[i] != 0x04:
                continue
            aid=int.from_bytes(frame[i+1:i+5],"little")
            if 100_000_000 <= aid <= 300_000_000:
                vals.append(aid)
        vals=list(dict.fromkeys(vals))
        return vals[0] if len(vals)==1 else None

    @staticmethod
    def _response_7502_counter(frame: bytes):
        if len(frame) < 7 or frame[2:4] not in (b"\x75\x02",b"\x55\x02"):
            return None
        return bytes(frame[5:7])

    def _is_primary_profile_7d02(self,frame: bytes) -> bool:
        # Profile family is session-dependent: 7D02 or XOR-0x20 => 5D02.
        if len(frame) not in (15,16) or frame[3]!=0x02 or frame[4:6]!=b"\x6c\x7d":
            return False
        return frame[2] in (0x7d,0x5d)

    def _active_lab_expired(self, ts: float) -> bool:
        return bool(self._active_lab and self._active_lab_request_ts is not None
                    and ts-self._active_lab_request_ts > self._active_lab_window_seconds)

    def _active_lab_consider_row(self, row: dict, source_kind: str, ts: float) -> bool:
        """Record every decoded 7502 row after the primary request; finalize only on target match."""
        if not (self._active_lab and self._active_lab_request_captured and self._active_lab_request_ts is not None):
            return False
        if ts < self._active_lab_request_ts:
            return False
        if self._active_lab_expired(ts):
            attempt_id=self._active_lab["id"]
            self.db.active_lab_timeout(attempt_id,
                f"No target response after {self._active_lab_candidates_seen} candidates / {int(self._active_lab_window_seconds)}s")
            self.log(f"ACTIVE-LAB TIMEOUT : {self._active_lab_candidates_seen} candidates observed without a target.")
            self._active_lab=None
            self._active_lab_request_captured=False
            self._active_lab_request_ts=None
            return False

        target_atlas=int(self._active_lab.get("atlas_id") or 0)
        target_wos=int(self._active_lab.get("wos_id") or 0)
        target_name=self._lab_norm_name(self._active_lab.get("pseudo_display") or "")
        try: got_atlas=int(row.get("atlas_id") or 0)
        except Exception: got_atlas=0
        try: got_wos=int(row.get("wos_id") or row.get("wos_id_candidate") or 0)
        except Exception: got_wos=0
        got_name=self._lab_norm_name(row.get("pseudo_display") or row.get("pseudo_core") or "")

        # Canonical Atlas comparison also handles stuffing aliases already known by the DB.
        try:
            ca_target=self.db.canonical_atlas(target_atlas) or target_atlas
            ca_got=self.db.canonical_atlas(got_atlas) or got_atlas
        except Exception:
            ca_target,ca_got=target_atlas,got_atlas
        atlas_match=bool(got_atlas and ca_got==ca_target)
        wos_match=bool(target_wos and got_wos and got_wos==target_wos)
        pseudo_match=bool(target_name and got_name and got_name==target_name)
        score=(100 if atlas_match else 0)+(90 if wos_match else 0)+(20 if pseudo_match else 0)
        self._active_lab_candidates_seen += 1
        note=f"A:{got_atlas or '?'} W:{got_wos or '?'} name:{row.get('pseudo_display') or '?'}"
        self.db.active_lab_candidate(self._active_lab["id"],row,source_kind,
                                     atlas_match,wos_match,pseudo_match,score,note)

        # A stable identity match (Atlas OR WOS) is required. Pseudo alone is diagnostic only.
        if atlas_match or wos_match:
            attempt_id=self._active_lab["id"]
            why=[]
            if atlas_match: why.append("Atlas")
            if wos_match: why.append("WOS")
            if pseudo_match: why.append("pseudo")
            self.db.active_lab_response(attempt_id,row,True,
                "Target match by "+"+".join(why)+f" after {self._active_lab_candidates_seen} candidates")
            self.log(f"ACTIVE-LAB VALIDATED : {row.get('pseudo_display') or got_atlas} | A:{got_atlas} W:{got_wos or '?'} P:{row.get('power') or '?'} | match {'+'.join(why)}")
            self._active_lab=None
            self._active_lab_request_captured=False
            self._active_lab_request_ts=None
            return True
        return False

    @staticmethod
    def _row_quality(row: dict):
        # Same ordering as the validated V2.1 offline deduplicator.
        return (
            1 if row.get("atlas_id") else 0,
            1 if row.get("identity_pair_valid") else 0,
            1 if row.get("wos_confidence")=="high" else 0,
            1 if row.get("power_confidence")=="high" else 0,
            1 if row.get("pseudo_display") else 0,
            int(row.get("block_len") or 0),
        )

    def log(self, msg):
        self.log_cb(msg)

    def _emit_stats(self):
        d = dict(self.stats_data)
        d.update(self.db.stats())
        self.stats_cb(d)

    def feed_tcp(self, src_ip, src_port, dst_ip, dst_port, seq, payload, ts=None):
        self.reassembler.feed(src_ip, src_port, dst_ip, dst_port, seq, payload, ts or time.time())

    @staticmethod
    def _mode_nonempty(values):
        vals=[v for v in values if v]
        if not vals:
            return ""
        from collections import Counter
        return Counter(vals).most_common(1)[0][0]

    def _vote_structured_roster_tag(self, member_blocks, frame_fid):
        """V3.34.6: vote only from the first structured alliance field of player blocks.

        V3.31/V3.32 searched every bounded 3-letter uppercase token in the
        complete server frame.  That allowed unrelated text such as SEA to
        accumulate votes beside the real roster tag.  Here a vote exists only
        when DecoderBundle.decode_direct_alliance() validates the local wire
        structure near B5 1E DC and takes ONLY the first nearby declared
        length-03 field (the second observed field can be SEA).

        Each decoded member block contributes at most one hit.  Distinct-frame
        coverage is still tracked separately so a single large TCP/application
        frame cannot lock the roster by itself.
        """
        if not self._roster_active or not member_blocks:
            return "","",0,0

        for block in member_blocks:
            tag,name,score=self.decoder.decode_direct_alliance(block)
            tag=(tag or "").strip()
            name=(name or "").strip()
            if not tag or score is None:
                continue
            # Avoid obvious protocol/UI tokens while retaining numeric tags.
            if not re.fullmatch(r"[A-Z0-9]{2,3}",tag):
                continue
            if tag in {"THE","AND","YOU","VIP","UTC","TCP","WOS"}:
                continue

            self._roster_tag_votes[tag]=self._roster_tag_votes.get(tag,0)+1
            self._roster_tag_frames.setdefault(tag,set()).add(frame_fid)
            if name:
                d=self._roster_tag_names.setdefault(tag,{})
                d[name]=d.get(name,0)+1

        eligible=[]
        for tag,count in self._roster_tag_votes.items():
            nframes=len(self._roster_tag_frames.get(tag,set()))
            if count>=3 and nframes>=2:
                eligible.append((count,nframes,tag))
        if not eligible:
            return "","",0,0
        eligible.sort(reverse=True)
        count,nframes,tag=eligible[0]

        # Prefer the name observed in the same structured member field.
        names=self._roster_tag_names.get(tag,{})
        name=max(names.items(), key=lambda kv:kv[1])[0] if names else ""
        if not name:
            for kt,kn,ka in self.db.known_alliance_tags():
                if kt==tag:
                    name=kn or ""
                    break
        return tag,name,count,nframes

    def _roster_vote_consensus_ready(self, tag: str, hits: int, nframes: int):
        """Require enough roster progress + dominance before publishing a TAG."""
        if not tag or not self._roster_active:
            return False,0,0,0

        requested=len(self._current_requested_ids)
        announced=max(0,int(self._current_roster_count or 0))
        # V4.0.23 small-roster fix. The old floor of 8 made consensus
        # mathematically impossible for alliances with fewer than 8 announced
        # members. Scale the progress requirement to the roster size while
        # retaining the old 25% rule for normal/large rosters.
        if announced:
            min_ids=min(announced, max(2, int(math.ceil(announced*0.25))))
        else:
            min_ids=12

        # Track winner stability over consecutive server frames.
        if tag==self._roster_vote_candidate:
            self._roster_vote_streak += 1
        else:
            self._roster_vote_candidate=tag
            self._roster_vote_streak=1

        # Runner-up pressure: winner must have a meaningful lead.
        others=[]
        for otag,ocount in self._roster_tag_votes.items():
            if otag==tag:
                continue
            oframes=len(self._roster_tag_frames.get(otag,set()))
            others.append((ocount,oframes,otag))
        runner_hits,runner_frames,runner_tag=max(others, default=(0,0,""))

        known={kt for kt,kn,ka in self.db.known_alliance_tags()}
        is_known=tag in known
        # V4.0.23: fixed thresholds (6/10 hits) could never be reached by
        # genuinely small alliances. Keep conservative defaults for normal
        # rosters, but cap them by the announced population.
        base_hits=6 if is_known else 10
        if announced:
            min_hits=min(base_hits, max(2, announced))
            min_frames=min(3 if is_known else 4, max(2, announced))
        else:
            min_hits=base_hits
            min_frames=3 if is_known else 4

        lead_ok = (hits >= runner_hits + 3) or (runner_hits==0 and hits>=min_hits)
        frame_lead_ok = nframes >= runner_frames or nframes>=min_frames+1
        ready=(
            requested >= min_ids and
            hits >= min_hits and
            nframes >= min_frames and
            self._roster_vote_streak >= 2 and
            lead_ok and frame_lead_ok
        )
        return ready,min_ids,runner_hits,runner_frames

    def _raw_canonical_alliance(self, frame: bytes):
        """Find a ranking-known alliance TAG directly in the raw 7502 bytes.

        This bypasses the generic string decoder which can turn KOR into 8PO or
        HPL into WET when transport stuffing bytes are interpreted as text.
        A candidate must be a known Alliance Discovery TAG and occur as a
        compact field (bounded by non-alphanumeric bytes).
        """
        candidates=[]
        for tag,name,aid in self.db.known_alliance_tags():
            try:
                btag=tag.encode("ascii")
            except Exception:
                continue
            if not (2<=len(btag)<=3):
                continue
            count=0; pos=0
            while True:
                p=frame.find(btag,pos)
                if p<0: break
                left=frame[p-1] if p>0 else 0
                right=frame[p+len(btag)] if p+len(btag)<len(frame) else 0
                def alnum(x):
                    return 48<=x<=57 or 65<=x<=90 or 97<=x<=122
                if not alnum(left) and not alnum(right):
                    count+=1
                pos=p+1
            if count:
                candidates.append((count,tag,name,aid))
        if not candidates:
            return "","",None,0
        candidates.sort(reverse=True,key=lambda x:(x[0],len(x[1])))
        count,tag,name,aid=candidates[0]
        return tag,name,aid,count

    def _canonicalize_alliance_observation(self, tag: str, name: str):
        """Return a conservative canonical (tag, name, strong) alliance observation.

        Only exact matches against Alliance Discovery or already remembered
        tag/name pairs are considered strong. This deliberately avoids fuzzy
        substitutions (e.g. KOR -> 8PO) on non-roster traffic.
        """
        import re
        raw_tag=(tag or "").strip()
        raw_name=(name or "").strip()

        # Keep only a plausible compact TAG. Do not try to repair it fuzzily.
        clean_tag=re.sub(r"[^A-Za-z0-9]", "", raw_tag).upper()
        if not (2 <= len(clean_tag) <= 3):
            clean_tag=""

        # Build canonical maps from persisted discovery plus this session cache.
        by_tag={}
        by_name={}
        try:
            known=self.db.known_alliance_tags()
        except Exception:
            known=[]
        for ktag,kname,_aid in known:
            ktag=(ktag or "").strip()
            kname=(kname or "").strip()
            if ktag:
                by_tag[ktag.upper()]=(ktag,kname)
            if kname:
                by_name[self._lab_norm_name(kname)]=(ktag,kname)
        for ktag,kname in self._alliance_tag_to_name.items():
            if ktag:
                by_tag[str(ktag).upper()]=(str(ktag),str(kname or ""))
        for kname,ktag in self._alliance_name_to_tag.items():
            if kname:
                by_name[self._lab_norm_name(kname)]=(str(ktag or ""),str(kname))

        # Exact known TAG is sufficient; if a known name exists, return it too.
        if clean_tag and clean_tag in by_tag:
            ctag,cname=by_tag[clean_tag]
            if raw_name:
                nkey=self._lab_norm_name(raw_name)
                # A conflicting known name means the block is ambiguous: reject.
                if nkey in by_name and by_name[nkey][0] and by_name[nkey][0].upper()!=ctag.upper():
                    return "","",False
            return ctag,cname or raw_name,True

        # Exact known alliance name may recover its canonical TAG.
        if raw_name:
            nkey=self._lab_norm_name(raw_name)
            if nkey and nkey in by_name:
                ctag,cname=by_name[nkey]
                if ctag:
                    return ctag,cname or raw_name,True

        # Unknown observations remain unverified and must not establish context.
        return clean_tag,raw_name,False

    def _remember_alliance(self, tag: str, name: str):
        tag=(tag or "").strip(); name=(name or "").strip()
        if tag and name:
            self._alliance_name_to_tag[name]=tag
            self._alliance_tag_to_name[tag]=name

    def _apply_alliance_context(self, row: dict, tag: str = "", name: str = ""):
        """V3.33.1: roster rows remain unverified until roster identity is locked.

        During an active roster epoch, individual decoded TAGs are NOT trusted:
        stuffing can turn KOR->8PO or HPL->WET, and raw incidental bytes can
        temporarily vote SEA. We buffer the rows and, only after a consensus
        lock, force the verified roster TAG onto Atlas IDs explicitly requested
        by that roster's 7902 batches.

        Outside an active roster, the previous canonical explicit-block logic
        remains available for normal profile/ranking observations.
        """
        r=dict(row)
        aid=None
        try: aid=int(r.get("atlas_id"))
        except Exception: pass

        # Active roster: no row may publish a membership before consensus lock.
        if self._roster_active:
            if not self._roster_identity_locked or not self._context_tag:
                r["alliance_tag"]=""
                r["alliance_name"]=""
                r["alliance_verified"]=False
                r["alliance_source"]=""
                return r

            # After lock, only Atlas IDs explicitly requested as roster members
            # inherit the locked identity.
            if aid is not None and aid in self._current_requested_ids:
                r["alliance_tag"]=self._context_tag
                r["alliance_name"]=self._context_name
                r["alliance_verified"]=True
                r["alliance_source"]="7902-roster-consensus"
                return r

            r["alliance_tag"]=""
            r["alliance_name"]=""
            r["alliance_verified"]=False
            r["alliance_source"]=""
            return r

        # Completed-roster tail: server member responses can continue after
        # reconciliation has switched _roster_active off. Preserve the locked
        # alliance ONLY for Atlas IDs that were explicitly requested in that
        # roster. Everything else stays unverified so an incidental KOR/SEA or
        # a compact Atlas false-positive cannot create a fake membership.
        if self._roster_tail_guard and self._completed_roster_tag:
            if aid is not None and aid in self._completed_roster_ids:
                r["alliance_tag"]=self._completed_roster_tag
                r["alliance_name"]=self._completed_roster_name
                r["alliance_verified"]=True
                r["alliance_source"]="7902-roster-tail"
                return r
            r["alliance_tag"]=""
            r["alliance_name"]=""
            r["alliance_verified"]=False
            r["alliance_source"]="roster-tail-rejected"
            return r

        # Non-roster traffic: retain canonical explicit-block behavior.
        raw_tag=(r.get("alliance_tag") or "").strip()
        raw_name=(r.get("alliance_name") or "").strip()
        rtag,rname,strong=self._canonicalize_alliance_observation(raw_tag,raw_name)
        r["alliance_tag"]=rtag
        r["alliance_name"]=rname
        r["alliance_verified"]=bool(strong)
        r["alliance_source"]="explicit-block-canonical" if strong else ""
        if strong:
            self._remember_alliance(rtag,rname)
        return r

    def _close_active_roster_context(self, reason: str):
        """Close an incomplete roster epoch without publishing a partial roster.

        A UI switch can occur before all 7902 requests for the previous alliance
        arrive. Keeping that epoch active is dangerous because the next
        alliance's request batch would inherit the old tag.
        """
        if not self._roster_active:
            return
        tag=self._context_tag or self._roster_vote_candidate or "?"
        got=len(self._current_requested_ids)
        announced=int(self._current_roster_count or 0)
        if self._context_tag and announced and got >= announced:
            self._maybe_reconcile_roster()
            return
        self.log(
            f"Roster context closed [{tag}] : {got}/{announced or '?'} correlated AIDs "
            f"({reason})"
        )
        self._roster_active=False
        self._roster_identity_locked=False
        self._context_tag=""
        self._context_name=""
        self._pending_context_rows=[]
        self._current_requested_ids=set()
        self._current_roster_hint_ids=set()
        self._roster_request_correlated=False
        self._roster_reconciled=False
        self._roster_tag_votes={}
        self._roster_tag_frames={}
        self._roster_tag_names={}
        self._roster_vote_candidate=""
        self._roster_vote_streak=0
        # A hard epoch switch means late rows from the old roster must not
        # inherit its membership either.
        self._completed_roster_tag=""
        self._completed_roster_name=""
        self._completed_roster_ids=set()
        self._roster_tail_guard=False

    def _maybe_reconcile_roster(self):
        if self._roster_reconciled or not self._roster_active:
            return
        if not self._context_tag or not self._current_roster_count:
            return
        if len(self._current_requested_ids) < self._current_roster_count:
            return
        self.db.reconcile_alliance_membership(
            self.session_id,self._context_tag,self._context_name,self._current_requested_ids
        )
        self._roster_reconciled=True
        # Snapshot the verified roster before leaving active-vote mode. This is
        # intentionally separate from _roster_active so ranking/map traffic can
        # never expand the roster, while delayed member responses remain safe.
        self._completed_roster_tag=self._context_tag
        self._completed_roster_name=self._context_name
        self._completed_roster_ids=set(self._current_requested_ids)
        self._roster_tail_guard=True
        self.log(
            f"Roster locked [{self._context_tag}] : "
            f"{len(self._current_requested_ids)}/{self._current_roster_count} verified Atlas"
        )
        # V3.34 final generic audit for ANY scanned alliance.
        try:
            ids=list(self._current_requested_ids)
            verified=provisional=conflict=unresolved=0
            dup_wos=0
            if ids:
                qs=",".join("?" for _ in ids)
                rows=self.db.conn.execute(
                    f"SELECT atlas_id,wos_id FROM players WHERE atlas_id IN ({qs})",ids
                ).fetchall()
                verified=sum(1 for r in rows if r["wos_id"] is not None)
                unresolved=max(0,len(ids)-verified)
                crows=self.db.conn.execute(
                    f"""SELECT status,COUNT(*) n FROM identity_observations
                        WHERE session_id=? AND atlas_id IN ({qs})
                        GROUP BY status""",[self.session_id]+ids
                ).fetchall()
                cm={r["status"]:int(r["n"]) for r in crows}
                provisional=cm.get("PROVISIONAL",0)
                conflict=cm.get("CONFLICT",0)
                d=self.db.conn.execute(
                    f"""SELECT wos_id,COUNT(*) n FROM players
                        WHERE atlas_id IN ({qs}) AND wos_id IS NOT NULL
                        GROUP BY wos_id HAVING COUNT(*)>1""",ids
                ).fetchall()
                dup_wos=len(d)
            self.log(
                f"Roster audit [{self._context_tag}] : {len(ids)} AID | "
                f"{verified} known WOS | {unresolved} without WOS | "
                f"{conflict} conflicts obs. | {provisional} provisional obs. | "
                f"{dup_wos} WOS duplicates"
            )
        except Exception as e:
            self.log(f"Roster audit: diagnostic unavailable ({e})")
        # Critical V3.22 fix retained: a completed roster must not leak its
        # alliance context into later ranking/map 7902 batches. The V3.34.6
        # tail guard above is whitelist-only and cannot add new members.
        self._roster_active=False
        self._pending_context_rows=[]

    def _store_row(self, row: dict, source: str = "7502-member"):
        if not row.get("atlas_id"):
            return

        # Unified V4.0.7 Atlas roster bridge. The Atlas import already gives us
        # the current player -> alliance membership. When the WOS ranking emits
        # normal 7902/7502 traffic, use that imported affiliation as a safe
        # membership anchor instead of requiring a compact alliance roster to be
        # opened again. Identity (WOS ID/power) is still validated by the normal
        # WOS observation guards below; Atlas never manufactures a WOS ID.
        try:
            anchor_fn=getattr(self.db,"atlas_anchor_for_player",None)
            anchor=anchor_fn(row.get("atlas_id")) if callable(anchor_fn) else None
            if anchor and anchor.get("alliance_tag"):
                if not row.get("alliance_verified") or not row.get("alliance_tag"):
                    row=dict(row)
                    row["alliance_tag"]=anchor.get("alliance_tag")
                    row["alliance_verified"]=True
                    row["alliance_source"]="atlas-roster-anchor"
                    if not row.get("pseudo_display") and anchor.get("pseudo_display"):
                        row["pseudo_display"]=anchor.get("pseudo_display")
        except Exception:
            pass

        self.stats_data["decoded_players"] += 1
        atlas_key=str(row.get("atlas_id") or "")

        # V3.34.6: session identity consensus. If the same Atlas produces
        # contradictory WOS IDs, do not allow one anomalous decode to become
        # the session's best row. An explicit profile is exempt.
        incoming_wos=row.get("wos_id")
        previous=self._best_rows.get(atlas_key)
        if previous is not None and incoming_wos and previous.get("wos_id") and str(incoming_wos) != str(previous.get("wos_id")) and not self.db._is_explicit_source(source):
            key=(atlas_key,str(incoming_wos))
            self._session_wos_confirmations[key]=self._session_wos_confirmations.get(key,0)+1
            required=3 if row.get("identity_pair_valid") else 5
            if self._session_wos_confirmations[key] < required or (row.get("wos_confidence") or "").lower() != "high":
                # Preserve all non-identity improvements while retaining the
                # established WOS ID for this Atlas.
                row=dict(row)
                row["wos_id"]=previous.get("wos_id")
                row["wos_id_candidate"]=incoming_wos
                row["wos_confidence"]=previous.get("wos_confidence") or row.get("wos_confidence")
        if previous is not None and self._row_quality(row) <= self._row_quality(previous):
            return
        self._best_rows[atlas_key]=row
        if self.db.upsert_player(row,self.session_id,source):
            self.stats_data["changed_players"] += 1
            name=row.get("pseudo_display") or f"Atlas {row['atlas_id']}"
            pshow=row.get("power") or (f"~{row.get('power_candidate')}?" if row.get('power_candidate') else "?")
            self.log(f"{name} | A:{row['atlas_id']} W:{row.get('wos_id') or '?'} P:{pshow} [{row.get('alliance_tag') or '?'}]")
        pconf=(row.get("power_confidence") or "").lower()
        verified_membership=bool(row.get("alliance_verified") and row.get("alliance_tag"))
        if verified_membership:
            self.db.record_membership(
                self.session_id,row.get("alliance_tag") or "",row.get("alliance_name") or "",
                [row.get("atlas_id")],row.get("alliance_source") or source,"verified"
            )
        if row.get("power") and pconf=="high":
            self.db.resolve_refresh(row.get("atlas_id"),self.session_id)
            if self.db._is_explicit_source(source):
                self.stats_data["profile_refreshes"] += 1
        elif verified_membership:
            # V3.5 queues ONLY verified alliance members. Context-only / stray
            # profile frames can never pollute another alliance's refresh queue.
            self.db.queue_refresh(row,self.session_id,"power_"+(pconf or "missing"))

    def _flush_pending_context(self):
        if not self._pending_context_rows or not (self._context_tag or self._context_name):
            return
        pending=self._pending_context_rows
        self._pending_context_rows=[]
        still=[]
        for row in pending:
            filled=self._apply_alliance_context(row,self._context_tag,self._context_name)
            if filled.get("alliance_verified"):
                self._store_row(filled)
            else:
                still.append(row)
        self._pending_context_rows=still

    @staticmethod
    def _decode_structured_alliance_ranking_entries(frame: bytes):
        """V3.27: flexible ranking-entry decoder.

        Two independent stuffing variants are now handled:
        - marker: DC 1C 08 OR DC 1C <stuff> 08
        - alliance ID: plain 4-byte LE, <stuff>+ID, or ID with one inserted byte

        Selection is deterministic: prefer a valid 4-byte ID at bytes 1..4
        (prefix stuffing), then bytes 0..3 (plain), then a unique single-byte
        deletion candidate. This correctly separates the observed POL, ZED,
        HPL and WET entries without borrowing labels from neighboring entries.
        """
        # Flexible entry markers. Keep exact byte spans so every segment is
        # bounded by the next marker, even when the marker itself is stuffed.
        marks=[]
        i=0
        while i < len(frame)-2:
            if frame[i:i+3] == b"\xdc\x1c\x08":
                marks.append((i,i+3)); i+=3; continue
            if i+4<=len(frame) and frame[i:i+2]==b"\xdc\x1c" and frame[i+3]==0x08:
                marks.append((i,i+4)); i+=4; continue
            i+=1

        out=[]
        for n,(mstart,mend) in enumerate(marks):
            end=marks[n+1][0] if n+1<len(marks) else len(frame)
            seg=frame[mend:end]
            if len(seg)<5:
                continue

            aid=None
            # 1) Prefix-stuffed representation: [stuff][4-byte LE ID].
            if len(seg)>=5:
                v=int.from_bytes(seg[1:5],"little")
                if 3693000000 <= v < 3693100000:
                    aid=v
            # 2) Plain representation.
            if aid is None:
                v=int.from_bytes(seg[:4],"little")
                if 3693000000 <= v < 3693100000:
                    aid=v
            # 3) One byte inserted inside a 5-byte representation.
            if aid is None and len(seg)>=5:
                q=seg[:5]
                cands=[]
                for drop in range(5):
                    v=int.from_bytes(q[:drop]+q[drop+1:],"little")
                    if 3693000000 <= v < 3693100000 and v not in cands:
                        cands.append(v)
                if len(cands)==1:
                    aid=cands[0]

            # Locate the alliance name. FC is common; other compact prefixes
            # are skipped until the first plausible printable/UTF-8 name byte.
            body=b""
            search_from=4
            fc=seg.find(b"\xfc",search_from,min(14,len(seg)))
            if fc>=0:
                body=seg[fc+1:]
            else:
                # Name must be followed by 03 (tag separator). Try starts after
                # the 4/5-byte ID and its compact prefix.
                for k in range(4,min(11,len(seg))):
                    if seg[k]>=32:
                        candidate=seg[k:]
                        if b"\x03" in candidate:
                            body=candidate
                            break
            if not body:
                continue

            sep=body.find(b"\x03")
            if sep<=0:
                continue
            raw_name=body[:sep]
            clean=(raw_name.replace(b"\x7f",b"")
                           .replace(b"\x8f",b"")
                           .replace(b"\xff\x00",b""))
            try:
                name=clean.decode("utf-8","ignore").replace("\x00","")
                # Drop transport/control residue before the visible name.
                name="".join(ch for ch in name if ord(ch)>=32).strip()
                # If an ASCII alliance name follows a decoded transport glyph,
                # trim only the prefix before the first ASCII alphanumeric.
                ascii_positions=[j for j,ch in enumerate(name)
                                 if ("0"<=ch<="9" or "A"<=ch<="Z" or "a"<=ch<="z")]
                if len(ascii_positions)>=3 and ascii_positions[0]>0:
                    name=name[ascii_positions[0]:]
            except Exception:
                name=""

            tagraw=body[sep+1:sep+8]
            # Tags are exactly three visible chars in the ranking. Read from
            # the beginning of the tag field and ignore control/stuffing bytes.
            # Do NOT scan into following metadata (the old code produced G1P,
            # OW1, Gg0 by doing that).
            tagchars=[]
            for b in tagraw:
                if 48<=b<=57 or 65<=b<=90 or 97<=b<=122:
                    tagchars.append(chr(b))
                    if len(tagchars)>=3:
                        break
            tag="".join(tagchars)
            if not (2<=len(tag)<=3): tag=""
            if not (1<=len(name)<=40): name=""

            if aid is not None or tag or name:
                out.append((aid,tag,name))
        return out

    @classmethod
    def _scan_state_alliance_ids(cls, frame: bytes):
        return list(dict.fromkeys(
            aid for aid,tag,name in cls._decode_structured_alliance_ranking_entries(frame)
            if aid is not None
        ))

    @classmethod
    def _scan_alliance_ranking_labels(cls, frame: bytes):
        return [(aid,tag,name)
                for aid,tag,name in cls._decode_structured_alliance_ranking_entries(frame)
                if aid is not None and (tag or name)]

    @staticmethod
    def _map_norm_name(value: str) -> str:
        import unicodedata
        s=unicodedata.normalize("NFKC", str(value or "")).replace("\xa0"," ")
        return " ".join(s.casefold().split())




    def _decode_map_frame(self, frame: bytes):
        """V4.0.15: conservative decoder for large world-map 7D02 responses.

        Map payloads contain many compact ``dc1c`` player/city records.  We reuse
        the proven member decoder, but NOTHING is committed unless the decoded
        record can be anchored back to the Atlas census already present in the
        database (Atlas ID + compatible name, or unique name/alliance fallback).
        This keeps map discovery read-only/conservative while we learn the exact
        coordinate/ID layout.
        """
        if len(frame) < 500:
            return
        self.stats_data["map_frames"] = self.stats_data.get("map_frames",0)+1
        starts=[m.start() for m in re.finditer(b"\\xda\\x1c|\\xdc\\x1c", frame)]
        if not starts:
            return
        resolver=getattr(self.db,"map_resolve_anchor",None)
        recorder=getattr(self.db,"map_record_observation",None)
        if not callable(resolver):
            return
        seen_local=set()
        for i,st in enumerate(starts):
            en=starts[i+1] if i+1<len(starts) else min(len(frame),st+900)
            # Include a little prefix: in map packets the compact record header
            # can sit just before dc1c, while capping the slice avoids one record
            # borrowing identifiers from a neighbour.
            bs=max(0,st-48); be=min(len(frame),max(en,st+220))
            block=frame[bs:be]
            self.stats_data["map_blocks"] = self.stats_data.get("map_blocks",0)+1
            try:
                row=self.decoder.decode_member_block(block)
            except Exception:
                continue
            if not row:
                continue
            try:
                anchor=resolver(row)
            except Exception:
                anchor=None
            if not anchor:
                decoded_atlas=None
                try: decoded_atlas=int(row.get("atlas_id")) if row.get("atlas_id") not in (None,"") else None
                except Exception: pass
                if decoded_atlas:
                    anchor = {"atlas_id": decoded_atlas, "pseudo_display": row.get("pseudo_display"), "alliance_tag": row.get("alliance_tag"), "anchor_kind": "unlocked-discovery"}
                else:
                    continue

            # --- Live coordinate extraction (Antigravity patch) ---
            v_idx = 0
            last_x, last_y = None, None
            while True:
                v_idx = frame.find(b'\x44\x06\x02\x1f', v_idx)
                if v_idx == -1 or v_idx > st: break
                try:
                    val, shift = 0, 0
                    p = v_idx + 4
                    while True:
                        b = frame[p]; val |= (b & 0x7f) << shift; p += 1; shift += 7
                        if not (b & 0x80): break
                    cx = val
                    val, shift = 0, 0
                    while True:
                        b = frame[p]; val |= (b & 0x7f) << shift; p += 1; shift += 7
                        if not (b & 0x80): break
                    cy = val
                    if 1 <= cx <= 1500 and 1 <= cy <= 1500:
                        last_x, last_y = cx, cy
                except: pass
                v_idx += 4
            if last_x and last_y:
                anchor['atlas_x'] = last_x
                anchor['atlas_y'] = last_y

            atlas=int(anchor["atlas_id"])
            k=(atlas,st)
            if k in seen_local:
                continue
            seen_local.add(k)
            self.stats_data["map_anchors"] = self.stats_data.get("map_anchors",0)+1

            decoded_atlas=None
            try: decoded_atlas=int(row.get("atlas_id")) if row.get("atlas_id") not in (None,"") else None
            except Exception: decoded_atlas=None
            # Atlas can anchor the block, but it must never manufacture structural
            # pair validity.  Only retain pair_valid when the decoder itself found
            # the same Atlas ID in this exact compact block.
            anchored=dict(row)
            anchored["atlas_id"]=atlas
            anchored["pseudo_display"]=anchor.get("pseudo_display") or row.get("pseudo_display") or ""
            anchored["alliance_tag"]=anchor.get("alliance_tag") or row.get("alliance_tag") or ""
            anchored["alliance_verified"]=bool(anchor.get("alliance_tag"))
            anchored["alliance_source"]="map-atlas-anchor"
            anchored["identity_pair_valid"]=bool(row.get("identity_pair_valid") and decoded_atlas==atlas)
            if decoded_atlas is not None and decoded_atlas!=atlas:
                # A unique-name fallback may still identify the city, but a numeric
                # ID decoded for another Atlas is quarantined and cannot become WOS.
                anchored["wos_id_candidate"]=row.get("wos_id") or row.get("wos_id_candidate")
                anchored["wos_id"]=""
                anchored["wos_confidence"]="suspect"
                anchored["identity_pair_valid"]=False

            if callable(recorder):
                try:
                    recorder(self.session_id, atlas, anchor, row, len(frame), st, block)
                except Exception:
                    pass
            # Store only rows with a trustworthy structural Atlas match.  Name-only
            # anchors are retained as map observations for coordinate work but are
            # not allowed to alter identity/power yet.
            if decoded_atlas==atlas:
                self.stats_data["map_rows"] = self.stats_data.get("map_rows",0)+1
                # V4.0.24: MAP records can identify Atlas/WOS structurally, but
                # decode_member_power() does NOT yet identify total player power
                # in this record family. Keep Pcand only in map_observations; do
                # not feed it into players/power_observations.
                anchored["power"]=""
                anchored["power_candidate"]=""
                anchored["power_confidence"]="map-field-unverified"
                self._store_row(anchored,"map-7d02-atlas-anchored")




    def heuristic_extract_roster(self, payload):
        import re, struct
        players = []
        matches = re.finditer(b"([A-Za-z0-9_]{4,15})", payload)
        seen_names = set()
        for m in matches:
            name = m.group(1).decode('ascii')
            if name in seen_names or "png" in name or "_" in name or name.lower() in ("false", "true", "perfectworld"):
                continue
            start = max(0, m.start() - 150)
            window = payload[start:m.start()]
            ints = []
            for i in range(len(window)-3):
                val = struct.unpack("<I", window[i:i+4])[0]
                ints.append(val)
            atlas_id = None
            power = None
            for val in reversed(ints):
                if 1_000_000 <= val <= 999_000_000:
                    if power is None and val < 100_000_000:
                        power = val
                    elif atlas_id is None and val != power:
                        atlas_id = val
            if atlas_id and power:
                players.append((atlas_id, name, power))
                seen_names.add(name)
        return players

    def _on_frame(self, key, frame: bytes, ts: float):
        src_ip, src_port, dst_ip, dst_port = key
        direction = "S>C" if src_port == GAME_PORT else "C>S"
        self.request_builder_observe(frame,direction)
        self.counter_lab_frame(frame,direction)
        opcode = frame[2:4].hex() if len(frame)>=4 else ""
        opcode_norm={"5d02":"7d02","5502":"7502","5902":"7902"}.get(opcode,opcode)
        if self.protocol_discovery and self.session_id and self._discovery_saved < self._discovery_limit:
            try:
                self.db.add_raw_protocol_event(self.session_id, direction, opcode or "????", frame)
                self._discovery_saved += 1
                if self._discovery_saved in (1,100,500,1000,5000,10000):
                    self.log(f"Protocol discovery: {self._discovery_saved} raw frames saved")
            except Exception as e:
                if self._discovery_saved == 0:
                    self.log(f"Protocol discovery: raw save error: {e}")
        seq = frame[5] if len(frame)>7 and frame[6:8] in (b"\x29\x01",b"\x29\x03") else None
        # V4.0.15 World-map census path: large server 7D02 responses are not
        # profile replies; decode their repeated dc1c city/player records separately.
        if direction == "S>C" and opcode_norm == "7d02" and len(frame) >= 500:
            self._decode_map_frame(frame)
        if opcode_norm == "7502" and direction == "S>C":
            self.stats_data["frames_7502"] += 1
        elif opcode_norm == "7902" and direction == "C>S":
            self.stats_data["req_7902"] += 1
            req_ids=decode_7902_atlas_ids(frame)
            if req_ids:
                added=self.db.discovery_observe_aids(req_ids,self.session_id,"7902-aid-list",opcode)
                self.log(f"{opcode.upper()} : {len(req_ids)} AIDs detected, {added} new")
            # Keep bulk requests briefly so a roster frame arriving AFTER its
            # 7902 request can still be correlated. This is required by ranking
            # traffic where request/response ordering is not roster-first.
            if req_ids:
                unique_hist=list(dict.fromkeys(req_ids))
                if len(unique_hist) >= 8:
                    self._recent_bulk_7902.append((float(ts),unique_hist))
                cutoff=float(ts)-60.0
                self._recent_bulk_7902=[
                    (t,ids) for (t,ids) in self._recent_bulk_7902 if t >= cutoff
                ]

            if self._roster_active and req_ids:
                # V3.34.6 Roster Epoch Correlation Guard.
                # A new alliance can be selected while late traffic from the
                # previous one is still flowing. Correlate 7902 IDs against the
                # Atlas hints carried by the compact roster frame before the
                # batch is allowed to extend the current alliance.
                hints=self._current_roster_hint_ids
                unique_req=list(dict.fromkeys(req_ids))
                overlap=sum(1 for aid in unique_req if aid in hints) if hints else 0
                denom=max(1,min(len(unique_req),len(hints))) if hints else 1
                ratio=(overlap/denom) if hints else 1.0
                meaningful=len(unique_req)>=8

                if hints and meaningful and not self._roster_request_correlated:
                    needed=max(3,int(math.ceil(denom*0.50)))
                    if overlap >= needed:
                        self._roster_request_correlated=True
                        self.log(
                            f"Roster/7902 correlated: {overlap}/{len(unique_req)} AID "
                            f"correspondent au roster"
                        )
                    elif overlap == 0:
                        oldtag=self._context_tag or self._roster_vote_candidate or "?"
                        self.log(
                            f"Batch 7902 hors roster [{oldtag}] : "
                            f"0/{len(unique_req)} compatible AIDs — ignored"
                        )
                    else:
                        self.log(
                            f"Ambiguous 7902 batch ignored for roster: "
                            f"{overlap}/{len(unique_req)} AID compatibles"
                        )
                elif hints and not meaningful:
                    # Small 2/4-ID follow-ups are accepted only after a bulk
                    # correlation, and only when at least one member belongs to
                    # the current roster hints.
                    if not self._roster_request_correlated or overlap==0:
                        pass
                    else:
                        self._roster_request_correlated=True

                if self._roster_active:
                    allow_batch=True
                    if hints:
                        if meaningful:
                            allow_batch=self._roster_request_correlated
                        else:
                            allow_batch=self._roster_request_correlated and overlap>0

                    if allow_batch:
                        # Never let a roster collect more IDs than announced.
                        remaining=max(0,int(self._current_roster_count or 0)-len(self._current_requested_ids))
                        accepted=[]
                        for aid in unique_req:
                            if hints and aid not in hints:
                                continue
                            if aid in self._current_requested_ids:
                                continue
                            if remaining <= 0:
                                break
                            self._current_requested_ids.add(aid)
                            accepted.append(aid)
                            remaining -= 1
                        if self._context_tag and accepted:
                            self.db.record_membership(
                                self.session_id,self._context_tag,self._context_name,accepted,"7902","verified"
                            )
                            self._flush_pending_context()
                        self._maybe_reconcile_roster()
            self.db.add_event(
                self.session_id, direction, opcode, seq, frame,
                f"member batch request ids={len(req_ids)}"
            )
        elif opcode_norm == "7d02" and direction == "C>S":
            self.stats_data["req_7d02"] += 1
            if self._sequence_lab and self._is_primary_profile_7d02(frame):
                self.sequence_lab_primary_7d02(frame)
            primary=self._is_primary_profile_7d02(frame)
            txkey=self._request_7d_counter(frame)
            txtarget=self._request_7d_single_target(frame)
            if txkey is not None:
                self._recent_7d_transactions[txkey]={
                    "ts":float(ts),"target":txtarget,"primary":bool(primary),
                    "length":len(frame)
                }
                cutoff=float(ts)-20.0
                self._recent_7d_transactions={
                    k:v for k,v in self._recent_7d_transactions.items()
                    if float(v.get("ts",0)) >= cutoff
                }
            # V3.34.6 removes the unsafe global "next 7502 is explicit" flag.
            # Authority is assigned later only to a row whose Atlas ID matches
            # the exact single-target request sharing the echoed counter.
            if primary and self._roster_tail_guard:
                self._roster_tail_guard=False
            self.db.add_event(self.session_id, direction, opcode, seq, frame,
                              "explicit/profile PRIMARY 6c7d" if primary else "explicit/profile auxiliary")
            if self._active_lab and not self._active_lab_request_captured:
                if primary:
                    self.db.active_lab_request(self._active_lab["id"],frame)
                    self._active_lab_request_captured=True
                    self._active_lab_request_ts=ts
                    self._active_lab_candidates_seen=0
                    self.log(f"ACTIVE-LAB : 7D02 primaire 6C7D capture ({len(frame)} octets). Fenetre multi-reponses {int(self._active_lab_window_seconds)}s...")
                else:
                    self.log(f"ACTIVE-LAB : 7D02 auxiliaire ignore ({len(frame)} octets, prefix {frame[4:6].hex() if len(frame)>=6 else '?'})")

        if direction == "S>C" and opcode_norm == "7502":
            alliance_ids=self._scan_state_alliance_ids(frame)
            if alliance_ids:
                new_alliances=self.db.alliance_discovery_observe(alliance_ids,self.session_id,opcode,"7502-alliance-ranking-flex-v328")
                for _aid,_tag,_name in self._scan_alliance_ranking_labels(frame):
                    self.db.alliance_discovery_enrich(_aid,_tag,_name)
                if new_alliances:
                    self.log(f"{opcode.upper()} : {len(alliance_ids)} Alliance IDs detected, {new_alliances} new")
            decode_frame=(frame[:2]+b"\x75\x02"+frame[4:]) if opcode=="5502" else frame
            response_tx=self._response_7502_counter(frame)
            txinfo=self._recent_7d_transactions.pop(response_tx,None) if response_tx is not None else None
            correlated_target=None
            correlated_primary=False
            if txinfo and 0 <= float(ts)-float(txinfo.get("ts",0)) <= 5.0:
                correlated_target=txinfo.get("target")
                correlated_primary=bool(txinfo.get("primary"))
            # V4.0.10: persist EVERY raw 7502/5502 response. Previous unified builds
            # incremented the counter but usually did not store the response payload,
            # making exact 7D02 -> 7502 transaction analysis impossible afterwards.
            tx_note = f"profile response ctr={response_tx.hex() if response_tx is not None else '?'}"
            if correlated_target is not None:
                tx_note += f" target={correlated_target} primary={1 if correlated_primary else 0}"
            self.db.add_event(self.session_id, direction, opcode, seq, frame, tx_note)

            explicit_profile_frame = False  # legacy next-frame heuristic disabled
            if self.roster.looks_like_roster(decode_frame):
                info = self.roster.decode(decode_frame)
                # V4.0.12 Ranking Legacy Shell.
                # V3.34.6 rejected every compact 7502 candidate with zero Atlas hints.
                # That guard prevented false startup payloads, but it also removed the
                # historical ranking workflow: some genuine alliance rosters are a
                # compact structural shell whose Atlas IDs arrive only in the following
                # 7902 batches. Accept a PLAUSIBLE zero-hint shell without granting it
                # any identity authority. 7902/member evidence must still populate and
                # validate the epoch before anything can be written as verified.
                hint_count=int(info.get("hint_count",0) or 0)
                if hint_count == 0:
                    cnt=int(info.get("count",0) or 0)
                    if 5 <= cnt <= 120:
                        info["legacy_shell"] = True
                        self.log(
                            f"Ranking roster detected: {cnt} compact entries "
                            "(0 hint Atlas, shell structurel waiting for 7902)"
                        )
                        self.db.add_event(self.session_id,direction,opcode,seq,frame,
                                          f"roster-ranking-shell {cnt} hints=0")
                    else:
                        self.log(
                            f"Roster candidate ignored: {cnt} entries, "
                            "0 Atlas hints and size out of ranking range"
                        )
                        self.db.add_event(self.session_id,direction,opcode,seq,frame,
                                          f"roster-candidate-rejected {cnt} hints=0")
                        info=None
                if info is not None and info["count"] > self.stats_data["roster_count"]:
                    self.stats_data["roster_count"] = info["count"]
                if info is not None:
                    if not info.get("legacy_shell"):
                        self.log(
                            f"Roster detected: {info['count']} compact entries "
                            f"({info.get('hint_count',0)} authoritative Atlas hints)"
                        )
                    self.db.add_event(self.session_id, direction, opcode, seq, frame, f"roster {info['count']}")


                if info is not None:
                    # V4 Dynamic Bypass: Extract full profiles directly from 7502
                    dynamic_players = self.heuristic_extract_roster(decode_frame)
                    if dynamic_players:
                        self.log(f"Dynamic Extraction: instantly recovered {len(dynamic_players)} full profiles from 7502.")
                        for (aid, name, pwr) in dynamic_players:
                            # We can fetch the Alliance Tag directly from the DB!
                            with self.db.lock:
                                r = self.db.conn.execute("SELECT alliance_tag FROM players WHERE atlas_id=?", (aid,)).fetchone()
                                existing_tag = r[0] if r else ""
                            
                            row = {
                                "atlas_id": aid,
                                "wos_id": 0,
                                "pseudo_display": name,
                                "pseudo_core": name,
                                "power": pwr,
                                "alliance_tag": existing_tag,
                                "alliance_name": existing_tag,
                                "wos_confidence": "low",
                                "power_confidence": "high",
                                "identity_pair_valid": True,
                                "alliance_verified": bool(existing_tag)
                            }
                            # Bypass the broken Context Queue and write directly!
                            self._store_row(row, "7502-member")
                            
                        self.stats_data["decoded_players"] += len(dynamic_players)
                        self.stats_data["changed_players"] = self.stats_data.get("changed_players", 0) + len(dynamic_players)

                    # A roster starts a fresh alliance-list epoch. Rows with missing
                    # TAG/name are held until the first strong member row reveals
                    # which alliance this roster belongs to.
                    # Finalize a complete previous roster, or explicitly close an
                    # incomplete epoch so it cannot leak into this alliance.
                    self._maybe_reconcile_roster()
                    if self._roster_active:
                        self._close_active_roster_context("new roster 7502")
                    self._roster_epoch += 1
                    self._roster_active = True
                    self._context_tag = ""
                    self._context_name = ""
                    self._pending_context_rows = []
                    self._current_roster_count = info["count"]
                    self._current_requested_ids = set()
                    self._current_roster_hint_ids = set(info.get("atlas_ids_hint") or [])
                    self._roster_identity_locked = False

                    # Unified V4.0.9 Atlas -> ranking bridge. The compact roster
                    # already gives us Atlas IDs. If Atlas imported a strong,
                    # coherent alliance majority for those exact IDs, lock only
                    # the ALLIANCE CONTEXT here. WOS identity/power validation is
                    # unchanged and still comes exclusively from WOS traffic.
                    if self._current_roster_hint_ids and hasattr(self.db,"atlas_roster_consensus"):
                        try:
                            ac=self.db.atlas_roster_consensus(self._current_roster_hint_ids)
                        except Exception as ex:
                            ac=None
                            self.log(f"Atlas/roster bridge error: {ex}")
                        if ac and ac.get("accepted"):
                            self._context_tag=str(ac.get("tag") or "")
                            self._context_name=""
                            self._roster_identity_locked=True
                            self.log(
                                f"ATLAS identity roster locked : [{self._context_tag}] "
                                f"{ac.get('hits',0)}/{ac.get('mapped',0)} mapped Atlas hints "
                                f"({ac.get('total',0)} roster hints)"
                            )
                            self.db.observe_alliance_roster(
                                self._context_tag,self._context_name,self._current_roster_count,self.session_id
                            )
                            self.db.record_membership(
                                self.session_id,self._context_tag,self._context_name,
                                self._current_roster_hint_ids,"atlas-roster-consensus","verified"
                            )
                        elif ac:
                            self.log(
                                f"Roster Atlas ambigu : [{ac.get('tag','?')}] "
                                f"{ac.get('hits',0)}/{ac.get('mapped',0)} mapped, "
                                f"coverage {ac.get('coverage',0):.0%} — consensus WOS requis"
                            )

                    # V3.34.6: structural Atlas hints are the authoritative roster
                    # membership. 7902 validates/enriches but is not required.
                    self._current_requested_ids = set(self._current_roster_hint_ids)
                    self._roster_request_correlated = bool(self._current_roster_hint_ids)

                    # V3.34.6 bidirectional epoch correlation:
                    # the bulk 7902 can precede the compact roster frame. Search the
                    # recent request history and seed only IDs that are actual roster
                    # hints. Never import non-hint IDs into the new alliance.
                    best_ids=[]
                    best_overlap=0
                    hints=self._current_roster_hint_ids
                    for bt,bids in reversed(self._recent_bulk_7902):
                        if float(ts)-bt > 60.0:
                            continue
                        ov=[aid for aid in bids if aid in hints]
                        if len(ov) > best_overlap:
                            best_overlap=len(ov); best_ids=ov
                    if hints and best_ids:
                        denom=max(1,min(len(hints),max(len(best_ids),1)))
                        needed=max(3,int(math.ceil(min(len(hints),50)*0.20)))
                        if best_overlap >= needed:
                            self._current_requested_ids.update(best_ids)
                            self._roster_request_correlated=True
                            self.log(
                                f"Upstream roster/7902 correlated: {best_overlap}/"
                                f"{self._current_roster_count} roster AIDs already seen"
                            )

                    self._roster_reconciled = False
                    self._roster_tag_votes = {}
                    self._roster_tag_frames = {}
                    self._roster_tag_names = {}
                    self._roster_vote_candidate = ""
                    self._roster_vote_streak = 0
                    # Keep an Atlas consensus lock obtained above; do not reset it here.
                    self._completed_roster_tag = ""
                    self._completed_roster_name = ""
                    self._completed_roster_ids = set()
                    self._roster_tail_guard = False

            starts = [m.start() for m in re.finditer(b"\xdc\x1c", decode_frame)]
            decoded_rows=[]
            decoded_vote_blocks=[]
            for i, st in enumerate(starts):
                en = starts[i+1] if i+1 < len(starts) else len(decode_frame)
                block = decode_frame[st:en]
                sig = hash(block)
                if sig in self._seen_blocks:
                    continue
                self._seen_blocks.add(sig)
                self.stats_data["member_blocks"] += 1
                try:
                    row = self.decoder.decode_member_block(block)

                    # Independent protocol sanity signal: default WOS names encode
                    # the player's WOS ID ("lord625312029"). If present, it is a
                    # stronger self-check than an ambiguous numeric candidate.
                    if row:
                        pname=(row.get("pseudo_display") or row.get("pseudo_core") or "").strip()
                        mm=re.fullmatch(r"(?i)lord\s*(\d{9})",pname)
                        if mm:
                            name_wos=int(mm.group(1))
                            decoded_wos=row.get("wos_id")
                            if decoded_wos not in (None,"") and int(decoded_wos)!=name_wos:
                                row["wos_id_candidate"]=decoded_wos
                                row["wos_id"]=name_wos
                                row["wos_confidence"]="high"
                                row["identity_pair_valid"]=True
                                row["wos_validation"]="default-name"
                            elif decoded_wos in (None,""):
                                row["wos_id"]=name_wos
                                row["wos_confidence"]="high"
                                row["identity_pair_valid"]=True
                                row["wos_validation"]="default-name"
                except Exception as e:
                    self.log(f"Block not decoded: {e}")
                    continue
                if row.get("atlas_id"):
                    decoded_rows.append(row)
                    # Votes for the current roster must come from an Atlas that
                    # structurally belongs to that roster when hints exist.
                    if (not self._roster_active or
                        not self._current_roster_hint_ids or
                        int(row.get("atlas_id")) in self._current_roster_hint_ids):
                        decoded_vote_blocks.append(block)
                else:
                    # V4.0.22: diagnostic capture only, no behaviour change. A
                    # block with no decoded Atlas ID is discarded right here --
                    # it never reaches upsert_player, so it produces zero rows
                    # in identity_observations. This is the exact chokepoint
                    # behind alliances that clearly generate roster traffic
                    # (dc1c-marked blocks visible in the raw capture) but end
                    # the session with zero decoded players (e.g. KOR/WET/HPL/
                    # POL): decode_member_atlas_id failed on these specific
                    # blocks. Log a bounded sample of the raw bytes so the
                    # next session gives real evidence instead of a guess.
                    self._atlas_fail_samples = getattr(self, "_atlas_fail_samples", 0)
                    if self._atlas_fail_samples < 25:
                        self._atlas_fail_samples += 1
                        self.log(
                            f"Block without Atlas ID (ignore) | guessed alliance=[{row.get('alliance_tag') or '?'}] "
                            f"| len={len(block)} | hex={block.hex()}"
                        )

            # V3.33.1 structural roster consensus. A provisional winner is NEVER
            # written into player membership. Rows stay buffered until lock.
            vote_tag,vote_name,vote_hits,vote_frames=self._vote_structured_roster_tag(
                decoded_vote_blocks, hash(frame)
            )
            if vote_tag and self._roster_active and not self._roster_identity_locked:
                ready,min_ids,runner_hits,runner_frames=self._roster_vote_consensus_ready(
                    vote_tag,vote_hits,vote_frames
                )
                if ready:
                    self._context_tag=vote_tag
                    self._context_name=vote_name
                    self._roster_identity_locked=True
                    self.log(
                        f"CONSENSUS identity roster locked: [{vote_tag}] {vote_name or ''} "
                        f"({vote_hits} occurrences / {vote_frames} frames, "
                        f"{len(self._current_requested_ids)}/{self._current_roster_count} IDs)"
                    )
                    self.db.observe_alliance_roster(
                        self._context_tag,self._context_name,self._current_roster_count,self.session_id
                    )
                    self.db.record_membership(
                        self.session_id,self._context_tag,self._context_name,
                        self._current_requested_ids,"7902-consensus","verified"
                    )
                    self._flush_pending_context()
                    self._maybe_reconcile_roster()
                elif vote_hits>=3 and vote_frames>=2:
                    self.log(
                        f"Roster vote provisoire [{vote_tag}] : {vote_hits}/{vote_frames} "
                        f"| IDs {len(self._current_requested_ids)}/{min_ids} mini "
                        f"| runner {runner_hits}/{runner_frames} — attente"
                    )

            # Raw canonical match is diagnostic only during a roster. It may not
            # establish context by itself because a single frame can contain an
            # unrelated known TAG.
            raw_tag,raw_name,raw_aid,raw_hits=self._raw_canonical_alliance(frame)
            if raw_tag and self._roster_active and not self._roster_identity_locked and raw_hits:
                # Keep this deliberately quiet unless it differs from vote.
                if vote_tag and raw_tag!=vote_tag:
                    self.log(f"Roster RAW-hint [{raw_tag}] ignored during vote [{vote_tag}]")

            if decoded_rows:
                frame_tag=self._mode_nonempty([r.get("alliance_tag","") for r in decoded_rows])
                frame_name=self._mode_nonempty([r.get("alliance_name","") for r in decoded_rows])

                # Generic decoded strings are diagnostic/name hints only.
                # They can never create or change the roster TAG.
                if self._roster_identity_locked and self._context_tag:
                    if not self._context_name and frame_tag==self._context_tag and frame_name:
                        self._context_name=frame_name
                    self.db.observe_alliance_roster(
                        self._context_tag,self._context_name,self._current_roster_count,self.session_id
                    )
                    self.db.record_membership(
                        self.session_id,self._context_tag,self._context_name,
                        self._current_requested_ids,"7902-consensus","verified"
                    )
                    self._flush_pending_context()
                    self._maybe_reconcile_roster()

                for row in decoded_rows:
                    filled=self._apply_alliance_context(
                        row,self._context_tag,self._context_name
                    )
                    if self._roster_active and not filled.get("alliance_verified"):
                        self.db.discovery_observe(filled,self.session_id,"passive-unverified",opcode)
                        self._pending_context_rows.append(row)
                    else:
                        row_atlas=self.db._to_int(filled.get("atlas_id"))
                        exact_correlated=bool(
                            correlated_target is not None and row_atlas==int(correlated_target)
                        )
                        source_kind = ("profile-correlated-primary" if correlated_primary else "profile-correlated-aux") if exact_correlated else "passive-player"
                        if exact_correlated:
                            filled["request_response_correlated"]=True
                            filled["request_response_counter"]=response_tx.hex() if response_tx else ""
                        self.db.discovery_observe(filled,self.session_id,source_kind,opcode)
                        # V3.34.6: while draining a completed roster, passive
                        # rows whose decoded Atlas is not one of the locked 90
                        # are diagnostic only. Do not let them alter players,
                        # history or membership. A primary explicit profile
                        # request disables the tail guard above.
                        if (self._roster_tail_guard and
                            filled.get("alliance_source")=="roster-tail-rejected" and
                            not exact_correlated):
                            continue
                        # V3.18 Passive-State-Discovery correlation is independent of the old
                        # "next explicit frame" heuristic. Every accepted decoded 7502 row in
                        # the post-request window is recorded and checked.
                        self._active_lab_consider_row(filled,source_kind,ts)
                        self._store_row(filled,source_kind)
                        if exact_correlated:
                            self.log(
                                f"TX-CORR-{'PRIMARY' if correlated_primary else 'AUX'} {response_tx.hex() if response_tx else '?'} : "
                                f"A:{row_atlas} -> W:{filled.get('wos_id') or '?'} "
                                "(target 7D02 request confirmed)"
                            )
        self._emit_stats()


    def finalize_session(self):
        self._flush_pending_context()
        self._maybe_reconcile_roster()
        self._emit_stats()


class LiveCapture:
    def __init__(self, engine: CollectorEngine, log_cb):
        self.engine = engine
        self.log = log_cb
        self.sniffer = None
        self.writer = None
        self.running = False

    @staticmethod
    def interfaces():
        try:
            from scapy.all import get_if_list
            return get_if_list()
        except Exception:
            return []

    def start(self, iface: Optional[str], pcap_path: Path):
        try:
            from scapy.all import AsyncSniffer, IP, IPv6, TCP, Raw, PcapWriter
        except ImportError:
            raise RuntimeError("Scapy n'est pas disponible dans le Python utilise par WOS Unified Manager. Lance INSTALL_DEPENDENCIES.bat dans ce dossier, puis redemarre START_WOS_UNIFIED_MANAGER.bat.")
        pcap_path.parent.mkdir(parents=True, exist_ok=True)
        self.writer = PcapWriter(str(pcap_path), append=False, sync=True)

        def callback(pkt):
            try:
                if self.writer:
                    self.writer.write(pkt)
                if TCP not in pkt or Raw not in pkt:
                    return
                tcp = pkt[TCP]
                if tcp.sport != GAME_PORT and tcp.dport != GAME_PORT:
                    return
                if IP in pkt:
                    src, dst = pkt[IP].src, pkt[IP].dst
                elif IPv6 in pkt:
                    src, dst = pkt[IPv6].src, pkt[IPv6].dst
                else:
                    return
                raw_payload=bytes(pkt[Raw].load)
                self.engine.raw_counter_packet(int(tcp.sport),int(tcp.dport),raw_payload,float(pkt.time))
                self.engine.raw_diag_packet(int(tcp.sport),int(tcp.dport),int(tcp.seq),raw_payload,float(pkt.time))
                self.engine.feed_tcp(src, int(tcp.sport), dst, int(tcp.dport), int(tcp.seq), raw_payload, float(pkt.time))
            except Exception:
                self.log("Packet error: " + traceback.format_exc().splitlines()[-1])

        kwargs = {"prn": callback, "store": False, "filter": f"tcp port {GAME_PORT}"}
        if iface and iface != "AUTO":
            kwargs["iface"] = iface
        self.sniffer = AsyncSniffer(**kwargs)
        self.sniffer.start()
        self.running = True

    def stop(self):
        if self.sniffer is not None:
            try: self.sniffer.stop()
            except Exception: pass
            self.sniffer = None
        if self.writer is not None:
            try: self.writer.close()
            except Exception: pass
            self.writer = None
        self.running = False


class OfflinePcapngReader:
    """Offline analysis preserving packet chronology.

    V3.5 needs 7902 membership requests and 7502 roster/member responses in
    their true order, otherwise alliance-roster locking cannot be validated.
    """
    def __init__(self, engine: CollectorEngine, core):
        self.engine = engine
        self.core = core

    def run(self, path: Path):
        data=path.read_bytes()
        events=[]
        for pn,pkt in self.core.pcapng_packets(data):
            parsed=self.core.tcp_payload(pkt)
            if not parsed: continue
            sport,dport,payload=parsed
            if dport==GAME_PORT and len(payload)>=4 and payload[2:4] in (b"\x79\x02",b"\x7d\x02"):
                events.append((pn,"client",payload))
        for msg in self.engine.decoder.members.reassembled_server_7502(path,self.core):
            frame=msg.get("payload") or b""
            if len(frame)>=4 and frame[2:4]==b"\x75\x02":
                pns=msg.get("packets") or [10**9]
                events.append((min(pns),"server",frame))
        events.sort(key=lambda x:x[0])
        for pn,kind,frame in events:
            if kind=="client":
                self.engine._on_frame(("client",0,"server",GAME_PORT),frame,time.time())
            else:
                self.engine._on_frame(("server",GAME_PORT,"client",0),frame,time.time())
        self.engine.finalize_session()


class CollectorGUI:
    def __init__(self, decoder: DecoderBundle, db: StateDB):
        import tkinter as tk
        from tkinter import ttk, filedialog, messagebox
        self.tk=tk; self.ttk=ttk; self.filedialog=filedialog; self.messagebox=messagebox
        self.root=tk.Tk(); self.root.title(f"WOS State Collector V{APP_VERSION}"); self.root.geometry("1050x720")
        self.events=queue.Queue()
        self.engine=CollectorEngine(decoder,db,self._log_threadsafe,self._stats_threadsafe)
        self.db=db
        self.live=LiveCapture(self.engine,self._log_threadsafe)
        self.session_id=""; self.capture_path=None
        self._build()
        self.root.after(100,self._poll)
        self.root.protocol("WM_DELETE_WINDOW", self.close)

    def _build(self):
        tk=self.tk; ttk=self.ttk

        # Persistent capture controls: compact and always visible.
        capture=ttk.Frame(self.root,padding=(10,10,10,5)); capture.pack(fill="x")
        ttk.Label(capture,text="Interface :").pack(side="left")
        self.iface=tk.StringVar(value="AUTO")
        ifaces=["AUTO"]+self.live.interfaces()
        self.combo=ttk.Combobox(capture,textvariable=self.iface,values=ifaces,width=38,state="readonly")
        self.combo.pack(side="left",padx=6)
        self.btn_start=ttk.Button(capture,text="▶ Start Capture",command=self.start)
        self.btn_start.pack(side="left",padx=4)
        self.btn_stop=ttk.Button(capture,text="■ Stop",command=self.stop,state="disabled")
        self.btn_stop.pack(side="left",padx=4)

        book=ttk.Notebook(self.root); book.pack(fill="x",padx=10,pady=(2,8))
        tab_collect=ttk.Frame(book,padding=8)
        tab_labs=ttk.Frame(book,padding=8)
        tab_data=ttk.Frame(book,padding=8)
        book.add(tab_collect,text="Collecte")
        book.add(tab_labs,text="Labs")
        book.add(tab_data,text="Data / Exports")

        # Collecte
        ttk.Button(tab_collect,text="Analyze PCAPNG",command=self.offline).pack(side="left",padx=4)
        ttk.Button(tab_collect,text="Export Players CSV",command=self.export).pack(side="left",padx=4)
        ttk.Button(tab_collect,text="Export Refresh Queue",command=self.export_refresh).pack(side="left",padx=4)

        # Labs: legacy tools remain available without crowding the main bar.
        ttk.Button(tab_labs,text="Active Lab",command=self.arm_active_lab).grid(row=0,column=0,padx=4,pady=3,sticky="ew")
        ttk.Button(tab_labs,text="Sequence Lab",command=self.start_sequence_lab).grid(row=0,column=1,padx=4,pady=3,sticky="ew")
        ttk.Button(tab_labs,text="Counter Lab",command=self.start_counter_lab).grid(row=0,column=2,padx=4,pady=3,sticky="ew")
        ttk.Button(tab_labs,text="Request Builder",command=self.start_request_builder).grid(row=0,column=3,padx=4,pady=3,sticky="ew")
        ttk.Button(tab_labs,text="Raw Diagnostic",command=self.start_raw_diag).grid(row=2,column=0,padx=4,pady=3,sticky="ew")
        ttk.Button(tab_labs,text="Stop Raw",command=self.stop_raw_diag).grid(row=2,column=1,padx=4,pady=3,sticky="ew")
        ttk.Button(tab_labs,text="Stop Sequence",command=self.stop_sequence_lab).grid(row=1,column=1,padx=4,pady=3,sticky="ew")
        ttk.Button(tab_labs,text="Stop Counter",command=self.stop_counter_lab).grid(row=1,column=2,padx=4,pady=3,sticky="ew")
        for c in range(4): tab_labs.columnconfigure(c,weight=1)

        # Data / exports - wrapped grid so the tab remains usable on 1050px windows.
        data_buttons=[
            ("Export Active Lab",self.export_active_lab),
            ("Export Sequence",self.export_sequence_lab),
            ("Export Counter",self.export_counter_lab),
            ("Export Request Builder",self.export_request_builder),
            ("Export Counter Tracker",self.export_counter_tracker),
            ("Export Raw Diagnostic",self.export_raw_diag),
            ("Export Raw Counter",self.export_raw_counter),
            ("Export State Discovery",self.export_state_discovery),
            ("Export Alliance Discovery",self.export_alliance_discovery),
            ("Couverture Alliances",self.show_alliance_coverage),
            ("Export Couverture",self.export_alliance_coverage),
        ]
        for i,(label,cmd) in enumerate(data_buttons):
            ttk.Button(tab_data,text=label,command=cmd).grid(
                row=i//6,column=i%6,padx=4,pady=3,sticky="ew"
            )
        for c in range(6): tab_data.columnconfigure(c,weight=1)

        stats=ttk.LabelFrame(self.root,text="Session / Base",padding=8); stats.pack(fill="x",padx=10,pady=(0,6))
        self.vars={k:tk.StringVar(value="0") for k in ["roster","blocks","decoded","players","complete","alliances","suspect","refresh","7902","7d02","discovered","resolved","alliance_discovered"]}
        items=[("Roster","roster"),("Blocks","blocks"),("Decoded","decoded"),("Players","players"),
               ("Complets","complete"),("Alliances","alliances"),("Suspect","suspect"),
               ("Refresh","refresh"),("7902/5902","7902"),("7D02/5D02","7d02"),
               ("Discovery","discovered"),("Resolved","resolved"),("Alliances Discovered","alliance_discovered")]
        for i,(lab,key) in enumerate(items):
            f=ttk.Frame(stats); f.grid(row=i//6,column=i%6,padx=18,pady=2,sticky="w")
            ttk.Label(f,text=lab).pack(side="left")
            ttk.Label(f,textvariable=self.vars[key],font=("Segoe UI",11,"bold")).pack(side="left",padx=(5,0))

        self.rb_status=tk.StringVar(value="Raw Counter : en attente de trafic client...")
        ttk.Label(self.root,textvariable=self.rb_status,foreground="#6b4b00").pack(anchor="w",padx=12,pady=(0,4))

        logframe=ttk.LabelFrame(self.root,text="Log",padding=5); logframe.pack(fill="both",expand=True,padx=10,pady=4)
        self.logbox=tk.Text(logframe,wrap="none",height=24,font=("Consolas",9))
        self.logbox.pack(side="left",fill="both",expand=True)
        sb=ttk.Scrollbar(logframe,orient="vertical",command=self.logbox.yview)
        sb.pack(side="right",fill="y"); self.logbox.configure(yscrollcommand=sb.set)

        self.status=tk.StringVar(value="Ready.")
        ttk.Label(self.root,textvariable=self.status,relief="sunken",anchor="w").pack(fill="x",side="bottom")

    def _log_threadsafe(self,msg): self.events.put(("log",msg))
    def _stats_threadsafe(self,d): self.events.put(("stats",d))
    def _poll(self):
        try:
            while True:
                kind,data=self.events.get_nowait()
                if kind=="log":
                    self.logbox.insert("end",f"[{datetime.now().strftime('%H:%M:%S')}] {data}\n"); self.logbox.see("end")
                elif kind=="stats":
                    self.vars["roster"].set(str(data.get("roster_count",0)))
                    self.vars["blocks"].set(str(data.get("member_blocks",0)))
                    self.vars["decoded"].set(str(data.get("decoded_players",0)))
                    self.vars["players"].set(str(data.get("players",0)))
                    self.vars["complete"].set(str(data.get("complete",0)))
                    self.vars["alliances"].set(str(data.get("alliances",0)))
                    self.vars["suspect"].set(str(data.get("power_suspect",0)))
                    self.vars["refresh"].set(str(data.get("refresh_pending",0)))
                    self.vars["7902"].set(str(data.get("req_7902",0)))
                    self.vars["7d02"].set(str(data.get("req_7d02",0)))
                    self.vars["discovered"].set(str(data.get("discovered",0)))
                    self.vars["alliance_discovered"].set(str(data.get("alliance_discovered",0)))
                    self.vars["resolved"].set(str(data.get("resolved",0)))
        except queue.Empty: pass
        try:
            c=self.engine._rb_raw_counter
            if c is not None and not self.engine._rb_test:
                op=self.engine._rb_raw_opcode or "?"
                mask=self.engine._session_opcode_mask
                fam=("7D/75/79" if mask==0 else "5D/55/59" if mask==0x20 else "detecting...")
                self.rb_status.set(f"Raw Counter : dernier={c} ({op}) | prochain={(c+2)&0xffff} | famille={fam} | trames={len(self.engine._rb_raw_seen)}")
        except Exception:
            pass
        self.root.after(100,self._poll)

    def start(self):
        if self.live.running: return
        try:
            stamp=datetime.now().strftime("%Y%m%d_%H%M%S")
            self.session_id=f"live_{stamp}"
            self.capture_path=SESSIONS_DIR/f"{self.session_id}.pcap"
            self.engine.reset(self.session_id)
            self.db.start_session(self.session_id,"live",str(self.capture_path))
            self.live.start(self.iface.get(),self.capture_path)
            self.btn_start.config(state="disabled"); self.btn_stop.config(state="normal")
            self.status.set(f"Capture en cours → {self.capture_path}")
            self._log_threadsafe("LIVE Capture started. Open WOS then an alliance list.")
        except Exception as e:
            self.messagebox.showerror("Capture impossible",str(e))

    def stop(self):
        if not self.live.running: return
        self.live.stop(); self.engine.finalize_session(); self.db.stop_session(self.session_id,self.engine.stats_data)
        self.btn_start.config(state="normal"); self.btn_stop.config(state="disabled")
        self.status.set("Capture stopped."); self._log_threadsafe("Capture stopped and session saved.")

    def offline(self):
        f=self.filedialog.askopenfilename(title="Choose capture file",filetypes=[("PCAP/PCAPNG","*.pcap *.pcapng"),("Tous","*.*")])
        if not f:return
        path=Path(f); stamp=datetime.now().strftime("%Y%m%d_%H%M%S")
        sid=f"offline_{safe_name(path.stem)}_{stamp}"
        self.engine.reset(sid); self.db.start_session(sid,"offline",str(path))
        def worker():
            try:
                self._log_threadsafe(f"Offline analysis : {path.name}")
                OfflinePcapngReader(self.engine,self.engine.decoder.core).run(path)
                self.db.stop_session(sid,self.engine.stats_data)
                self._log_threadsafe("Offline analysis complete.")
            except Exception as e:
                self._log_threadsafe("Offline error: "+repr(e))
        threading.Thread(target=worker,daemon=True).start()

    def export(self):
        stamp=datetime.now().strftime("%Y%m%d_%H%M%S")
        default=EXPORT_DIR/f"WOS_players_{stamp}.csv"
        f=self.filedialog.asksaveasfilename(initialdir=str(EXPORT_DIR),initialfile=default.name,defaultextension=".csv",filetypes=[("CSV","*.csv")])
        if not f:return
        self.db.export_csv(Path(f)); self.status.set(f"Export : {f}"); self._log_threadsafe(f"CSV exported: {f}")

    def export_refresh(self):
        stamp=datetime.now().strftime("%Y%m%d_%H%M%S")
        default=EXPORT_DIR/f"WOS_refresh_queue_{stamp}.csv"
        f=self.filedialog.asksaveasfilename(initialdir=str(EXPORT_DIR),initialfile=default.name,defaultextension=".csv",filetypes=[("CSV","*.csv")])
        if not f:return
        self.db.export_refresh_csv(Path(f)); self.status.set(f"Refresh file : {f}"); self._log_threadsafe(f"Refresh queue exported : {f}")

    def arm_active_lab(self):
        rows=list(self.db.pending_refresh_rows())
        if not rows:
            self.messagebox.showinfo("Active Lab","No pending target in the current roster.")
            return

        # V3.8: graphical picker -- no Atlas ID typing required.
        win=self.tk.Toplevel(self.root)
        win.title("Active Lab - Choose a player")
        win.geometry("820x520")
        win.transient(self.root)
        win.grab_set()

        top=self.ttk.Frame(win,padding=10); top.pack(fill="x")
        self.ttk.Label(top,text="Recherche :").pack(side="left")
        search=self.tk.StringVar()
        ent=self.ttk.Entry(top,textvariable=search,width=35); ent.pack(side="left",padx=6)
        alliance=self.tk.StringVar(value="Toutes")
        tags=["Toutes"]+sorted({(r["alliance_tag"] or "?") for r in rows})
        combo=self.ttk.Combobox(top,textvariable=alliance,values=tags,state="readonly",width=10)
        combo.pack(side="left",padx=6)

        cols=("pseudo","alliance","atlas","wos","reason")
        tree=self.ttk.Treeview(win,columns=cols,show="headings",selectmode="browse")
        tree.heading("pseudo",text="Pseudo"); tree.column("pseudo",width=220)
        tree.heading("alliance",text="Alliance"); tree.column("alliance",width=80,anchor="center")
        tree.heading("atlas",text="Atlas ID"); tree.column("atlas",width=110,anchor="center")
        tree.heading("wos",text="WOS ID"); tree.column("wos",width=110,anchor="center")
        tree.heading("reason",text="Raison"); tree.column("reason",width=180)
        tree.pack(fill="both",expand=True,padx=10,pady=(0,8))

        def refresh(*_):
            q=search.get().strip().casefold()
            tag=alliance.get()
            for item in tree.get_children(): tree.delete(item)
            for r in rows:
                pseudo=r["pseudo_display"] or "?"
                rtag=r["alliance_tag"] or "?"
                if tag!="Toutes" and rtag!=tag: continue
                hay=f"{pseudo} {rtag} {r['atlas_id']} {r['wos_id'] or ''}".casefold()
                if q and q not in hay: continue
                tree.insert("", "end", iid=str(r["atlas_id"]),
                    values=(pseudo,rtag,r["atlas_id"],r["wos_id"] or "",r["reason"]))

        def choose(*_):
            sel=tree.selection()
            if not sel:return
            aid=int(sel[0])
            try:
                self.engine.arm_active_lab(aid)
                pseudo=tree.item(sel[0],"values")[0]
                self.status.set(f"Active Lab arme : {pseudo}")
                win.destroy()
            except Exception as e:
                self.messagebox.showerror("Active Lab",str(e),parent=win)

        bottom=self.ttk.Frame(win,padding=(10,0,10,10)); bottom.pack(fill="x")
        self.ttk.Label(bottom,text="Select a player then double-click, or click Arm.").pack(side="left")
        self.ttk.Button(bottom,text="Cancel",command=win.destroy).pack(side="right",padx=4)
        self.ttk.Button(bottom,text="Arm Target",command=choose).pack(side="right",padx=4)
        search.trace_add("write",refresh)
        combo.bind("<<ComboboxSelected>>",refresh)
        tree.bind("<Double-1>",choose)
        refresh()
        ent.focus_set()

    def export_active_lab(self):
        stamp=datetime.now().strftime("%Y%m%d_%H%M%S")
        default=EXPORT_DIR/f"WOS_active_lab_{stamp}.csv"
        f=self.filedialog.asksaveasfilename(initialdir=str(EXPORT_DIR),initialfile=default.name,
            defaultextension=".csv",filetypes=[("CSV","*.csv")])
        if not f:return
        self.db.export_active_lab_csv(Path(f))
        self.status.set(f"Active Lab : {f}")
        self._log_threadsafe(f"Active Lab exporte : {f}")

    def start_sequence_lab(self):
        try:
            rows=list(self.db.current_roster_rows())
        except Exception as ex:
            self._log_threadsafe("SEQUENCE-LAB OPEN ERROR: "+repr(ex))
            self.messagebox.showerror("Sequence Lab","Impossible d'ouvrir la liste :\n"+str(ex))
            return
        if not rows:
            self.messagebox.showinfo("Sequence Lab","Aucun roster courant disponible."); return
        win=self.tk.Toplevel(self.root); win.title("Sequence Lab - Choose 5 players"); win.geometry("850x560"); win.transient(self.root); win.grab_set()
        top=self.ttk.Frame(win,padding=10); top.pack(fill="x")
        self.ttk.Label(top,text="Recherche :").pack(side="left")
        q=self.tk.StringVar(); ent=self.ttk.Entry(top,textvariable=q,width=34); ent.pack(side="left",padx=6)
        tag=self.tk.StringVar(value="Toutes"); tags=["Toutes"]+sorted({r["alliance_tag"] or "?" for r in rows})
        cb=self.ttk.Combobox(top,textvariable=tag,values=tags,state="readonly",width=10); cb.pack(side="left",padx=6)
        pane=self.ttk.Panedwindow(win,orient="horizontal"); pane.pack(fill="both",expand=True,padx=10,pady=(0,8))
        left=self.ttk.Frame(pane); right=self.ttk.Frame(pane); pane.add(left,weight=3); pane.add(right,weight=2)
        tree=self.ttk.Treeview(left,columns=("pseudo","alliance","atlas","wos"),show="headings",selectmode="browse")
        for col,text,width in [("pseudo","Pseudo",230),("alliance","Alliance",80),("atlas","Atlas ID",110),("wos","WOS ID",110)]:
            tree.heading(col,text=text); tree.column(col,width=width,anchor="center" if col!="pseudo" else "w")
        tree.pack(fill="both",expand=True)
        self.ttk.Label(right,text="Ordre du test",font=("Segoe UI",10,"bold")).pack(anchor="w",pady=(0,5))
        order=self.tk.Listbox(right,height=18); order.pack(fill="both",expand=True); chosen=[]
        def refresh(*_):
            query=q.get().strip().casefold(); t=tag.get()
            for x in tree.get_children(): tree.delete(x)
            for r in rows:
                pseudo=r["pseudo_display"] or "?"; rt=r["alliance_tag"] or "?"
                if t!="Toutes" and rt!=t: continue
                hay=f"{pseudo} {rt} {r['atlas_id']} {r['wos_id'] or ''}".casefold()
                if query and query not in hay: continue
                tree.insert("","end",iid=str(r["atlas_id"]),values=(pseudo,rt,r["atlas_id"],r["wos_id"] or ""))
        def add_one(*_):
            if len(chosen)>=5: return
            sel=tree.selection()
            if not sel: return
            aid=int(sel[0])
            if any(int(x["atlas_id"])==aid for x in chosen): return
            r=next(x for x in rows if int(x["atlas_id"])==aid); chosen.append(dict(r))
            order.insert("end",f"{len(chosen)}. [{r['alliance_tag'] or '?'}] {r['pseudo_display'] or '?'} ({aid})")
        def remove_one():
            sel=order.curselection()
            if not sel:return
            i=sel[0]; chosen.pop(i); order.delete(0,"end")
            for j,r in enumerate(chosen,1): order.insert("end",f"{j}. [{r['alliance_tag'] or '?'}] {r['pseudo_display'] or '?'} ({r['atlas_id']})")
        def launch():
            if len(chosen)!=5:
                self.messagebox.showinfo("Sequence Lab","Choose exactly 5 players.",parent=win); return
            try:
                first=self.engine.start_sequence_lab(chosen); self.status.set(f"Sequence Lab: open {first['pseudo_display']}"); win.destroy()
            except Exception as ex: self.messagebox.showerror("Sequence Lab",str(ex),parent=win)
        btns=self.ttk.Frame(right); btns.pack(fill="x",pady=6)
        self.ttk.Button(btns,text="Ajouter →",command=add_one).pack(side="left",padx=3); self.ttk.Button(btns,text="Retirer",command=remove_one).pack(side="left",padx=3)
        bottom=self.ttk.Frame(win,padding=(10,0,10,10)); bottom.pack(fill="x")
        self.ttk.Button(bottom,text="Cancel",command=win.destroy).pack(side="right",padx=4); self.ttk.Button(bottom,text="Start",command=launch).pack(side="right",padx=4)
        q.trace_add("write",refresh); cb.bind("<<ComboboxSelected>>",refresh); tree.bind("<Double-1>",add_one); refresh(); ent.focus_set()

    def stop_sequence_lab(self):
        self.engine.stop_sequence_lab("manual stop"); self.status.set("Sequence Lab arrete.")

    def export_sequence_lab(self):
        stamp=datetime.now().strftime("%Y%m%d_%H%M%S"); default=EXPORT_DIR/f"WOS_sequence_lab_{stamp}.csv"
        f=self.filedialog.asksaveasfilename(initialdir=str(EXPORT_DIR),initialfile=default.name,defaultextension=".csv",filetypes=[("CSV","*.csv")])
        if not f:return
        self.db.export_sequence_lab_csv(Path(f)); self.status.set(f"Sequence Lab : {f}"); self._log_threadsafe(f"Sequence Lab exporte : {f}")

    def start_counter_lab(self):
        rows=list(self.db.current_roster_rows())
        if not rows:
            self.messagebox.showinfo("Counter Lab","Aucun roster courant disponible."); return
        win=self.tk.Toplevel(self.root); win.title("Counter Lab - Choose a player"); win.geometry("760x500")
        win.transient(self.root); win.grab_set()
        top=self.ttk.Frame(win,padding=10); top.pack(fill="x")
        self.ttk.Label(top,text="Recherche :").pack(side="left")
        q=self.tk.StringVar(); ent=self.ttk.Entry(top,textvariable=q,width=35); ent.pack(side="left",padx=6)
        tag=self.tk.StringVar(value="Toutes")
        tags=["Toutes"]+sorted({r["alliance_tag"] or "?" for r in rows})
        cb=self.ttk.Combobox(top,textvariable=tag,values=tags,state="readonly",width=10); cb.pack(side="left")
        tree=self.ttk.Treeview(win,columns=("pseudo","alliance","atlas","wos"),show="headings",selectmode="browse")
        for col,text,width in [("pseudo","Pseudo",260),("alliance","Alliance",90),("atlas","Atlas ID",130),("wos","WOS ID",130)]:
            tree.heading(col,text=text); tree.column(col,width=width,anchor="center" if col!="pseudo" else "w")
        tree.pack(fill="both",expand=True,padx=10,pady=(0,8))
        def refresh(*_):
            query=q.get().strip().casefold(); t=tag.get()
            for x in tree.get_children(): tree.delete(x)
            for r in rows:
                pseudo=r["pseudo_display"] or "?"; rt=r["alliance_tag"] or "?"
                if t!="Toutes" and rt!=t: continue
                hay=f"{pseudo} {rt} {r['atlas_id']} {r['wos_id'] or ''}".casefold()
                if query and query not in hay: continue
                tree.insert("","end",iid=str(r["atlas_id"]),values=(pseudo,rt,r["atlas_id"],r["wos_id"] or ""))
        def choose(*_):
            sel=tree.selection()
            if not sel:return
            aid=int(sel[0]); r=next(x for x in rows if int(x["atlas_id"])==aid)
            try:
                self.engine.start_counter_lab(dict(r),5)
                self.status.set(f"Counter Lab: open 5 times {r['pseudo_display'] or aid}")
                win.destroy()
            except Exception as ex:self.messagebox.showerror("Counter Lab",str(ex),parent=win)
        bottom=self.ttk.Frame(win,padding=(10,0,10,10)); bottom.pack(fill="x")
        self.ttk.Label(bottom,text="Choose ONE player and open/close their profile 5 times.").pack(side="left")
        self.ttk.Button(bottom,text="Cancel",command=win.destroy).pack(side="right",padx=4)
        self.ttk.Button(bottom,text="Start x5",command=choose).pack(side="right",padx=4)
        q.trace_add("write",refresh); cb.bind("<<ComboboxSelected>>",refresh); tree.bind("<Double-1>",choose)
        refresh(); ent.focus_set()

    def stop_counter_lab(self):
        self.engine.stop_counter_lab("manual stop"); self.status.set("Counter Lab stopped.")

    def export_counter_lab(self):
        stamp=datetime.now().strftime("%Y%m%d_%H%M%S")
        f=self.filedialog.asksaveasfilename(initialdir=str(EXPORT_DIR),
            initialfile=f"WOS_counter_lab_{stamp}.csv",defaultextension=".csv",filetypes=[("CSV","*.csv")])
        if not f:return
        self.db.export_counter_lab_csv(Path(f))
        self.status.set(f"Counter Lab : {f}")

    def start_request_builder(self):
        rows=list(self.db.current_roster_rows())
        if not rows:
            self.messagebox.showinfo("Request Builder","Aucun roster courant disponible."); return
        win=self.tk.Toplevel(self.root); win.title("Raw Counter Builder - Choose a target"); win.geometry("790x510")
        win.transient(self.root); win.grab_set()
        top=self.ttk.Frame(win,padding=10); top.pack(fill="x")
        self.ttk.Label(top,text="Recherche :").pack(side="left")
        q=self.tk.StringVar(); ent=self.ttk.Entry(top,textvariable=q,width=36); ent.pack(side="left",padx=6)
        tag=self.tk.StringVar(value="Toutes")
        tags=["Toutes"]+sorted({r["alliance_tag"] or "?" for r in rows})
        cb=self.ttk.Combobox(top,textvariable=tag,values=tags,state="readonly",width=10); cb.pack(side="left")
        tree=self.ttk.Treeview(win,columns=("pseudo","alliance","atlas","wos"),show="headings",selectmode="browse")
        for col,text,width in [("pseudo","Pseudo",280),("alliance","Alliance",90),("atlas","Atlas ID",130),("wos","WOS ID",130)]:
            tree.heading(col,text=text); tree.column(col,width=width,anchor="center" if col!="pseudo" else "w")
        tree.pack(fill="both",expand=True,padx=10,pady=(0,8))
        def refresh(*_):
            query=q.get().strip().casefold(); t=tag.get()
            for x in tree.get_children(): tree.delete(x)
            for r in rows:
                pseudo=r["pseudo_display"] or "?"; rt=r["alliance_tag"] or "?"
                if t!="Toutes" and rt!=t: continue
                hay=f"{pseudo} {rt} {r['atlas_id']} {r['wos_id'] or ''}".casefold()
                if query and query not in hay: continue
                tree.insert("","end",iid=str(r["atlas_id"]),values=(pseudo,rt,r["atlas_id"],r["wos_id"] or ""))
        def choose(*_):
            sel=tree.selection()
            if not sel:return
            aid=int(sel[0]); r=next(x for x in rows if int(x["atlas_id"])==aid)
            try:
                info=self.engine.arm_request_builder(dict(r))
                self.rb_status.set(
                    f"Request Builder: {r['pseudo_display'] or aid} | predicted counter "
                    f"{info['predicted_counter']} | attente du vrai 7D02"
                )
                self.status.set(f"Raw Builder armed : {r['pseudo_display'] or aid}")
                win.destroy()
            except Exception as ex:
                self.messagebox.showerror("Request Builder",str(ex),parent=win)
        bottom=self.ttk.Frame(win,padding=(10,0,10,10)); bottom.pack(fill="x")
        self.ttk.Label(bottom,text="After Arming: immediately open this profile in WOS, without any other action.").pack(side="left")
        self.ttk.Button(bottom,text="Cancel",command=win.destroy).pack(side="right",padx=4)
        self.ttk.Button(bottom,text="Construire / Armer",command=choose).pack(side="right",padx=4)
        q.trace_add("write",refresh); cb.bind("<<ComboboxSelected>>",refresh); tree.bind("<Double-1>",choose)
        refresh(); ent.focus_set()

    def export_request_builder(self):
        stamp=datetime.now().strftime("%Y%m%d_%H%M%S")
        f=self.filedialog.asksaveasfilename(initialdir=str(EXPORT_DIR),
            initialfile=f"WOS_request_builder_{stamp}.csv",defaultextension=".csv",
            filetypes=[("CSV","*.csv")])
        if not f:return
        self.db.export_request_builder_csv(Path(f))
        self.status.set(f"Request Builder exported : {f}")

    def export_counter_tracker(self):
        stamp=datetime.now().strftime("%Y%m%d_%H%M%S")
        f=self.filedialog.asksaveasfilename(initialdir=str(EXPORT_DIR),
            initialfile=f"WOS_counter_tracker_{stamp}.csv",defaultextension=".csv",
            filetypes=[("CSV","*.csv")])
        if not f:return
        with Path(f).open("w",newline="",encoding="utf-8-sig") as h:
            w=csv.writer(h); w.writerow(["seen_at","opcode","counter","frame_hex"])
            for row in self.engine._rb_counter_history: w.writerow(row)
        self.status.set(f"Counter Tracker exported : {f}")

    def start_raw_diag(self):
        rows=list(self.db.current_roster_rows())
        if not rows:self.messagebox.showinfo("Raw Diagnostic","Aucun roster courant.");return
        win=self.tk.Toplevel(self.root);win.title("Raw Diagnostic");win.geometry("760x500");win.transient(self.root);win.grab_set()
        top=self.ttk.Frame(win,padding=10);top.pack(fill="x");self.ttk.Label(top,text="Recherche :").pack(side="left")
        q=self.tk.StringVar();e=self.ttk.Entry(top,textvariable=q,width=36);e.pack(side="left",padx=6)
        tree=self.ttk.Treeview(win,columns=("pseudo","alliance","atlas"),show="headings",selectmode="browse")
        for c,t,w in [("pseudo","Pseudo",300),("alliance","Alliance",100),("atlas","Atlas ID",150)]:
            tree.heading(c,text=t);tree.column(c,width=w)
        tree.pack(fill="both",expand=True,padx=10,pady=5)
        def refresh(*_):
            query=q.get().casefold().strip()
            for x in tree.get_children():tree.delete(x)
            for r in rows:
                hay=f"{r['pseudo_display'] or ''} {r['alliance_tag'] or ''} {r['atlas_id']}".casefold()
                if query and query not in hay:continue
                tree.insert("","end",iid=str(r["atlas_id"]),values=(r["pseudo_display"] or "?",r["alliance_tag"] or "?",r["atlas_id"]))
        def choose(*_):
            sel=tree.selection()
            if not sel:return
            aid=int(sel[0]);r=next(x for x in rows if int(x["atlas_id"])==aid)
            try:self.engine.start_raw_diag(dict(r));win.destroy();self.status.set(f"Raw Diagnostic : {r['pseudo_display'] or aid}")
            except Exception as ex:self.messagebox.showerror("Raw Diagnostic",str(ex),parent=win)
        b=self.ttk.Frame(win,padding=10);b.pack(fill="x");self.ttk.Button(b,text="Armer",command=choose).pack(side="right")
        self.ttk.Label(b,text="Arm, open this profile ONCE, wait 5s, then Stop Raw.").pack(side="left")
        q.trace_add("write",refresh);tree.bind("<Double-1>",choose);refresh();e.focus_set()

    def stop_raw_diag(self):
        d=self.engine.stop_raw_diag()
        if d:self.status.set(f"Raw Diagnostic complete : {d['packets']} payloads.")

    def export_raw_diag(self):
        stamp=datetime.now().strftime("%Y%m%d_%H%M%S")
        f=self.filedialog.asksaveasfilename(initialdir=str(EXPORT_DIR),initialfile=f"WOS_raw_diag_{stamp}.csv",
            defaultextension=".csv",filetypes=[("CSV","*.csv")])
        if f:self.db.export_raw_diag_csv(Path(f));self.status.set(f"Raw Diagnostic exported : {f}")

    def export_raw_counter(self):
        stamp=datetime.now().strftime("%Y%m%d_%H%M%S")
        f=self.filedialog.asksaveasfilename(initialdir=str(EXPORT_DIR),
            initialfile=f"WOS_raw_counter_{stamp}.csv",defaultextension=".csv",
            filetypes=[("CSV","*.csv")])
        if not f:return
        with Path(f).open("w",newline="",encoding="utf-8-sig") as h:
            w=csv.writer(h);w.writerow(["seen_at","opcode","counter","frame_hex"])
            for row in self.engine._rb_raw_seen:w.writerow(row)
        self.status.set(f"Raw Counter exported : {f}")

    def show_alliance_coverage(self):
        rows=list(self.db.alliance_coverage_rows())
        win=self.tk.Toplevel(self.root)
        win.title("Alliance / State Coverage")
        win.geometry("1180x650")
        top=self.ttk.Frame(win,padding=8); top.pack(fill="x")
        stats=self.db.alliance_coverage_stats()
        summary=(f"Alliances: {stats['total']}  |  Rosters vus: {stats['roster_seen']}  |  "
                 f"Complete Rosters: {stats['roster_complete']}  |  Captured Members: {stats['captured_members']}  |  "
                 f"Resolved Profiles: {stats['profiles_resolved']}")
        self.ttk.Label(top,text=summary,font=("Segoe UI",10,"bold")).pack(side="left")
        q=self.tk.StringVar()
        self.ttk.Label(top,text="Filtre:").pack(side="left",padx=(20,4))
        ent=self.ttk.Entry(top,textvariable=q,width=24); ent.pack(side="left")

        cols=("tag","name","aid","status","announced","captured","resolved","pct","session")
        tree=self.ttk.Treeview(win,columns=cols,show="headings")
        spec=[
            ("tag","TAG",70),("name","Alliance",220),("aid","Alliance ID",120),
            ("status","Roster",125),("announced","Announced",75),("captured","Captured",75),
            ("resolved","Resolved",70),("pct","Profils %",70),("session","Last Roster",180)
        ]
        for c,label,w in spec:
            tree.heading(c,text=label); tree.column(c,width=w,anchor="center" if c not in ("name","session") else "w")
        y=self.ttk.Scrollbar(win,orient="vertical",command=tree.yview)
        tree.configure(yscrollcommand=y.set); y.pack(side="right",fill="y")
        tree.pack(fill="both",expand=True,padx=(8,0),pady=(0,8))

        def refresh(*_):
            query=q.get().casefold().strip()
            for x in tree.get_children(): tree.delete(x)
            for r in rows:
                hay=f"{r['alliance_tag'] or ''} {r['alliance_name'] or ''} {r['alliance_id'] or ''} {r['roster_status']}".casefold()
                if query and query not in hay: continue
                captured=int(r["captured_members"] or 0); resolved=int(r["profiles_resolved"] or 0)
                pct=f"{(resolved*100.0/captured):.1f}" if captured else "0.0"
                tree.insert("","end",values=(
                    r["alliance_tag"] or "?",r["alliance_name"] or "?",r["alliance_id"] or "?",
                    r["roster_status"],r["announced_members"] or 0,captured,resolved,pct,
                    r["last_roster_session"] or "-"
                ))
        q.trace_add("write",refresh); refresh(); ent.focus_set()

    def export_alliance_coverage(self):
        stamp=datetime.now().strftime("%Y%m%d_%H%M%S")
        f=self.filedialog.asksaveasfilename(initialdir=str(EXPORT_DIR),
            initialfile=f"WOS_alliance_coverage_{stamp}.csv",defaultextension=".csv",
            filetypes=[("CSV","*.csv")])
        if not f:return
        self.db.export_alliance_coverage_csv(Path(f))
        self.status.set(f"Alliance coverage exported : {f}")

    def export_alliance_discovery(self):
        stamp=datetime.now().strftime("%Y%m%d_%H%M%S")
        f=self.filedialog.asksaveasfilename(initialdir=str(EXPORT_DIR),
            initialfile=f"WOS_alliance_discovery_{stamp}.csv",defaultextension=".csv",
            filetypes=[("CSV","*.csv")])
        if not f: return
        self.db.export_alliance_discovery_csv(Path(f))
        self.status.set(f"Alliance discovery exported : {f}")

    def export_state_discovery(self):
        stamp=datetime.now().strftime("%Y%m%d_%H%M%S")
        f=self.filedialog.asksaveasfilename(initialdir=str(EXPORT_DIR),
            initialfile=f"WOS_state_discovery_{stamp}.csv",defaultextension=".csv",
            filetypes=[("CSV","*.csv")])
        if not f:return
        self.db.export_state_discovery_csv(Path(f))
        self.status.set(f"State discovery exported : {f}")

    def close(self):
        try:
            if self.live.running:self.stop()
        finally:self.root.destroy()

    def run(self): self.root.mainloop()


def main():
    DATA_DIR.mkdir(parents=True,exist_ok=True); SESSIONS_DIR.mkdir(parents=True,exist_ok=True); EXPORT_DIR.mkdir(parents=True,exist_ok=True)
    ap=argparse.ArgumentParser(description="WOS State Collector V3.29 Alliance Coverage")
    ap.add_argument("--offline",type=Path,help="Analyser un PCAPNG sans interface graphique")
    ap.add_argument("--export",type=Path,help="Export CSV database then quit")
    args=ap.parse_args()
    decoder=DecoderBundle(BASE_DIR); db=StateDB(DB_PATH)
    cleaned_v320 = db.cleanup_v320_false_aids()
    if cleaned_v320:
        print(f"V3.23: {cleaned_v320} faux AID V3.20 retires de State Discovery")
    repaired_rosters = db.cleanup_oversized_roster_sessions()
    for sid,tag,n,limit,removed in repaired_rosters:
        print(f"V3.23: roster contamine repare [{tag}] session={sid}: {n}->{limit}, {removed} affiliations excedentaires retirees")
    if args.export:
        db.export_csv(args.export); print(args.export); return
    if args.offline:
        sid=f"offline_{safe_name(args.offline.stem)}_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        engine=CollectorEngine(decoder,db,print,lambda d:None); engine.reset(sid); db.start_session(sid,"offline",str(args.offline))
        OfflinePcapngReader(engine,decoder.core).run(args.offline); db.stop_session(sid,engine.stats_data)
        print(json.dumps({**engine.stats_data,**db.stats()},ensure_ascii=False,indent=2)); return
    CollectorGUI(decoder,db).run()

if __name__=="__main__":
    main()
