"""
CinemaOS-style stream resolver — Render-deployable FastAPI service.
Endpoints:
  GET /          → HTML UI
  GET /resolve   → JSON API
  GET /health    → health check
"""

from __future__ import annotations

import asyncio
import base64
import hashlib
import hmac
import json
import os
import re
import time
import traceback
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, quote, unquote, urlencode, urlparse

import requests
from fastapi import FastAPI, Query
from fastapi.responses import HTMLResponse, JSONResponse

app = FastAPI(title="CinemaOS Stream Resolver")

# ── Constants ──────────────────────────────────────────────────────────────────
DEFAULT_TEST_URL  = "https://cinemaos.tech/player/254"
BASE_ORIGIN       = "https://cinemaos.tech"
GT_VALUE          = "2549b22d9bf0d91847a2811baac98d0079e02dba592aea94"
MAX_HINT_URLS     = 200

HASH_PRIMARY   = "a7f3b9c2e8d4f1a6b5c9e2d7f4a8b3c6e1d9f7a4b2c8e5d3f9a6b4c1e7d2f8a5"
HASH_SECONDARY = "d3f8a5b2c9e6d1f7a4b8c5e2d9f3a6b1c7e4d8f2a9b5c3e7d4f1a8b6c2e9d5f3"
DEFAULT_ENC_KEY= "a1b2c3d4e4f6477658455678901477567890abcdef1234567890abcdef123456"

SCRAPERS = [
    ("s7","Vidrock"),("n3","Vidzee-Duke"),("k9","Icefy"),("q4","Multimovies"),
    ("z2","Rive"),("f8","Castle"),("w6","Vidlink"),("b5","Videasy"),
    ("j1","Pkaystream"),("h0","Xpass"),
]

MEDIA_RE = re.compile(
    r"https?://[^\s\"'<>\\]+?(?:\.m3u8|\.mpd|\.mp4|/api/proxy|/tcloud|/api\?url=)[^\s\"'<>\\]*",
    re.IGNORECASE,
)
IFRAME_RE = re.compile(r"<iframe[^>]+src=[\"']([^\"']+)", re.IGNORECASE)

# ── Helpers ────────────────────────────────────────────────────────────────────
def now_ms() -> int:
    return int(time.time() * 1000)

def add_unique(items: list, value: Any) -> None:
    if value and value not in items:
        items.append(value)

def browser_headers(referer=None, origin=None):
    h = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/147.0.0.0 Safari/537.36",
        "Accept": "*/*",
        "Accept-Language": "en-US,en;q=0.9",
    }
    if referer: h["Referer"] = referer
    if origin:  h["Origin"]  = origin
    return h

def make_session():
    s = requests.Session()
    s.headers.update(browser_headers())
    return s

def generate_content_hash(tmdb_id, imdb_id=None, season_id=None, episode_id=None):
    parts = []
    if tmdb_id:               parts.append(f"tmdbId:{tmdb_id}")
    if imdb_id:               parts.append(f"imdbId:{imdb_id}")
    if season_id  not in (None,""): parts.append(f"seasonId:{season_id}")
    if episode_id not in (None,""): parts.append(f"episodeId:{episode_id}")
    if not parts: raise ValueError("No content info for hash")
    content = "|".join(parts).encode()
    first = hmac.new(HASH_PRIMARY.encode(),   content,        hashlib.sha256).hexdigest()
    return  hmac.new(HASH_SECONDARY.encode(), first.encode(), hashlib.sha256).hexdigest()

def decrypt_provider_data(data):
    encrypted = data.get("encrypted")
    iv_hex    = data.get("cin")
    tag_hex   = data.get("mao")
    if not (encrypted and iv_hex and tag_hex):
        raise ValueError("Missing encrypted/cin/mao")
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    key_hex    = os.environ.get("ENCRYPTION_KEY", DEFAULT_ENC_KEY)
    iv         = bytes.fromhex(iv_hex)
    tag        = bytes.fromhex(tag_hex)
    ciphertext = bytes.fromhex(encrypted)
    salt = bytes.fromhex(str(data["salt"])) if data.get("salt") else hashlib.sha256(iv).digest()[:32]
    use_kdf = not ("version" in data and not (int(data.get("version") or 0) >= 1))
    key = hashlib.pbkdf2_hmac("sha256", key_hex.encode(), salt, 100000, 32) if use_kdf else bytes.fromhex(key_hex)
    plaintext = AESGCM(key).decrypt(iv, ciphertext + tag, None)
    text = plaintext.decode("utf-8", errors="replace")
    try:    return json.loads(text)
    except: return text

def maybe_decrypt(payload):
    if isinstance(payload, dict):
        if payload.get("encrypted") and isinstance(payload.get("data"), dict):
            return decrypt_provider_data(payload["data"])
        if {"encrypted","cin","mao"}.issubset(payload.keys()):
            return decrypt_provider_data(payload)
        if isinstance(payload.get("data"), dict) and {"encrypted","cin","mao"}.issubset(payload["data"].keys()):
            return decrypt_provider_data(payload["data"])
    return payload

def extract_player_id(url):
    parsed = urlparse(url)
    m = re.search(r"/player/([^/?#]+)", parsed.path)
    if m: return unquote(m.group(1))
    qs = parse_qs(parsed.query)
    for k in ("tmdbId","id"):
        if qs.get(k): return qs[k][0]
    if url.strip().isdigit(): return url.strip()
    return None

def normalize_type(v):
    return "tv" if v and v.lower() in {"tv","series","show"} else "movie"

def parse_year(meta):
    for k in ("release_year","year"):
        if meta.get(k): return str(meta[k])
    for k in ("release_date","first_air_date"):
        v = meta.get(k)
        if v:
            m = re.match(r"(\d{4})", str(v))
            if m: return m.group(1)
    return ""

def unwrap_payload(payload):
    if isinstance(payload, dict):
        for k in ("data","result","movie","tv","item"):
            if isinstance(payload.get(k), dict): return payload[k]
        return payload
    return {}

def find_meta_in_html(html):
    candidates = []
    for m in re.finditer(r"<script[^>]*>(.*?)</script>", html, re.DOTALL|re.IGNORECASE):
        t = m.group(1)
        if "imdb" in t.lower() or "tmdb" in t.lower() or "release_date" in t:
            candidates.append(t)
    joined = "\n".join(candidates)
    meta = {}
    for k, pat in {
        "imdb_id":      r'"imdb_id"\s*:\s*"([^"]+)"',
        "title":        r'"title"\s*:\s*"([^"]+)"',
        "name":         r'"name"\s*:\s*"([^"]+)"',
        "release_date": r'"release_date"\s*:\s*"([^"]+)"',
        "first_air_date":r'"first_air_date"\s*:\s*"([^"]+)"',
    }.items():
        found = re.search(pat, joined)
        if found: meta[k] = found.group(1)
    return meta

def fetch_json(session, url, steps, timeout=20):
    t0 = now_ms()
    r = session.get(url, timeout=timeout, allow_redirects=True)
    steps.append({"method":"GET","url":url,"status":r.status_code,
                  "elapsed_ms":now_ms()-t0,"content_type":r.headers.get("content-type","")})
    r.raise_for_status()
    return r.json()

def fetch_text(session, url, steps, timeout=20):
    t0 = now_ms()
    r = session.get(url, timeout=timeout, allow_redirects=True)
    steps.append({"method":"GET","url":url,"status":r.status_code,
                  "elapsed_ms":now_ms()-t0,"content_type":r.headers.get("content-type","")})
    r.raise_for_status()
    return r.text

def fetch_metadata(session, tmdb_id, media_type, input_url, steps):
    rid = "tvData" if media_type == "tv" else "movieData"
    for url in [
        f"{BASE_ORIGIN}/api/tmdb?{urlencode({'id':tmdb_id,'requestID':rid,'language':'en-US'})}",
        f"{BASE_ORIGIN}/api/tmdb?{urlencode({'requestID':rid,'id':tmdb_id,'language':'en-US'})}",
    ]:
        try:
            payload = fetch_json(session, url, steps)
            meta = unwrap_payload(payload)
            if meta: return meta
        except: pass
    try:
        html = fetch_text(session, input_url, steps)
        meta = find_meta_in_html(html)
        if meta: return meta
    except: pass
    raise RuntimeError("Could not fetch metadata")

def build_params(tmdb_id, media_type, meta, season=None, episode=None):
    imdb_id = (meta.get("imdb_id") or meta.get("imdbId")
               or (meta.get("external_ids") or {}).get("imdb_id") or "")
    title   = (meta.get("title") or meta.get("name")
               or meta.get("original_title") or meta.get("original_name") or "")
    params = {"type":media_type,"tmdbId":str(tmdb_id),"imdbId":str(imdb_id),
              "t":str(title),"ry":parse_year(meta)}
    if media_type == "tv":
        params["seasonId"]  = str(season  or 1)
        params["episodeId"] = str(episode or 1)
    params = {k:v for k,v in params.items() if v not in ("","None")}
    params["secret"] = generate_content_hash(
        params.get("tmdbId"), params.get("imdbId"),
        params.get("seasonId"), params.get("episodeId"))
    params["_gt"] = GT_VALUE
    return params

def fetch_provider(session, params, steps, scraper_id=None):
    endpoint = "/api/providerv4/scrape" if scraper_id else "/api/providerv4"
    query = dict(params)
    if scraper_id: query["scraper"] = scraper_id
    url = f"{BASE_ORIGIN}{endpoint}?{urlencode(query)}"
    session.headers.update(browser_headers(referer=f"{BASE_ORIGIN}/player/{query.get('tmdbId')}"))
    payload = fetch_json(session, url, steps, timeout=30)
    return maybe_decrypt(payload)

def walk_values(value):
    out = []
    if isinstance(value, dict):
        for v in value.values(): out.extend(walk_values(v))
    elif isinstance(value, list):
        for v in value: out.extend(walk_values(v))
    else: out.append(value)
    return out

def extract_urls(payload):
    urls = []
    for v in walk_values(payload):
        if isinstance(v, str):
            if v.startswith(("http://","https://")): add_unique(urls, v)
            for u in MEDIA_RE.findall(v): add_unique(urls, u)
            for u in IFRAME_RE.findall(v): add_unique(urls, u)
    return urls

def classify_urls(urls):
    groups = {"m3u8":[],"mpd":[],"mp4":[],"iframe_or_embed":[],"proxy_urls":[],"decoded_proxy_targets":[],"other_resources":[]}
    for url in urls:
        lo = url.lower()
        if   ".m3u8" in lo: add_unique(groups["m3u8"], url)
        elif ".mpd"  in lo: add_unique(groups["mpd"],  url)
        elif ".mp4"  in lo: add_unique(groups["mp4"],  url)
        elif any(x in lo for x in ("embed","iframe","/player/")): add_unique(groups["iframe_or_embed"], url)
        else: add_unique(groups["other_resources"], url)
    return groups

def source_list(payload):
    if isinstance(payload, dict):
        s = payload.get("sources")
        if isinstance(s, dict): return s
        if isinstance(s, list): return {str(i): item for i,item in enumerate(s)}
    return {}

def resolve(input_url, *, media_type=None, season=None, episode=None):
    t0    = now_ms()
    steps = []
    errors= []
    result= {
        "status":"started","ids":{},"metadata":{},"sources":{},
        "media_urls":{"m3u8":[],"mpd":[],"mp4":[],"iframe_or_embed":[],
                      "proxy_urls":[],"decoded_proxy_targets":[],"other_resources":[]},
        "errors":errors,"request_steps":steps,
    }

    tmdb_id = extract_player_id(input_url)
    if not tmdb_id:
        result["status"] = "error"
        errors.append("Could not extract TMDB id from URL")
        return result

    parsed = urlparse(input_url)
    qs = parse_qs(parsed.query)
    media_type = normalize_type(media_type or (qs.get("type") or [None])[0])
    season  = season  or (qs.get("season")  or qs.get("seasonId")  or [None])[0]
    episode = episode or (qs.get("episode") or qs.get("episodeId") or [None])[0]
    result["ids"] = {"tmdb_id":tmdb_id,"type":media_type,"season":season,"episode":episode}

    session = make_session()
    try:
        meta   = fetch_metadata(session, tmdb_id, media_type, input_url, steps)
        result["metadata"] = {
            "title":   meta.get("title") or meta.get("name"),
            "imdb_id": meta.get("imdb_id") or (meta.get("external_ids") or {}).get("imdb_id"),
            "year":    parse_year(meta),
        }
        params  = build_params(tmdb_id, media_type, meta, season, episode)
        payload = fetch_provider(session, params, steps)
        sources = source_list(payload)

        if not sources:
            for sid, sname in SCRAPERS:
                try:
                    sp = fetch_provider(session, params, steps, scraper_id=sid)
                    ss = source_list(sp)
                    if ss: sources.update(ss)
                except Exception as e:
                    errors.append(f"{sname}: {e}")

        result["sources"] = sources
        urls = extract_urls(payload if sources else {"sources": sources})
        # also extract from sources dict directly
        urls += extract_urls(sources)
        classified = classify_urls(list(dict.fromkeys(urls)))
        result["media_urls"] = classified

        result["status"] = "resolved" if (sources or any(v for v in classified.values())) else "no_sources_found"
    except Exception as e:
        result["status"] = "error"
        errors.append(str(e))

    result["elapsed_ms"] = now_ms() - t0
    return result

# ── HTML UI ────────────────────────────────────────────────────────────────────
HTML = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"/>
<meta name="viewport" content="width=device-width,initial-scale=1"/>
<title>CinemaOS Resolver</title>
<style>
  *{box-sizing:border-box;margin:0;padding:0}
  body{font-family:'Segoe UI',system-ui,sans-serif;background:#0a0a0a;color:#e0e0e0;min-height:100vh;padding:0 0 60px}

  /* ── Header ── */
  header{background:linear-gradient(135deg,#1a0000 0%,#0d0d0d 60%);border-bottom:1px solid #2a0000;padding:32px 24px 28px;text-align:center}
  header h1{font-size:2rem;font-weight:800;color:#fff;letter-spacing:-0.5px}
  header h1 span{color:#e50914}
  header p{color:#777;margin-top:6px;font-size:.93rem}

  /* ── Search form ── */
  .search-wrap{max-width:680px;margin:32px auto 0;padding:0 16px}
  .search-box{background:#161616;border:1px solid #2a2a2a;border-radius:16px;padding:24px}
  .field-row{display:flex;gap:12px;flex-wrap:wrap}
  .field{flex:1;min-width:140px}
  .field.grow{flex:2;min-width:260px}
  label{display:block;font-size:.78rem;color:#777;margin-bottom:6px;font-weight:500;text-transform:uppercase;letter-spacing:.04em}
  input,select{width:100%;padding:11px 14px;background:#0d0d0d;border:1px solid #2a2a2a;border-radius:10px;color:#e0e0e0;font-size:.93rem;outline:none;transition:border .15s}
  input:focus,select:focus{border-color:#e50914}
  select option{background:#161616}
  .btn-resolve{margin-top:16px;width:100%;padding:13px;background:#e50914;color:#fff;font-size:1rem;font-weight:700;border:none;border-radius:10px;cursor:pointer;letter-spacing:.02em;transition:background .15s}
  .btn-resolve:hover{background:#c0070f}
  .btn-resolve:disabled{background:#2a2a2a;color:#555;cursor:not-allowed}

  /* ── Spinner ── */
  .spinner{display:none;text-align:center;padding:32px 0;color:#555;font-size:.9rem}
  .spinner.on{display:block}
  .spin-ring{width:36px;height:36px;border:3px solid #222;border-top-color:#e50914;border-radius:50%;animation:spin .8s linear infinite;margin:0 auto 12px}
  @keyframes spin{to{transform:rotate(360deg)}}

  /* ── Results wrapper ── */
  #result{max-width:680px;margin:28px auto 0;padding:0 16px}

  /* ── Info banner ── */
  .info-banner{border-radius:14px;padding:20px 24px;margin-bottom:20px;display:flex;align-items:center;gap:16px}
  .info-banner.ok{background:#0d1f0d;border:1px solid #1a3a1a}
  .info-banner.err{background:#1f0d0d;border:1px solid #3a1a1a}
  .info-banner.warn{background:#1a1a0d;border:1px solid #3a3a1a}
  .status-icon{font-size:2rem;flex-shrink:0}
  .info-title{font-size:1.1rem;font-weight:700;color:#fff}
  .info-meta{margin-top:6px;display:flex;flex-wrap:wrap;gap:8px}
  .chip{background:#1a1a1a;border:1px solid #2a2a2a;border-radius:6px;padding:3px 10px;font-size:.78rem;color:#aaa}
  .chip b{color:#e0e0e0}
  .err-msg{color:#e05050;font-size:.85rem;margin-top:8px}

  /* ── Section ── */
  .section{margin-bottom:16px}
  .section-header{display:flex;align-items:center;gap:10px;padding:12px 0 10px;border-bottom:1px solid #1a1a1a;margin-bottom:12px}
  .section-icon{font-size:1.1rem}
  .section-title{font-size:.9rem;font-weight:700;color:#ccc;flex:1}
  .section-count{background:#1a1a1a;border:1px solid #2a2a2a;border-radius:999px;padding:2px 10px;font-size:.75rem;color:#888;font-weight:600}

  /* ── Stream cards ── */
  .stream-grid{display:flex;flex-direction:column;gap:8px}
  .stream-card{background:#111;border:1px solid #1e1e1e;border-radius:10px;padding:14px 16px;display:flex;align-items:center;gap:12px;transition:border-color .15s}
  .stream-card:hover{border-color:#333}
  .stream-num{background:#1a1a1a;border:1px solid #252525;border-radius:6px;width:28px;height:28px;display:flex;align-items:center;justify-content:center;font-size:.75rem;font-weight:700;color:#666;flex-shrink:0}
  .stream-info{flex:1;min-width:0}
  .stream-type{font-size:.7rem;font-weight:700;text-transform:uppercase;letter-spacing:.06em;margin-bottom:3px}
  .stream-type.m3u8{color:#4caf50}
  .stream-type.mpd{color:#2196f3}
  .stream-type.mp4{color:#ff9800}
  .stream-type.other{color:#9c27b0}
  .stream-url{font-size:.78rem;color:#888;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
  .stream-actions{display:flex;gap:6px;flex-shrink:0}
  .btn-copy{background:#1a1a1a;color:#aaa;border:1px solid #2a2a2a;border-radius:7px;padding:6px 12px;font-size:.75rem;font-weight:600;cursor:pointer;transition:all .15s;white-space:nowrap}
  .btn-copy:hover{background:#e50914;color:#fff;border-color:#e50914}
  .btn-open{background:transparent;color:#555;border:1px solid #222;border-radius:7px;padding:6px 10px;font-size:.75rem;cursor:pointer;text-decoration:none;display:flex;align-items:center;transition:all .15s}
  .btn-open:hover{color:#e0e0e0;border-color:#444}

  /* ── Stats bar ── */
  .stats-bar{display:flex;gap:8px;flex-wrap:wrap;margin-top:20px}
  .stat{background:#111;border:1px solid #1e1e1e;border-radius:8px;padding:10px 16px;font-size:.8rem;color:#666;flex:1;text-align:center;min-width:100px}
  .stat b{display:block;font-size:1.1rem;color:#ccc;margin-bottom:2px}

  /* ── Empty ── */
  .empty{text-align:center;padding:40px 0;color:#444;font-size:.9rem}
</style>
</head>
<body>

<header>
  <h1>🎬 Cinema<span>OS</span> Resolver</h1>
  <p>Resolve stream URLs from CinemaOS-style players instantly</p>
</header>

<div class="search-wrap">
  <div class="search-box">
    <div class="field-row">
      <div class="field grow">
        <label>Player URL or TMDB ID</label>
        <input id="url" type="text" placeholder="https://cinemaos.tech/player/254  or  254"/>
      </div>
      <div class="field">
        <label>Media Type</label>
        <select id="type" onchange="toggleEp()">
          <option value="movie">🎬 Movie</option>
          <option value="tv">📺 TV Show</option>
        </select>
      </div>
    </div>
    <div class="field-row" id="ep-row" style="display:none;margin-top:12px">
      <div class="field">
        <label>Season</label>
        <input id="season" type="number" value="1" min="1"/>
      </div>
      <div class="field">
        <label>Episode</label>
        <input id="episode" type="number" value="1" min="1"/>
      </div>
    </div>
    <button class="btn-resolve" id="btn" onclick="doResolve()">⚡ Resolve Stream</button>
  </div>
  <div class="spinner" id="spinner">
    <div class="spin-ring"></div>
    Resolving stream sources… this may take a few seconds
  </div>
</div>

<div id="result"></div>

<script>
function toggleEp(){
  document.getElementById('ep-row').style.display=
    document.getElementById('type').value==='tv'?'flex':'none';
}

function esc(s){
  return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
}

async function doResolve(){
  const urlVal=document.getElementById('url').value.trim();
  if(!urlVal){alert('Please enter a URL or TMDB ID');return;}
  const type=document.getElementById('type').value;
  const season=document.getElementById('season').value;
  const episode=document.getElementById('episode').value;
  const btn=document.getElementById('btn');
  const spinner=document.getElementById('spinner');
  const result=document.getElementById('result');
  btn.disabled=true;
  spinner.classList.add('on');
  result.innerHTML='';

  let apiUrl=`/resolve?url=${encodeURIComponent(urlVal)}&type=${type}`;
  if(type==='tv') apiUrl+=`&season=${season}&episode=${episode}`;

  try{
    const res=await fetch(apiUrl);
    const d=await res.json();
    result.innerHTML=render(d);
  }catch(e){
    result.innerHTML=`<div class="info-banner err"><div class="status-icon">❌</div><div><div class="info-title">Request Failed</div><div class="err-msg">${esc(e.message)}</div></div></div>`;
  }finally{
    btn.disabled=false;
    spinner.classList.remove('on');
  }
}

function render(d){
  const status=d.status||'unknown';
  const isOk=status==='resolved';
  const isErr=status.includes('error')||status.includes('fail');
  const bannerClass=isOk?'ok':isErr?'err':'warn';
  const icon=isOk?'✅':isErr?'❌':'⚠️';
  const statusLabel=isOk?'Resolved':status==='no_sources_found'?'No Sources Found':status;
  const meta=d.metadata||{};
  const ids=d.ids||{};

  let html=`<div class="info-banner ${bannerClass}">
    <div class="status-icon">${icon}</div>
    <div style="flex:1;min-width:0">
      <div class="info-title">${esc(meta.title||'Unknown Title')} ${meta.year?'('+esc(meta.year)+')':''}</div>
      <div class="info-meta">
        ${meta.imdb_id?`<span class="chip">IMDb <b>${esc(meta.imdb_id)}</b></span>`:''}
        <span class="chip">Type <b>${esc(ids.type||'—')}</b></span>
        ${ids.season?`<span class="chip">S<b>${esc(ids.season)}</b> E<b>${esc(ids.episode||'?')}</b></span>`:''}
        <span class="chip">Status <b>${esc(statusLabel)}</b></span>
      </div>
      ${(d.errors||[]).map(e=>`<div class="err-msg">⚠️ ${esc(e)}</div>`).join('')}
    </div>
  </div>`;

  const mu=d.media_urls||{};
  const groups=[
    ['m3u8','🎞','HLS Streams','m3u8'],
    ['mpd','📦','DASH Streams','mpd'],
    ['mp4','🎬','MP4 Files','mp4'],
    ['decoded_proxy_targets','🔗','Proxy Targets','other'],
    ['iframe_or_embed','🖼','Embeds','other'],
    ['other_resources','📎','Other Resources','other'],
  ];

  let totalStreams=0;
  let sectionsHtml='';

  for(const [key,icon2,label,typeClass] of groups){
    const urls=mu[key]||[];
    if(!urls.length) continue;
    totalStreams+=urls.length;
    sectionsHtml+=`<div class="section">
      <div class="section-header">
        <span class="section-icon">${icon2}</span>
        <span class="section-title">${label}</span>
        <span class="section-count">${urls.length}</span>
      </div>
      <div class="stream-grid">`;
    urls.forEach((u,i)=>{
      const ext=u.includes('.m3u8')?'M3U8':u.includes('.mpd')?'MPD':u.includes('.mp4')?'MP4':'URL';
      const safe=esc(u);
      const safeJs=u.replace(/\\/g,'\\\\').replace(/'/g,"\\'");
      sectionsHtml+=`<div class="stream-card">
        <div class="stream-num">${i+1}</div>
        <div class="stream-info">
          <div class="stream-type ${typeClass}">${ext}</div>
          <div class="stream-url" title="${safe}">${safe}</div>
        </div>
        <div class="stream-actions">
          <button class="btn-copy" onclick="cp('${safeJs}',this)">Copy</button>
          <a class="btn-open" href="${safe}" target="_blank" rel="noopener" title="Open">↗</a>
        </div>
      </div>`;
    });
    sectionsHtml+=`</div></div>`;
  }

  if(!totalStreams){
    sectionsHtml=`<div class="empty">😕 No playable stream URLs were found for this title.</div>`;
  }

  html+=sectionsHtml;

  html+=`<div class="stats-bar">
    <div class="stat"><b>${totalStreams}</b>streams found</div>
    <div class="stat"><b>${d.elapsed_ms||0}ms</b>resolve time</div>
    <div class="stat"><b>${(d.request_steps||[]).length}</b>API requests</div>
  </div>`;

  return html;
}

function cp(url,btn){
  navigator.clipboard.writeText(url);
  const orig=btn.textContent;
  btn.textContent='✓ Copied';
  btn.style.background='#1a3a1a';
  btn.style.color='#4caf50';
  btn.style.borderColor='#1a3a1a';
  setTimeout(()=>{btn.textContent=orig;btn.style.background='';btn.style.color='';btn.style.borderColor='';},2000);
}
</script>
</body>
</html>"""

# ── Routes ─────────────────────────────────────────────────────────────────────
@app.get("/", response_class=HTMLResponse)
def root():
    return HTMLResponse(content=HTML, status_code=200)

@app.get("/health")
def health():
    return {"ok": True}

@app.get("/resolve")
def resolve_endpoint(
    url:     str = Query(DEFAULT_TEST_URL),
    type:    str = Query("movie"),
    season:  str = Query(None),
    episode: str = Query(None),
):
    try:
        result = resolve(url, media_type=type, season=season, episode=episode)
        return JSONResponse(result)
    except Exception as e:
        return JSONResponse({"status":"error","error":str(e),"trace":traceback.format_exc()}, status_code=500)
