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
body{font-family:'Segoe UI',sans-serif;background:#0d0d0d;color:#e0e0e0;min-height:100vh;display:flex;flex-direction:column;align-items:center;padding:40px 16px}
h1{font-size:1.8rem;color:#e50914;margin-bottom:6px}
p.sub{color:#888;margin-bottom:30px;font-size:.95rem}
.card{background:#1a1a1a;border:1px solid #2a2a2a;border-radius:12px;padding:28px;width:100%;max-width:580px}
label{display:block;font-size:.82rem;color:#aaa;margin-top:14px;margin-bottom:4px}
input,select{width:100%;padding:10px 12px;background:#111;border:1px solid #333;border-radius:8px;color:#e0e0e0;font-size:.95rem;outline:none}
input:focus,select:focus{border-color:#e50914}
.row{display:flex;gap:12px}.row>div{flex:1}
button{margin-top:22px;width:100%;padding:12px;background:#e50914;color:#fff;font-size:1rem;font-weight:600;border:none;border-radius:8px;cursor:pointer}
button:hover{background:#c0070f}
button:disabled{background:#444;cursor:not-allowed}
#result{margin-top:28px;width:100%;max-width:580px}
.box{background:#1a1a1a;border:1px solid #2a2a2a;border-radius:12px;padding:20px;margin-bottom:16px}
.box h2{font-size:.95rem;color:#aaa;margin-bottom:12px}
.meta-grid{display:grid;grid-template-columns:auto 1fr;gap:6px 16px;font-size:.87rem}
.meta-grid span:nth-child(odd){color:#888}
.url-item{background:#111;border:1px solid #222;border-radius:8px;padding:10px 14px;margin-bottom:8px;font-size:.82rem;display:flex;justify-content:space-between;align-items:center;gap:8px}
.url-item a{color:#e50914;text-decoration:none;flex:1;word-break:break-all}
.url-item a:hover{text-decoration:underline}
.copy-btn{background:#2a2a2a;color:#ccc;border:none;border-radius:6px;padding:4px 10px;font-size:.75rem;cursor:pointer;white-space:nowrap}
.copy-btn:hover{background:#e50914;color:#fff}
.badge{display:inline-block;padding:2px 8px;border-radius:999px;font-size:.75rem;font-weight:600;margin-left:8px}
.badge.ok{background:#1a3a1a;color:#4caf50}
.badge.none{background:#2a2a1a;color:#888}
.err{color:#e50914;font-size:.88rem;margin-top:10px}
.spinner{display:none;text-align:center;color:#888;margin-top:20px;font-size:.9rem}
.spinner.on{display:block}
.tag{display:inline-block;padding:3px 10px;border-radius:6px;font-size:.75rem;font-weight:700;margin-bottom:12px}
.tag.resolved{background:#1a3a1a;color:#4caf50}
.tag.error{background:#3a1a1a;color:#e50914}
.tag.no_sources{background:#2a2a1a;color:#aaa}
</style>
</head>
<body>
<h1>🎬 CinemaOS Resolver</h1>
<p class="sub">Resolve stream URLs from CinemaOS-style players</p>

<div class="card">
  <label>Player URL or TMDB ID</label>
  <input id="url" type="text" placeholder="https://cinemaos.tech/player/254  or  254"/>

  <label>Media Type</label>
  <select id="type">
    <option value="movie">Movie</option>
    <option value="tv">TV Show</option>
  </select>

  <div class="row" id="ep-row" style="display:none">
    <div><label>Season</label><input id="season" type="number" value="1" min="1"/></div>
    <div><label>Episode</label><input id="episode" type="number" value="1" min="1"/></div>
  </div>

  <button id="btn" onclick="resolve()">Resolve Stream</button>
  <div class="spinner" id="spinner">⏳ Resolving… please wait</div>
</div>

<div id="result"></div>

<script>
document.getElementById('type').addEventListener('change',function(){
  document.getElementById('ep-row').style.display=this.value==='tv'?'flex':'none';
});

async function resolve(){
  const urlVal=document.getElementById('url').value.trim();
  if(!urlVal){alert('Enter a URL or TMDB ID');return;}
  const type=document.getElementById('type').value;
  const season=document.getElementById('season').value;
  const episode=document.getElementById('episode').value;
  const btn=document.getElementById('btn');
  const spinner=document.getElementById('spinner');
  const result=document.getElementById('result');
  btn.disabled=true;spinner.classList.add('on');result.innerHTML='';

  let apiUrl=`/resolve?url=${encodeURIComponent(urlVal)}&type=${type}`;
  if(type==='tv') apiUrl+=`&season=${season}&episode=${episode}`;

  try{
    const res=await fetch(apiUrl);
    const d=await res.json();
    result.innerHTML=renderResult(d);
  }catch(e){
    result.innerHTML=`<p class="err">❌ ${e.message}</p>`;
  }finally{
    btn.disabled=false;spinner.classList.remove('on');
  }
}

function renderResult(d){
  const status=d.status||'unknown';
  const tagClass=status==='resolved'?'resolved':status.includes('error')||status.includes('fail')?'error':'no_sources';
  const tagLabel=status==='resolved'?'✅ Resolved':status==='no_sources_found'?'⚠️ No Sources':'❌ '+status;

  let html=`<div class="box">
    <span class="tag ${tagClass}">${tagLabel}</span>`;

  if(d.metadata&&(d.metadata.title||d.metadata.year)){
    html+=`<div class="meta-grid">
      <span>Title</span><span>${d.metadata.title||'—'}</span>
      <span>Year</span><span>${d.metadata.year||'—'}</span>
      <span>IMDB</span><span>${d.metadata.imdb_id||'—'}</span>
      <span>Type</span><span>${(d.ids||{}).type||'—'}</span>
    </div>`;
  }
  if(d.errors&&d.errors.length){
    html+=d.errors.map(e=>`<p class="err" style="margin-top:8px">⚠️ ${e}</p>`).join('');
  }
  html+=`</div>`;

  const mu=d.media_urls||{};
  const groups=[
    ['m3u8','🎞 M3U8 Streams'],['mpd','📦 MPD Streams'],
    ['mp4','🎬 MP4 Files'],['decoded_proxy_targets','🔗 Proxy Targets'],
    ['iframe_or_embed','🖼 Embeds'],['other_resources','📎 Other'],
  ];
  for(const [key,label] of groups){
    const urls=mu[key]||[];
    if(!urls.length) continue;
    html+=`<div class="box"><h2>${label} <span class="badge ok">${urls.length}</span></h2>`;
    urls.forEach((u,i)=>{
      html+=`<div class="url-item">
        <a href="${u}" target="_blank" rel="noopener">Stream ${i+1}: ${u}</a>
        <button class="copy-btn" onclick="cp('${u.replace(/'/g,"\\'")}',this)">Copy</button>
      </div>`;
    });
    html+=`</div>`;
  }

  if(!Object.values(mu).some(v=>v.length)){
    html+=`<div class="box"><p style="color:#888;font-size:.9rem">No playable stream URLs were found for this title.</p></div>`;
  }

  html+=`<div class="box"><h2>⏱ ${d.elapsed_ms||0}ms &nbsp;·&nbsp; ${(d.request_steps||[]).length} requests</h2></div>`;
  return html;
}

function cp(url,btn){
  navigator.clipboard.writeText(url);
  btn.textContent='Copied!';
  setTimeout(()=>btn.textContent='Copy',2000);
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