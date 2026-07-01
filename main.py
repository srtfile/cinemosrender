"""
CinemaOS-style stream resolver — Render-deployable FastAPI service.
"""
from __future__ import annotations
import hashlib, hmac, json, os, re, time, traceback
from urllib.parse import parse_qs, urlencode, unquote, urlparse
import requests
from fastapi import FastAPI, Query
from fastapi.responses import HTMLResponse, JSONResponse

app = FastAPI()

BASE_ORIGIN     = "https://cinemaos.tech"
GT_VALUE        = "2549b22d9bf0d91847a2811baac98d0079e02dba592aea94"
HASH_PRIMARY    = "a7f3b9c2e8d4f1a6b5c9e2d7f4a8b3c6e1d9f7a4b2c8e5d3f9a6b4c1e7d2f8a5"
HASH_SECONDARY  = "d3f8a5b2c9e6d1f7a4b8c5e2d9f3a6b1c7e4d8f2a9b5c3e7d4f1a8b6c2e9d5f3"
DEFAULT_ENC_KEY = "a1b2c3d4e4f6477658455678901477567890abcdef1234567890abcdef123456"

SCRAPERS = [
    ("s7","Vidrock"),("n3","Vidzee-Duke"),("k9","Icefy"),("q4","Multimovies"),
    ("z2","Rive"),("f8","Castle"),("w6","Vidlink"),("b5","Videasy"),
    ("j1","Pkaystream"),("h0","Xpass"),
]

MEDIA_RE = re.compile(
    r"https?://[^\s\"'<>\\]+?(?:\.m3u8|\.mpd|\.mp4|/api/proxy|/tcloud|/api\?url=)[^\s\"'<>\\]*",
    re.IGNORECASE)
IFRAME_RE = re.compile(r"<iframe[^>]+src=[\"']([^\"']+)", re.IGNORECASE)

def now_ms(): return int(time.time() * 1000)
def add_u(lst, v):
    if v and v not in lst: lst.append(v)

def hdrs(ref=None):
    h = {"User-Agent":"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/147.0.0.0 Safari/537.36",
         "Accept":"*/*","Accept-Language":"en-US,en;q=0.9"}
    if ref: h["Referer"] = ref
    return h

def gen_hash(tmdb, imdb=None, season=None, episode=None):
    parts = []
    if tmdb:    parts.append(f"tmdbId:{tmdb}")
    if imdb:    parts.append(f"imdbId:{imdb}")
    if season   not in (None,""): parts.append(f"seasonId:{season}")
    if episode  not in (None,""): parts.append(f"episodeId:{episode}")
    c = "|".join(parts).encode()
    f = hmac.new(HASH_PRIMARY.encode(), c, hashlib.sha256).hexdigest()
    return hmac.new(HASH_SECONDARY.encode(), f.encode(), hashlib.sha256).hexdigest()

def maybe_decrypt(payload):
    if not isinstance(payload, dict): return payload
    for candidate in [payload, payload.get("data",{})]:
        if isinstance(candidate,dict) and {"encrypted","cin","mao"}.issubset(candidate.keys()):
            try:
                from cryptography.hazmat.primitives.ciphers.aead import AESGCM
                key_hex = os.environ.get("ENCRYPTION_KEY", DEFAULT_ENC_KEY)
                iv  = bytes.fromhex(candidate["cin"])
                tag = bytes.fromhex(candidate["mao"])
                ct  = bytes.fromhex(candidate["encrypted"])
                salt = bytes.fromhex(str(candidate["salt"])) if candidate.get("salt") else hashlib.sha256(iv).digest()[:32]
                use_kdf = not ("version" in candidate and not (int(candidate.get("version") or 0) >= 1))
                key = hashlib.pbkdf2_hmac("sha256", key_hex.encode(), salt, 100000, 32) if use_kdf else bytes.fromhex(key_hex)
                pt = AESGCM(key).decrypt(iv, ct+tag, None).decode("utf-8","replace")
                try: return json.loads(pt)
                except: return pt
            except: pass
    return payload

def get_id(url):
    p = urlparse(url)
    m = re.search(r"/player/([^/?#]+)", p.path)
    if m: return unquote(m.group(1))
    qs = parse_qs(p.query)
    for k in ("tmdbId","id"):
        if qs.get(k): return qs[k][0]
    if url.strip().isdigit(): return url.strip()
    return None

def norm_type(v):
    return "tv" if v and v.lower() in {"tv","series","show"} else "movie"

def parse_year(m):
    for k in ("release_year","year"):
        if m.get(k): return str(m[k])
    for k in ("release_date","first_air_date"):
        v = m.get(k)
        if v:
            x = re.match(r"(\d{4})", str(v))
            if x: return x.group(1)
    return ""

def sess_get(url, steps, timeout=20, ref=None):
    t0 = now_ms()
    r = requests.get(url, headers=hdrs(ref), timeout=timeout, allow_redirects=True)
    steps.append({"url":url,"status":r.status_code,"ms":now_ms()-t0})
    r.raise_for_status()
    return r

def get_meta(tmdb, mtype, input_url, steps):
    rid = "tvData" if mtype=="tv" else "movieData"
    for url in [
        f"{BASE_ORIGIN}/api/tmdb?{urlencode({'id':tmdb,'requestID':rid,'language':'en-US'})}",
        f"{BASE_ORIGIN}/api/tmdb?{urlencode({'requestID':rid,'id':tmdb,'language':'en-US'})}",
    ]:
        try:
            r = sess_get(url, steps, ref=BASE_ORIGIN+"/")
            d = r.json()
            for k in ("data","result","movie","tv","item"):
                if isinstance(d.get(k),dict): return d[k]
            if isinstance(d,dict) and d: return d
        except: pass
    # fallback: scrape page
    try:
        r = sess_get(input_url, steps, ref=BASE_ORIGIN+"/")
        html = r.text
        meta = {}
        for k,pat in {"imdb_id":r'"imdb_id"\s*:\s*"([^"]+)"',"title":r'"title"\s*:\s*"([^"]+)"',
                      "name":r'"name"\s*:\s*"([^"]+)"',"release_date":r'"release_date"\s*:\s*"([^"]+)"',
                      "first_air_date":r'"first_air_date"\s*:\s*"([^"]+)"'}.items():
            x = re.search(pat, html)
            if x: meta[k] = x.group(1)
        if meta: return meta
    except: pass
    raise RuntimeError("Metadata fetch failed — cinemaos.tech may be blocking this server's IP")

def get_provider(tmdb, mtype, meta, steps, season=None, episode=None, scraper=None):
    imdb  = meta.get("imdb_id") or (meta.get("external_ids") or {}).get("imdb_id") or ""
    title = meta.get("title") or meta.get("name") or ""
    p = {"type":mtype,"tmdbId":str(tmdb),"imdbId":str(imdb),"t":str(title),"ry":parse_year(meta)}
    if mtype=="tv":
        p["seasonId"]  = str(season  or 1)
        p["episodeId"] = str(episode or 1)
    p = {k:v for k,v in p.items() if v not in ("","None")}
    p["secret"] = gen_hash(p.get("tmdbId"), p.get("imdbId"), p.get("seasonId"), p.get("episodeId"))
    p["_gt"] = GT_VALUE
    if scraper: p["scraper"] = scraper
    ep = "/api/providerv4/scrape" if scraper else "/api/providerv4"
    url = f"{BASE_ORIGIN}{ep}?{urlencode(p)}"
    r = sess_get(url, steps, timeout=30, ref=f"{BASE_ORIGIN}/player/{tmdb}")
    return maybe_decrypt(r.json())

def walk(v):
    if isinstance(v,dict):
        for x in v.values(): yield from walk(x)
    elif isinstance(v,list):
        for x in v: yield from walk(x)
    else: yield v

def get_urls(payload):
    urls = []
    for v in walk(payload):
        if isinstance(v,str):
            if v.startswith(("http://","https://")): add_u(urls,v)
            for u in MEDIA_RE.findall(v): add_u(urls,u)
            for u in IFRAME_RE.findall(v): add_u(urls,u)
    return urls

def classify(urls):
    g = {"m3u8":[],"mpd":[],"mp4":[],"iframe_or_embed":[],"other_resources":[]}
    for u in urls:
        lo=u.lower()
        if   ".m3u8" in lo: add_u(g["m3u8"],u)
        elif ".mpd"  in lo: add_u(g["mpd"],u)
        elif ".mp4"  in lo: add_u(g["mp4"],u)
        elif any(x in lo for x in ("embed","iframe","/player/")): add_u(g["iframe_or_embed"],u)
        else: add_u(g["other_resources"],u)
    return g

def src_list(p):
    if isinstance(p,dict):
        s=p.get("sources")
        if isinstance(s,dict): return s
        if isinstance(s,list): return {str(i):x for i,x in enumerate(s)}
    return {}

def resolve(input_url, media_type=None, season=None, episode=None):
    t0=now_ms(); steps=[]; errors=[]
    out={"status":"started","ids":{},"metadata":{},"sources":{},
         "media_urls":{"m3u8":[],"mpd":[],"mp4":[],"iframe_or_embed":[],"other_resources":[]},
         "errors":errors,"steps":steps}

    tmdb = get_id(input_url)
    if not tmdb:
        out["status"]="error"; errors.append("Cannot extract TMDB id"); return out

    qs = parse_qs(urlparse(input_url).query)
    mtype   = norm_type(media_type or (qs.get("type") or [None])[0])
    season  = season  or (qs.get("season")  or qs.get("seasonId")  or [None])[0]
    episode = episode or (qs.get("episode") or qs.get("episodeId") or [None])[0]
    out["ids"] = {"tmdb_id":tmdb,"type":mtype,"season":season,"episode":episode}

    try:
        meta = get_meta(tmdb, mtype, input_url, steps)
        out["metadata"] = {"title":meta.get("title") or meta.get("name"),
                           "imdb_id":meta.get("imdb_id") or (meta.get("external_ids") or {}).get("imdb_id"),
                           "year":parse_year(meta)}
        payload = get_provider(tmdb, mtype, meta, steps, season, episode)
        sources = src_list(payload)
        if not sources:
            for sid,sname in SCRAPERS:
                try:
                    sp = get_provider(tmdb, mtype, meta, steps, season, episode, scraper=sid)
                    ss = src_list(sp)
                    if ss: sources.update(ss)
                except Exception as e: errors.append(f"{sname}: {e}")
        out["sources"] = sources
        all_urls = get_urls(payload) + get_urls(sources)
        cl = classify(list(dict.fromkeys(all_urls)))
        out["media_urls"] = cl
        out["status"] = "resolved" if (sources or any(cl.values())) else "no_sources_found"
    except Exception as e:
        out["status"]="error"; errors.append(str(e))

    out["elapsed_ms"] = now_ms()-t0
    return out


HTML = r"""<!DOCTYPE html>
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
.card{background:#1a1a1a;border:1px solid #2a2a2a;border-radius:12px;padding:28px;width:100%;max-width:620px}
label{display:block;font-size:.82rem;color:#aaa;margin-top:14px;margin-bottom:4px}
input,select{width:100%;padding:10px 12px;background:#111;border:1px solid #333;border-radius:8px;color:#e0e0e0;font-size:.95rem;outline:none}
input:focus,select:focus{border-color:#e50914}
.row{display:flex;gap:12px}.row>div{flex:1}
.go{margin-top:20px;width:100%;padding:12px;background:#e50914;color:#fff;font-size:1rem;font-weight:700;border:none;border-radius:8px;cursor:pointer}
.go:hover{background:#c0070f}.go:disabled{background:#444;cursor:not-allowed}
#spin{display:none;text-align:center;color:#888;margin-top:16px;font-size:.9rem}
#out{margin-top:24px;width:100%;max-width:620px}
.box{background:#1a1a1a;border:1px solid #2a2a2a;border-radius:12px;padding:18px;margin-bottom:14px}
.sh{font-size:.88rem;font-weight:700;color:#aaa;margin-bottom:10px}
.ok{color:#4caf50}.er{color:#e50914}
.ui{background:#111;border:1px solid #222;border-radius:8px;padding:9px 13px;margin-bottom:7px;display:flex;align-items:center;gap:8px}
.ua{color:#4fc3f7;text-decoration:none;flex:1;word-break:break-all;font-size:.8rem}
.ua:hover{text-decoration:underline}
.cb{background:#252525;color:#bbb;border:none;border-radius:6px;padding:5px 11px;font-size:.74rem;cursor:pointer;flex-shrink:0}
.cb:hover{background:#e50914;color:#fff}
.chips{display:flex;gap:8px;flex-wrap:wrap;margin-top:8px}
.chip{background:#111;border:1px solid #2a2a2a;border-radius:6px;padding:3px 10px;font-size:.78rem;color:#aaa}
.chip b{color:#ddd}
</style>
</head>
<body>
<h1>🎬 CinemaOS Resolver</h1>
<p class="sub">Resolve stream URLs from CinemaOS-style players</p>

<div class="card">
  <label>Player URL or TMDB ID</label>
  <input id="Q_URL" type="text" value="https://cinemaos.tech/player/254"/>

  <label>Media Type</label>
  <select id="Q_TYPE">
    <option value="movie">Movie</option>
    <option value="tv">TV Show</option>
  </select>

  <div class="row" id="Q_EPROW" style="display:none">
    <div><label>Season</label><input id="Q_S" type="number" value="1" min="1"/></div>
    <div><label>Episode</label><input id="Q_E" type="number" value="1" min="1"/></div>
  </div>

  <button class="go" id="Q_BTN">⚡ Resolve Stream</button>
  <div id="spin">⏳ Resolving… please wait</div>
</div>

<div id="out"></div>

<script>
document.getElementById('Q_TYPE').onchange = function(){
  document.getElementById('Q_EPROW').style.display = this.value==='tv' ? 'flex' : 'none';
};

document.getElementById('Q_BTN').onclick = function(){
  var urlv = document.getElementById('Q_URL').value.trim();
  if(!urlv){ alert('Enter a URL or TMDB ID'); return; }
  var mt = document.getElementById('Q_TYPE').value;
  var s  = document.getElementById('Q_S').value;
  var e  = document.getElementById('Q_E').value;

  document.getElementById('Q_BTN').disabled = true;
  document.getElementById('spin').style.display = 'block';
  document.getElementById('out').innerHTML = '';

  var qs = 'url=' + encodeURIComponent(urlv) + '&type=' + mt;
  if(mt === 'tv') qs += '&season=' + s + '&episode=' + e;

  var xhr = new XMLHttpRequest();
  xhr.open('GET', '/resolve?' + qs);
  xhr.timeout = 90000;
  xhr.onload = function(){
    document.getElementById('Q_BTN').disabled = false;
    document.getElementById('spin').style.display = 'none';
    try{
      var d = JSON.parse(xhr.responseText);
      document.getElementById('out').innerHTML = buildOut(d);
    }catch(ex){
      document.getElementById('out').innerHTML =
        '<div class="box"><p class="er">Parse error: ' + ex.message + '<br><pre style="font-size:.7rem;margin-top:8px;overflow:auto">' + xhr.responseText.slice(0,400) + '</pre></p></div>';
    }
  };
  xhr.onerror = function(){
    document.getElementById('Q_BTN').disabled = false;
    document.getElementById('spin').style.display = 'none';
    document.getElementById('out').innerHTML = '<div class="box"><p class="er">❌ Network error</p></div>';
  };
  xhr.ontimeout = function(){
    document.getElementById('Q_BTN').disabled = false;
    document.getElementById('spin').style.display = 'none';
    document.getElementById('out').innerHTML = '<div class="box"><p class="er">❌ Request timed out</p></div>';
  };
  xhr.send();
};

function buildOut(d){
  var html = '<div class="box">';
  var ok = d.status === 'resolved';
  html += '<p style="font-size:1rem;font-weight:700" class="'+(ok?'ok':'er')+'">'+(ok?'✅ Resolved':'⚠️ '+e2(d.status||'unknown'))+'</p>';
  var m = d.metadata || {};
  if(m.title || m.year){
    html += '<div class="chips" style="margin-top:10px">';
    if(m.title)   html += '<span class="chip">📽 <b>'+e2(m.title)+'</b></span>';
    if(m.year)    html += '<span class="chip">📅 <b>'+e2(m.year)+'</b></span>';
    if(m.imdb_id) html += '<span class="chip">🎬 <b>'+e2(m.imdb_id)+'</b></span>';
    var ids = d.ids||{};
    if(ids.type)  html += '<span class="chip">📺 <b>'+e2(ids.type)+'</b></span>';
    html += '</div>';
  }
  (d.errors||[]).forEach(function(er){ html += '<p class="er" style="margin-top:6px;font-size:.82rem">⚠️ '+e2(er)+'</p>'; });
  html += '<p style="margin-top:10px;font-size:.78rem;color:#555">'+((d.elapsed_ms||0))+'ms · '+((d.steps||[]).length)+' requests</p>';
  html += '</div>';

  var mu = d.media_urls || {};
  var grps = [['m3u8','🎞 HLS Streams'],['mpd','📦 DASH'],['mp4','🎬 MP4'],['iframe_or_embed','🖼 Embeds'],['other_resources','📎 Other']];
  var total = 0;
  grps.forEach(function(g){
    var urls = mu[g[0]] || [];
    if(!urls.length) return;
    total += urls.length;
    html += '<div class="box"><div class="sh">'+g[1]+' <span style="background:#1a3a1a;color:#4caf50;border-radius:999px;padding:1px 8px;font-size:.72rem">'+urls.length+'</span></div>';
    urls.forEach(function(u,i){
      html += '<div class="ui"><a class="ua" href="'+e2(u)+'" target="_blank" rel="noopener">#'+(i+1)+' '+e2(u)+'</a>'+
              '<button class="cb" data-url="'+e2(u)+'">Copy</button></div>';
    });
    html += '</div>';
  });

  if(!total) html += '<div class="box"><p style="color:#666">No stream URLs found.</p></div>';
  return html;
}

function e2(s){ return String(s||'').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;'); }

document.addEventListener('click', function(ev){
  if(ev.target.classList.contains('cb')){
    var u = ev.target.getAttribute('data-url');
    navigator.clipboard.writeText(u).then(function(){
      ev.target.textContent = '✓';
      setTimeout(function(){ ev.target.textContent = 'Copy'; }, 1500);
    });
  }
});
</script>
</body>
</html>"""


@app.get("/", response_class=HTMLResponse)
def root():
    return HTMLResponse(content=HTML, status_code=200)

@app.get("/health")
def health():
    return {"ok": True}

@app.get("/resolve")
def api_resolve(
    url:     str = Query("https://cinemaos.tech/player/254"),
    type:    str = Query("movie"),
    season:  str = Query(None),
    episode: str = Query(None),
):
    try:
        r = resolve(url, media_type=type, season=season, episode=episode)
        return JSONResponse(r)
    except Exception as e:
        return JSONResponse({"status":"error","error":str(e),"trace":traceback.format_exc()}, status_code=500)