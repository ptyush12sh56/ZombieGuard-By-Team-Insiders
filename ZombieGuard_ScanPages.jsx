// ═══════════════════════════════════════════════════════════════════
// ZombieGuard — Two New Feature Pages
// Feature 1: URL/API Link Scanner  →  POST /api/scan/url
// Feature 2: File Upload Scanner   →  POST /api/scan/upload
// ═══════════════════════════════════════════════════════════════════

import { useState, useRef } from "react";

/* ── design tokens (same as App.jsx) ── */
const C = {
  bg:"#050a0f",bg1:"#080e16",bg2:"#0d1520",bg3:"#111d2c",bg4:"#162335",
  border:"#1e3050",border2:"#263d60",
  red:"#e8242c",red2:"#b81820",redT:"rgba(232,36,44,.12)",
  teal:"#00d4a8",teal2:"#00a882",tealT:"rgba(0,212,168,.1)",
  amber:"#f5a623",amberT:"rgba(245,166,35,.1)",
  purple:"#9b59f5",purpleT:"rgba(155,89,245,.1)",
  blue:"#1e6fff",blueT:"rgba(30,111,255,.1)",
  green:"#1db954",greenT:"rgba(29,185,84,.1)",
  pink:"#ec4899",pinkT:"rgba(236,72,153,.1)",
  txt0:"#dde8f5",txt1:"#7a9ab8",txt2:"#3d5570",txt3:"#1d3050",
};
const mono = { fontFamily:"'IBM Plex Mono',monospace" };
const display = { fontFamily:"'Bebas Neue',sans-serif" };

/* ── shared helpers ── */
function Panel({ children, style }) {
  return <div style={{ background:C.bg2, border:`1px solid ${C.border}`, borderRadius:8, padding:16, ...style }}>{children}</div>;
}
function PH({ title, right }) {
  return (
    <div style={{ display:"flex", alignItems:"center", justifyContent:"space-between", marginBottom:14 }}>
      <span style={{ ...mono, fontSize:10, color:C.txt2, textTransform:"uppercase", letterSpacing:"2px" }}>{title}</span>
      {right}
    </div>
  );
}
function Badge({ children, color=C.teal, bg=C.tealT, border=C.teal2 }) {
  return <span style={{ ...mono, fontSize:9, padding:"2px 7px", borderRadius:2, background:bg, color, border:`1px solid ${border}` }}>{children}</span>;
}
function Btn({ children, onClick, disabled, variant="default", style }) {
  const base = { display:"inline-flex", alignItems:"center", gap:5, padding:"7px 14px", borderRadius:8, fontSize:11, fontWeight:600, cursor:disabled?"not-allowed":"pointer", border:`1px solid ${C.border2}`, background:C.bg3, color:C.txt0, transition:"all .15s", opacity:disabled?0.4:1, fontFamily:"'Instrument Sans',sans-serif" };
  const variants = { primary:{ background:C.red, borderColor:C.red, color:"#fff" }, teal:{ background:C.tealT, borderColor:C.teal2, color:C.teal }, amber:{ background:C.amberT, borderColor:C.amber, color:C.amber } };
  return <button onClick={onClick} disabled={disabled} style={{ ...base, ...(variants[variant]||{}), ...style }}>{children}</button>;
}
function Toggle({ on, onChange, label }) {
  return (
    <div onClick={() => onChange(!on)} style={{ display:"flex", alignItems:"center", gap:9, fontSize:11, color:C.txt1, padding:"5px 0", cursor:"pointer" }}>
      <span style={{ width:34, height:18, borderRadius:9, background:on?C.teal:C.bg1, border:`1px solid ${on?C.teal2:C.border2}`, position:"relative", transition:"all .2s", flexShrink:0, display:"inline-block" }}>
        <span style={{ position:"absolute", top:2, left:on?18:2, width:12, height:12, borderRadius:"50%", background:"#fff", transition:"left .2s" }} />
      </span>
      {label}
    </div>
  );
}
function LogBox({ logs }) {
  const ref = useRef(null);
  return (
    <div ref={ref} style={{ background:C.bg1, border:`1px solid ${C.border}`, borderRadius:8, padding:12, ...mono, fontSize:10, lineHeight:2, maxHeight:220, overflowY:"auto" }}>
      {logs.length === 0
        ? <span style={{ color:C.txt2 }}>Waiting for scan…</span>
        : logs.map((l,i) => <div key={i}><span style={{ color:C.txt3 }}>[{l.ts}]</span> <span style={{ color:l.type==="ok"?C.teal:l.type==="err"?C.red:l.type==="warn"?C.amber:l.type==="kafka"?C.purple:l.type==="bs"?"#ec4899":C.blue }}>{l.text}</span></div>)
      }
    </div>
  );
}
function ResultsPreview({ results, title="Top Results by Risk Score" }) {
  if (!results?.length) return null;
  const rChip = (s) => {
    const [col,bg,border] = s>=80?[C.red,C.redT,C.red2]:s>=60?[C.amber,C.amberT,C.amber]:s>=40?[C.blue,C.blueT,C.blue]:[C.teal,C.tealT,C.teal2];
    return <span style={{ ...mono, fontSize:10, fontWeight:600, padding:"2px 7px", borderRadius:2, background:bg, color:col, border:`1px solid ${border}` }}>{s}</span>;
  };
  const clsBadge = (cls) => {
    const map = { ZOMBIE:[C.red,C.redT], SHADOW:[C.purple,C.purpleT], ACTIVE:[C.teal,C.tealT], DEPRECATED:[C.amber,C.amberT] };
    const [color,bgc] = map[cls]||[C.txt1,C.bg3];
    return <span style={{ ...mono, fontSize:9, padding:"1px 6px", borderRadius:2, background:bgc, color }}>{cls}</span>;
  };
  return (
    <Panel style={{ marginTop:14 }}>
      <PH title={title} right={<Badge>{results.length} endpoints</Badge>} />
      {results.map((r,i) => (
        <div key={i} style={{ display:"flex", alignItems:"center", gap:8, padding:"7px 0", borderBottom:`1px solid ${C.border}` }}>
          <span style={{ ...mono, fontSize:9, flex:1, overflow:"hidden", textOverflow:"ellipsis", whiteSpace:"nowrap" }}>{r.endpoint}</span>
          {clsBadge(r.classification)}
          <div style={{ width:55, height:4, background:C.bg1, borderRadius:2, overflow:"hidden" }}>
            <div style={{ width:`${r.risk_score}%`, height:"100%", background:r.risk_score>=80?C.red:r.risk_score>=60?C.amber:C.teal, borderRadius:2 }} />
          </div>
          {rChip(r.risk_score)}
        </div>
      ))}
    </Panel>
  );
}
function SummaryCards({ data }) {
  if (!data) return null;
  const cards = [
    { label:"Total APIs", val:data.total_apis||data.total_scanned, color:C.teal },
    { label:"🧟 Zombie",  val:data.zombie,   color:C.red    },
    { label:"👻 Shadow",  val:data.shadow,   color:C.purple },
    { label:"⚠ Deprecated", val:data.deprecated, color:C.amber },
    { label:"🔴 Disabled",  val:data.disabled,   color:C.red   },
    { label:"🔔 Alerts",    val:data.alerts,      color:C.amber },
  ];
  return (
    <div style={{ display:"grid", gridTemplateColumns:"repeat(6,1fr)", gap:10, marginBottom:14 }}>
      {cards.map(k => (
        <div key={k.label} style={{ background:C.bg2, border:`1px solid ${C.border}`, borderRadius:8, padding:"13px 14px 11px", position:"relative", overflow:"hidden" }}>
          <div style={{ position:"absolute", bottom:0, left:0, right:0, height:2, background:`linear-gradient(90deg,${k.color},transparent)` }} />
          <div style={{ ...mono, fontSize:9, color:C.txt2, textTransform:"uppercase", letterSpacing:"1.5px", marginBottom:5 }}>{k.label}</div>
          <div style={{ ...display, fontSize:28, color:k.color, lineHeight:1 }}>{k.val ?? "—"}</div>
        </div>
      ))}
    </div>
  );
}

/* ═══════════════════════════════════════════════════════════════════
   FEATURE 1 — URL / API LINK SCANNER
═══════════════════════════════════════════════════════════════════ */
export function URLScanPage() {
  const [url, setUrl]           = useState("");
  const [scanType, setScanType] = useState("auto");
  const [maxEps, setMaxEps]     = useState(50);
  const [cont, setCont]         = useState(15);
  const [stale, setStale]       = useState(30);
  const [autoDisable, setAutoDisable] = useState(true);
  const [rotateKeys, setRotateKeys]   = useState(true);
  const [webhook, setWebhook]         = useState(true);
  const [scanning, setScanning] = useState(false);
  const [logs, setLogs]         = useState([]);
  const [result, setResult]     = useState(null);
  const [error, setError]       = useState("");

  const addLog = (text, type="info") => {
    const ts = new Date().toLocaleTimeString("en-GB");
    setLogs(l => [...l, { ts, text, type }]);
  };

  const EXAMPLE_URLS = [
    { label:"httpbin.org (REST API)", url:"https://httpbin.org" },
    { label:"jsonplaceholder (mock)", url:"https://jsonplaceholder.typicode.com" },
    { label:"petstore.swagger.io",    url:"https://petstore.swagger.io" },
    { label:"reqres.in (test API)",   url:"https://reqres.in" },
    { label:"fakestoreapi.com",       url:"https://fakestoreapi.com" },
  ];

  const handleScan = async () => {
    if (!url.trim()) { setError("Please enter a URL or API link"); return; }
    setError("");
    setScanning(true);
    setLogs([]);
    setResult(null);

    addLog(`🌐 Starting URL scan: ${url}`, "info");
    addLog("BeautifulSoup initialised — fetching page source…", "bs");
    addLog("Checking for Swagger/OpenAPI spec at common paths…", "bs");
    addLog("Probing common API path patterns…", "info");
    addLog("Apache Kafka — publishing discovered endpoints to api-gateway-logs topic…", "kafka");
    addLog("IsolationForest + LSTM pipeline starting…", "ok");

    try {
      const res = await fetch("/api/scan/url", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          url: url.trim(),
          scan_type: scanType,
          max_endpoints: maxEps,
          contamination: cont / 100,
          staleness_days: stale,
          auto_disable: autoDisable,
          rotate_keys: rotateKeys,
          fire_webhook: webhook,
        }),
      });
      const data = await res.json();

      if (data.status === "no_endpoints") {
        addLog("⚠ No API endpoints discovered at this URL", "warn");
        addLog("Tip: Try a URL with a Swagger UI, /api path, or JSON API", "info");
        setError(data.message);
      } else if (data.status === "success") {
        const d = data.data;
        // Log URL meta info
        if (d.url_meta?.logs) d.url_meta.logs.forEach(l => addLog(l, "bs"));
        addLog(`✅ ${d.total_apis} endpoints discovered · ${d.zombie} zombie · ${d.shadow} shadow`, "ok");
        addLog(`NumPy CVSS scoring complete · ${d.disabled} auto-disabled · ${d.alerts} alerts fired`, "ok");
        addLog(`Scan complete in ${d.scan_duration_s}s — SQL Alchemy session #${d.session_id}`, "ok");
        setResult(d);
      } else {
        addLog("❌ Scan failed: " + (data.message || JSON.stringify(data)), "err");
        setError(data.message || "Scan failed");
      }
    } catch (e) {
      addLog("❌ Network error: " + e.message + " — Is the backend running? (python run.py)", "err");
      setError(e.message);
    }
    setScanning(false);
  };

  return (
    <div>
      {/* Hero banner */}
      <div style={{ background:`linear-gradient(135deg,rgba(232,36,44,.1),rgba(155,89,245,.1))`, border:`1px solid rgba(232,36,44,.3)`, borderRadius:8, padding:"14px 18px", marginBottom:16, display:"flex", alignItems:"center", gap:14 }}>
        <div style={{ fontSize:28 }}>🌐</div>
        <div>
          <div style={{ ...display, fontSize:18, letterSpacing:2, color:C.red, marginBottom:3 }}>URL / API LINK SCANNER</div>
          <div style={{ ...mono, fontSize:9, color:C.txt1 }}>
            Paste any website URL or API base link → ZombieGuard fetches the page, parses Swagger/OpenAPI docs with BeautifulSoup, probes common API paths, and runs the full IsolationForest + CVSS pipeline on discovered endpoints
          </div>
        </div>
      </div>

      <div style={{ display:"grid", gridTemplateColumns:"1fr 1fr", gap:14 }}>
        {/* Config panel */}
        <Panel>
          <PH title="Target URL Configuration — POST /api/scan/url" />

          {/* URL input */}
          <div style={{ marginBottom:12 }}>
            <div style={{ ...mono, fontSize:9, color:C.txt2, marginBottom:5, letterSpacing:1 }}>WEBSITE URL OR API BASE URL</div>
            <div style={{ display:"flex", gap:8 }}>
              <input
                value={url} onChange={e => setUrl(e.target.value)}
                onKeyDown={e => e.key === "Enter" && handleScan()}
                placeholder="https://api.example.com  or  https://example.com/api/v1"
                style={{ flex:1, background:C.bg1, border:`1px solid ${error?C.red:url?C.teal2:C.border2}`, borderRadius:8, color:C.txt0, padding:"9px 12px", fontSize:12, fontFamily:"'Instrument Sans',sans-serif", transition:"border-color .2s" }}
              />
            </div>
            {error && <div style={{ ...mono, fontSize:9, color:C.red, marginTop:4 }}>⚠ {error}</div>}
          </div>

          {/* Quick examples */}
          <div style={{ marginBottom:14 }}>
            <div style={{ ...mono, fontSize:9, color:C.txt2, marginBottom:6, letterSpacing:1 }}>QUICK EXAMPLES</div>
            <div style={{ display:"flex", flexWrap:"wrap", gap:5 }}>
              {EXAMPLE_URLS.map(ex => (
                <button
                  key={ex.url}
                  onClick={() => { setUrl(ex.url); setError(""); }}
                  style={{ ...mono, fontSize:9, padding:"3px 9px", borderRadius:4, background:C.bg3, border:`1px solid ${C.border2}`, color:C.txt1, cursor:"pointer", transition:"all .15s" }}
                >
                  {ex.label}
                </button>
              ))}
            </div>
          </div>

          {/* Scan type */}
          <div style={{ marginBottom:10 }}>
            <div style={{ ...mono, fontSize:9, color:C.txt2, marginBottom:4, letterSpacing:1 }}>SCAN TYPE</div>
            <div style={{ display:"grid", gridTemplateColumns:"1fr 1fr", gap:6 }}>
              {[["auto","🤖 Auto-detect"],["swagger","📋 Swagger/OpenAPI"],["api","⚡ REST API"],["website","🌐 Website"]].map(([val,label]) => (
                <div
                  key={val} onClick={() => setScanType(val)}
                  style={{ padding:"8px 10px", borderRadius:6, border:`1px solid ${scanType===val?C.teal2:C.border}`, background:scanType===val?C.tealT:C.bg3, cursor:"pointer", ...mono, fontSize:10, color:scanType===val?C.teal:C.txt1, transition:"all .15s" }}
                >
                  {label}
                </div>
              ))}
            </div>
          </div>

          {/* Max endpoints slider */}
          <div style={{ marginBottom:10 }}>
            <div style={{ ...mono, fontSize:9, color:C.txt2, marginBottom:4, letterSpacing:1 }}>MAX ENDPOINTS TO DISCOVER: <span style={{ color:C.teal }}>{maxEps}</span></div>
            <input type="range" min="5" max="100" value={maxEps} onChange={e => setMaxEps(+e.target.value)} />
          </div>
          <div style={{ marginBottom:10 }}>
            <div style={{ ...mono, fontSize:9, color:C.txt2, marginBottom:4, letterSpacing:1 }}>ML CONTAMINATION: <span style={{ color:C.teal }}>{cont}%</span></div>
            <input type="range" min="5" max="40" value={cont} onChange={e => setCont(+e.target.value)} />
          </div>
          <div style={{ marginBottom:14 }}>
            <div style={{ ...mono, fontSize:9, color:C.txt2, marginBottom:4, letterSpacing:1 }}>STALENESS THRESHOLD: <span style={{ color:C.teal }}>{stale}d</span></div>
            <input type="range" min="7" max="90" value={stale} onChange={e => setStale(+e.target.value)} />
          </div>

          <div style={{ height:1, background:`linear-gradient(90deg,${C.red},${C.teal},transparent)`, margin:"12px 0", opacity:.4 }} />
          <Toggle on={autoDisable} onChange={setAutoDisable} label="Auto-disable CRITICAL endpoints (FastAPI)" />
          <Toggle on={rotateKeys}  onChange={setRotateKeys}  label="Rotate API keys on disable (Pydantic)" />
          <Toggle on={webhook}     onChange={setWebhook}     label="Fire SecOps webhook (Slack/Email/PagerDuty)" />

          {/* How it works */}
          <div style={{ marginTop:12, padding:10, background:C.bg1, border:`1px solid ${C.border}`, borderRadius:6 }}>
            <div style={{ ...mono, fontSize:9, color:C.txt2, marginBottom:6, letterSpacing:1 }}>HOW IT WORKS</div>
            {[
              ["🌐","Fetch main page + JS files","BeautifulSoup4 HTML/JS parser"],
              ["📋","Try Swagger / OpenAPI spec","/openapi.json, /swagger.json paths"],
              ["🔍","Extract API paths from source","Regex + BeautifulSoup regex patterns"],
              ["🛡️","Probe 25 common API paths","/api, /api/v1, /api/v2, /health…"],
              ["🤖","Run ML pipeline on discovered endpoints","IsolationForest + LSTM + NumPy CVSS"],
            ].map(([icon,title,sub],i) => (
              <div key={i} style={{ display:"flex", alignItems:"center", gap:8, marginBottom:6, padding:"4px 0" }}>
                <span style={{ fontSize:14, flexShrink:0 }}>{icon}</span>
                <div>
                  <div style={{ fontSize:11, fontWeight:600, marginBottom:1 }}>{title}</div>
                  <div style={{ ...mono, fontSize:9, color:C.txt2 }}>{sub}</div>
                </div>
              </div>
            ))}
          </div>

          <Btn variant="primary" onClick={handleScan} disabled={scanning} style={{ marginTop:14, width:"100%", justifyContent:"center", letterSpacing:1 }}>
            {scanning
              ? <><span style={{ width:12, height:12, border:`2px solid rgba(255,255,255,.3)`, borderTopColor:"#fff", borderRadius:"50%", animation:"spin .6s linear infinite", display:"inline-block" }} /> SCANNING URL…</>
              : "🌐 SCAN URL / API LINK"
            }
          </Btn>
        </Panel>

        {/* Results panel */}
        <div>
          <Panel>
            <PH
              title="Scan Output"
              right={scanning
                ? <Badge color={C.amber} bg={C.amberT} border={C.amber}>● Scanning…</Badge>
                : result ? <Badge>✅ Complete</Badge> : null
              }
            />
            <LogBox logs={logs} />
          </Panel>

          {result && (
            <>
              <SummaryCards data={result} />
              {/* URL meta info */}
              <Panel style={{ marginBottom:14 }}>
                <PH title="Discovery Meta" />
                <div style={{ display:"grid", gridTemplateColumns:"1fr 1fr 1fr", gap:8 }}>
                  {[
                    { label:"Swagger/OpenAPI", val:result.url_meta?.swagger_count ?? 0, color:C.teal },
                    { label:"HTML/JS Extracted", val:result.url_meta?.html_extracted ?? 0, color:"#ec4899" },
                    { label:"Path Probing", val:result.url_meta?.probe_count ?? 0, color:C.purple },
                  ].map(k => (
                    <div key={k.label} style={{ background:C.bg3, border:`1px solid ${C.border}`, borderRadius:6, padding:"10px", textAlign:"center" }}>
                      <div style={{ ...display, fontSize:22, color:k.color }}>{k.val}</div>
                      <div style={{ ...mono, fontSize:9, color:C.txt2, marginTop:2 }}>{k.label}</div>
                    </div>
                  ))}
                </div>
                <div style={{ marginTop:10, padding:"8px 10px", background:C.bg1, borderRadius:6, ...mono, fontSize:9, color:C.txt1, border:`1px solid ${C.border}` }}>
                  <div>🎯 Target: <span style={{ color:C.teal }}>{result.target_url}</span></div>
                  <div>⏱ Scan Time: <span style={{ color:C.amber }}>{result.scan_duration_s}s</span></div>
                  <div>🗄 Session: <span style={{ color:C.purple }}>#{result.session_id}</span></div>
                </div>
              </Panel>
              <ResultsPreview results={result.results_preview} title="Top Riskiest Discovered Endpoints" />
            </>
          )}
        </div>
      </div>
    </div>
  );
}


/* ═══════════════════════════════════════════════════════════════════
   FEATURE 2 — FILE UPLOAD SCANNER
═══════════════════════════════════════════════════════════════════ */
export function FileUploadPage() {
  const [file, setFile]         = useState(null);
  const [dragOver, setDragOver] = useState(false);
  const [cont, setCont]         = useState(15);
  const [stale, setStale]       = useState(30);
  const [autoDisable, setAutoDisable] = useState(true);
  const [rotateKeys, setRotateKeys]   = useState(true);
  const [webhook, setWebhook]         = useState(true);
  const [scanning, setScanning] = useState(false);
  const [logs, setLogs]         = useState([]);
  const [result, setResult]     = useState(null);
  const [error, setError]       = useState("");
  const fileRef = useRef(null);

  const addLog = (text, type="info") => {
    const ts = new Date().toLocaleTimeString("en-GB");
    setLogs(l => [...l, { ts, text, type }]);
  };

  const onFileChange = (f) => {
    if (!f) return;
    const ext = f.name.split(".").pop().toLowerCase();
    if (!["csv","json","txt","yaml","yml"].includes(ext)) {
      setError(`Unsupported format: .${ext}. Use CSV, JSON, TXT, or YAML`);
      return;
    }
    if (f.size > 10 * 1024 * 1024) {
      setError("File too large. Max 10MB.");
      return;
    }
    setFile(f);
    setError("");
    setResult(null);
    setLogs([]);
  };

  const handleDrop = (e) => {
    e.preventDefault();
    setDragOver(false);
    const f = e.dataTransfer.files[0];
    if (f) onFileChange(f);
  };

  const handleScan = async () => {
    if (!file) { setError("Please select a file first"); return; }
    setError("");
    setScanning(true);
    setLogs([]);
    setResult(null);

    addLog(`📂 Reading file: ${file.name} (${(file.size/1024).toFixed(1)}KB)`, "info");
    addLog("Pydantic v2 validating all endpoint records…", "ok");
    addLog("Apache Kafka — publishing to api-gateway-logs topic…", "kafka");
    addLog("IsolationForest(n=200) + LSTM 30-day window running…", "ok");
    addLog("NumPy vectorised CVSS scoring all endpoints…", "ok");

    const formData = new FormData();
    formData.append("file", file);
    formData.append("contamination", cont / 100);
    formData.append("staleness_days", stale);
    formData.append("auto_disable", autoDisable);
    formData.append("rotate_keys", rotateKeys);
    formData.append("fire_webhook", webhook);

    try {
      const res = await fetch("/api/scan/upload", { method:"POST", body:formData });
      const data = await res.json();

      if (data.status === "no_endpoints") {
        addLog("⚠ No valid endpoints found in file", "warn");
        setError(data.message || "No endpoints parsed");
        if (data.parse_logs) data.parse_logs.forEach(l => addLog(l, "info"));
      } else if (data.status === "success") {
        const d = data.data;
        if (d.parse_logs) d.parse_logs.forEach(l => addLog(l, "bs"));
        addLog(`✅ ${d.total_parsed} records parsed · ${d.total_scanned} scanned`, "ok");
        addLog(`ML: zombie=${d.zombie} shadow=${d.shadow} active=${d.active}`, "ok");
        addLog(`${d.disabled} auto-disabled · ${d.alerts} alerts fired · session #${d.session_id}`, "ok");
        addLog(`Scan complete in ${d.scan_duration_s}s — SQL Alchemy persisted`, "ok");
        setResult(d);
      } else {
        addLog("❌ Scan failed: " + (data.message || JSON.stringify(data)), "err");
        setError(data.message || "Scan failed");
      }
    } catch (e) {
      addLog("❌ Network error: " + e.message + " — Is the backend running? (python run.py)", "err");
      setError(e.message);
    }
    setScanning(false);
  };

  const downloadSample = async (fmt) => {
    const res = await fetch(`/api/scan/sample-files?fmt=${fmt}`);
    const blob = await res.blob();
    const a = document.createElement("a");
    a.href = URL.createObjectURL(blob);
    a.download = `sample_endpoints.${fmt}`;
    a.click();
  };

  const FORMAT_SPECS = [
    { ext:"CSV", color:C.teal, borderColor:C.teal2, icon:"📊",
      desc:"One endpoint per row",
      cols:"endpoint, method, has_auth, calls_per_day, days_since_active, protocol, owner_team",
      example:`endpoint,method,has_auth\n/api/v1/login,POST,false\n/api/v2/payments,GET,true` },
    { ext:"JSON", color:C.purple, borderColor:C.purple, icon:"{ }",
      desc:"Array of endpoint objects",
      cols:'endpoint, method, has_auth, calls_per_day, days_since_active (+ any extra fields)',
      example:`[\n  {"endpoint":"/api/v1/test","method":"POST","has_auth":false},\n  {"endpoint":"/api/v2/pay","method":"GET","has_auth":true}\n]` },
    { ext:"TXT", color:C.amber, borderColor:C.amber, icon:"≡",
      desc:"One URL/path per line",
      cols:"Optional METHOD prefix (GET /path or just /path)",
      example:`/api/v1/accounts\nPOST /api/v2/payments\nGET /api/internal/debug` },
    { ext:"YAML", color:C.blue, borderColor:C.blue, icon:"Y",
      desc:"OpenAPI / Swagger spec",
      cols:"Full Swagger 2.0 or OpenAPI 3.0 spec — paths + methods extracted automatically",
      example:`paths:\n  /api/v1/users:\n    get:\n      summary: Get users\n  /api/v2/pay:\n    post:\n      security: [bearerAuth]` },
  ];

  return (
    <div>
      {/* Hero banner */}
      <div style={{ background:`linear-gradient(135deg,rgba(30,111,255,.1),rgba(29,185,84,.1))`, border:`1px solid rgba(30,111,255,.3)`, borderRadius:8, padding:"14px 18px", marginBottom:16, display:"flex", alignItems:"center", gap:14 }}>
        <div style={{ fontSize:28 }}>📂</div>
        <div>
          <div style={{ ...display, fontSize:18, letterSpacing:2, color:C.blue, marginBottom:3 }}>FILE UPLOAD SCANNER</div>
          <div style={{ ...mono, fontSize:9, color:C.txt1 }}>
            Upload a CSV, JSON, TXT, or YAML file containing multiple API endpoints → Pydantic validates every record → Full IsolationForest + LSTM + NumPy CVSS pipeline runs on all endpoints → Results saved to SQL Alchemy
          </div>
        </div>
      </div>

      <div style={{ display:"grid", gridTemplateColumns:"1fr 1fr", gap:14 }}>
        {/* Upload + config */}
        <div>
          <Panel style={{ marginBottom:14 }}>
            <PH title="Upload API Endpoints File — POST /api/scan/upload" />

            {/* Drop zone */}
            <div
              onDragOver={e => { e.preventDefault(); setDragOver(true); }}
              onDragLeave={() => setDragOver(false)}
              onDrop={handleDrop}
              onClick={() => fileRef.current?.click()}
              style={{
                border:`2px dashed ${dragOver?C.teal:file?C.blue:error?C.red:C.border2}`,
                borderRadius:10, padding:"28px 20px", textAlign:"center", cursor:"pointer",
                background:dragOver?C.tealT:file?C.blueT:C.bg1, transition:"all .2s", marginBottom:12,
              }}
            >
              <div style={{ fontSize:32, marginBottom:8 }}>{file ? "📄" : "📤"}</div>
              {file ? (
                <>
                  <div style={{ fontSize:13, fontWeight:700, color:C.blue, marginBottom:3 }}>{file.name}</div>
                  <div style={{ ...mono, fontSize:9, color:C.txt2 }}>{(file.size/1024).toFixed(1)} KB · {file.name.split(".").pop().toUpperCase()}</div>
                  <div style={{ ...mono, fontSize:9, color:C.teal, marginTop:4 }}>✅ Ready to scan — click Run below</div>
                </>
              ) : (
                <>
                  <div style={{ fontSize:13, fontWeight:600, color:C.txt1, marginBottom:4 }}>Drop file here or click to browse</div>
                  <div style={{ ...mono, fontSize:9, color:C.txt2 }}>Supported: CSV · JSON · TXT · YAML — Max 10MB · Up to 500 endpoints</div>
                </>
              )}
              <input ref={fileRef} type="file" accept=".csv,.json,.txt,.yaml,.yml" onChange={e => onFileChange(e.target.files[0])} style={{ display:"none" }} />
            </div>
            {error && <div style={{ ...mono, fontSize:9, color:C.red, marginBottom:10 }}>⚠ {error}</div>}

            {/* Sample downloads */}
            <div style={{ marginBottom:12 }}>
              <div style={{ ...mono, fontSize:9, color:C.txt2, marginBottom:6, letterSpacing:1 }}>DOWNLOAD SAMPLE FILES TO TEST</div>
              <div style={{ display:"flex", gap:6 }}>
                {["csv","json","txt"].map(fmt => (
                  <button
                    key={fmt}
                    onClick={() => downloadSample(fmt)}
                    style={{ ...mono, fontSize:9, padding:"4px 10px", borderRadius:4, background:C.bg3, border:`1px solid ${C.border2}`, color:C.txt1, cursor:"pointer" }}
                  >
                    ⬇ sample.{fmt}
                  </button>
                ))}
              </div>
            </div>

            {/* Sliders */}
            <div style={{ marginBottom:10 }}>
              <div style={{ ...mono, fontSize:9, color:C.txt2, marginBottom:4, letterSpacing:1 }}>ML CONTAMINATION: <span style={{ color:C.teal }}>{cont}%</span></div>
              <input type="range" min="5" max="40" value={cont} onChange={e => setCont(+e.target.value)} />
            </div>
            <div style={{ marginBottom:14 }}>
              <div style={{ ...mono, fontSize:9, color:C.txt2, marginBottom:4, letterSpacing:1 }}>STALENESS THRESHOLD: <span style={{ color:C.teal }}>{stale}d</span></div>
              <input type="range" min="7" max="90" value={stale} onChange={e => setStale(+e.target.value)} />
            </div>

            <div style={{ height:1, background:`linear-gradient(90deg,${C.blue},${C.teal},transparent)`, margin:"10px 0", opacity:.4 }} />
            <Toggle on={autoDisable} onChange={setAutoDisable} label="Auto-disable CRITICAL endpoints (FastAPI)" />
            <Toggle on={rotateKeys}  onChange={setRotateKeys}  label="Rotate API keys on disable (Pydantic)" />
            <Toggle on={webhook}     onChange={setWebhook}     label="Fire SecOps webhook (Slack/Email/PagerDuty)" />

            <Btn variant="primary" onClick={handleScan} disabled={scanning || !file} style={{ marginTop:14, width:"100%", justifyContent:"center", letterSpacing:1, background:C.blue, borderColor:C.blue }}>
              {scanning
                ? <><span style={{ width:12, height:12, border:`2px solid rgba(255,255,255,.3)`, borderTopColor:"#fff", borderRadius:"50%", animation:"spin .6s linear infinite", display:"inline-block" }} /> SCANNING FILE…</>
                : "📂 SCAN UPLOADED FILE"
              }
            </Btn>
          </Panel>

          {/* Format specs */}
          <Panel>
            <PH title="Supported File Formats" />
            {FORMAT_SPECS.map(f => (
              <div key={f.ext} style={{ marginBottom:10, padding:"10px 12px", background:C.bg3, border:`1px solid ${f.borderColor}22`, borderRadius:6, borderLeft:`3px solid ${f.borderColor}` }}>
                <div style={{ display:"flex", alignItems:"center", gap:8, marginBottom:4 }}>
                  <span style={{ ...mono, fontSize:10, padding:"1px 7px", borderRadius:2, background:`${f.color}22`, color:f.color, border:`1px solid ${f.borderColor}` }}>{f.ext}</span>
                  <span style={{ fontSize:11, fontWeight:700 }}>{f.desc}</span>
                </div>
                <div style={{ ...mono, fontSize:9, color:C.txt2, marginBottom:5 }}>{f.cols}</div>
                <pre style={{ ...mono, fontSize:9, color:C.txt1, background:C.bg1, padding:"6px 8px", borderRadius:4, overflowX:"auto", whiteSpace:"pre-wrap", border:`1px solid ${C.border}` }}>{f.example}</pre>
              </div>
            ))}
          </Panel>
        </div>

        {/* Scan output */}
        <div>
          <Panel style={{ marginBottom:14 }}>
            <PH
              title="Scan Output — Pipeline Log"
              right={scanning
                ? <Badge color={C.amber} bg={C.amberT} border={C.amber}>● Processing…</Badge>
                : result ? <Badge color={C.blue} bg={C.blueT} border={C.blue}>✅ Complete</Badge> : null
              }
            />
            <LogBox logs={logs} />
          </Panel>

          {result && (
            <>
              <SummaryCards data={result} />
              {/* File + parse meta */}
              <Panel style={{ marginBottom:14 }}>
                <PH title="Parse & ML Metadata" />
                <div style={{ display:"grid", gridTemplateColumns:"1fr 1fr", gap:8, marginBottom:10 }}>
                  {[
                    { label:"File", val:result.filename || "uploaded" },
                    { label:"Records Parsed", val:result.total_parsed },
                    { label:"Endpoints Scanned", val:result.total_scanned },
                    { label:"Scan Duration", val:result.scan_duration_s + "s" },
                    { label:"IF Anomalies", val:result.ml_meta?.if_anomalies ?? "—" },
                    { label:"LSTM Flags", val:result.ml_meta?.lstm_anomalies ?? "—" },
                  ].map(k => (
                    <div key={k.label} style={{ background:C.bg3, borderRadius:6, padding:"8px 10px", border:`1px solid ${C.border}` }}>
                      <div style={{ ...mono, fontSize:9, color:C.txt2, marginBottom:2 }}>{k.label}</div>
                      <div style={{ fontSize:13, fontWeight:700, color:C.teal }}>{k.val}</div>
                    </div>
                  ))}
                </div>
                <div style={{ padding:"8px 10px", background:C.bg1, borderRadius:6, ...mono, fontSize:9, color:C.txt1, border:`1px solid ${C.border}` }}>
                  <div>🗄 Session: <span style={{ color:C.purple }}>#{result.session_id}</span></div>
                  <div>🤖 Model: <span style={{ color:C.teal }}>{result.ml_meta?.model || "IsolationForest+LSTM"}</span></div>
                  <div>📊 Contamination: <span style={{ color:C.amber }}>{result.ml_meta?.contamination}</span></div>
                </div>
              </Panel>
              <ResultsPreview results={result.results_preview} title="Top Riskiest Endpoints from File" />
            </>
          )}
        </div>
      </div>
    </div>
  );
}
