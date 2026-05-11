import { useState, useRef } from "react";
import { apiService } from "../services/api";
import { MODELS_INFO } from "../constants/theme";

// ─── Palette ────────────────────────────────────────────────
const C = {
  bg:       "#0a0e1a",
  card:     "#111827",
  card2:    "#1f2937",
  border:   "#1f2937",
  border2:  "#374151",
  text:     "#f1f5f9",
  text2:    "#9ca3af",
  text3:    "#6b7280",
  blue:     "#3b82f6",
  purple:   "#8b5cf6",
  green:    "#22c55e",
  red:      "#ef4444",
  orange:   "#f97316",
  cyan:     "#06b6d4",
  yellow:   "#f59e0b",
};

const RISK_COLOR = { LOW: C.green, MEDIUM: C.yellow, HIGH: C.orange, CRITICAL: C.red };

// ─── Features attendues par le backend ──────────────────────
const FEATURE_FIELDS = [
  { key: "id_orig_p",          label: "Port Source",               default: 12345,   min: 0,   max: 65535, step: 1    },
  { key: "id_resp_p",          label: "Port Destination",          default: 80,      min: 0,   max: 65535, step: 1    },
  { key: "duration",           label: "Duree (s)",                 default: 1.5,     min: 0,   max: 1e6,   step: 0.001 },
  { key: "orig_bytes",         label: "Octets Source",             default: 500,     min: 0,   max: 1e9,   step: 1    },
  { key: "resp_bytes",         label: "Octets Destination",        default: 200,     min: 0,   max: 1e9,   step: 1    },
  { key: "missed_bytes",       label: "Octets Perdus",             default: 0,       min: 0,   max: 1e9,   step: 1    },
  { key: "orig_pkts",          label: "Paquets Source",            default: 5,       min: 0,   max: 1e6,   step: 1    },
  { key: "orig_ip_bytes",      label: "Octets IP Source",          default: 600,     min: 0,   max: 1e9,   step: 1    },
  { key: "resp_pkts",          label: "Paquets Destination",       default: 3,       min: 0,   max: 1e6,   step: 1    },
  { key: "resp_ip_bytes",      label: "Octets IP Destination",     default: 250,     min: 0,   max: 1e9,   step: 1    },
  { key: "is_orig_local",      label: "IP Locale (0/1)",           default: 1,       min: 0,   max: 1,     step: 1    },
  { key: "orig_h_count",       label: "Freq. IP Source",           default: 10,      min: 0,   max: 1e6,   step: 1    },
  { key: "resp_h_count",       label: "Freq. IP Destination",      default: 5,       min: 0,   max: 1e6,   step: 1    },
  { key: "is_well_known_port", label: "Port Connu <1024 (0/1)",    default: 1,       min: 0,   max: 1,     step: 1    },
  { key: "hour",               label: "Heure (0-23)",              default: 14,      min: 0,   max: 23,    step: 1    },
  { key: "minute",             label: "Minute (0-59)",             default: 30,      min: 0,   max: 59,    step: 1    },
  { key: "day_of_week",        label: "Jour Semaine (0=lun)",      default: 1,       min: 0,   max: 6,     step: 1    },
  { key: "inter_arrival_time", label: "Inter-arrivee (s)",         default: 0.5,     min: 0,   max: 1e6,   step: 0.001 },
  { key: "pkt_ratio",          label: "Ratio Paquets",             default: 1.67,    min: 0,   max: 1e4,   step: 0.001 },
  { key: "avg_orig_pkt_size",  label: "Taille Moy. Pkt Source",    default: 100,     min: 0,   max: 1e6,   step: 0.1  },
  { key: "avg_resp_pkt_size",  label: "Taille Moy. Pkt Dest.",     default: 62.5,    min: 0,   max: 1e6,   step: 0.1  },
];

// Mapping flexible des colonnes Excel → clés internes
const COL_ALIASES = {
  "id.orig_p": "id_orig_p", "id_orig_p": "id_orig_p", "orig_port": "id_orig_p", "sport": "id_orig_p",
  "id.resp_p": "id_resp_p", "id_resp_p": "id_resp_p", "resp_port": "id_resp_p", "dport": "id_resp_p", "dst_port": "id_resp_p",
  "duration": "duration", "orig_bytes": "orig_bytes", "resp_bytes": "resp_bytes",
  "missed_bytes": "missed_bytes", "orig_pkts": "orig_pkts", "orig_ip_bytes": "orig_ip_bytes",
  "resp_pkts": "resp_pkts", "resp_ip_bytes": "resp_ip_bytes", "is_orig_local": "is_orig_local",
  "orig_h_count": "orig_h_count", "resp_h_count": "resp_h_count",
  "is_well_known_port": "is_well_known_port", "hour": "hour", "minute": "minute",
  "day_of_week": "day_of_week", "inter_arrival_time": "inter_arrival_time",
  "pkt_ratio": "pkt_ratio", "avg_orig_pkt_size": "avg_orig_pkt_size",
  "avg_resp_pkt_size": "avg_resp_pkt_size",
};

const REQUIRED_KEYS = FEATURE_FIELDS.map(f => f.key);

// ─── Scénarios prédéfinis ────────────────────────────────────
const SCENARIOS = [
  { id: "mirai_telnet",  label: "Mirai Telnet Scan",    icon: "[SCAN]", color: "#ef4444", desc: "Scan port 23 — signature Mirai IoT",         model: "random_forest",
    payload: { id_orig_p:51524, id_resp_p:23, duration:0.0102, orig_bytes:0, resp_bytes:0, missed_bytes:0, orig_pkts:0.05, orig_ip_bytes:0.0602, resp_pkts:0, resp_ip_bytes:0, is_orig_local:1, orig_h_count:991061, resp_h_count:3, is_well_known_port:1, hour:15, minute:30, day_of_week:2, inter_arrival_time:2.93e-9, pkt_ratio:0.1765, avg_orig_pkt_size:45, avg_resp_pkt_size:0 } },
  { id: "mirai_rapide",  label: "Mirai Scan Rapide",    icon: "[FAST]", color: "#f97316", desc: "Variante rapide du scan Mirai",               model: "xgboost",
    payload: { id_orig_p:56305, id_resp_p:23, duration:0, orig_bytes:0, resp_bytes:0, missed_bytes:0, orig_pkts:0.0167, orig_ip_bytes:0.0201, resp_pkts:0, resp_ip_bytes:0, is_orig_local:1, orig_h_count:991061, resp_h_count:2, is_well_known_port:1, hour:15, minute:30, day_of_week:2, inter_arrival_time:3.67e-8, pkt_ratio:0.0588, avg_orig_pkt_size:30, avg_resp_pkt_size:0 } },
  { id: "mirai_port23",  label: "Mirai Port 23 Massif", icon: "[DDOS]", color: "#dc2626", desc: "Scan massif botnet IoT port 23",              model: "knn",
    payload: { id_orig_p:60905, id_resp_p:23, duration:0.0102, orig_bytes:0, resp_bytes:0, missed_bytes:0, orig_pkts:0.05, orig_ip_bytes:0.0602, resp_pkts:0, resp_ip_bytes:0, is_orig_local:1, orig_h_count:991061, resp_h_count:3, is_well_known_port:1, hour:3, minute:0, day_of_week:6, inter_arrival_time:2.97e-9, pkt_ratio:0.1765, avg_orig_pkt_size:45, avg_resp_pkt_size:0 } },
  { id: "brute_ssh",     label: "Brute Force SSH",      icon: "[BRF]",  color: "#8b5cf6", desc: "Attaque SSH par dictionnaire port 22",        model: "decision_tree",
    payload: { id_orig_p:45678, id_resp_p:22, duration:0.5, orig_bytes:200, resp_bytes:50, missed_bytes:0, orig_pkts:10, orig_ip_bytes:300, resp_pkts:5, resp_ip_bytes:100, is_orig_local:0, orig_h_count:1000, resp_h_count:1, is_well_known_port:1, hour:2, minute:30, day_of_week:5, inter_arrival_time:0.05, pkt_ratio:2.0, avg_orig_pkt_size:27.3, avg_resp_pkt_size:16.7 } },
  { id: "botnet_c2",     label: "Botnet C2 IRC",        icon: "[BOT]",  color: "#06b6d4", desc: "Communication Command & Control IRC",         model: "random_forest",
    payload: { id_orig_p:22222, id_resp_p:6667, duration:300, orig_bytes:500, resp_bytes:500, missed_bytes:0, orig_pkts:50, orig_ip_bytes:600, resp_pkts:50, resp_ip_bytes:600, is_orig_local:1, orig_h_count:3, resp_h_count:1, is_well_known_port:0, hour:3, minute:30, day_of_week:6, inter_arrival_time:6.0, pkt_ratio:1.0, avg_orig_pkt_size:11.8, avg_resp_pkt_size:11.8 } },
  { id: "exfil",         label: "Exfiltration Donnees", icon: "[EXF]",  color: "#f59e0b", desc: "Fuite de donnees via HTTPS port 443",         model: "xgboost",
    payload: { id_orig_p:11111, id_resp_p:443, duration:120, orig_bytes:50000, resp_bytes:100, missed_bytes:500, orig_pkts:500, orig_ip_bytes:51000, resp_pkts:10, resp_ip_bytes:200, is_orig_local:1, orig_h_count:2, resp_h_count:1, is_well_known_port:1, hour:4, minute:0, day_of_week:6, inter_arrival_time:0.24, pkt_ratio:50.0, avg_orig_pkt_size:101.6, avg_resp_pkt_size:18.2 } },
  { id: "normal_http",   label: "Trafic HTTP Normal",   icon: "[OK]",   color: "#22c55e", desc: "Connexion HTTP legitime port 80",             model: "random_forest",
    payload: { id_orig_p:12345, id_resp_p:80, duration:1.5, orig_bytes:500, resp_bytes:200, missed_bytes:0, orig_pkts:5, orig_ip_bytes:600, resp_pkts:3, resp_ip_bytes:250, is_orig_local:1, orig_h_count:10, resp_h_count:5, is_well_known_port:1, hour:14, minute:30, day_of_week:1, inter_arrival_time:0.5, pkt_ratio:1.67, avg_orig_pkt_size:100, avg_resp_pkt_size:62.5 } },
  { id: "normal_dns",    label: "Trafic DNS Normal",    icon: "[DNS]",  color: "#10b981", desc: "Requete DNS normale port 53",                 model: "knn",
    payload: { id_orig_p:54321, id_resp_p:53, duration:0.1, orig_bytes:100, resp_bytes:150, missed_bytes:0, orig_pkts:2, orig_ip_bytes:120, resp_pkts:2, resp_ip_bytes:170, is_orig_local:1, orig_h_count:5, resp_h_count:2, is_well_known_port:1, hour:10, minute:15, day_of_week:2, inter_arrival_time:0.05, pkt_ratio:1.0, avg_orig_pkt_size:40, avg_resp_pkt_size:56.7 } },
];

// ─── Composants utilitaires ──────────────────────────────────
function SectionTitle({ number, title, color = C.blue }) {
  return (
    <div style={{ display:"flex", alignItems:"center", gap:10, marginBottom:16 }}>
      <span style={{ background:color+"25", color, borderRadius:"50%", width:26, height:26, display:"inline-flex", alignItems:"center", justifyContent:"center", fontSize:"0.75rem", fontWeight:800, flexShrink:0 }}>{number}</span>
      <h3 style={{ margin:0, fontSize:"0.95rem", fontWeight:700, color:C.text, fontFamily:"JetBrains Mono, monospace" }}>{title}</h3>
    </div>
  );
}

function ResultBadge({ result }) {
  if (!result) return null;
  const isM  = result.label === "Malicious";
  const col  = isM ? C.red : C.green;
  const rc   = RISK_COLOR[result.risk_level] || C.text2;
  return (
    <div style={{ background:isM?"rgba(239,68,68,0.07)":"rgba(34,197,94,0.07)", border:`2px solid ${col}`, borderRadius:12, padding:"16px 20px", marginTop:12 }}>
      <div style={{ display:"flex", justifyContent:"space-between", alignItems:"center", marginBottom:10 }}>
        <span style={{ fontWeight:800, fontSize:"1.1rem", color:col, fontFamily:"JetBrains Mono, monospace" }}>{isM ? "MALICIOUS" : "BENIGN"}</span>
        <span style={{ fontWeight:800, fontSize:"1.4rem", color:col }}>{result.confidence}%</span>
      </div>
      <div style={{ background:C.card2, borderRadius:4, height:6, overflow:"hidden", marginBottom:12 }}>
        <div style={{ width:`${result.confidence}%`, height:"100%", background:`linear-gradient(90deg,${col}80,${col})`, borderRadius:4, transition:"width 1s ease" }} />
      </div>
      <div style={{ display:"flex", gap:8, flexWrap:"wrap" }}>
        <span style={{ fontSize:"0.72rem", padding:"3px 10px", borderRadius:999, background:rc+"20", color:rc, fontWeight:700 }}>
          Risque : {result.risk_level}
        </span>
        <span style={{ fontSize:"0.72rem", padding:"3px 10px", borderRadius:999, background:C.blue+"20", color:C.blue, fontWeight:600 }}>
          Modele : {result.model_used}
        </span>
      </div>
    </div>
  );
}

// ═══════════════════════════════════════════════════════════════
// SECTION 1 — Scénarios prédéfinis
// ═══════════════════════════════════════════════════════════════
function ScenarioSection({ onResult }) {
  const [results,  setResults]  = useState({});
  const [loading,  setLoading]  = useState({});
  const [selModel, setSelModel] = useState(null); // null = modele du scenario

  const runOne = async (sc) => {
    setLoading(p => ({ ...p, [sc.id]: true }));
    setResults(p => ({ ...p, [sc.id]: null }));
    const payload = { ...sc.payload, model: selModel || sc.model };
    try {
      const { data } = await apiService.predict(payload);
      setResults(p => ({ ...p, [sc.id]: data }));
      onResult?.();
    } catch (e) {
      setResults(p => ({ ...p, [sc.id]: { error: e.response?.data?.detail || e.message } }));
    }
    setLoading(p => ({ ...p, [sc.id]: false }));
  };

  const runAll = async () => {
    for (const sc of SCENARIOS) {
      await runOne(sc);
      await new Promise(r => setTimeout(r, 250));
    }
  };

  return (
    <div className="card">
      <div style={{ display:"flex", justifyContent:"space-between", alignItems:"flex-start", marginBottom:16, flexWrap:"wrap", gap:10 }}>
        <SectionTitle number="1" title="Scenarios Predéfinis CTU-IoT" color={C.red} />
        <div style={{ display:"flex", gap:8, alignItems:"center", flexWrap:"wrap" }}>
          <select
            value={selModel || ""}
            onChange={e => setSelModel(e.target.value || null)}
            style={{ background:C.card2, border:`1px solid ${C.border2}`, borderRadius:8, padding:"6px 10px", color:C.text2, fontSize:"0.75rem", cursor:"pointer" }}
          >
            <option value="">Modele du scenario</option>
            {MODELS_INFO.map(m => <option key={m.key} value={m.key}>{m.name}</option>)}
          </select>
          <button
            onClick={runAll}
            style={{ background:`linear-gradient(135deg,${C.red},${C.orange})`, border:"none", borderRadius:8, padding:"7px 16px", color:"#fff", fontSize:"0.78rem", fontWeight:700, cursor:"pointer" }}
          >
            Tout tester
          </button>
        </div>
      </div>

      <div style={{ marginBottom:14, padding:"7px 12px", background:C.card2, borderRadius:8, fontSize:"0.72rem", color:C.text2, borderLeft:`3px solid ${C.blue}` }}>
        Scenarios bases sur de vraies signatures du dataset CTU-IoT-Malware-Capture (Stratosphere Lab)
      </div>

      <div style={{ display:"grid", gridTemplateColumns:"repeat(auto-fill, minmax(280px, 1fr))", gap:12 }}>
        {SCENARIOS.map(sc => {
          const res  = results[sc.id];
          const busy = loading[sc.id];
          const isM  = res?.label === "Malicious";
          const borderCol = res ? (res.error ? C.orange : isM ? C.red : C.green) : C.border2;
          return (
            <div key={sc.id} style={{ background:C.card2, border:`2px solid ${borderCol}`, borderRadius:12, padding:"14px 16px", transition:"border-color 0.3s" }}>
              <div style={{ display:"flex", alignItems:"center", gap:10, marginBottom:10 }}>
                <span style={{ fontWeight:700, fontSize:"0.78rem", color:sc.color, background:sc.color+"20", padding:"2px 7px", borderRadius:4, fontFamily:"monospace", flexShrink:0 }}>{sc.icon}</span>
                <div style={{ minWidth:0 }}>
                  <div style={{ fontWeight:700, fontSize:"0.82rem", color:sc.color, fontFamily:"JetBrains Mono, monospace", overflow:"hidden", textOverflow:"ellipsis", whiteSpace:"nowrap" }}>{sc.label}</div>
                  <div style={{ fontSize:"0.68rem", color:C.text2 }}>{sc.desc}</div>
                  <div style={{ fontSize:"0.63rem", color:C.text3, marginTop:2 }}>
                    Modele : <strong style={{ color:C.text2 }}>{selModel || sc.model}</strong>
                  </div>
                </div>
              </div>

              {res && !res.error && (
                <div style={{ background:isM?"rgba(239,68,68,0.08)":"rgba(34,197,94,0.08)", borderRadius:8, padding:"7px 10px", marginBottom:10, display:"flex", justifyContent:"space-between" }}>
                  <span style={{ fontWeight:700, fontSize:"0.8rem", color:isM ? C.red : C.green }}>{res.label}</span>
                  <span style={{ fontSize:"0.75rem", color:C.text2 }}>{res.confidence}%</span>
                </div>
              )}
              {res?.error && (
                <div style={{ color:C.orange, fontSize:"0.7rem", marginBottom:10, wordBreak:"break-word" }}>
                  {res.error}
                </div>
              )}

              <button
                onClick={() => runOne(sc)}
                disabled={busy}
                style={{ width:"100%", background:"transparent", border:`1px solid ${sc.color}`, borderRadius:8, padding:"7px 0", color:sc.color, fontSize:"0.78rem", fontWeight:700, cursor:busy?"not-allowed":"pointer", opacity:busy?0.6:1 }}
              >
                {busy ? "Analyse..." : "Tester"}
              </button>
            </div>
          );
        })}
      </div>
    </div>
  );
}

// ═══════════════════════════════════════════════════════════════
// SECTION 2 — Upload Excel
// ═══════════════════════════════════════════════════════════════
function parseCSV(text) {
  const lines = text.trim().split(/\r?\n/);
  if (lines.length < 2) throw new Error("Fichier CSV vide ou invalide");
  const headers = lines[0].split(",").map(h => h.trim().replace(/^"|"$/g, ""));
  return lines.slice(1).map(line => {
    const vals = line.split(",").map(v => v.trim().replace(/^"|"$/g, ""));
    const row = {};
    headers.forEach((h, i) => { row[h] = vals[i] ?? ""; });
    return row;
  }).filter(row => Object.values(row).some(v => v !== ""));
}

function normalizeRow(rawRow) {
  const row = {};
  for (const [k, v] of Object.entries(rawRow)) {
    const clean = k.trim().toLowerCase().replace(/\s+/g, "_");
    const mapped = COL_ALIASES[clean] || COL_ALIASES[k.trim()] || null;
    if (mapped) row[mapped] = parseFloat(v) || 0;
  }
  const missing = REQUIRED_KEYS.filter(k => !(k in row));
  if (missing.length > 0) throw new Error(`Colonnes manquantes : ${missing.slice(0,3).join(", ")}${missing.length > 3 ? "..." : ""}`);
  return row;
}

function ExcelSection({ onResult }) {
  const fileRef  = useRef(null);
  const [file,      setFile]      = useState(null);
  const [rows,      setRows]      = useState([]);
  const [parseErr,  setParseErr]  = useState(null);
  const [model,     setModel]     = useState("random_forest");
  const [running,   setRunning]   = useState(false);
  const [results,   setResults]   = useState([]);
  const [progress,  setProgress]  = useState(0);

  const handleFile = (f) => {
    setFile(f); setRows([]); setParseErr(null); setResults([]); setProgress(0);
    if (!f) return;

    const reader = new FileReader();
    reader.onload = (e) => {
      try {
        const text = e.target.result;
        const parsed = parseCSV(text);
        if (parsed.length === 0) throw new Error("Aucune ligne valide trouvée");
        // Valider la première ligne
        normalizeRow(parsed[0]);
        setRows(parsed);
      } catch (err) {
        setParseErr(err.message);
      }
    };
    // Lire comme texte (CSV uniquement côté frontend sans dépendance xlsx)
    reader.readAsText(f);
  };

  const runAnalysis = async () => {
    if (!rows.length) return;
    setRunning(true); setResults([]); setProgress(0);
    const out = [];
    for (let i = 0; i < rows.length; i++) {
      try {
        const normalized = normalizeRow(rows[i]);
        const payload = { ...normalized, model };
        const { data } = await apiService.predict(payload);
        out.push({ index: i + 1, ...data, error: null });
      } catch (e) {
        out.push({ index: i + 1, error: e.response?.data?.detail || e.message });
      }
      setProgress(Math.round(((i + 1) / rows.length) * 100));
      setResults([...out]);
    }
    setRunning(false);
    onResult?.();
  };

  const mal   = results.filter(r => r.label === "Malicious").length;
  const ben   = results.filter(r => r.label === "Benign").length;
  const errs  = results.filter(r => r.error).length;

  return (
    <div className="card">
      <SectionTitle number="2" title="Upload Fichier CSV — Analyse en Masse" color={C.cyan} />

      {/* Zone de drop */}
      <div
        onClick={() => fileRef.current?.click()}
        onDragOver={e => e.preventDefault()}
        onDrop={e => { e.preventDefault(); handleFile(e.dataTransfer.files[0]); }}
        style={{ border:`2px dashed ${file ? C.cyan : C.border2}`, borderRadius:12, padding:"28px 20px", textAlign:"center", cursor:"pointer", background:file ? C.cyan+"08" : C.card2, transition:"all 0.2s", marginBottom:16 }}
      >
        <input ref={fileRef} type="file" accept=".csv" style={{ display:"none" }} onChange={e => handleFile(e.target.files[0])} />
        <div style={{ fontSize:"2rem", marginBottom:8 }}>📂</div>
        {file ? (
          <>
            <div style={{ fontWeight:700, color:C.cyan, fontSize:"0.9rem" }}>{file.name}</div>
            <div style={{ fontSize:"0.72rem", color:C.text2, marginTop:4 }}>
              {rows.length > 0 ? `${rows.length} ligne(s) detectee(s) — pret pour l analyse` : "Lecture en cours..."}
            </div>
          </>
        ) : (
          <>
            <div style={{ color:C.text2, fontSize:"0.85rem", fontWeight:600 }}>Glissez votre fichier CSV ici</div>
            <div style={{ color:C.text3, fontSize:"0.72rem", marginTop:4 }}>ou cliquez pour parcourir — Format : .csv</div>
          </>
        )}
      </div>

      {parseErr && (
        <div style={{ background:"rgba(239,68,68,0.08)", border:`1px solid ${C.red}40`, borderRadius:8, padding:"10px 14px", color:C.red, fontSize:"0.78rem", marginBottom:12 }}>
          Erreur de lecture : {parseErr}
        </div>
      )}

      <div style={{ marginBottom:12, padding:"8px 12px", background:C.card2, borderRadius:8, fontSize:"0.72rem", color:C.text2, borderLeft:`3px solid ${C.cyan}` }}>
        Format attendu : colonnes CSV avec les features reseau. La normalisation est automatique.
        Les colonnes acceptees incluent : id_orig_p, id_resp_p, duration, orig_bytes, resp_bytes, orig_pkts, resp_pkts, etc.
      </div>

      {rows.length > 0 && (
        <div style={{ display:"flex", gap:10, alignItems:"center", marginBottom:16, flexWrap:"wrap" }}>
          <select
            value={model}
            onChange={e => setModel(e.target.value)}
            style={{ background:C.card2, border:`1px solid ${C.border2}`, borderRadius:8, padding:"8px 12px", color:C.text, fontSize:"0.8rem", cursor:"pointer" }}
          >
            {MODELS_INFO.map(m => <option key={m.key} value={m.key}>{m.name} ({m.acc}%)</option>)}
          </select>
          <button
            onClick={runAnalysis}
            disabled={running}
            style={{ background:running?"#374151":`linear-gradient(135deg,${C.cyan},${C.blue})`, border:"none", borderRadius:8, padding:"8px 20px", color:running?"#6b7280":"#fff", fontWeight:700, fontSize:"0.82rem", cursor:running?"not-allowed":"pointer" }}
          >
            {running ? `Analyse... ${progress}%` : `Analyser ${rows.length} connexion(s)`}
          </button>
          {file && <button onClick={() => { setFile(null); setRows([]); setResults([]); setParseErr(null); }} style={{ background:"transparent", border:`1px solid ${C.border2}`, borderRadius:8, padding:"8px 12px", color:C.text2, fontSize:"0.78rem", cursor:"pointer" }}>Effacer</button>}
        </div>
      )}

      {/* Barre de progression */}
      {running && (
        <div style={{ background:C.card2, borderRadius:4, height:6, overflow:"hidden", marginBottom:12 }}>
          <div style={{ width:`${progress}%`, height:"100%", background:`linear-gradient(90deg,${C.cyan},${C.blue})`, transition:"width 0.3s" }} />
        </div>
      )}

      {/* Résumé */}
      {results.length > 0 && !running && (
        <div style={{ display:"grid", gridTemplateColumns:"repeat(4,1fr)", gap:10, marginBottom:16 }}>
          {[
            { label:"Total",        value:results.length, color:C.blue  },
            { label:"Malveillants", value:mal,            color:C.red   },
            { label:"Benins",       value:ben,            color:C.green },
            { label:"Erreurs",      value:errs,           color:C.orange },
          ].map(({ label, value, color }) => (
            <div key={label} style={{ background:color+"15", border:`1px solid ${color}30`, borderRadius:10, padding:"10px 12px", textAlign:"center" }}>
              <div style={{ fontSize:"1.4rem", fontWeight:800, color }}>{value}</div>
              <div style={{ fontSize:"0.68rem", color:C.text2 }}>{label}</div>
            </div>
          ))}
        </div>
      )}

      {/* Tableau résultats */}
      {results.length > 0 && (
        <div style={{ overflowX:"auto" }}>
          <table style={{ width:"100%", borderCollapse:"collapse", fontSize:"0.75rem" }}>
            <thead>
              <tr style={{ background:C.card2 }}>
                {["#","Statut","Confiance","Risque","Modele"].map(h => (
                  <th key={h} style={{ padding:"8px 10px", textAlign:"left", color:C.text2, fontWeight:600, borderBottom:`1px solid ${C.border}` }}>{h}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {results.slice(0, 100).map((r, i) => {
                const isM = r.label === "Malicious";
                const col = r.error ? C.orange : isM ? C.red : C.green;
                return (
                  <tr key={i} style={{ borderBottom:`1px solid ${C.border}`, background:i%2===0?"transparent":C.card2+"80" }}>
                    <td style={{ padding:"6px 10px", color:C.text3, fontFamily:"monospace" }}>{r.index}</td>
                    <td style={{ padding:"6px 10px" }}>
                      {r.error
                        ? <span style={{ color:C.orange, fontSize:"0.68rem" }}>Erreur</span>
                        : <span style={{ color:col, fontWeight:700 }}>{r.label}</span>
                      }
                    </td>
                    <td style={{ padding:"6px 10px", color:col, fontWeight:600 }}>{r.error ? "—" : `${r.confidence}%`}</td>
                    <td style={{ padding:"6px 10px" }}>
                      {r.risk_level && <span style={{ color:RISK_COLOR[r.risk_level]||C.text2, fontSize:"0.7rem", fontWeight:700 }}>{r.risk_level}</span>}
                    </td>
                    <td style={{ padding:"6px 10px", color:C.text3, fontSize:"0.7rem" }}>{r.model_used || "—"}</td>
                  </tr>
                );
              })}
            </tbody>
          </table>
          {results.length > 100 && (
            <div style={{ textAlign:"center", padding:"8px", color:C.text3, fontSize:"0.72rem" }}>
              Affichage limité à 100 lignes sur {results.length}
            </div>
          )}
        </div>
      )}
    </div>
  );
}

// ═══════════════════════════════════════════════════════════════
// SECTION 3 — Saisie manuelle
// ═══════════════════════════════════════════════════════════════
function ManualSection({ onResult }) {
  const initVals = () => Object.fromEntries(FEATURE_FIELDS.map(f => [f.key, f.default]));
  const [vals,    setVals]    = useState(initVals());
  const [model,   setModel]   = useState("random_forest");
  const [loading, setLoading] = useState(false);
  const [result,  setResult]  = useState(null);
  const [error,   setError]   = useState(null);

  const set = (key, val) => setVals(p => ({ ...p, [key]: parseFloat(val) || 0 }));

  const run = async () => {
    setLoading(true); setResult(null); setError(null);
    try {
      const { data } = await apiService.predict({ ...vals, model });
      setResult(data); onResult?.();
    } catch (e) {
      setError(e.response?.data?.detail || e.message);
    }
    setLoading(false);
  };

  const presets = [
    { label:"HTTP Normal",  color:C.green,  vals:{ id_orig_p:12345, id_resp_p:80,  duration:1.5,  orig_bytes:500,   resp_bytes:200,  missed_bytes:0, orig_pkts:5,   orig_ip_bytes:600,   resp_pkts:3,  resp_ip_bytes:250,  is_orig_local:1, orig_h_count:10,     resp_h_count:5,  is_well_known_port:1, hour:14, minute:30, day_of_week:1, inter_arrival_time:0.5,     pkt_ratio:1.67,  avg_orig_pkt_size:100,  avg_resp_pkt_size:62.5 } },
    { label:"Mirai Scan",   color:C.red,    vals:{ id_orig_p:51524, id_resp_p:23,  duration:0.01, orig_bytes:0,     resp_bytes:0,    missed_bytes:0, orig_pkts:0.05,orig_ip_bytes:0.06,  resp_pkts:0,  resp_ip_bytes:0,    is_orig_local:1, orig_h_count:991061, resp_h_count:3,  is_well_known_port:1, hour:3,  minute:0,  day_of_week:6, inter_arrival_time:2.93e-9, pkt_ratio:0.1765,avg_orig_pkt_size:45,   avg_resp_pkt_size:0    } },
    { label:"Exfiltration", color:C.orange, vals:{ id_orig_p:11111, id_resp_p:443, duration:120,  orig_bytes:50000, resp_bytes:100,  missed_bytes:500,orig_pkts:500, orig_ip_bytes:51000, resp_pkts:10, resp_ip_bytes:200,  is_orig_local:1, orig_h_count:2,      resp_h_count:1,  is_well_known_port:1, hour:4,  minute:0,  day_of_week:6, inter_arrival_time:0.24,    pkt_ratio:50,    avg_orig_pkt_size:101.6,avg_resp_pkt_size:18.2 } },
  ];

  return (
    <div className="card">
      <SectionTitle number="3" title="Saisie Manuelle des Features" color={C.purple} />

      {/* Presets rapides */}
      <div style={{ display:"flex", gap:8, marginBottom:16, flexWrap:"wrap" }}>
        <span style={{ fontSize:"0.72rem", color:C.text3, alignSelf:"center" }}>Preset rapide :</span>
        {presets.map(p => (
          <button key={p.label} onClick={() => { setVals(p.vals); setResult(null); }}
            style={{ background:p.color+"20", border:`1px solid ${p.color}40`, borderRadius:6, padding:"4px 12px", color:p.color, fontSize:"0.72rem", fontWeight:700, cursor:"pointer" }}>
            {p.label}
          </button>
        ))}
        <button onClick={() => { setVals(initVals()); setResult(null); }}
          style={{ background:"transparent", border:`1px solid ${C.border2}`, borderRadius:6, padding:"4px 12px", color:C.text3, fontSize:"0.72rem", cursor:"pointer", marginLeft:"auto" }}>
          Reset
        </button>
      </div>

      {/* Sélecteur modèle */}
      <div style={{ marginBottom:16 }}>
        <label style={{ fontSize:"0.75rem", color:C.text2, display:"block", marginBottom:6, fontWeight:600 }}>Modele ML</label>
        <div style={{ display:"flex", gap:8, flexWrap:"wrap" }}>
          {MODELS_INFO.map(m => (
            <button key={m.key} onClick={() => setModel(m.key)}
              style={{ background:model===m.key ? m.color+"25" : C.card2, border:`2px solid ${model===m.key ? m.color : C.border2}`, borderRadius:8, padding:"6px 14px", color:model===m.key ? m.color : C.text2, fontSize:"0.75rem", fontWeight:700, cursor:"pointer", transition:"all 0.15s" }}>
              {m.name}
            </button>
          ))}
        </div>
      </div>

      {/* Grille des features */}
      <div style={{ display:"grid", gridTemplateColumns:"repeat(auto-fill, minmax(200px, 1fr))", gap:10, marginBottom:20 }}>
        {FEATURE_FIELDS.map(f => (
          <div key={f.key}>
            <label style={{ fontSize:"0.68rem", color:C.text3, display:"block", marginBottom:3 }}>{f.label}</label>
            <input
              type="number"
              value={vals[f.key]}
              min={f.min} max={f.max} step={f.step}
              onChange={e => set(f.key, e.target.value)}
              style={{ width:"100%", background:C.card2, border:`1px solid ${C.border2}`, borderRadius:6, padding:"7px 10px", color:C.text, fontSize:"0.78rem", boxSizing:"border-box", outline:"none" }}
            />
          </div>
        ))}
      </div>

      <button
        onClick={run}
        disabled={loading}
        style={{ width:"100%", background:loading?"#374151":`linear-gradient(135deg,${C.purple},${C.blue})`, border:"none", borderRadius:10, padding:"13px 0", color:loading?"#6b7280":"#fff", fontWeight:700, fontSize:"0.9rem", fontFamily:"JetBrains Mono, monospace", cursor:loading?"not-allowed":"pointer", transition:"all 0.2s" }}
      >
        {loading ? "Analyse en cours..." : `Lancer l analyse — ${MODELS_INFO.find(m=>m.key===model)?.name || model}`}
      </button>

      {error && (
        <div style={{ background:"rgba(239,68,68,0.08)", border:`1px solid ${C.red}40`, borderRadius:8, padding:"10px 14px", color:C.red, fontSize:"0.8rem", marginTop:12 }}>
          Erreur : {error}
        </div>
      )}

      <ResultBadge result={result} />
    </div>
  );
}

// ═══════════════════════════════════════════════════════════════
// PAGE PRINCIPALE
// ═══════════════════════════════════════════════════════════════
const TABS = [
  { id:"scenarios", label:"Scenarios Predéfinis", icon:"🎯" },
  { id:"excel",     label:"Upload CSV",            icon:"📊" },
  { id:"manual",    label:"Saisie Manuelle",       icon:"⌨️"  },
];

export default function AnalysisPage({ onResult }) {
  const [tab, setTab] = useState("scenarios");

  return (
    <div style={{ display:"flex", flexDirection:"column", gap:20 }}>
      <div>
        <h2 style={{ fontFamily:"JetBrains Mono, monospace", fontSize:"1.1rem", marginBottom:6, color:C.text }}>
          Systeme d Analyse — ITGATE
        </h2>
        <p style={{ fontSize:"0.8rem", color:C.text2 }}>
          Scenarios CTU-IoT, upload CSV en masse, ou saisie manuelle des features.
        </p>
      </div>

      {/* Onglets */}
      <div style={{ display:"flex", gap:4, background:C.card2, padding:4, borderRadius:10, width:"fit-content" }}>
        {TABS.map(t => (
          <button key={t.id} onClick={() => setTab(t.id)}
            style={{ background:tab===t.id ? `linear-gradient(135deg,${C.blue},${C.purple})` : "transparent", border:"none", borderRadius:7, padding:"8px 18px", color:tab===t.id ? "#fff" : C.text2, fontSize:"0.8rem", fontWeight:tab===t.id ? 700 : 500, cursor:"pointer", transition:"all 0.2s", whiteSpace:"nowrap" }}>
            {t.icon} {t.label}
          </button>
        ))}
      </div>

      {tab === "scenarios" && <ScenarioSection onResult={onResult} />}
      {tab === "excel"     && <ExcelSection    onResult={onResult} />}
      {tab === "manual"    && <ManualSection   onResult={onResult} />}
    </div>
  );
}