import { useState, useRef } from "react";
import { apiService } from "../services/api";
import { COLORS } from "../constants/theme";

// ============================================================
// AnalysisPage.jsx - CICIDS-2017
// Architecture simplifiee :
//   - Import CSV/Excel (workflow principal)
//   - Saisie manuelle + 2 boutons demo rapide
//   - Plus de scenarios hardcodes complexes
// ============================================================

// 20 features exactes attendues par le backend CICIDS-2017
const FEATURE_NAMES = [
  "Packet Length Std", "Packet Length Max", "RST Flag Count",
  "Fwd Packet Length Max", "Total Length of Fwd Packet",
  "Fwd Packet Length Mean", "Bwd Packet Length Std", "Packet Length Mean",
  "Subflow Fwd Bytes", "Flow IAT Max", "Bwd Packet Length Mean",
  "Bwd Packet Length Max", "Packet Length Variance", "Dst Port",
  "Bwd Segment Size Avg", "Bwd PSH Flags", "Flow Bytes/s",
  "Flow Packets/s", "Average Packet Size", "Fwd Segment Size Avg"
];

// Pydantic field names (backend)
const PYDANTIC_FIELDS = [
  "packet_length_std", "packet_length_max", "rst_flag_count",
  "fwd_packet_length_max", "total_length_of_fwd_packet",
  "fwd_packet_length_mean", "bwd_packet_length_std", "packet_length_mean",
  "subflow_fwd_bytes", "flow_iat_max", "bwd_packet_length_mean",
  "bwd_packet_length_max", "packet_length_variance", "dst_port",
  "bwd_segment_size_avg", "bwd_psh_flags", "flow_bytes_s",
  "flow_packets_s", "average_packet_size", "fwd_segment_size_avg"
];

// CSV column name -> pydantic field
const COL_TO_FIELD = {};
FEATURE_NAMES.forEach((name, i) => {
  COL_TO_FIELD[name.toLowerCase()] = PYDANTIC_FIELDS[i];
  COL_TO_FIELD[name.toLowerCase().replace(/ /g, "_")] = PYDANTIC_FIELDS[i];
  COL_TO_FIELD[PYDANTIC_FIELDS[i]] = PYDANTIC_FIELDS[i];
});

// Default values (benign median)
const DEFAULTS = {
  packet_length_std: 50.8, packet_length_max: 128.0,
  rst_flag_count: 0.0, fwd_packet_length_max: 46.0,
  total_length_of_fwd_packet: 84.0, fwd_packet_length_mean: 43.0,
  bwd_packet_length_std: 0.0, packet_length_mean: 81.0,
  subflow_fwd_bytes: 22.0, flow_iat_max: 55053000.0,
  bwd_packet_length_mean: 115.3, bwd_packet_length_max: 127.0,
  packet_length_variance: 2581.3, dst_port: 443.0,
  bwd_segment_size_avg: 115.3, bwd_psh_flags: 0.0,
  flow_bytes_s: 4945.8, flow_packets_s: 63.7,
  average_packet_size: 81.0, fwd_segment_size_avg: 43.0,
};

// 2 demo rapide uniquement
const QUICK_DEMOS = [
  {
    id: "benign_http", label: "HTTP Normal", color: "#22c55e",
    values: { ...DEFAULTS, dst_port: 80.0 }
  },
  {
    id: "dos_hulk", label: "DoS Hulk", color: "#ef4444",
    values: {
      packet_length_std: 1792.24, packet_length_max: 5952.6,
      rst_flag_count: 1.82, fwd_packet_length_max: 345.74,
      total_length_of_fwd_packet: 411.76, fwd_packet_length_mean: 51.85,
      bwd_packet_length_std: 2424.64, packet_length_mean: 855.38,
      subflow_fwd_bytes: 28.39, flow_iat_max: 685055.63,
      bwd_packet_length_mean: 1874.91, bwd_packet_length_max: 5952.54,
      packet_length_variance: 3401765.74, dst_port: 80.0,
      bwd_segment_size_avg: 1874.91, bwd_psh_flags: 1.01,
      flow_bytes_s: 219930.83, flow_packets_s: 252.14,
      average_packet_size: 855.38, fwd_segment_size_avg: 51.85,
    }
  },
];

const MODELS = [
  { key: "random_forest",    label: "Random Forest"    },
  { key: "xgboost",          label: "XGBoost"          },
  { key: "decision_tree",    label: "Decision Tree"    },
  { key: "knn",              label: "KNN"              },
  { key: "svm",              label: "SVM"              },
  { key: "isolation_forest", label: "Isolation Forest" },
];

const TABS = [
  { id: "csv",    label: "Import CSV / Excel" },
  { id: "manual", label: "Saisie Manuelle"    },
];

// Generate CSV template content
function generateTemplate() {
  const header = FEATURE_NAMES.join(",");
  const row    = PYDANTIC_FIELDS.map(f => DEFAULTS[f]).join(",");
  return `${header}\n${row}\n`;
}

// Download a text file
function downloadFile(content, filename, mime = "text/csv") {
  const blob = new Blob([content], { type: mime });
  const url  = URL.createObjectURL(blob);
  const a    = document.createElement("a");
  a.href = url; a.download = filename;
  document.body.appendChild(a); a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
}

export default function AnalysisPage({ onResult }) {
  const [tab,          setTab]          = useState("csv");
  const [model,        setModel]        = useState("random_forest");
  const [manualVals,   setManualVals]   = useState({ ...DEFAULTS });
  const [manualRes,    setManualRes]    = useState(null);
  const [manualLoad,   setManualLoad]   = useState(false);
  const [csvRows,      setCsvRows]      = useState([]);
  const [csvLoading,   setCsvLoading]   = useState(false);
  const [csvError,     setCsvError]     = useState(null);
  const [csvProgress,  setCsvProgress]  = useState(0);
  const [demoLoad,     setDemoLoad]     = useState({});
  const [demoRes,      setDemoRes]      = useState({});
  const fileRef = useRef(null);

  // ── CSV Upload ─────────────────────────────────────────────
  const handleFile = async (e) => {
    const file = e.target.files?.[0];
    if (!file) return;
    setCsvError(null); setCsvRows([]); setCsvLoading(true); setCsvProgress(0);

    try {
      let rows = [];

      if (file.name.endsWith(".xlsx") || file.name.endsWith(".xls")) {
        // Excel via SheetJS
        const XLSX = await import("https://cdn.sheetjs.com/xlsx-0.20.1/package/xlsx.mjs");
        const buf  = await file.arrayBuffer();
        const wb   = XLSX.read(buf);
        const ws   = wb.Sheets[wb.SheetNames[0]];
        rows = XLSX.utils.sheet_to_json(ws, { defval: 0 });
      } else {
        // CSV
        const text   = await file.text();
        const lines  = text.trim().split("\n").filter(Boolean);
        if (lines.length < 2) throw new Error("Fichier vide ou sans donnees.");
        const sep    = lines[0].includes(";") ? ";" : ",";
        const hdr    = lines[0].split(sep).map(h => h.trim().replace(/"/g, "").toLowerCase());
        for (let i = 1; i < lines.length; i++) {
          const cells = lines[i].split(sep).map(c => c.trim().replace(/"/g, ""));
          const obj   = {};
          hdr.forEach((h, j) => { obj[h] = cells[j]; });
          rows.push(obj);
        }
      }

      if (rows.length === 0) throw new Error("Aucune ligne de donnees trouvee.");

      // Validate columns
      const firstRow   = rows[0];
      const foundKeys  = Object.keys(firstRow).map(k => k.toLowerCase().replace(/ /g, "_"));
      const missing    = PYDANTIC_FIELDS.filter(f =>
        !foundKeys.includes(f) &&
        !Object.keys(COL_TO_FIELD).find(k => COL_TO_FIELD[k] === f && foundKeys.includes(k))
      );
      if (missing.length > 10) {
        throw new Error(
          `Format invalide. ${missing.length} colonnes manquantes.\n` +
          `Utilisez le template CSV fourni (bouton "Telecharger Template").`
        );
      }

      // Process rows (max 200)
      const toProcess = rows.slice(0, 200);
      const results   = [];
      const expectedLabels = [];

      for (let i = 0; i < toProcess.length; i++) {
        const rawRow = toProcess[i];
        const payload = { model };

        // Fill defaults
        PYDANTIC_FIELDS.forEach(f => { payload[f] = DEFAULTS[f]; });

        // Map CSV columns to pydantic fields
        Object.entries(rawRow).forEach(([col, val]) => {
          const normCol = col.toLowerCase().replace(/ /g, "_");
          const field   = COL_TO_FIELD[normCol] || COL_TO_FIELD[col.toLowerCase()];
          if (field) {
            const n = parseFloat(val);
            if (!isNaN(n)) payload[field] = n;
          }
        });

        // Extract expected label if present
        const expLabel = rawRow["expected_label"] || rawRow["label"] ||
                         rawRow["Label"] || rawRow["Expected_Label"] || null;
        if (expLabel) expectedLabels.push(String(expLabel).trim());
        else          expectedLabels.push(null);

        try {
          const { data } = await apiService.predict(payload);
          const expected = expectedLabels[i];
          results.push({
            row:      i + 1,
            label:    data.label,
            expected: expected,
            correct:  expected ? data.label.toLowerCase() === expected.toLowerCase() : null,
            confidence: data.confidence,
            model:    data.model,
          });
          onResult?.(data);
        } catch (err) {
          results.push({
            row: i + 1, label: "Erreur", expected: expectedLabels[i],
            correct: null, confidence: 0, model: model,
            error: err.response?.data?.detail || err.message,
          });
        }

        setCsvProgress(Math.round((i + 1) / toProcess.length * 100));
        if (i % 10 === 9) setCsvRows([...results]);
      }

      setCsvRows(results);
    } catch (err) {
      setCsvError(err.message);
    }

    setCsvLoading(false);
    if (fileRef.current) fileRef.current.value = "";
  };

  // ── Manual predict ─────────────────────────────────────────
  const handleManual = async () => {
    setManualLoad(true); setManualRes(null);
    try {
      const { data } = await apiService.predict({ ...manualVals, model });
      setManualRes(data); onResult?.(data);
    } catch (e) {
      setManualRes({ error: e.response?.data?.detail || e.message });
    }
    setManualLoad(false);
  };

  // ── Quick demo ─────────────────────────────────────────────
  const handleDemo = async (demo) => {
    setDemoLoad(prev => ({ ...prev, [demo.id]: true }));
    setDemoRes(prev  => ({ ...prev, [demo.id]: null }));
    try {
      const { data } = await apiService.predict({ ...demo.values, model });
      setDemoRes(prev => ({ ...prev, [demo.id]: data }));
      onResult?.(data);
    } catch (e) {
      setDemoRes(prev => ({ ...prev, [demo.id]: { error: e.response?.data?.detail || e.message } }));
    }
    setDemoLoad(prev => ({ ...prev, [demo.id]: false }));
  };

  // ── CSV stats ──────────────────────────────────────────────
  const malCount  = csvRows.filter(r => r.label === "Malicious").length;
  const benCount  = csvRows.filter(r => r.label === "Benign").length;
  const corrCount = csvRows.filter(r => r.correct === true).length;
  const hasExp    = csvRows.some(r => r.expected !== null);

  const S = {
    tabBtn: (active) => ({
      padding: "8px 18px", borderRadius: 8, border: "none", cursor: "pointer",
      fontSize: "0.83rem", fontWeight: 600, transition: "all 0.2s",
      background: active ? "#3b82f6" : "#1f2937",
      color: active ? "white" : "#9ca3af",
    }),
    select: {
      background: "#1f2937", color: "#f1f5f9", border: "1px solid #374151",
      borderRadius: 6, padding: "7px 12px", fontSize: "0.83rem", cursor: "pointer",
    },
    input: {
      background: "#1f2937", color: "#f1f5f9", border: "1px solid #374151",
      borderRadius: 6, padding: "6px 10px", fontSize: "0.8rem", width: "100%",
    },
    lbl: { fontSize: "0.7rem", color: "#9ca3af", marginBottom: 3, display: "block" },
  };

  return (
    <div>
      {/* Tab bar */}
      <div className="card" style={{ marginBottom: 14 }}>
        <div style={{ display: "flex", gap: 8, flexWrap: "wrap", alignItems: "center",
                      justifyContent: "space-between" }}>
          <div style={{ display: "flex", gap: 8 }}>
            {TABS.map(t => (
              <button key={t.id} style={S.tabBtn(tab === t.id)}
                onClick={() => setTab(t.id)}>{t.label}</button>
            ))}
          </div>
          <select value={model} onChange={e => setModel(e.target.value)} style={S.select}>
            {MODELS.map(m => <option key={m.key} value={m.key}>{m.label}</option>)}
          </select>
        </div>
      </div>

      {/* ── TAB CSV ─────────────────────────────────────────── */}
      {tab === "csv" && (
        <div className="card">
          <p className="card__title">Import CSV / Excel — CICIDS-2017</p>

          {/* Info + template download */}
          <div style={{ background: "#1f2937", borderRadius: 8, padding: "12px 16px",
                        marginBottom: 16, fontSize: "0.8rem", color: "#9ca3af",
                        borderLeft: "3px solid #3b82f6" }}>
            <strong style={{ color: "#60a5fa" }}>Format requis :</strong>
            &nbsp;Colonnes exactes CICIDS-2017 dans l'ordre :<br/>
            <code style={{ fontSize: "0.72rem", color: "#a78bfa" }}>
              {FEATURE_NAMES.join(", ")}
            </code>
            <br/><br/>
            <strong style={{ color: "#60a5fa" }}>Colonne optionnelle :</strong>
            &nbsp;<code style={{ color: "#a78bfa" }}>expected_label</code>
            &nbsp;(Benign ou Malicious) pour valider les predictions.
          </div>

          {/* Actions */}
          <div style={{ display: "flex", gap: 10, alignItems: "center",
                        flexWrap: "wrap", marginBottom: 16 }}>
            <button className="btn btn--ghost"
              style={{ borderColor: "#3b82f6", color: "#3b82f6", fontSize: "0.8rem" }}
              onClick={() => downloadFile(generateTemplate(), "CICIDS2017_template.csv")}>
              Telecharger Template CSV
            </button>
            <input ref={fileRef} type="file" accept=".csv,.txt,.xlsx,.xls"
              onChange={handleFile} disabled={csvLoading}
              style={{ color: "#f1f5f9", fontSize: "0.8rem" }} />
          </div>

          {/* Progress */}
          {csvLoading && (
            <div style={{ marginBottom: 12 }}>
              <div style={{ fontSize: "0.8rem", color: "#9ca3af", marginBottom: 6 }}>
                Analyse en cours... {csvProgress}%
              </div>
              <div style={{ height: 6, background: "#1f2937", borderRadius: 3 }}>
                <div style={{ height: "100%", borderRadius: 3, background: "#3b82f6",
                              width: `${csvProgress}%`, transition: "width 0.3s" }} />
              </div>
            </div>
          )}

          {/* Error */}
          {csvError && (
            <div style={{ color: "#f87171", background: "rgba(239,68,68,0.08)",
                          padding: "10px 14px", borderRadius: 8, marginBottom: 16,
                          fontSize: "0.82rem", whiteSpace: "pre-line" }}>
              {csvError}
            </div>
          )}

          {/* Results summary */}
          {csvRows.length > 0 && (
            <>
              <div style={{ display: "flex", gap: 16, marginBottom: 14,
                            flexWrap: "wrap" }}>
                <span style={{ color: "#22c55e", fontWeight: 700 }}>
                  Benign : {benCount}
                </span>
                <span style={{ color: "#ef4444", fontWeight: 700 }}>
                  Malicious : {malCount}
                </span>
                <span style={{ color: "#9ca3af" }}>
                  Total : {csvRows.length}
                </span>
                {hasExp && (
                  <span style={{ color: "#f59e0b", fontWeight: 700 }}>
                    Correct : {corrCount}/{csvRows.filter(r => r.correct !== null).length}
                    ({Math.round(corrCount / csvRows.filter(r => r.correct !== null).length * 100)}%)
                  </span>
                )}
              </div>

              {/* Table */}
              <div style={{ maxHeight: 450, overflowY: "auto" }}>
                <table style={{ width: "100%", borderCollapse: "collapse",
                                fontSize: "0.78rem" }}>
                  <thead>
                    <tr style={{ background: "#1f2937", position: "sticky", top: 0 }}>
                      {["#", "Prediction", hasExp ? "Attendu" : null,
                        hasExp ? "OK?" : null, "Confiance", "Modele"]
                        .filter(Boolean).map(h => (
                        <th key={h} style={{ padding: "8px 12px", textAlign: "left",
                                             color: "#9ca3af", fontWeight: 600,
                                             borderBottom: "1px solid #374151" }}>
                          {h}
                        </th>
                      ))}
                    </tr>
                  </thead>
                  <tbody>
                    {csvRows.map((r, i) => (
                      <tr key={i} style={{
                        background: i % 2 === 0 ? "#0f1117" : "#111827",
                        borderBottom: "1px solid #1f2937"
                      }}>
                        <td style={{ padding: "6px 12px", color: "#6b7280" }}>{r.row}</td>
                        <td style={{ padding: "6px 12px", fontWeight: 700,
                                     color: r.error ? "#f59e0b"
                                           : r.label === "Malicious" ? "#ef4444"
                                           : "#22c55e" }}>
                          {r.error ? "Erreur" : r.label}
                        </td>
                        {hasExp && (
                          <td style={{ padding: "6px 12px", color: "#9ca3af" }}>
                            {r.expected || "-"}
                          </td>
                        )}
                        {hasExp && (
                          <td style={{ padding: "6px 12px" }}>
                            {r.correct === true  && <span style={{ color: "#22c55e" }}>✓</span>}
                            {r.correct === false && <span style={{ color: "#ef4444" }}>✗</span>}
                            {r.correct === null  && <span style={{ color: "#6b7280" }}>-</span>}
                          </td>
                        )}
                        <td style={{ padding: "6px 12px", color: "#f1f5f9" }}>
                          {r.confidence ? `${r.confidence}%` : r.error || "-"}
                        </td>
                        <td style={{ padding: "6px 12px", color: "#9ca3af" }}>
                          {r.model || "-"}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </>
          )}
        </div>
      )}

      {/* ── TAB MANUEL ──────────────────────────────────────── */}
      {tab === "manual" && (
        <div className="card">
          <p className="card__title">Saisie Manuelle — 20 Features CICIDS-2017</p>

          {/* Quick demos */}
          <div style={{ marginBottom: 20, padding: "12px 16px", background: "#1f2937",
                        borderRadius: 8, borderLeft: "3px solid #22c55e" }}>
            <div style={{ fontSize: "0.78rem", color: "#9ca3af", marginBottom: 10 }}>
              Tests rapides (charge les valeurs dans le formulaire) :
            </div>
            <div style={{ display: "flex", gap: 10, flexWrap: "wrap" }}>
              {QUICK_DEMOS.map(demo => {
                const res  = demoRes[demo.id];
                const busy = demoLoad[demo.id];
                const isM  = res?.label === "Malicious";
                return (
                  <div key={demo.id} style={{ display: "flex", alignItems: "center",
                                              gap: 8 }}>
                    <button className="btn btn--ghost"
                      style={{ borderColor: demo.color, color: demo.color,
                               fontSize: "0.8rem" }}
                      onClick={() => {
                        setManualVals({ ...demo.values });
                        handleDemo(demo);
                      }}
                      disabled={busy}>
                      {busy ? "..." : demo.label}
                    </button>
                    {res && !res.error && (
                      <span style={{ fontSize: "0.78rem", fontWeight: 700,
                                     color: isM ? "#ef4444" : "#22c55e" }}>
                        {isM ? "Malicious" : "Benign"} {res.confidence}%
                      </span>
                    )}
                  </div>
                );
              })}
            </div>
          </div>

          {/* Manual fields */}
          <div style={{ display: "grid",
                        gridTemplateColumns: "repeat(auto-fill, minmax(210px, 1fr))",
                        gap: 10, marginBottom: 20 }}>
            {PYDANTIC_FIELDS.map((field, i) => (
              <div key={field}>
                <label style={S.lbl}>{FEATURE_NAMES[i]}</label>
                <input type="number" style={S.input}
                  value={manualVals[field] ?? 0}
                  onChange={e => setManualVals(prev => ({
                    ...prev, [field]: parseFloat(e.target.value) || 0
                  }))} />
              </div>
            ))}
          </div>

          <button className="btn btn--primary" onClick={handleManual}
            disabled={manualLoad} style={{ marginBottom: 16 }}>
            {manualLoad ? "Analyse..." : "Analyser"}
          </button>

          {/* Manual result */}
          {manualRes && !manualRes.error && (
            <div style={{
              padding: "14px 18px", borderRadius: 10, marginTop: 8,
              background: manualRes.label === "Malicious"
                ? "rgba(239,68,68,0.1)" : "rgba(34,197,94,0.1)",
              border: `1px solid ${manualRes.label === "Malicious" ? "#ef4444" : "#22c55e"}`,
              display: "flex", justifyContent: "space-between", alignItems: "center"
            }}>
              <div>
                <div style={{ fontWeight: 700, fontSize: "1.1rem",
                              color: manualRes.label === "Malicious" ? "#ef4444" : "#22c55e" }}>
                  {manualRes.label === "Malicious" ? "MALICIOUS" : "BENIGN"}
                </div>
                <div style={{ fontSize: "0.75rem", color: "#9ca3af", marginTop: 4 }}>
                  Modele : {manualRes.model?.replace(/_/g, " ").toUpperCase()}
                </div>
              </div>
              <div style={{ textAlign: "right" }}>
                <div style={{ fontSize: "1.4rem", fontWeight: 700, color: "#f1f5f9" }}>
                  {manualRes.confidence}%
                </div>
                <div style={{ fontSize: "0.72rem", color: "#9ca3af" }}>Confiance</div>
              </div>
            </div>
          )}

          {manualRes?.error && (
            <div style={{ color: "#f87171", padding: "10px 14px",
                          background: "rgba(239,68,68,0.08)", borderRadius: 8,
                          fontSize: "0.82rem" }}>
              {manualRes.error}
            </div>
          )}
        </div>
      )}
    </div>
  );
}
