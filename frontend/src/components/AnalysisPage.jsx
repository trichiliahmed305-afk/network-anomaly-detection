import { useState, useRef } from "react";
import { apiService } from "../services/api";
import AttackSimulator from "./AttackSimulator";

// ============================================================
// AnalysisPage.jsx - CICIDS-2017
// 3 onglets :
//   1. Scenarios Predéfinis  -> utilise AttackSimulator (CICIDS-2017)
//   2. Upload CSV/Excel      -> colonnes CICIDS-2017
//   3. Saisie Manuelle       -> 20 features CICIDS-2017
// ============================================================

const TABS = [
  { id: "scenarios", label: "🎯 Scenarios Prédéfinis" },
  { id: "upload",    label: "📊 Upload CSV" },
  { id: "manual",    label: "✏️ Saisie Manuelle" },
];

// 20 features CICIDS-2017 pour saisie manuelle
const CICIDS_FIELDS = [
  { key: "packet_length_std",          label: "Packet Length Std",             default: 215.0  },
  { key: "packet_length_max",          label: "Packet Length Max",             default: 1460.0 },
  { key: "rst_flag_count",             label: "RST Flag Count",                default: 0.0    },
  { key: "fwd_packet_length_max",      label: "Fwd Packet Length Max",         default: 1460.0 },
  { key: "total_length_of_fwd_packet", label: "Total Length of Fwd Packet",    default: 4380.0 },
  { key: "fwd_packet_length_mean",     label: "Fwd Packet Length Mean",        default: 438.0  },
  { key: "bwd_packet_length_std",      label: "Bwd Packet Length Std",         default: 258.0  },
  { key: "packet_length_mean",         label: "Packet Length Mean",            default: 390.0  },
  { key: "subflow_fwd_bytes",          label: "Subflow Fwd Bytes",             default: 4380.0 },
  { key: "flow_iat_max",               label: "Flow IAT Max",                  default: 2500000000.0 },
  { key: "bwd_packet_length_mean",     label: "Bwd Packet Length Mean",        default: 680.0  },
  { key: "bwd_packet_length_max",      label: "Bwd Packet Length Max",         default: 1460.0 },
  { key: "packet_length_variance",     label: "Packet Length Variance",        default: 46225.0 },
  { key: "dst_port",                   label: "Dst Port",                      default: 443.0  },
  { key: "bwd_segment_size_avg",       label: "Bwd Segment Size Avg",          default: 680.0  },
  { key: "bwd_psh_flags",              label: "Bwd PSH Flags",                 default: 1.0    },
  { key: "flow_bytes_s",               label: "Flow Bytes/s",                  default: 3800.0 },
  { key: "flow_packets_s",             label: "Flow Packets/s",                default: 6.2    },
  { key: "average_packet_size",        label: "Average Packet Size",           default: 390.0  },
  { key: "fwd_segment_size_avg",       label: "Fwd Segment Size Avg",          default: 438.0  },
];

const MODELS = [
  { key: "random_forest",    label: "Random Forest"    },
  { key: "xgboost",          label: "XGBoost"          },
  { key: "decision_tree",    label: "Decision Tree"    },
  { key: "knn",              label: "KNN"              },
  { key: "svm",              label: "SVM"              },
  { key: "isolation_forest", label: "Isolation Forest" },
];

// CSV column aliases -> CICIDS field keys
const COL_ALIASES = {
  "packet length std":             "packet_length_std",
  "packet length max":             "packet_length_max",
  "rst flag count":                "rst_flag_count",
  "fwd packet length max":         "fwd_packet_length_max",
  "total length of fwd packet":    "total_length_of_fwd_packet",
  "fwd packet length mean":        "fwd_packet_length_mean",
  "bwd packet length std":         "bwd_packet_length_std",
  "packet length mean":            "packet_length_mean",
  "subflow fwd bytes":             "subflow_fwd_bytes",
  "flow iat max":                  "flow_iat_max",
  "bwd packet length mean":        "bwd_packet_length_mean",
  "bwd packet length max":         "bwd_packet_length_max",
  "packet length variance":        "packet_length_variance",
  "dst port":                      "dst_port",
  "destination port":              "dst_port",
  "bwd segment size avg":          "bwd_segment_size_avg",
  "bwd psh flags":                 "bwd_psh_flags",
  "flow bytes/s":                  "flow_bytes_s",
  "flow packets/s":                "flow_packets_s",
  "average packet size":           "average_packet_size",
  "fwd segment size avg":          "fwd_segment_size_avg",
};

function normalizeColName(col) {
  return col.trim().toLowerCase().replace(/_/g, " ");
}

export default function AnalysisPage({ onResult }) {
  const [activeTab,    setActiveTab]    = useState("scenarios");
  const [model,        setModel]        = useState("random_forest");
  const [manualValues, setManualValues] = useState(
    Object.fromEntries(CICIDS_FIELDS.map(f => [f.key, f.default]))
  );
  const [manualResult, setManualResult] = useState(null);
  const [manualLoading,setManualLoading]= useState(false);
  const [csvResults,   setCsvResults]   = useState([]);
  const [csvLoading,   setCsvLoading]   = useState(false);
  const [csvError,     setCsvError]     = useState(null);
  const fileRef = useRef(null);

  // ── Saisie manuelle ────────────────────────────────────────
  const handleManualPredict = async () => {
    setManualLoading(true);
    setManualResult(null);
    try {
      const payload = { ...manualValues, model };
      const { data } = await apiService.predict(payload);
      setManualResult(data);
      onResult?.(data);
    } catch (e) {
      setManualResult({ error: e.response?.data?.detail || e.message });
    }
    setManualLoading(false);
  };

  // ── Upload CSV ─────────────────────────────────────────────
  const handleFileUpload = async (e) => {
    const file = e.target.files?.[0];
    if (!file) return;
    setCsvError(null);
    setCsvResults([]);
    setCsvLoading(true);

    try {
      const text = await file.text();
      const lines = text.trim().split("\n").filter(Boolean);
      if (lines.length < 2) throw new Error("Fichier vide ou sans donnees");

      // Parse header
      const sep     = lines[0].includes(";") ? ";" : ",";
      const headers = lines[0].split(sep).map(h => h.trim().replace(/"/g, ""));
      const colMap  = {};
      headers.forEach((h, i) => {
        const norm = normalizeColName(h);
        const key  = COL_ALIASES[norm];
        if (key) colMap[i] = key;
      });

      if (Object.keys(colMap).length === 0) {
        throw new Error(
          "Aucune colonne CICIDS-2017 reconnue. " +
          "Colonnes attendues : Packet Length Std, Flow Bytes/s, Dst Port, etc."
        );
      }

      // Process rows (max 100)
      const rows    = lines.slice(1, 101);
      const results = [];

      for (let i = 0; i < rows.length; i++) {
        const cells  = rows[i].split(sep).map(c => c.trim().replace(/"/g, ""));
        const payload = { model };

        // Fill with defaults first
        CICIDS_FIELDS.forEach(f => { payload[f.key] = f.default; });

        // Override with CSV values
        Object.entries(colMap).forEach(([idx, key]) => {
          const val = parseFloat(cells[idx]);
          if (!isNaN(val)) payload[key] = val;
        });

        try {
          const { data } = await apiService.predict(payload);
          results.push({ row: i + 1, ...data });
          onResult?.(data);
        } catch (err) {
          results.push({ row: i+1, error: err.response?.data?.detail || err.message });
        }

        // Update progressively every 5 rows
        if (i % 5 === 4) setCsvResults([...results]);
      }

      setCsvResults(results);
    } catch (err) {
      setCsvError(err.message);
    }
    setCsvLoading(false);
    if (fileRef.current) fileRef.current.value = "";
  };

  const malCount = csvResults.filter(r => r.label === "Malicious").length;
  const benCount = csvResults.filter(r => r.label === "Benign").length;

  // ── Styles ─────────────────────────────────────────────────
  const S = {
    tabBtn: (active) => ({
      padding: "8px 16px", borderRadius: 8, border: "none",
      cursor: "pointer", fontSize: "0.82rem", fontWeight: 600,
      background: active ? "#3b82f6" : "#1f2937",
      color: active ? "white" : "#9ca3af",
      transition: "all 0.2s",
    }),
    input: {
      background: "#1f2937", color: "#f1f5f9",
      border: "1px solid #374151", borderRadius: 6,
      padding: "6px 10px", fontSize: "0.8rem", width: "100%",
    },
    label: {
      fontSize: "0.72rem", color: "#9ca3af", marginBottom: 3, display: "block"
    },
    select: {
      background: "#1f2937", color: "#f1f5f9",
      border: "1px solid #374151", borderRadius: 6,
      padding: "8px 12px", fontSize: "0.85rem", cursor: "pointer",
    },
  };

  return (
    <div>
      {/* ── Tab navigation ──────────────────────────────── */}
      <div className="card" style={{ marginBottom: 16 }}>
        <div style={{ display: "flex", gap: 8, flexWrap: "wrap" }}>
          {TABS.map(t => (
            <button key={t.id} style={S.tabBtn(activeTab === t.id)}
              onClick={() => setActiveTab(t.id)}>
              {t.label}
            </button>
          ))}
        </div>
      </div>

      {/* ── TAB 1 : Scenarios ───────────────────────────── */}
      {activeTab === "scenarios" && (
        <AttackSimulator onResult={onResult} />
      )}

      {/* ── TAB 2 : Upload CSV ──────────────────────────── */}
      {activeTab === "upload" && (
        <div className="card">
          <p className="card__title">Import CSV / Excel — CICIDS-2017</p>
          <p style={{ fontSize: "0.8rem", color: "#9ca3af", marginBottom: 16 }}>
            Importez un fichier CSV avec les colonnes CICIDS-2017.
            Colonnes reconnues : Packet Length Std, Flow Bytes/s, Dst Port,
            RST Flag Count, Fwd Packet Length Max, etc.
            Max 100 lignes analysees.
          </p>

          <div style={{ display: "flex", gap: 12, alignItems: "center",
                        marginBottom: 16, flexWrap: "wrap" }}>
            <select value={model} onChange={e => setModel(e.target.value)}
              style={S.select}>
              {MODELS.map(m => (
                <option key={m.key} value={m.key}>{m.label}</option>
              ))}
            </select>
            <input ref={fileRef} type="file" accept=".csv,.txt"
              onChange={handleFileUpload} disabled={csvLoading}
              style={{ color: "#f1f5f9", fontSize: "0.82rem" }} />
            {csvLoading && (
              <span style={{ color: "#9ca3af", fontSize: "0.8rem" }}>
                Analyse en cours...
              </span>
            )}
          </div>

          {csvError && (
            <div style={{ color: "#f87171", background: "rgba(239,68,68,0.08)",
                          padding: "10px 14px", borderRadius: 8, marginBottom: 16,
                          fontSize: "0.82rem" }}>
              {csvError}
            </div>
          )}

          {csvResults.length > 0 && (
            <>
              <div style={{ display: "flex", gap: 16, marginBottom: 14 }}>
                <span style={{ color: "#22c55e", fontWeight: 700 }}>
                  ✓ Benign : {benCount}
                </span>
                <span style={{ color: "#ef4444", fontWeight: 700 }}>
                  ⚠ Malicious : {malCount}
                </span>
                <span style={{ color: "#9ca3af" }}>
                  Total : {csvResults.length}
                </span>
              </div>

              <div style={{ maxHeight: 400, overflowY: "auto" }}>
                <table style={{ width: "100%", borderCollapse: "collapse",
                                fontSize: "0.78rem" }}>
                  <thead>
                    <tr style={{ background: "#1f2937" }}>
                      {["#", "Label", "Confiance", "Modele"].map(h => (
                        <th key={h} style={{ padding: "8px 12px", textAlign: "left",
                                             color: "#9ca3af", fontWeight: 600,
                                             borderBottom: "1px solid #374151" }}>
                          {h}
                        </th>
                      ))}
                    </tr>
                  </thead>
                  <tbody>
                    {csvResults.map((r, i) => (
                      <tr key={i} style={{
                        background: i % 2 === 0 ? "#0f1117" : "#111827",
                        borderBottom: "1px solid #1f2937"
                      }}>
                        <td style={{ padding: "6px 12px", color: "#6b7280" }}>
                          {r.row}
                        </td>
                        <td style={{ padding: "6px 12px",
                                     color: r.error ? "#f59e0b"
                                           : r.label === "Malicious" ? "#ef4444"
                                           : "#22c55e",
                                     fontWeight: 700 }}>
                          {r.error ? "Erreur" : r.label}
                        </td>
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

      {/* ── TAB 3 : Saisie manuelle ─────────────────────── */}
      {activeTab === "manual" && (
        <div className="card">
          <p className="card__title">Saisie Manuelle — 20 Features CICIDS-2017</p>

          <div style={{ display: "flex", gap: 12, alignItems: "center",
                        marginBottom: 20 }}>
            <select value={model} onChange={e => setModel(e.target.value)}
              style={S.select}>
              {MODELS.map(m => (
                <option key={m.key} value={m.key}>{m.label}</option>
              ))}
            </select>
            <button className="btn btn--primary" onClick={handleManualPredict}
              disabled={manualLoading}>
              {manualLoading ? "Analyse..." : "Analyser"}
            </button>
          </div>

          {/* Features grid */}
          <div style={{ display: "grid",
                        gridTemplateColumns: "repeat(auto-fill, minmax(220px, 1fr))",
                        gap: 12, marginBottom: 20 }}>
            {CICIDS_FIELDS.map(field => (
              <div key={field.key}>
                <label style={S.label}>{field.label}</label>
                <input
                  type="number"
                  style={S.input}
                  value={manualValues[field.key]}
                  onChange={e => setManualValues(prev => ({
                    ...prev, [field.key]: parseFloat(e.target.value) || 0
                  }))}
                />
              </div>
            ))}
          </div>

          {/* Result */}
          {manualResult && !manualResult.error && (
            <div style={{
              padding: "16px 20px", borderRadius: 10,
              background: manualResult.label === "Malicious"
                ? "rgba(239,68,68,0.1)" : "rgba(34,197,94,0.1)",
              border: `1px solid ${manualResult.label === "Malicious"
                ? "#ef4444" : "#22c55e"}`,
              display: "flex", justifyContent: "space-between", alignItems: "center"
            }}>
              <div>
                <div style={{
                  fontWeight: 700, fontSize: "1.1rem",
                  color: manualResult.label === "Malicious" ? "#ef4444" : "#22c55e"
                }}>
                  {manualResult.label === "Malicious" ? "⚠ MALICIOUS" : "✓ BENIGN"}
                </div>
                <div style={{ fontSize: "0.78rem", color: "#9ca3af", marginTop: 4 }}>
                  Modele : {manualResult.model?.replace(/_/g, " ").toUpperCase()}
                </div>
              </div>
              <div style={{ textAlign: "right" }}>
                <div style={{ fontSize: "1.4rem", fontWeight: 700, color: "#f1f5f9" }}>
                  {manualResult.confidence}%
                </div>
                <div style={{ fontSize: "0.72rem", color: "#9ca3af" }}>Confiance</div>
              </div>
            </div>
          )}

          {manualResult?.error && (
            <div style={{ color: "#f87171", padding: "12px 16px",
                          background: "rgba(239,68,68,0.08)", borderRadius: 8,
                          fontSize: "0.82rem" }}>
              {manualResult.error}
            </div>
          )}
        </div>
      )}
    </div>
  );
}