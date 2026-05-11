import { useState } from "react";
import { apiService } from "../services/api";
import { COLORS } from "../constants/theme";

// ============================================================
// AttackSimulator.jsx — CICIDS-2017
// Payloads bases sur les VRAIES statistiques du dataset :
// Source : analyse des distributions par type d'attaque
//
// Valeurs cles du dataset CICIDS-2017 (non normalisees) :
//   DoS Hulk         : Flow Bytes/s = 1,300,000+, Packets/s = 1500+
//   DDoS             : Flow Packets/s = 43000+, IAT Max = 63
//   PortScan         : RST Flag = 1, Pkt Length = 6
//   FTP-Patator      : Dst Port = 21, Bwd PSH = 1
//   SSH-Patator      : Dst Port = 22, petits paquets reguliers
//   Botnet           : Long IAT, gros paquets, port 443/8080
//   Web Attack XSS   : port 80, paquets moyens, PSH flags
//   Benign HTTPS     : IAT Max eleve, paquets grands, confiance
// ============================================================

const SCENARIO_DEFINITIONS = [
  {
    id: "dos_hulk",
    label: "DoS Hulk",
    icon: "💥", color: "#ef4444", tag: "DOS",
    description: "HTTP flood massif - port 80",
    features: {
      // DoS Hulk : debit tres eleve, aucune reponse backward
      packet_length_std: 828.0,
      packet_length_max: 1514.0,
      rst_flag_count: 0.0,
      fwd_packet_length_max: 1514.0,
      total_length_of_fwd_packet: 65535.0,
      fwd_packet_length_mean: 892.0,
      bwd_packet_length_std: 0.0,
      packet_length_mean: 892.0,
      subflow_fwd_bytes: 65535.0,
      flow_iat_max: 98000.0,
      bwd_packet_length_mean: 0.0,
      bwd_packet_length_max: 0.0,
      packet_length_variance: 685584.0,
      dst_port: 80.0,
      bwd_segment_size_avg: 0.0,
      bwd_psh_flags: 0.0,
      flow_bytes_s: 1300000.0,
      flow_packets_s: 1500.0,
      average_packet_size: 892.0,
      fwd_segment_size_avg: 892.0,
    }
  },
  {
    id: "ddos",
    label: "DDoS Attack",
    icon: "🌊", color: "#dc2626", tag: "DDOS",
    description: "UDP flood distribue - debit massif",
    features: {
      // DDoS : tres nombreux petits paquets, IAT minimal
      packet_length_std: 0.0,
      packet_length_max: 28.0,
      rst_flag_count: 0.0,
      fwd_packet_length_max: 28.0,
      total_length_of_fwd_packet: 28.0,
      fwd_packet_length_mean: 28.0,
      bwd_packet_length_std: 0.0,
      packet_length_mean: 28.0,
      subflow_fwd_bytes: 28.0,
      flow_iat_max: 63.0,
      bwd_packet_length_mean: 0.0,
      bwd_packet_length_max: 0.0,
      packet_length_variance: 0.0,
      dst_port: 0.0,
      bwd_segment_size_avg: 0.0,
      bwd_psh_flags: 0.0,
      flow_bytes_s: 1120000.0,
      flow_packets_s: 43000.0,
      average_packet_size: 28.0,
      fwd_segment_size_avg: 28.0,
    }
  },
  {
    id: "portscan",
    label: "Port Scan",
    icon: "🔍", color: "#f97316", tag: "SCAN",
    description: "Scan de ports - RST flags",
    features: {
      // PortScan : RST=1, paquets minuscules, reponse courte
      packet_length_std: 3.19,
      packet_length_max: 6.0,
      rst_flag_count: 1.0,
      fwd_packet_length_max: 0.0,
      total_length_of_fwd_packet: 0.0,
      fwd_packet_length_mean: 0.0,
      bwd_packet_length_std: 0.0,
      packet_length_mean: 3.19,
      subflow_fwd_bytes: 0.0,
      flow_iat_max: 12000000.0,
      bwd_packet_length_mean: 6.0,
      bwd_packet_length_max: 6.0,
      packet_length_variance: 10.17,
      dst_port: 0.0,
      bwd_segment_size_avg: 6.0,
      bwd_psh_flags: 0.0,
      flow_bytes_s: 4800.0,
      flow_packets_s: 820.0,
      average_packet_size: 3.19,
      fwd_segment_size_avg: 0.0,
    }
  },
  {
    id: "ftp_patator",
    label: "FTP Brute Force",
    icon: "🔐", color: "#8b5cf6", tag: "BRF",
    description: "FTP-Patator port 21",
    features: {
      // FTP-Patator : port 21, petits paquets bidirectionnels reguliers
      packet_length_std: 19.38,
      packet_length_max: 93.0,
      rst_flag_count: 0.0,
      fwd_packet_length_max: 93.0,
      total_length_of_fwd_packet: 285.0,
      fwd_packet_length_mean: 47.5,
      bwd_packet_length_std: 15.2,
      packet_length_mean: 38.7,
      subflow_fwd_bytes: 285.0,
      flow_iat_max: 4200000.0,
      bwd_packet_length_mean: 30.1,
      bwd_packet_length_max: 58.0,
      packet_length_variance: 375.8,
      dst_port: 21.0,
      bwd_segment_size_avg: 30.1,
      bwd_psh_flags: 1.0,
      flow_bytes_s: 6250.0,
      flow_packets_s: 95.0,
      average_packet_size: 38.7,
      fwd_segment_size_avg: 47.5,
    }
  },
  {
    id: "ssh_patator",
    label: "SSH Brute Force",
    icon: "🔑", color: "#06b6d4", tag: "SSH",
    description: "SSH-Patator port 22",
    features: {
      // SSH-Patator : port 22, sessions courtes repetitives
      packet_length_std: 25.6,
      packet_length_max: 182.0,
      rst_flag_count: 0.0,
      fwd_packet_length_max: 182.0,
      total_length_of_fwd_packet: 520.0,
      fwd_packet_length_mean: 86.7,
      bwd_packet_length_std: 19.4,
      packet_length_mean: 68.3,
      subflow_fwd_bytes: 520.0,
      flow_iat_max: 3100000.0,
      bwd_packet_length_mean: 50.2,
      bwd_packet_length_max: 95.0,
      packet_length_variance: 654.4,
      dst_port: 22.0,
      bwd_segment_size_avg: 50.2,
      bwd_psh_flags: 1.0,
      flow_bytes_s: 11200.0,
      flow_packets_s: 108.0,
      average_packet_size: 68.3,
      fwd_segment_size_avg: 86.7,
    }
  },
  {
    id: "botnet",
    label: "Botnet ARES",
    icon: "🤖", color: "#f59e0b", tag: "BOT",
    description: "Communication botnet C&C",
    features: {
      // Botnet : longs intervalles, gros paquets, port 8080/443
      packet_length_std: 442.0,
      packet_length_max: 1460.0,
      rst_flag_count: 0.0,
      fwd_packet_length_max: 1460.0,
      total_length_of_fwd_packet: 14820.0,
      fwd_packet_length_mean: 742.0,
      bwd_packet_length_std: 318.0,
      packet_length_mean: 625.0,
      subflow_fwd_bytes: 14820.0,
      flow_iat_max: 120000000.0,
      bwd_packet_length_mean: 508.0,
      bwd_packet_length_max: 1200.0,
      packet_length_variance: 195364.0,
      dst_port: 8080.0,
      bwd_segment_size_avg: 508.0,
      bwd_psh_flags: 1.0,
      flow_bytes_s: 3200.0,
      flow_packets_s: 4.8,
      average_packet_size: 625.0,
      fwd_segment_size_avg: 742.0,
    }
  },
  {
    id: "web_xss",
    label: "Web Attack XSS",
    icon: "🕷️", color: "#ec4899", tag: "WEB",
    description: "Injection XSS port 80",
    features: {
      // Web Attack : port 80, paquets moyens, PSH actif
      packet_length_std: 312.0,
      packet_length_max: 1294.0,
      rst_flag_count: 0.0,
      fwd_packet_length_max: 1294.0,
      total_length_of_fwd_packet: 6540.0,
      fwd_packet_length_mean: 654.0,
      bwd_packet_length_std: 245.0,
      packet_length_mean: 520.0,
      subflow_fwd_bytes: 6540.0,
      flow_iat_max: 25000000.0,
      bwd_packet_length_mean: 386.0,
      bwd_packet_length_max: 876.0,
      packet_length_variance: 97344.0,
      dst_port: 80.0,
      bwd_segment_size_avg: 386.0,
      bwd_psh_flags: 1.0,
      flow_bytes_s: 32000.0,
      flow_packets_s: 42.0,
      average_packet_size: 520.0,
      fwd_segment_size_avg: 654.0,
    }
  },
  {
    id: "normal_https",
    label: "Trafic HTTPS Normal",
    icon: "✅", color: "#22c55e", tag: "OK",
    description: "Navigation HTTPS legitime",
    features: {
      // Benign HTTPS : longs IAT, paquets de taille normale, bidirectionnel equilibre
      packet_length_std: 215.0,
      packet_length_max: 1460.0,
      rst_flag_count: 0.0,
      fwd_packet_length_max: 1460.0,
      total_length_of_fwd_packet: 4380.0,
      fwd_packet_length_mean: 438.0,
      bwd_packet_length_std: 258.0,
      packet_length_mean: 390.0,
      subflow_fwd_bytes: 4380.0,
      flow_iat_max: 2500000000.0,
      bwd_packet_length_mean: 680.0,
      bwd_packet_length_max: 1460.0,
      packet_length_variance: 46225.0,
      dst_port: 443.0,
      bwd_segment_size_avg: 680.0,
      bwd_psh_flags: 1.0,
      flow_bytes_s: 3800.0,
      flow_packets_s: 6.2,
      average_packet_size: 390.0,
      fwd_segment_size_avg: 438.0,
    }
  },
];

const MODELS = [
  { key: "random_forest",    label: "Random Forest" },
  { key: "xgboost",          label: "XGBoost" },
  { key: "decision_tree",    label: "Decision Tree" },
  { key: "knn",              label: "KNN" },
  { key: "svm",              label: "SVM" },
  { key: "isolation_forest", label: "Isolation Forest" },
];

export default function AttackSimulator({ onResult }) {
  const [results,       setResults]       = useState({});
  const [loading,       setLoading]       = useState({});
  const [globalLoading, setGlobalLoading] = useState(false);
  const [selectedModel, setSelectedModel] = useState("random_forest");

  const runScenario = async (scenario) => {
    setLoading(prev => ({ ...prev, [scenario.id]: true }));
    setResults(prev => ({ ...prev, [scenario.id]: null }));
    try {
      const payload = { ...scenario.features, model: selectedModel };
      const { data } = await apiService.predict(payload);
      setResults(prev => ({ ...prev, [scenario.id]: data }));
      // Pass prediction result up for immediate timeline update
      onResult?.(data);
    } catch (e) {
      const msg = e.response?.data?.detail || e.message || "Erreur";
      setResults(prev => ({ ...prev, [scenario.id]: { error: msg } }));
    }
    setLoading(prev => ({ ...prev, [scenario.id]: false }));
  };

  const runAll = async () => {
    setGlobalLoading(true);
    for (const sc of SCENARIO_DEFINITIONS) {
      await runScenario(sc);
      await new Promise(r => setTimeout(r, 300));
    }
    setGlobalLoading(false);
  };

  return (
    <div className="card">
      <div style={{ display:"flex", justifyContent:"space-between",
                    alignItems:"center", marginBottom:16, flexWrap:"wrap", gap:10 }}>
        <p className="card__title" style={{ margin:0 }}>
          Scenarios Predéfinis CICIDS-2017
        </p>
        <div style={{ display:"flex", gap:10, alignItems:"center" }}>
          <select
            value={selectedModel}
            onChange={e => setSelectedModel(e.target.value)}
            style={{
              background:"#1f2937", color:"#f1f5f9",
              border:"1px solid #374151", borderRadius:6,
              padding:"6px 12px", fontSize:"0.82rem", cursor:"pointer"
            }}
          >
            {MODELS.map(m => (
              <option key={m.key} value={m.key}>{m.label}</option>
            ))}
          </select>
          <button className="btn btn--primary" onClick={runAll} disabled={globalLoading}>
            {globalLoading ? "En cours..." : "Tout tester"}
          </button>
        </div>
      </div>

      <div style={{ marginBottom:14, padding:"8px 12px", background:"#1f2937",
                    borderRadius:8, fontSize:"0.72rem", color:"#9ca3af",
                    borderLeft:"3px solid #3b82f6" }}>
        Modele actif : <strong style={{ color:"#60a5fa" }}>
          {MODELS.find(m => m.key === selectedModel)?.label}
        </strong>
        &nbsp;— 8 scenarios couvrant DoS, DDoS, Scan, BruteForce, Botnet, Web, Normal
      </div>

      <div className="simulator-grid">
        {SCENARIO_DEFINITIONS.map(scenario => {
          const res  = results[scenario.id];
          const busy = loading[scenario.id];
          const isM  = res?.label === "Malicious";

          return (
            <div key={scenario.id} className="simulator-card"
              style={{ borderColor: res
                ? (res.error ? "#f59e0b" : isM ? COLORS.malicious : COLORS.benign)
                : undefined }}>

              <div style={{ display:"flex", alignItems:"flex-start",
                            gap:8, marginBottom:10 }}>
                <span style={{ fontSize:"1.2rem", marginTop:2 }}>{scenario.icon}</span>
                <div style={{ flex:1 }}>
                  <div style={{ display:"flex", alignItems:"center", gap:6, marginBottom:3 }}>
                    <span style={{
                      fontSize:"0.6rem", fontWeight:700, padding:"2px 5px",
                      borderRadius:3, background:"rgba(255,255,255,0.07)",
                      color:scenario.color, fontFamily:"monospace"
                    }}>
                      [{scenario.tag}]
                    </span>
                  </div>
                  <div style={{ fontWeight:700, fontSize:"0.82rem",
                                color:scenario.color, fontFamily:"monospace" }}>
                    {scenario.label}
                  </div>
                  <div style={{ fontSize:"0.68rem", color:COLORS.text2, marginTop:2 }}>
                    {scenario.description}
                  </div>
                </div>
              </div>

              {res && !res.error && (
                <div style={{
                  background: isM ? "rgba(239,68,68,0.1)" : "rgba(34,197,94,0.1)",
                  borderRadius:6, padding:"7px 10px", marginBottom:10,
                  display:"flex", justifyContent:"space-between", alignItems:"center"
                }}>
                  <span style={{ fontWeight:700, fontSize:"0.82rem",
                                 color: isM ? COLORS.malicious : COLORS.benign }}>
                    {isM ? "⚠ Malicious" : "✓ Benign"}
                  </span>
                  <span style={{ fontSize:"0.75rem", color:COLORS.text2 }}>
                    {res.confidence}%
                  </span>
                </div>
              )}

              {res?.error && (
                <div style={{ color:"#f87171", fontSize:"0.7rem", marginBottom:10,
                              wordBreak:"break-word", padding:"6px 8px",
                              background:"rgba(239,68,68,0.08)", borderRadius:6 }}>
                  {res.error}
                </div>
              )}

              <button
                className="btn btn--ghost"
                style={{ width:"100%", justifyContent:"center",
                         borderColor:scenario.color, color:scenario.color,
                         fontSize:"0.78rem" }}
                onClick={() => runScenario(scenario)}
                disabled={busy || globalLoading}
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
