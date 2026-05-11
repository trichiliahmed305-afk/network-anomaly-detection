import { useState } from "react";
import { apiService } from "../services/api";
import { COLORS } from "../constants/theme";

const SCENARIO_DEFINITIONS = [
  {
    id: "dos_hulk", label: "DoS Hulk", icon: "💥",
    color: "#ef4444", tag: "DOS",
    description: "HTTP flood massif - debit 184 MB/s",
    features: {
      packet_length_std: 3284.5465, packet_length_max: 22338.0,
      rst_flag_count: 0.0, fwd_packet_length_max: 22338.0,
      total_length_of_fwd_packet: 609381.0, fwd_packet_length_mean: 4601.6092,
      bwd_packet_length_std: 0.0, packet_length_mean: 1482.7962,
      subflow_fwd_bytes: 1568.7, flow_iat_max: 5997530.5,
      bwd_packet_length_mean: 0.0, bwd_packet_length_max: 0.0,
      packet_length_variance: 12692053.613, dst_port: 80.0,
      bwd_segment_size_avg: 0.0, bwd_psh_flags: 0.0,
      flow_bytes_s: 184000000.0, flow_packets_s: 1600000.0,
      average_packet_size: 1482.7962, fwd_segment_size_avg: 4601.6092,
    }
  },
  {
    id: "ddos", label: "DDoS Attack", icon: "🌊",
    color: "#dc2626", tag: "DDOS",
    description: "UDP flood - 190 MB/s, 1.9M paquets/s",
    features: {
      packet_length_std: 0.0, packet_length_max: 28.0,
      rst_flag_count: 0.0, fwd_packet_length_max: 28.0,
      total_length_of_fwd_packet: 28.0, fwd_packet_length_mean: 28.0,
      bwd_packet_length_std: 0.0, packet_length_mean: 28.0,
      subflow_fwd_bytes: 28.0, flow_iat_max: 63.0,
      bwd_packet_length_mean: 0.0, bwd_packet_length_max: 0.0,
      packet_length_variance: 0.0, dst_port: 0.0,
      bwd_segment_size_avg: 0.0, bwd_psh_flags: 0.0,
      flow_bytes_s: 190000000.0, flow_packets_s: 1900000.0,
      average_packet_size: 28.0, fwd_segment_size_avg: 28.0,
    }
  },
  {
    id: "portscan", label: "Port Scan", icon: "🔍",
    color: "#f97316", tag: "SCAN",
    description: "RST flags eleves - reconnaissance reseau",
    features: {
      packet_length_std: 3.19, packet_length_max: 6.0,
      rst_flag_count: 86.5, fwd_packet_length_max: 0.0,
      total_length_of_fwd_packet: 0.0, fwd_packet_length_mean: 0.0,
      bwd_packet_length_std: 0.0, packet_length_mean: 3.19,
      subflow_fwd_bytes: 0.0, flow_iat_max: 113953079.5,
      bwd_packet_length_mean: 6.0, bwd_packet_length_max: 6.0,
      packet_length_variance: 10.17, dst_port: 0.0,
      bwd_segment_size_avg: 6.0, bwd_psh_flags: 0.0,
      flow_bytes_s: 4800.0, flow_packets_s: 820.0,
      average_packet_size: 3.19, fwd_segment_size_avg: 0.0,
    }
  },
  {
    id: "ftp_bruteforce", label: "FTP Brute Force", icon: "🔐",
    color: "#8b5cf6", tag: "BRF",
    description: "FTP-Patator port 21",
    features: {
      packet_length_std: 309.1338, packet_length_max: 1241.0,
      rst_flag_count: 0.0, fwd_packet_length_max: 1241.0,
      total_length_of_fwd_packet: 13541.8, fwd_packet_length_mean: 324.8195,
      bwd_packet_length_std: 268.6295, packet_length_mean: 122.1126,
      subflow_fwd_bytes: 34.86, flow_iat_max: 71970366.0,
      bwd_packet_length_mean: 193.8667, bwd_packet_length_max: 637.12,
      packet_length_variance: 895909.6668, dst_port: 21.0,
      bwd_segment_size_avg: 193.8667, bwd_psh_flags: 659.5,
      flow_bytes_s: 10000000.0, flow_packets_s: 200000.0,
      average_packet_size: 122.1126, fwd_segment_size_avg: 324.8195,
    }
  },
  {
    id: "ssh_bruteforce", label: "SSH Brute Force", icon: "🔑",
    color: "#06b6d4", tag: "SSH",
    description: "SSH-Patator port 22",
    features: {
      packet_length_std: 386.4172, packet_length_max: 1737.4,
      rst_flag_count: 0.0, fwd_packet_length_max: 1737.4,
      total_length_of_fwd_packet: 20312.7, fwd_packet_length_mean: 433.0926,
      bwd_packet_length_std: 335.7869, packet_length_mean: 157.0019,
      subflow_fwd_bytes: 52.29, flow_iat_max: 65972835.5,
      bwd_packet_length_mean: 271.4133, bwd_packet_length_max: 955.68,
      packet_length_variance: 1194546.2224, dst_port: 22.0,
      bwd_segment_size_avg: 271.4133, bwd_psh_flags: 791.4,
      flow_bytes_s: 12000000.0, flow_packets_s: 240000.0,
      average_packet_size: 157.0019, fwd_segment_size_avg: 433.0926,
    }
  },
  {
    id: "botnet", label: "Botnet ARES", icon: "🤖",
    color: "#f59e0b", tag: "BOT",
    description: "Communication C&C - port 8080",
    features: {
      packet_length_std: 2704.9206, packet_length_max: 18615.0,
      rst_flag_count: 0.0, fwd_packet_length_max: 18615.0,
      total_length_of_fwd_packet: 406254.0, fwd_packet_length_mean: 3789.5605,
      bwd_packet_length_std: 4365.2299, packet_length_mean: 1221.1263,
      subflow_fwd_bytes: 1045.8, flow_iat_max: 113953079.5,
      bwd_packet_length_mean: 2520.2667, bwd_packet_length_max: 11149.6,
      packet_length_variance: 10452279.446, dst_port: 8080.0,
      bwd_segment_size_avg: 2520.2667, bwd_psh_flags: 1978.5,
      flow_bytes_s: 4000000.0, flow_packets_s: 20000.0,
      average_packet_size: 1221.1263, fwd_segment_size_avg: 3789.5605,
    }
  },
  {
    id: "web_xss", label: "Web Attack XSS", icon: "🕷",
    color: "#ec4899", tag: "WEB",
    description: "Injection XSS port 80",
    features: {
      packet_length_std: 2125.2948, packet_length_max: 13651.0,
      rst_flag_count: 0.0, fwd_packet_length_max: 13651.0,
      total_length_of_fwd_packet: 304690.5, fwd_packet_length_mean: 2977.5118,
      bwd_packet_length_std: 3357.8692, packet_length_mean: 959.4564,
      subflow_fwd_bytes: 784.35, flow_iat_max: 47980244.0,
      bwd_packet_length_mean: 1938.6667, bwd_packet_length_max: 7964.0,
      packet_length_variance: 8212505.279, dst_port: 80.0,
      bwd_segment_size_avg: 1938.6667, bwd_psh_flags: 1648.75,
      flow_bytes_s: 30000000.0, flow_packets_s: 300000.0,
      average_packet_size: 959.4564, fwd_segment_size_avg: 2977.5118,
    }
  },
  {
    id: "normal_https", label: "Trafic HTTPS Normal", icon: "✅",
    color: "#22c55e", tag: "OK",
    description: "Navigation HTTPS legitime port 443",
    features: {
      packet_length_std: 1352.4603, packet_length_max: 9928.0,
      rst_flag_count: 0.0, fwd_packet_length_max: 9928.0,
      total_length_of_fwd_packet: 203127.0, fwd_packet_length_mean: 1894.7803,
      bwd_packet_length_std: 2551.9806, packet_length_mean: 662.8971,
      subflow_fwd_bytes: 522.9, flow_iat_max: 101958018.5,
      bwd_packet_length_mean: 1550.9333, bwd_packet_length_max: 6371.2,
      packet_length_variance: 5226139.723, dst_port: 443.0,
      bwd_segment_size_avg: 1550.9333, bwd_psh_flags: 659.5,
      flow_bytes_s: 2000000.0, flow_packets_s: 20000.0,
      average_packet_size: 662.8971, fwd_segment_size_avg: 1894.7803,
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
          Scenarios Predefinis CICIDS-2017
        </p>
        <div style={{ display:"flex", gap:10, alignItems:"center" }}>
          <select value={selectedModel} onChange={e => setSelectedModel(e.target.value)}
            style={{ background:"#1f2937", color:"#f1f5f9", border:"1px solid #374151",
                     borderRadius:6, padding:"6px 12px", fontSize:"0.82rem", cursor:"pointer" }}>
            {MODELS.map(m => <option key={m.key} value={m.key}>{m.label}</option>)}
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
              <div style={{ display:"flex", alignItems:"flex-start", gap:8, marginBottom:10 }}>
                <span style={{ fontSize:"1.2rem" }}>{scenario.icon}</span>
                <div>
                  <span style={{ fontSize:"0.6rem", fontWeight:700, padding:"2px 5px",
                                 borderRadius:3, background:"rgba(255,255,255,0.07)",
                                 color:scenario.color, fontFamily:"monospace" }}>
                    [{scenario.tag}]
                  </span>
                  <div style={{ fontWeight:700, fontSize:"0.82rem",
                                color:scenario.color, fontFamily:"monospace", marginTop:3 }}>
                    {scenario.label}
                  </div>
                  <div style={{ fontSize:"0.68rem", color:COLORS.text2, marginTop:2 }}>
                    {scenario.description}
                  </div>
                </div>
              </div>

              {res && !res.error && (
                <div style={{ background: isM ? "rgba(239,68,68,0.1)" : "rgba(34,197,94,0.1)",
                              borderRadius:6, padding:"7px 10px", marginBottom:10,
                              display:"flex", justifyContent:"space-between" }}>
                  <span style={{ fontWeight:700, fontSize:"0.82rem",
                                 color: isM ? COLORS.malicious : COLORS.benign }}>
                    {isM ? "Malicious" : "Benign"}
                  </span>
                  <span style={{ fontSize:"0.75rem", color:COLORS.text2 }}>
                    {res.confidence}%
                  </span>
                </div>
              )}

              {res?.error && (
                <div style={{ color:"#f87171", fontSize:"0.7rem", marginBottom:10,
                              padding:"6px 8px", background:"rgba(239,68,68,0.08)",
                              borderRadius:6, wordBreak:"break-word" }}>
                  {res.error}
                </div>
              )}

              <button className="btn btn--ghost"
                style={{ width:"100%", justifyContent:"center",
                         borderColor:scenario.color, color:scenario.color }}
                onClick={() => runScenario(scenario)} disabled={busy || globalLoading}>
                {busy ? "Analyse..." : "Tester"}
              </button>
            </div>
          );
        })}
      </div>
    </div>
  );
}
