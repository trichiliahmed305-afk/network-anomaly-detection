import { useState } from "react";
import { apiService } from "../services/api";
import { COLORS } from "../constants/theme";

// ============================================================
// Payloads bases sur les VRAIES MOYENNES du dataset CICIDS-2017
// Extraites directement depuis les donnees d'entrainement
// ============================================================

const SCENARIO_DEFINITIONS = [
  {
    id: "dos_hulk", label: "DoS Hulk", icon: "💥",
    color: "#ef4444", tag: "DOS",
    description: "HTTP flood - moyennes reelles CICIDS-2017",
    features: {
      packet_length_std: 1792.2382, packet_length_max: 5952.5964,
      rst_flag_count: 1.8201, fwd_packet_length_max: 345.7354,
      total_length_of_fwd_packet: 411.756, fwd_packet_length_mean: 51.8468,
      bwd_packet_length_std: 2424.6444, packet_length_mean: 855.3772,
      subflow_fwd_bytes: 28.3875, flow_iat_max: 685055.6314,
      bwd_packet_length_mean: 1874.9113, bwd_packet_length_max: 5952.5417,
      packet_length_variance: 3401765.7393, dst_port: 80.0,
      bwd_segment_size_avg: 1874.9113, bwd_psh_flags: 1.0091,
      flow_bytes_s: 219930.8275, flow_packets_s: 252.1405,
      average_packet_size: 855.3772, fwd_segment_size_avg: 51.8468,
    }
  },
  {
    id: "ddos", label: "DDoS Attack", icon: "🌊",
    color: "#dc2626", tag: "DDOS",
    description: "DDoS - moyennes reelles CICIDS-2017",
    features: {
      packet_length_std: 2198.9914, packet_length_max: 7239.5456,
      rst_flag_count: 1.0005, fwd_packet_length_max: 20.0,
      total_length_of_fwd_packet: 20.0004, fwd_packet_length_mean: 2.529,
      bwd_packet_length_std: 3222.5088, packet_length_mean: 881.2562,
      subflow_fwd_bytes: 1.0028, flow_iat_max: 6127882.743,
      bwd_packet_length_mean: 2224.9041, bwd_packet_length_max: 7239.5412,
      packet_length_variance: 5148709.1501, dst_port: 80.0,
      bwd_segment_size_avg: 2224.9041, bwd_psh_flags: 1.0472,
      flow_bytes_s: 3840.9888, flow_packets_s: 4.4011,
      average_packet_size: 881.2562, fwd_segment_size_avg: 2.529,
    }
  },
  {
    id: "portscan", label: "Port Scan", icon: "🔍",
    color: "#f97316", tag: "SCAN",
    description: "PortScan - moyennes reelles CICIDS-2017",
    features: {
      packet_length_std: 0.9259, packet_length_max: 2.7843,
      rst_flag_count: 0.9991, fwd_packet_length_max: 0.0588,
      total_length_of_fwd_packet: 0.0588, fwd_packet_length_mean: 0.0098,
      bwd_packet_length_std: 1.1622, packet_length_mean: 0.4842,
      subflow_fwd_bytes: 0.0053, flow_iat_max: 3145.8485,
      bwd_packet_length_mean: 1.0952, bwd_packet_length_max: 2.7727,
      packet_length_variance: 1586.4205, dst_port: 8622.4211,
      bwd_segment_size_avg: 1.0952, bwd_psh_flags: 0.0012,
      flow_bytes_s: 1012.8211, flow_packets_s: 63136.5922,
      average_packet_size: 0.4842, fwd_segment_size_avg: 0.0098,
    }
  },
  {
    id: "ftp_bruteforce", label: "FTP Brute Force", icon: "🔐",
    color: "#8b5cf6", tag: "BRF",
    description: "FTP-Patator - moyennes reelles CICIDS-2017",
    features: {
      packet_length_std: 12.3318, packet_length_max: 33.992,
      rst_flag_count: 1.9854, fwd_packet_length_max: 23.9769,
      total_length_of_fwd_packet: 119.6298, fwd_packet_length_mean: 10.8832,
      bwd_packet_length_std: 14.2215, packet_length_mean: 10.9814,
      subflow_fwd_bytes: 3.9372, flow_iat_max: 3249525.8916,
      bwd_packet_length_mean: 11.0527, bwd_packet_length_max: 33.9448,
      packet_length_variance: 152.1979, dst_port: 21.0,
      bwd_segment_size_avg: 11.0527, bwd_psh_flags: 6.9701,
      flow_bytes_s: 35.1112, flow_packets_s: 3.3843,
      average_packet_size: 10.9814, fwd_segment_size_avg: 10.8832,
    }
  },
  {
    id: "ssh_bruteforce", label: "SSH Brute Force", icon: "🔑",
    color: "#06b6d4", tag: "SSH",
    description: "SSH-Patator - moyennes reelles CICIDS-2017",
    features: {
      packet_length_std: 187.1003, packet_length_max: 967.3373,
      rst_flag_count: 0.0137, fwd_packet_length_max: 634.8099,
      total_length_of_fwd_packet: 1990.5596, fwd_packet_length_mean: 90.1068,
      bwd_packet_length_std: 216.3456, packet_length_mean: 85.8394,
      subflow_fwd_bytes: 35.6944, flow_iat_max: 2441416.5003,
      bwd_packet_length_mean: 83.1677, bwd_packet_length_max: 966.8768,
      packet_length_variance: 35387.9931, dst_port: 22.0,
      bwd_segment_size_avg: 83.1677, bwd_psh_flags: 14.8307,
      flow_bytes_s: 468.4422, flow_packets_s: 29.8471,
      average_packet_size: 85.8394, fwd_segment_size_avg: 90.1068,
    }
  },
  {
    id: "botnet", label: "Botnet ARES", icon: "🤖",
    color: "#f59e0b", tag: "BOT",
    description: "Botnet - moyennes reelles CICIDS-2017",
    features: {
      packet_length_std: 38.2641, packet_length_max: 164.7856,
      rst_flag_count: 0.8137, fwd_packet_length_max: 164.7856,
      total_length_of_fwd_packet: 1079.8553, fwd_packet_length_mean: 42.0393,
      bwd_packet_length_std: 9.285, packet_length_mean: 18.5425,
      subflow_fwd_bytes: 16.4202, flow_iat_max: 216287.1795,
      bwd_packet_length_mean: 4.5644, bwd_packet_length_max: 19.6236,
      packet_length_variance: 80254.6583, dst_port: 8080.0,
      bwd_segment_size_avg: 4.5644, bwd_psh_flags: 0.1678,
      flow_bytes_s: 10584.4855, flow_packets_s: 3000.9413,
      average_packet_size: 18.5425, fwd_segment_size_avg: 42.0393,
    }
  },
  {
    id: "web_xss", label: "Web Attack XSS", icon: "🕷",
    color: "#ec4899", tag: "WEB",
    description: "Web XSS - moyennes reelles CICIDS-2017",
    features: {
      packet_length_std: 36.3356, packet_length_max: 117.3662,
      rst_flag_count: 0.001, fwd_packet_length_max: 50.3541,
      total_length_of_fwd_packet: 1978.3546, fwd_packet_length_mean: 14.6148,
      bwd_packet_length_std: 37.1924, packet_length_mean: 27.2494,
      subflow_fwd_bytes: 8.9018, flow_iat_max: 5317729.858,
      bwd_packet_length_mean: 50.2158, bwd_packet_length_max: 113.0934,
      packet_length_variance: 20709.9549, dst_port: 80.0,
      bwd_segment_size_avg: 50.2158, bwd_psh_flags: 4.4489,
      flow_bytes_s: 203.3301, flow_packets_s: 1.5889,
      average_packet_size: 27.2494, fwd_segment_size_avg: 14.6148,
    }
  },
  {
    id: "normal_https", label: "Trafic HTTPS Normal", icon: "✅",
    color: "#22c55e", tag: "OK",
    description: "Benign HTTPS - mediane reelle CICIDS-2017",
    features: {
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
        &nbsp;— Valeurs moyennes reelles extraites du dataset CICIDS-2017
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
