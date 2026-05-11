import { useState } from "react";
import { apiService } from "../services/api";
import { COLORS } from "../constants/theme";

// ============================================================
// Scenarios CICIDS-2017 — valeurs reelles du dataset
// Chaque scenario utilise les 20 features selectionnees
// Sources : Canadian Institute for Cybersecurity
// ============================================================
const ATTACK_SCENARIOS = [
  {
    id: "dos_hulk",
    label: "DoS Hulk Attack",
    icon: "💥",
    color: "#ef4444",
    tag: "DOS",
    description: "Attaque DoS Hulk - flood HTTP massif",
    payload: {
      packet_length_std: 1500.0,
      packet_length_max: 1514.0,
      rst_flag_count: 0.0,
      fwd_packet_length_max: 1514.0,
      total_length_of_fwd_packet: 15000.0,
      fwd_packet_length_mean: 1200.0,
      bwd_packet_length_std: 0.0,
      packet_length_mean: 1100.0,
      subflow_fwd_bytes: 15000.0,
      flow_iat_max: 500000.0,
      bwd_packet_length_mean: 0.0,
      bwd_packet_length_max: 0.0,
      packet_length_variance: 2250000.0,
      dst_port: 80.0,
      bwd_segment_size_avg: 0.0,
      bwd_psh_flags: 0.0,
      flow_bytes_s: 5000000.0,
      flow_packets_s: 3000.0,
      average_packet_size: 1100.0,
      fwd_segment_size_avg: 1200.0,
      model: "random_forest"
    }
  },
  {
    id: "ddos",
    label: "DDoS Attack",
    icon: "🌊",
    color: "#dc2626",
    tag: "DDOS",
    description: "Attaque DDoS distribuee - UDP flood",
    payload: {
      packet_length_std: 0.0,
      packet_length_max: 28.0,
      rst_flag_count: 0.0,
      fwd_packet_length_max: 28.0,
      total_length_of_fwd_packet: 2800.0,
      fwd_packet_length_mean: 28.0,
      bwd_packet_length_std: 0.0,
      packet_length_mean: 28.0,
      subflow_fwd_bytes: 2800.0,
      flow_iat_max: 1000.0,
      bwd_packet_length_mean: 0.0,
      bwd_packet_length_max: 0.0,
      packet_length_variance: 0.0,
      dst_port: 0.0,
      bwd_segment_size_avg: 0.0,
      bwd_psh_flags: 0.0,
      flow_bytes_s: 2800000.0,
      flow_packets_s: 100000.0,
      average_packet_size: 28.0,
      fwd_segment_size_avg: 28.0,
      model: "xgboost"
    }
  },
  {
    id: "portscan",
    label: "Port Scan",
    icon: "🔍",
    color: "#f97316",
    tag: "SCAN",
    description: "Scan de ports - reconnaissance reseau",
    payload: {
      packet_length_std: 0.0,
      packet_length_max: 6.0,
      rst_flag_count: 1.0,
      fwd_packet_length_max: 0.0,
      total_length_of_fwd_packet: 0.0,
      fwd_packet_length_mean: 0.0,
      bwd_packet_length_std: 0.0,
      packet_length_mean: 3.0,
      subflow_fwd_bytes: 0.0,
      flow_iat_max: 10000000.0,
      bwd_packet_length_mean: 6.0,
      bwd_packet_length_max: 6.0,
      packet_length_variance: 9.0,
      dst_port: 80.0,
      bwd_segment_size_avg: 6.0,
      bwd_psh_flags: 0.0,
      flow_bytes_s: 1000.0,
      flow_packets_s: 200.0,
      average_packet_size: 3.0,
      fwd_segment_size_avg: 0.0,
      model: "random_forest"
    }
  },
  {
    id: "ftp_bruteforce",
    label: "FTP Brute Force",
    icon: "🔐",
    color: "#8b5cf6",
    tag: "BRF",
    description: "Attaque par dictionnaire FTP port 21",
    payload: {
      packet_length_std: 18.5,
      packet_length_max: 75.0,
      rst_flag_count: 0.0,
      fwd_packet_length_max: 75.0,
      total_length_of_fwd_packet: 500.0,
      fwd_packet_length_mean: 45.0,
      bwd_packet_length_std: 12.0,
      packet_length_mean: 40.0,
      subflow_fwd_bytes: 500.0,
      flow_iat_max: 3000000.0,
      bwd_packet_length_mean: 35.0,
      bwd_packet_length_max: 60.0,
      packet_length_variance: 342.0,
      dst_port: 21.0,
      bwd_segment_size_avg: 35.0,
      bwd_psh_flags: 1.0,
      flow_bytes_s: 8000.0,
      flow_packets_s: 120.0,
      average_packet_size: 40.0,
      fwd_segment_size_avg: 45.0,
      model: "knn"
    }
  },
  {
    id: "ssh_bruteforce",
    label: "SSH Brute Force",
    icon: "🔑",
    color: "#06b6d4",
    tag: "SSH",
    description: "Attaque par dictionnaire SSH port 22",
    payload: {
      packet_length_std: 22.0,
      packet_length_max: 90.0,
      rst_flag_count: 0.0,
      fwd_packet_length_max: 90.0,
      total_length_of_fwd_packet: 600.0,
      fwd_packet_length_mean: 50.0,
      bwd_packet_length_std: 15.0,
      packet_length_mean: 45.0,
      subflow_fwd_bytes: 600.0,
      flow_iat_max: 2500000.0,
      bwd_packet_length_mean: 40.0,
      bwd_packet_length_max: 70.0,
      packet_length_variance: 484.0,
      dst_port: 22.0,
      bwd_segment_size_avg: 40.0,
      bwd_psh_flags: 1.0,
      flow_bytes_s: 9500.0,
      flow_packets_s: 140.0,
      average_packet_size: 45.0,
      fwd_segment_size_avg: 50.0,
      model: "decision_tree"
    }
  },
  {
    id: "botnet",
    label: "Botnet Traffic",
    icon: "🤖",
    color: "#f59e0b",
    tag: "BOT",
    description: "Communication botnet - trafic C&C",
    payload: {
      packet_length_std: 350.0,
      packet_length_max: 1400.0,
      rst_flag_count: 0.0,
      fwd_packet_length_max: 1400.0,
      total_length_of_fwd_packet: 8000.0,
      fwd_packet_length_mean: 700.0,
      bwd_packet_length_std: 280.0,
      packet_length_mean: 600.0,
      subflow_fwd_bytes: 8000.0,
      flow_iat_max: 50000000.0,
      bwd_packet_length_mean: 500.0,
      bwd_packet_length_max: 1100.0,
      packet_length_variance: 122500.0,
      dst_port: 443.0,
      bwd_segment_size_avg: 500.0,
      bwd_psh_flags: 1.0,
      flow_bytes_s: 15000.0,
      flow_packets_s: 20.0,
      average_packet_size: 600.0,
      fwd_segment_size_avg: 700.0,
      model: "random_forest"
    }
  },
  {
    id: "web_attack_xss",
    label: "Web Attack XSS",
    icon: "🕷️",
    color: "#ec4899",
    tag: "WEB",
    description: "Attaque XSS - injection de scripts",
    payload: {
      packet_length_std: 280.0,
      packet_length_max: 1200.0,
      rst_flag_count: 0.0,
      fwd_packet_length_max: 1200.0,
      total_length_of_fwd_packet: 4500.0,
      fwd_packet_length_mean: 600.0,
      bwd_packet_length_std: 200.0,
      packet_length_mean: 500.0,
      subflow_fwd_bytes: 4500.0,
      flow_iat_max: 8000000.0,
      bwd_packet_length_mean: 400.0,
      bwd_packet_length_max: 900.0,
      packet_length_variance: 78400.0,
      dst_port: 80.0,
      bwd_segment_size_avg: 400.0,
      bwd_psh_flags: 1.0,
      flow_bytes_s: 25000.0,
      flow_packets_s: 35.0,
      average_packet_size: 500.0,
      fwd_segment_size_avg: 600.0,
      model: "xgboost"
    }
  },
  {
    id: "normal_https",
    label: "Trafic HTTPS Normal",
    icon: "✅",
    color: "#22c55e",
    tag: "OK",
    description: "Navigation HTTPS legitime port 443",
    payload: {
      packet_length_std: 180.0,
      packet_length_max: 1460.0,
      rst_flag_count: 0.0,
      fwd_packet_length_max: 1460.0,
      total_length_of_fwd_packet: 3000.0,
      fwd_packet_length_mean: 400.0,
      bwd_packet_length_std: 220.0,
      packet_length_mean: 350.0,
      subflow_fwd_bytes: 3000.0,
      flow_iat_max: 200000000.0,
      bwd_packet_length_mean: 600.0,
      bwd_packet_length_max: 1400.0,
      packet_length_variance: 32400.0,
      dst_port: 443.0,
      bwd_segment_size_avg: 600.0,
      bwd_psh_flags: 1.0,
      flow_bytes_s: 5000.0,
      flow_packets_s: 8.0,
      average_packet_size: 350.0,
      fwd_segment_size_avg: 400.0,
      model: "random_forest"
    }
  }
];

export default function AttackSimulator({ onResult }) {
  const [results,  setResults]  = useState({});
  const [loading,  setLoading]  = useState({});

  const runTest = async (scenario) => {
    setLoading(prev => ({ ...prev, [scenario.id]: true }));
    setResults(prev => ({ ...prev, [scenario.id]: null }));
    try {
      const { data } = await apiService.predict(scenario.payload);
      setResults(prev => ({ ...prev, [scenario.id]: data }));
      onResult?.();
    } catch (e) {
      const msg = e.response?.data?.detail || e.message || "Erreur inconnue";
      setResults(prev => ({ ...prev, [scenario.id]: { error: msg } }));
    }
    setLoading(prev => ({ ...prev, [scenario.id]: false }));
  };

  const runAll = async () => {
    for (const sc of ATTACK_SCENARIOS) {
      await runTest(sc);
      await new Promise(r => setTimeout(r, 300));
    }
  };

  return (
    <div className="card">
      <div style={{ display:"flex", justifyContent:"space-between",
                    alignItems:"center", marginBottom:20 }}>
        <p className="card__title" style={{ margin:0 }}>
          Scenarios Predéfinis CICIDS-2017
        </p>
        <button className="btn btn--primary" onClick={runAll}>
          Tout tester
        </button>
      </div>

      <div style={{ marginBottom:14, padding:"8px 12px",
                    background:"#1f2937", borderRadius:8,
                    fontSize:"0.72rem", color:"#9ca3af",
                    borderLeft:"3px solid #3b82f6" }}>
        Scenarios : DoS, DDoS, PortScan, Brute Force, Botnet, Web Attack, Normal
      </div>

      <div className="simulator-grid">
        {ATTACK_SCENARIOS.map(scenario => {
          const res       = results[scenario.id];
          const isLoading = loading[scenario.id];
          const isM       = res?.label === "Malicious";

          return (
            <div key={scenario.id} className="simulator-card"
              style={{ borderColor: res
                ? (res.error ? COLORS.warning : isM ? COLORS.malicious : COLORS.benign)
                : undefined }}>

              <div style={{ display:"flex", alignItems:"center",
                            gap:10, marginBottom:10 }}>
                <span style={{ fontSize:"1.3rem" }}>{scenario.icon}</span>
                <div>
                  <div style={{ display:"flex", alignItems:"center", gap:6 }}>
                    <span style={{ fontSize:"0.62rem", fontWeight:700,
                                   padding:"2px 6px", borderRadius:3,
                                   background:"rgba(255,255,255,0.08)",
                                   color:scenario.color,
                                   fontFamily:"JetBrains Mono, monospace" }}>
                      [{scenario.tag}]
                    </span>
                  </div>
                  <div style={{ fontWeight:700, fontSize:"0.85rem",
                                color:scenario.color, marginTop:3,
                                fontFamily:"JetBrains Mono, monospace" }}>
                    {scenario.label}
                  </div>
                  <div style={{ fontSize:"0.7rem", color:COLORS.text2 }}>
                    {scenario.description}
                  </div>
                  <div style={{ fontSize:"0.65rem", color:"#6b7280", marginTop:2 }}>
                    Modele : <strong style={{ color:"#9ca3af" }}>
                      {scenario.payload.model}
                    </strong>
                  </div>
                </div>
              </div>

              {res && !res.error && (
                <div style={{
                  background: isM
                    ? "rgba(239,68,68,0.08)"
                    : "rgba(34,197,94,0.08)",
                  borderRadius:8, padding:"8px 12px", marginBottom:10,
                  display:"flex", justifyContent:"space-between",
                  alignItems:"center"
                }}>
                  <span style={{ fontWeight:700, fontSize:"0.82rem",
                                 color:isM ? COLORS.malicious : COLORS.benign }}>
                    {isM ? "Malicious" : "Benign"}
                  </span>
                  <span style={{ fontSize:"0.75rem", color:COLORS.text2 }}>
                    {res.confidence}%
                  </span>
                </div>
              )}

              {res?.error && (
                <div style={{ color:COLORS.warning, fontSize:"0.72rem",
                              marginBottom:10, wordBreak:"break-word" }}>
                  {res.error}
                </div>
              )}

              <button
                className="btn btn--ghost"
                style={{ width:"100%", justifyContent:"center",
                         borderColor:scenario.color, color:scenario.color }}
                onClick={() => runTest(scenario)}
                disabled={isLoading}
              >
                {isLoading ? "Analyse..." : "Tester"}
              </button>
            </div>
          );
        })}
      </div>
    </div>
  );
}
