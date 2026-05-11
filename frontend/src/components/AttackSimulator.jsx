import { useState } from "react";
import { apiService } from "../services/api";
import { COLORS } from "../constants/theme";

// Scenarios bases sur les vraies signatures CTU-IoT-Malware-Capture
// Valeurs pre-normalisees compatibles avec le nouveau scaler MinMaxScaler
const ATTACK_SCENARIOS = [
  {
    id: "mirai_telnet", label: "Mirai Telnet Scan", icon: "🔍", color: "#ef4444",
    description: "Scan port 23 botnet Mirai IoT",
    payload: {
      id_orig_p: 51524, id_resp_p: 23,
      duration: 0.0, orig_bytes: 0.0, resp_bytes: 0.0, missed_bytes: 0.0,
      orig_pkts: 0.0167, orig_ip_bytes: 0.0134, resp_pkts: 0.0, resp_ip_bytes: 0.0,
      is_orig_local: 1, orig_h_count: 991061.0, resp_h_count: 1.0,
      is_well_known_port: 1, hour: 3, minute: 0, day_of_week: 6,
      inter_arrival_time: 0.0, pkt_ratio: 0.0588,
      avg_orig_pkt_size: 20.0, avg_resp_pkt_size: 0.0,
      model: "random_forest"
    }
  },
  {
    id: "port_scan", label: "Port Scan Port 9527", icon: "🔎", color: "#f97316",
    description: "Scan horizontal port non standard",
    payload: {
      id_orig_p: 43763, id_resp_p: 9527,
      duration: 0.0, orig_bytes: 0.0, resp_bytes: 0.0, missed_bytes: 0.0,
      orig_pkts: 0.0167, orig_ip_bytes: 0.0134, resp_pkts: 0.0, resp_ip_bytes: 0.0,
      is_orig_local: 1, orig_h_count: 991061.0, resp_h_count: 1.0,
      is_well_known_port: 0, hour: 15, minute: 30, day_of_week: 2,
      inter_arrival_time: 0.0, pkt_ratio: 0.0588,
      avg_orig_pkt_size: 20.0, avg_resp_pkt_size: 0.0,
      model: "xgboost"
    }
  },
  {
    id: "brute_ssh", label: "Brute Force SSH", icon: "🔐", color: "#8b5cf6",
    description: "Attaque SSH par dictionnaire port 22",
    payload: {
      id_orig_p: 45678, id_resp_p: 22,
      duration: 0.5, orig_bytes: 200.0, resp_bytes: 50.0, missed_bytes: 0.0,
      orig_pkts: 10.0, orig_ip_bytes: 300.0, resp_pkts: 5.0, resp_ip_bytes: 100.0,
      is_orig_local: 0, orig_h_count: 1000.0, resp_h_count: 1.0,
      is_well_known_port: 1, hour: 2, minute: 30, day_of_week: 5,
      inter_arrival_time: 0.05, pkt_ratio: 2.0,
      avg_orig_pkt_size: 27.3, avg_resp_pkt_size: 16.7,
      model: "knn"
    }
  },
  {
    id: "ddos_flood", label: "DDoS Flood Massif", icon: "💥", color: "#dc2626",
    description: "Flood massif vers port 80",
    payload: {
      id_orig_p: 33333, id_resp_p: 80,
      duration: 0.002, orig_bytes: 0.0, resp_bytes: 0.0, missed_bytes: 0.0,
      orig_pkts: 1.0, orig_ip_bytes: 48.0, resp_pkts: 0.0, resp_ip_bytes: 0.0,
      is_orig_local: 0, orig_h_count: 800.0, resp_h_count: 1.0,
      is_well_known_port: 1, hour: 1, minute: 45, day_of_week: 6,
      inter_arrival_time: 0.002, pkt_ratio: 1.0,
      avg_orig_pkt_size: 24.0, avg_resp_pkt_size: 0.0,
      model: "random_forest"
    }
  },
  {
    id: "botnet_c2", label: "Botnet C2 Communication", icon: "🤖", color: "#06b6d4",
    description: "Communication Command and Control IRC",
    payload: {
      id_orig_p: 22222, id_resp_p: 6667,
      duration: 300.0, orig_bytes: 500.0, resp_bytes: 500.0, missed_bytes: 0.0,
      orig_pkts: 50.0, orig_ip_bytes: 600.0, resp_pkts: 50.0, resp_ip_bytes: 600.0,
      is_orig_local: 1, orig_h_count: 3.0, resp_h_count: 1.0,
      is_well_known_port: 0, hour: 3, minute: 30, day_of_week: 6,
      inter_arrival_time: 6.0, pkt_ratio: 1.0,
      avg_orig_pkt_size: 11.8, avg_resp_pkt_size: 11.8,
      model: "decision_tree"
    }
  },
  {
    id: "normal_udp", label: "Trafic Normal UDP", icon: "✅", color: "#22c55e",
    description: "Connexion UDP legitime port aleatoire",
    payload: {
      id_orig_p: 43763, id_resp_p: 14336,
      duration: 1.5, orig_bytes: 500.0, resp_bytes: 200.0, missed_bytes: 0.0,
      orig_pkts: 5.0, orig_ip_bytes: 600.0, resp_pkts: 3.0, resp_ip_bytes: 250.0,
      is_orig_local: 1, orig_h_count: 10.0, resp_h_count: 5.0,
      is_well_known_port: 0, hour: 14, minute: 30, day_of_week: 1,
      inter_arrival_time: 0.5, pkt_ratio: 1.67,
      avg_orig_pkt_size: 100.0, avg_resp_pkt_size: 62.5,
      model: "random_forest"
    }
  },
];

export default function AttackSimulator({ onResult }) {
  const [results, setResults] = useState({});
  const [loading, setLoading] = useState({});

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
    for (const scenario of ATTACK_SCENARIOS) {
      await runTest(scenario);
      await new Promise(r => setTimeout(r, 300));
    }
  };

  return (
    <div className="card">
      <div style={{ display:"flex", justifyContent:"space-between", alignItems:"center", marginBottom:20 }}>
        <p className="card__title" style={{ margin:0 }}>
          Simulateur — Scenarios Diversifies CTU-IoT
        </p>
        <button className="btn btn--primary" onClick={runAll}>
          Tout tester
        </button>
      </div>

      <div style={{ marginBottom:14, padding:"8px 12px", background:"#1f2937", borderRadius:8, fontSize:"0.72rem", color:"#9ca3af", borderLeft:"3px solid #3b82f6" }}>
        Scenarios : Port Scan, Brute Force, DDoS, Botnet, Trafic Normal
      </div>

      <div className="simulator-grid">
        {ATTACK_SCENARIOS.map(scenario => {
          const res       = results[scenario.id];
          const isLoading = loading[scenario.id];
          const isM       = res?.label === "Malicious";

          return (
            <div key={scenario.id} className="simulator-card"
              style={{ borderColor: res ? (res.error ? COLORS.warning : isM ? COLORS.malicious : COLORS.benign) : undefined }}>

              <div style={{ display:"flex", alignItems:"center", gap:10, marginBottom:10 }}>
                <span style={{ fontSize:"1.3rem" }}>{scenario.icon}</span>
                <div>
                  <div style={{ fontWeight:700, fontSize:"0.85rem", color:scenario.color, fontFamily:"JetBrains Mono, monospace" }}>
                    {scenario.label}
                  </div>
                  <div style={{ fontSize:"0.7rem", color:COLORS.text2 }}>
                    {scenario.description}
                  </div>
                  <div style={{ fontSize:"0.65rem", color:"#6b7280", marginTop:2 }}>
                    Modele : <strong style={{ color:"#9ca3af" }}>{scenario.payload.model}</strong>
                  </div>
                </div>
              </div>

              {res && !res.error && (
                <div style={{
                  background: isM ? "rgba(239,68,68,0.08)" : "rgba(34,197,94,0.08)",
                  borderRadius:8, padding:"8px 12px", marginBottom:10,
                  display:"flex", justifyContent:"space-between", alignItems:"center"
                }}>
                  <span style={{ fontWeight:700, fontSize:"0.82rem", color:isM ? COLORS.malicious : COLORS.benign }}>
                    {isM ? "Malicious" : "Benign"}
                  </span>
                  <span style={{ fontSize:"0.75rem", color:COLORS.text2 }}>
                    {res.confidence}%
                  </span>
                </div>
              )}

              {res?.error && (
                <div style={{ color:COLORS.warning, fontSize:"0.72rem", marginBottom:10, wordBreak:"break-word" }}>
                  {res.error}
                </div>
              )}

              <button
                className="btn btn--ghost"
                style={{ width:"100%", justifyContent:"center", borderColor:scenario.color, color:scenario.color }}
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
