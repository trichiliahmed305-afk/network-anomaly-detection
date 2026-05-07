import { useState } from "react";
import { apiService } from "../services/api";
import { COLORS } from "../constants/theme";

const ATTACK_SCENARIOS = [
  {
    id: "mirai_telnet", label: "Mirai Telnet Scan", icon: "🔍", color: "#ef4444",
    description: "Scan Telnet — signature reelle Mirai",
    payload: {
      id_orig_p: 51524.0, id_resp_p: 23.0,
      duration: 0.0102, orig_bytes: 0.0, resp_bytes: 0.0,
      missed_bytes: 0.0, orig_pkts: 0.05, orig_ip_bytes: 0.0602,
      resp_pkts: 0.0, resp_ip_bytes: 0.0,
      is_orig_local: 1, orig_h_count: 991061.0, resp_h_count: 3.0,
      is_well_known_port: 1, hour: 15, minute: 30, day_of_week: 2,
      inter_arrival_time: 2.93e-9, pkt_ratio: 0.1765,
      avg_orig_pkt_size: 45.0, avg_resp_pkt_size: 0.0,
      model: "random_forest"
    }
  },
  {
    id: "mirai_rapide", label: "Mirai Scan Rapide", icon: "⚡", color: "#f97316",
    description: "Variante rapide du scan Mirai",
    payload: {
      id_orig_p: 56305.0, id_resp_p: 23.0,
      duration: 0.0, orig_bytes: 0.0, resp_bytes: 0.0,
      missed_bytes: 0.0, orig_pkts: 0.0167, orig_ip_bytes: 0.0201,
      resp_pkts: 0.0, resp_ip_bytes: 0.0,
      is_orig_local: 1, orig_h_count: 991061.0, resp_h_count: 2.0,
      is_well_known_port: 1, hour: 15, minute: 30, day_of_week: 2,
      inter_arrival_time: 3.67e-8, pkt_ratio: 0.0588,
      avg_orig_pkt_size: 30.0, avg_resp_pkt_size: 0.0,
      model: "random_forest"
    }
  },
  {
    id: "mirai_port23", label: "Mirai Port 23 Massif", icon: "💥", color: "#dc2626",
    description: "Scan massif port 23 botnet IoT",
    payload: {
      id_orig_p: 60905.0, id_resp_p: 23.0,
      duration: 0.0102, orig_bytes: 0.0, resp_bytes: 0.0,
      missed_bytes: 0.0, orig_pkts: 0.05, orig_ip_bytes: 0.0602,
      resp_pkts: 0.0, resp_ip_bytes: 0.0,
      is_orig_local: 1, orig_h_count: 991061.0, resp_h_count: 3.0,
      is_well_known_port: 1, hour: 3, minute: 0, day_of_week: 6,
      inter_arrival_time: 2.97e-9, pkt_ratio: 0.1765,
      avg_orig_pkt_size: 45.0, avg_resp_pkt_size: 0.0,
      model: "xgboost"
    }
  },
  {
    id: "normal_port", label: "Trafic Normal", icon: "✅", color: "#22c55e",
    description: "Connexion legitime port aleatoire",
    payload: {
      id_orig_p: 43763.0, id_resp_p: 14336.0,
      duration: 0.0, orig_bytes: 0.0, resp_bytes: 0.0,
      missed_bytes: 0.0, orig_pkts: 0.0167, orig_ip_bytes: 0.0134,
      resp_pkts: 0.0, resp_ip_bytes: 0.0,
      is_orig_local: 1, orig_h_count: 991061.0, resp_h_count: 1.0,
      is_well_known_port: 0, hour: 15, minute: 30, day_of_week: 2,
      inter_arrival_time: 0.0, pkt_ratio: 0.0588,
      avg_orig_pkt_size: 20.0, avg_resp_pkt_size: 0.0,
      model: "random_forest"
    }
  },
  {
    id: "normal_11764", label: "Trafic Normal DNS", icon: "🌐", color: "#06b6d4",
    description: "Connexion reseau normale port 11764",
    payload: {
      id_orig_p: 43763.0, id_resp_p: 11764.0,
      duration: 0.0, orig_bytes: 0.0, resp_bytes: 0.0,
      missed_bytes: 0.0, orig_pkts: 0.0167, orig_ip_bytes: 0.0134,
      resp_pkts: 0.0, resp_ip_bytes: 0.0,
      is_orig_local: 1, orig_h_count: 991061.0, resp_h_count: 1.0,
      is_well_known_port: 0, hour: 15, minute: 30, day_of_week: 2,
      inter_arrival_time: 3.85e-6, pkt_ratio: 0.0588,
      avg_orig_pkt_size: 20.0, avg_resp_pkt_size: 0.0,
      model: "knn"
    }
  },
  {
    id: "normal_bidi", label: "Trafic Bidirectionnel", icon: "↔️", color: "#10b981",
    description: "Echange bidirectionnel normal",
    payload: {
      id_orig_p: 34243.0, id_resp_p: 49560.0,
      duration: 0.0102, orig_bytes: 0.0, resp_bytes: 0.0,
      missed_bytes: 0.0, orig_pkts: 0.05, orig_ip_bytes: 0.0602,
      resp_pkts: 0.0, resp_ip_bytes: 0.0,
      is_orig_local: 1, orig_h_count: 991061.0, resp_h_count: 3.0,
      is_well_known_port: 0, hour: 15, minute: 30, day_of_week: 2,
      inter_arrival_time: 2.97e-9, pkt_ratio: 0.1765,
      avg_orig_pkt_size: 45.0, avg_resp_pkt_size: 0.0,
      model: "decision_tree"
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
      setResults(prev => ({ ...prev, [scenario.id]: { error: e.message } }));
    }
    setLoading(prev => ({ ...prev, [scenario.id]: false }));
  };

  const runAll = async () => {
    for (const scenario of ATTACK_SCENARIOS) {
      await runTest(scenario);
      await new Promise(r => setTimeout(r, 200));
    }
  };

  return (
    <div className="card">
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 20 }}>
        <p className="card__title" style={{ margin: 0 }}>
          Simulateur — Scenarios CTU-IoT
        </p>
        <button className="btn btn--primary" onClick={runAll}>
          Tout tester
        </button>
      </div>

      <div style={{ marginBottom: 14, padding: "8px 12px", background: "#1f2937", borderRadius: 8, fontSize: "0.72rem", color: "#9ca3af", borderLeft: "3px solid #3b82f6" }}>
        Scenarios bases sur de vraies donnees du dataset CTU-IoT-Malware-Capture
      </div>

      <div className="simulator-grid">
        {ATTACK_SCENARIOS.map(scenario => {
          const res       = results[scenario.id];
          const isLoading = loading[scenario.id];
          const isM       = res?.label === "Malicious";

          return (
            <div key={scenario.id} className="simulator-card"
              style={{ borderColor: res ? (isM ? COLORS.malicious : COLORS.benign) : undefined }}>

              <div style={{ display: "flex", alignItems: "center", gap: 10, marginBottom: 10 }}>
                <span style={{ fontSize: "1.3rem" }}>{scenario.icon}</span>
                <div>
                  <div style={{ fontWeight: 700, fontSize: "0.85rem", color: scenario.color, fontFamily: "JetBrains Mono, monospace" }}>
                    {scenario.label}
                  </div>
                  <div style={{ fontSize: "0.7rem", color: COLORS.text2 }}>
                    {scenario.description}
                  </div>
                  <div style={{ fontSize: "0.65rem", color: "#6b7280", marginTop: 2 }}>
                    Modele : <strong style={{ color: "#9ca3af" }}>{scenario.payload.model}</strong>
                  </div>
                </div>
              </div>

              {res && !res.error && (
                <div style={{
                  background: isM ? "rgba(239,68,68,0.08)" : "rgba(34,197,94,0.08)",
                  borderRadius: 8, padding: "8px 12px", marginBottom: 10,
                  display: "flex", justifyContent: "space-between", alignItems: "center"
                }}>
                  <span style={{ fontWeight: 700, fontSize: "0.82rem", color: isM ? COLORS.malicious : COLORS.benign }}>
                    {isM ? "Malicious" : "Benign"}
                  </span>
                  <span style={{ fontSize: "0.75rem", color: COLORS.text2 }}>
                    {res.confidence}%
                  </span>
                </div>
              )}

              {res?.error && (
                <div style={{ color: COLORS.malicious, fontSize: "0.72rem", marginBottom: 10 }}>
                  Erreur : {res.error}
                </div>
              )}

              <button
                className="btn btn--ghost"
                style={{ width: "100%", justifyContent: "center", borderColor: scenario.color, color: scenario.color }}
                onClick={() => runTest(scenario)}
                disabled={isLoading}
              >
                {isLoading ? "Analyse..." : `Tester`}
              </button>
            </div>
          );
        })}
      </div>
    </div>
  );
}