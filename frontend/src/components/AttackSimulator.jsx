import { useState } from "react";
import { apiService } from "../services/api";
import { COLORS } from "../constants/theme";

const ATTACK_SCENARIOS = [
  { id:"mirai_telnet",    label:"Mirai Telnet Scan",       icon:"[SCAN]", color:"#ef4444", description:"Scan port 23 botnet Mirai IoT",          payload:{id_orig_p:53854,id_resp_p:23,duration:0,orig_bytes:0,resp_bytes:0,missed_bytes:0,orig_pkts:1,orig_ip_bytes:60,resp_pkts:0,resp_ip_bytes:0,is_orig_local:1,orig_h_count:991061,resp_h_count:1,is_well_known_port:1,hour:3,minute:0,day_of_week:6,inter_arrival_time:2.93e-9,pkt_ratio:0.0588,avg_orig_pkt_size:30,avg_resp_pkt_size:0,model:"random_forest"}},
  { id:"port_scan_9527",  label:"Port Scan Port 9527",      icon:"[SCAN]", color:"#f97316", description:"Scan horizontal port non standard",       payload:{id_orig_p:36495,id_resp_p:9527,duration:0,orig_bytes:0,resp_bytes:0,missed_bytes:0,orig_pkts:1,orig_ip_bytes:60,resp_pkts:0,resp_ip_bytes:0,is_orig_local:1,orig_h_count:991061,resp_h_count:1,is_well_known_port:0,hour:2,minute:15,day_of_week:5,inter_arrival_time:3.67e-8,pkt_ratio:0.0588,avg_orig_pkt_size:30,avg_resp_pkt_size:0,model:"xgboost"}},
  { id:"brute_force_ssh", label:"Brute Force SSH",          icon:"[BRF]",  color:"#8b5cf6", description:"Attaque SSH par dictionnaire port 22",    payload:{id_orig_p:45678,id_resp_p:22,duration:0.5,orig_bytes:200,resp_bytes:50,missed_bytes:0,orig_pkts:0.05,orig_ip_bytes:0.06,resp_pkts:0,resp_ip_bytes:0,is_orig_local:0,orig_h_count:991061,resp_h_count:1,is_well_known_port:1,hour:2,minute:30,day_of_week:5,inter_arrival_time:0.05,pkt_ratio:0.1765,avg_orig_pkt_size:45,avg_resp_pkt_size:0,model:"knn"}},
  { id:"ddos_flood",      label:"DDoS Flood Massif",        icon:"[DOS]",  color:"#ec4899", description:"Flood massif vers port 80",               payload:{id_orig_p:9999,id_resp_p:80,duration:0,orig_bytes:0,resp_bytes:0,missed_bytes:0,orig_pkts:0.05,orig_ip_bytes:0.0602,resp_pkts:0,resp_ip_bytes:0,is_orig_local:0,orig_h_count:991061,resp_h_count:1,is_well_known_port:1,hour:3,minute:0,day_of_week:6,inter_arrival_time:0.0001,pkt_ratio:0.1765,avg_orig_pkt_size:45,avg_resp_pkt_size:0,model:"random_forest"}},
  { id:"botnet_c2",       label:"Botnet C2 Communication",  icon:"[BOT]",  color:"#f59e0b", description:"Communication Command and Control IRC",   payload:{id_orig_p:22222,id_resp_p:6667,duration:300,orig_bytes:0,resp_bytes:0,missed_bytes:0,orig_pkts:0.05,orig_ip_bytes:0.0602,resp_pkts:0,resp_ip_bytes:0,is_orig_local:1,orig_h_count:3,resp_h_count:1,is_well_known_port:0,hour:3,minute:30,day_of_week:6,inter_arrival_time:6,pkt_ratio:0.1765,avg_orig_pkt_size:45,avg_resp_pkt_size:0,model:"decision_tree"}},
  { id:"normal_udp",      label:"Trafic Normal UDP",        icon:"[OK]",   color:"#22c55e", description:"Connexion UDP legitime port aleatoire",   payload:{id_orig_p:43763,id_resp_p:41534,duration:0,orig_bytes:0,resp_bytes:0,missed_bytes:0,orig_pkts:1,orig_ip_bytes:40,resp_pkts:0,resp_ip_bytes:0,is_orig_local:1,orig_h_count:991061,resp_h_count:1,is_well_known_port:0,hour:15,minute:30,day_of_week:2,inter_arrival_time:0,pkt_ratio:0.0588,avg_orig_pkt_size:20,avg_resp_pkt_size:0,model:"random_forest"}},
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
      <div style={{ display:"flex", justifyContent:"space-between", alignItems:"center", marginBottom:16 }}>
        <p className="card__title" style={{ margin:0 }}>Simulateur — Scenarios Diversifies CTU-IoT</p>
        <button className="btn btn--primary" onClick={runAll}>Tout tester</button>
      </div>
      <div style={{ marginBottom:14, padding:"8px 12px", background:"#1f2937", borderRadius:8, fontSize:"0.72rem", color:"#9ca3af", borderLeft:"3px solid #3b82f6" }}>
        Scenarios diversifies : Port Scan, Brute Force, DDoS, Botnet, Trafic Normal
      </div>
      <div className="simulator-grid">
        {ATTACK_SCENARIOS.map(scenario => {
          const res       = results[scenario.id];
          const isLoading = loading[scenario.id];
          const isM       = res?.label === "Malicious";
          return (
            <div key={scenario.id} className="simulator-card"
              style={{ borderColor: res ? (isM ? COLORS.malicious : COLORS.benign) : undefined }}>
              <div style={{ display:"flex", alignItems:"center", gap:10, marginBottom:10 }}>
                <span style={{ fontSize:"0.78rem", fontWeight:700, color:scenario.color, background:scenario.color+"20", padding:"2px 6px", borderRadius:4, flexShrink:0 }}>{scenario.icon}</span>
                <div>
                  <div style={{ fontWeight:700, fontSize:"0.85rem", color:scenario.color, fontFamily:"JetBrains Mono, monospace" }}>{scenario.label}</div>
                  <div style={{ fontSize:"0.7rem", color:COLORS.text2 }}>{scenario.description}</div>
                  <div style={{ fontSize:"0.65rem", color:"#6b7280", marginTop:2 }}>Modele : <strong style={{ color:"#9ca3af" }}>{scenario.payload.model}</strong></div>
                </div>
              </div>
              {res && !res.error && (
                <div style={{ background:isM?"rgba(239,68,68,0.08)":"rgba(34,197,94,0.08)", borderRadius:8, padding:"8px 12px", marginBottom:10, display:"flex", justifyContent:"space-between", alignItems:"center" }}>
                  <span style={{ fontWeight:700, fontSize:"0.82rem", color:isM?COLORS.malicious:COLORS.benign }}>{isM?"Malicious":"Benign"}</span>
                  <span style={{ fontSize:"0.75rem", color:COLORS.text2 }}>{res.confidence}%</span>
                </div>
              )}
              {res?.error && <div style={{ color:COLORS.malicious, fontSize:"0.72rem", marginBottom:10 }}>Erreur : {res.error}</div>}
              <button className="btn btn--ghost" style={{ width:"100%", justifyContent:"center", borderColor:scenario.color, color:scenario.color }} onClick={() => runTest(scenario)} disabled={isLoading}>
                {isLoading ? "Analyse..." : "Tester"}
              </button>
            </div>
          );
        })}
      </div>
    </div>
  );
}
