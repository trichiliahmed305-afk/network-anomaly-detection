import { useState } from "react";
import { apiService } from "../services/api";
import { MODELS_INFO } from "../constants/theme";
import { useIsMobile } from "../hooks/useIsMobile";

// NOTE: model field is NOT in payloads here — it is injected at runtime
// from selectedModel.key so any model works with any scenario
const ATTACK_SCENARIOS = [
  { id: "mirai_telnet", label: "Mirai Telnet Scan",    icon: "[SCAN]", color: "#ef4444", desc: "Scan Telnet signature reelle Mirai",
    payload: { id_orig_p: 51524.0, id_resp_p: 23.0, duration: 0.0102, orig_bytes: 0.0, resp_bytes: 0.0, missed_bytes: 0.0, orig_pkts: 0.05, orig_ip_bytes: 0.0602, resp_pkts: 0.0, resp_ip_bytes: 0.0, is_orig_local: 1, orig_h_count: 991061.0, resp_h_count: 3.0, is_well_known_port: 1, hour: 15, minute: 30, day_of_week: 2, inter_arrival_time: 2.93e-9, pkt_ratio: 0.1765, avg_orig_pkt_size: 45.0, avg_resp_pkt_size: 0.0 } },
  { id: "mirai_rapide", label: "Mirai Scan Rapide",    icon: "[FAST]", color: "#f97316", desc: "Variante rapide du scan Mirai",
    payload: { id_orig_p: 56305.0, id_resp_p: 23.0, duration: 0.0, orig_bytes: 0.0, resp_bytes: 0.0, missed_bytes: 0.0, orig_pkts: 0.0167, orig_ip_bytes: 0.0201, resp_pkts: 0.0, resp_ip_bytes: 0.0, is_orig_local: 1, orig_h_count: 991061.0, resp_h_count: 2.0, is_well_known_port: 1, hour: 15, minute: 30, day_of_week: 2, inter_arrival_time: 3.67e-8, pkt_ratio: 0.0588, avg_orig_pkt_size: 30.0, avg_resp_pkt_size: 0.0 } },
  { id: "mirai_port23", label: "Mirai Port 23 Massif", icon: "[DDOS]", color: "#dc2626", desc: "Scan massif port 23 botnet IoT",
    payload: { id_orig_p: 60905.0, id_resp_p: 23.0, duration: 0.0102, orig_bytes: 0.0, resp_bytes: 0.0, missed_bytes: 0.0, orig_pkts: 0.05, orig_ip_bytes: 0.0602, resp_pkts: 0.0, resp_ip_bytes: 0.0, is_orig_local: 1, orig_h_count: 991061.0, resp_h_count: 3.0, is_well_known_port: 1, hour: 3, minute: 0, day_of_week: 6, inter_arrival_time: 2.97e-9, pkt_ratio: 0.1765, avg_orig_pkt_size: 45.0, avg_resp_pkt_size: 0.0 } },
  { id: "normal_port",  label: "Trafic Normal",         icon: "[OK]",   color: "#22c55e", desc: "Connexion legitime port aleatoire",
    payload: { id_orig_p: 43763.0, id_resp_p: 14336.0, duration: 0.0, orig_bytes: 0.0, resp_bytes: 0.0, missed_bytes: 0.0, orig_pkts: 0.0167, orig_ip_bytes: 0.0134, resp_pkts: 0.0, resp_ip_bytes: 0.0, is_orig_local: 1, orig_h_count: 991061.0, resp_h_count: 1.0, is_well_known_port: 0, hour: 15, minute: 30, day_of_week: 2, inter_arrival_time: 0.0, pkt_ratio: 0.0588, avg_orig_pkt_size: 20.0, avg_resp_pkt_size: 0.0 } },
  { id: "normal_11764", label: "Trafic Normal DNS",     icon: "[DNS]",  color: "#06b6d4", desc: "Connexion reseau normale port 11764",
    payload: { id_orig_p: 43763.0, id_resp_p: 11764.0, duration: 0.0, orig_bytes: 0.0, resp_bytes: 0.0, missed_bytes: 0.0, orig_pkts: 0.0167, orig_ip_bytes: 0.0134, resp_pkts: 0.0, resp_ip_bytes: 0.0, is_orig_local: 1, orig_h_count: 991061.0, resp_h_count: 1.0, is_well_known_port: 0, hour: 15, minute: 30, day_of_week: 2, inter_arrival_time: 3.85e-6, pkt_ratio: 0.0588, avg_orig_pkt_size: 20.0, avg_resp_pkt_size: 0.0 } },
  { id: "normal_bidi",  label: "Trafic Bidirectionnel", icon: "[BIDI]", color: "#10b981", desc: "Echange bidirectionnel normal",
    payload: { id_orig_p: 34243.0, id_resp_p: 49560.0, duration: 0.0102, orig_bytes: 0.0, resp_bytes: 0.0, missed_bytes: 0.0, orig_pkts: 0.05, orig_ip_bytes: 0.0602, resp_pkts: 0.0, resp_ip_bytes: 0.0, is_orig_local: 1, orig_h_count: 991061.0, resp_h_count: 3.0, is_well_known_port: 0, hour: 15, minute: 30, day_of_week: 2, inter_arrival_time: 2.97e-9, pkt_ratio: 0.1765, avg_orig_pkt_size: 45.0, avg_resp_pkt_size: 0.0 } },
];

function SelectCard({ item, selected, onClick, type }) {
  const isSelected = selected?.id === item.id || selected?.key === item.key;
  const itemColor  = item.color;
  return (
    <button onClick={() => onClick(item)}
      style={{ background: isSelected ? itemColor+"15":"#1f2937", border:`2px solid ${isSelected ? itemColor : "#374151"}`, borderRadius:10, padding:"12px 14px", cursor:"pointer", textAlign:"left", transition:"all 0.2s ease", width:"100%", transform:isSelected?"translateY(-1px)":"none", boxShadow:isSelected?`0 4px 16px ${itemColor}25`:"none" }}>
      <div style={{ display:"flex", alignItems:"center", gap:10 }}>
        <span style={{ fontSize:"0.85rem", fontWeight:700, color:itemColor, fontFamily:"monospace", flexShrink:0, background:itemColor+"20", padding:"2px 6px", borderRadius:4 }}>{item.icon}</span>
        <div style={{ flex:1, minWidth:0 }}>
          <div style={{ fontWeight:700, fontSize:"0.85rem", color:isSelected ? itemColor : "#f1f5f9", fontFamily:"JetBrains Mono, monospace", whiteSpace:"nowrap", overflow:"hidden", textOverflow:"ellipsis" }}>{item.name || item.label}</div>
          <div style={{ fontSize:"0.7rem", color:"#9ca3af", marginTop:1 }}>{item.desc}</div>
        </div>
        {isSelected && <span style={{ fontSize:"0.65rem", fontWeight:700, padding:"2px 7px", borderRadius:999, background:itemColor+"30", color:itemColor, flexShrink:0 }}>OK</span>}
      </div>
      {type === "model" && (
        <div style={{ marginTop:8, display:"flex", gap:12, alignItems:"center" }}>
          <span style={{ fontSize:"0.7rem", color:"#9ca3af" }}>Acc: <strong style={{ color:itemColor }}>{item.acc}%</strong></span>
          <span style={{ fontSize:"0.7rem", color:"#9ca3af" }}>F1: <strong style={{ color:itemColor }}>{item.f1}%</strong></span>
          <span style={{ marginLeft:"auto", fontSize:"0.62rem", fontWeight:700, padding:"1px 7px", borderRadius:999, background:"rgba(34,197,94,0.15)", color:"#22c55e" }}>Actif</span>
        </div>
      )}
    </button>
  );
}

function ResultPanel({ result, selectedModel, selectedAttack }) {
  if (!result) return null;
  const isM  = result.label === "Malicious";
  const conf = result.confidence;
  const color = isM ? "#ef4444" : "#22c55e";
  const riskColor = { LOW:"#22c55e", MEDIUM:"#f59e0b", HIGH:"#f97316", CRITICAL:"#ef4444" };
  return (
    <div style={{ background:isM?"rgba(239,68,68,0.06)":"rgba(34,197,94,0.06)", border:`2px solid ${color}`, borderRadius:14, padding:"20px 24px" }}>
      <div style={{ display:"flex", alignItems:"center", gap:14, marginBottom:18 }}>
        <div style={{ fontSize:"1.5rem", background:color+"15", borderRadius:"50%", width:52, height:52, display:"flex", alignItems:"center", justifyContent:"center", fontWeight:700, color }}>{isM ? "!" : "OK"}</div>
        <div style={{ flex:1 }}>
          <div style={{ fontSize:"1.3rem", fontWeight:800, color, fontFamily:"JetBrains Mono, monospace" }}>{isM ? "MALICIOUS" : "BENIGN"}</div>
          <div style={{ fontSize:"0.78rem", color:"#9ca3af" }}>{isM ? "Comportement malveillant detecte" : "Trafic legitime identifie"}</div>
        </div>
        <div style={{ textAlign:"right" }}>
          <div style={{ fontSize:"1.8rem", fontWeight:800, color, fontFamily:"JetBrains Mono, monospace" }}>{conf}%</div>
          <div style={{ fontSize:"0.7rem", color:"#9ca3af" }}>Confiance</div>
        </div>
      </div>
      <div style={{ marginBottom:16 }}>
        <div style={{ background:"#1f2937", borderRadius:6, height:7, overflow:"hidden" }}>
          <div style={{ width:`${conf}%`, height:"100%", background:`linear-gradient(90deg, ${color}70, ${color})`, borderRadius:6, transition:"width 1s ease" }} />
        </div>
      </div>
      <div style={{ display:"grid", gridTemplateColumns:"repeat(3,1fr)", gap:10 }}>
        {[
          { label:"Modele",   value: selectedModel?.name  || "—", color: selectedModel?.color  || "#3b82f6" },
          { label:"Scenario", value: selectedAttack?.label || "—", color: selectedAttack?.color || "#9ca3af" },
          { label:"Risque",   value: result.risk_level     || "—", color: riskColor[result.risk_level] || "#9ca3af" },
        ].map(({ label, value, color: c }) => (
          <div key={label} style={{ background:"#111827", border:"1px solid #1f2937", borderRadius:8, padding:"10px 12px" }}>
            <div style={{ fontSize:"0.65rem", color:"#6b7280", textTransform:"uppercase", marginBottom:3 }}>{label}</div>
            <div style={{ fontSize:"0.82rem", fontWeight:700, color:c }}>{value}</div>
          </div>
        ))}
      </div>
    </div>
  );
}

export default function PredictForm({ onResult }) {
  const isMobile = useIsMobile();
  const [selectedModel,  setSelectedModel]  = useState(MODELS_INFO[3]);
  const [selectedAttack, setSelectedAttack] = useState(null);
  const [loading,        setLoading]        = useState(false);
  const [result,         setResult]         = useState(null);
  const [error,          setError]          = useState(null);

  const canAnalyze = selectedModel && selectedAttack && !loading;

  const runAnalysis = async () => {
    if (!canAnalyze) return;
    setLoading(true); setResult(null); setError(null);
    // Inject the selected model key into the payload
    const payload = { ...selectedAttack.payload, model: selectedModel.key };
    try {
      const { data } = await apiService.predict(payload);
      setResult(data);
      onResult?.();
    } catch (e) {
      setError(e.response?.data?.detail || e.message);
    }
    setLoading(false);
  };

  return (
    <div style={{ display:"flex", flexDirection:"column", gap:20 }}>
      <div>
        <h2 style={{ fontFamily:"JetBrains Mono, monospace", fontSize:"1rem", marginBottom:4 }}>Systeme d Analyse</h2>
        <p style={{ fontSize:"0.8rem", color:"#9ca3af" }}>Scenarios bases sur de vraies donnees CTU-IoT. Selectionnez un modele et un scenario.</p>
      </div>
      <div style={{ display:"grid", gridTemplateColumns:isMobile ? "1fr" : "1fr 1fr", gap:20, alignItems:"start" }}>

        {/* Colonne gauche — choix modele */}
        <div className="card">
          <p className="card__title" style={{ marginBottom:14 }}>
            <span style={{ background:"#3b82f620", color:"#3b82f6", borderRadius:"50%", width:20, height:20, display:"inline-flex", alignItems:"center", justifyContent:"center", fontSize:"0.72rem", fontWeight:800, marginRight:8 }}>1</span>
            Choisir le modele ML
          </p>
          <div style={{ display:"flex", flexDirection:"column", gap:7 }}>
            {MODELS_INFO.map(model => (
              <SelectCard key={model.key} item={model} selected={selectedModel} onClick={setSelectedModel} type="model" />
            ))}
          </div>
        </div>

        {/* Colonne droite — choix scenario + bouton */}
        <div style={{ display:"flex", flexDirection:"column", gap:16 }}>
          <div className="card">
            <p className="card__title" style={{ marginBottom:14 }}>
              <span style={{ background:"#ef444420", color:"#ef4444", borderRadius:"50%", width:20, height:20, display:"inline-flex", alignItems:"center", justifyContent:"center", fontSize:"0.72rem", fontWeight:800, marginRight:8 }}>2</span>
              Choisir le scenario
            </p>
            <div style={{ marginBottom:10, padding:"8px 12px", background:"#1f2937", borderRadius:8, fontSize:"0.72rem", color:"#9ca3af", borderLeft:"3px solid #3b82f6" }}>
              Scenarios extraits du dataset CTU-IoT-Malware-Capture
            </div>
            <div style={{ display:"flex", flexDirection:"column", gap:7 }}>
              {ATTACK_SCENARIOS.map(attack => (
                <SelectCard key={attack.id} item={attack} selected={selectedAttack} onClick={setSelectedAttack} type="attack" />
              ))}
            </div>
          </div>

          {selectedModel && selectedAttack && !result && (
            <div style={{ background:"#111827", border:"1px solid #1f2937", borderRadius:10, padding:"12px 16px" }}>
              <div style={{ fontSize:"0.68rem", color:"#6b7280", textTransform:"uppercase", marginBottom:8 }}>Recapitulatif</div>
              <div style={{ fontSize:"0.82rem", color:"#9ca3af", marginBottom:4 }}>Modele : <strong style={{ color:selectedModel.color }}>{selectedModel.name}</strong></div>
              <div style={{ fontSize:"0.82rem", color:"#9ca3af" }}>Scenario : <strong style={{ color:selectedAttack.color }}>{selectedAttack.label}</strong></div>
            </div>
          )}

          <button
            onClick={runAnalysis}
            disabled={!canAnalyze}
            style={{ background:canAnalyze ? "linear-gradient(135deg, #3b82f6, #8b5cf6)" : "#374151", border:"none", borderRadius:12, padding:"15px 24px", color:canAnalyze ? "#fff" : "#6b7280", cursor:canAnalyze ? "pointer" : "not-allowed", fontFamily:"JetBrains Mono, monospace", fontWeight:700, fontSize:"0.9rem", display:"flex", alignItems:"center", justifyContent:"center", gap:10, transition:"all 0.2s ease", boxShadow:canAnalyze ? "0 4px 20px rgba(59,130,246,0.3)" : "none" }}
          >
            {loading ? "Analyse en cours..." : !selectedAttack ? "Selectionnez un scenario" : `Lancer l analyse — ${selectedModel?.name}`}
          </button>

          {error && (
            <div style={{ background:"rgba(239,68,68,0.08)", border:"1px solid rgba(239,68,68,0.3)", borderRadius:10, padding:"12px 16px", fontSize:"0.82rem", color:"#ef4444" }}>
              Erreur : {error}
            </div>
          )}

          <ResultPanel result={result} selectedModel={selectedModel} selectedAttack={selectedAttack} />
        </div>
      </div>
    </div>
  );
}