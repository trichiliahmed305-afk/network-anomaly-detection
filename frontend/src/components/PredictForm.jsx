import { useState, useRef } from "react";
import { apiService } from "../services/api";
import { MODELS_INFO } from "../constants/theme";
import { useIsMobile } from "../hooks/useIsMobile";

const ATTACK_SCENARIOS = [
  {
    id:'portscan_1',
    label:'Port Scan - Horizontal Scan',
    icon:'[SCAN]',
    color:'#ef4444',
    desc:'Horizontal port scan — real CTU-IoT data (95% confidence)',
    payload:{id_orig_p:51524,id_resp_p:23,duration:2.999051,orig_bytes:0,resp_bytes:0,missed_bytes:0,orig_pkts:3,orig_ip_bytes:180,resp_pkts:0,resp_ip_bytes:0,is_orig_local:1,orig_h_count:991061,resp_h_count:3,is_well_known_port:1,hour:15,minute:30,day_of_week:2,inter_arrival_time:0.000738,pkt_ratio:1.0,avg_orig_pkt_size:60,avg_resp_pkt_size:0,model:"random_forest"}
  },
  {
    id:'portscan_2',
    label:'Port Scan - Fast Scan',
    icon:'[SCAN]',
    color:'#f97316',
    desc:'Fast horizontal scan — real CTU-IoT data (91.9% confidence)',
    payload:{id_orig_p:56305,id_resp_p:23,duration:0,orig_bytes:0,resp_bytes:0,missed_bytes:0,orig_pkts:1,orig_ip_bytes:60,resp_pkts:0,resp_ip_bytes:0,is_orig_local:1,orig_h_count:991061,resp_h_count:2,is_well_known_port:1,hour:15,minute:30,day_of_week:2,inter_arrival_time:0.009244,pkt_ratio:1.0,avg_orig_pkt_size:60,avg_resp_pkt_size:0,model:"random_forest"}
  },
  {
    id:'attack_ssh_1',
    label:'Attack - SSH Brute Force',
    icon:'[ATK]',
    color:'#8b5cf6',
    desc:'SSH brute force attack — real CTU-IoT data (79% confidence)',
    payload:{id_orig_p:53190,id_resp_p:22,duration:2.503441,orig_bytes:589,resp_bytes:2565,missed_bytes:0,orig_pkts:16,orig_ip_bytes:1429,resp_pkts:14,resp_ip_bytes:3301,is_orig_local:1,orig_h_count:154886,resp_h_count:5,is_well_known_port:1,hour:19,minute:19,day_of_week:5,inter_arrival_time:0.003479,pkt_ratio:0.533333,avg_orig_pkt_size:89.3125,avg_resp_pkt_size:235.785714,model:"random_forest"}
  },
  {
    id:'attack_ssh_2',
    label:'Attack - SSH Brute Force v2',
    icon:'[ATK]',
    color:'#dc2626',
    desc:'SSH brute force variant — real CTU-IoT data (79% confidence)',
    payload:{id_orig_p:53193,id_resp_p:22,duration:2.089540,orig_bytes:589,resp_bytes:2565,missed_bytes:0,orig_pkts:14,orig_ip_bytes:1325,resp_pkts:14,resp_ip_bytes:3301,is_orig_local:1,orig_h_count:154886,resp_h_count:5,is_well_known_port:1,hour:19,minute:19,day_of_week:5,inter_arrival_time:0.289234,pkt_ratio:0.5,avg_orig_pkt_size:94.642857,avg_resp_pkt_size:235.785714,model:"random_forest"}
  },
  {
    id:'benign_1',
    label:'Normal - Legitimate Traffic',
    icon:'[OK]',
    color:'#22c55e',
    desc:'Normal benign traffic — real CTU-IoT data (61.4% confidence)',
    payload:{id_orig_p:43763,id_resp_p:14336,duration:0,orig_bytes:0,resp_bytes:0,missed_bytes:0,orig_pkts:1,orig_ip_bytes:40,resp_pkts:0,resp_ip_bytes:0,is_orig_local:1,orig_h_count:991061,resp_h_count:1,is_well_known_port:0,hour:15,minute:30,day_of_week:2,inter_arrival_time:0,pkt_ratio:1.0,avg_orig_pkt_size:40,avg_resp_pkt_size:0,model:"random_forest"}
  },
  {
    id:'benign_2',
    label:'Normal - Internal Connection',
    icon:'[OK]',
    color:'#06b6d4',
    desc:'Normal internal connection — real CTU-IoT data (61.1% confidence)',
    payload:{id_orig_p:43763,id_resp_p:11764,duration:0,orig_bytes:0,resp_bytes:0,missed_bytes:0,orig_pkts:1,orig_ip_bytes:40,resp_pkts:0,resp_ip_bytes:0,is_orig_local:1,orig_h_count:991061,resp_h_count:1,is_well_known_port:0,hour:15,minute:30,day_of_week:2,inter_arrival_time:0.970448,pkt_ratio:1.0,avg_orig_pkt_size:40,avg_resp_pkt_size:0,model:"random_forest"}
  },
];

const MANUAL_FIELDS = [
  {key:"id_orig_p",          label:"Port Source",           default:51524},
  {key:"id_resp_p",          label:"Port Destination",      default:23},
  {key:"duration",           label:"Duration",              default:0.001},
  {key:"orig_bytes",         label:"Orig Bytes",            default:0},
  {key:"resp_bytes",         label:"Resp Bytes",            default:0},
  {key:"missed_bytes",       label:"Missed Bytes",          default:0},
  {key:"orig_pkts",          label:"Orig Pkts",             default:0.05},
  {key:"orig_ip_bytes",      label:"Orig IP Bytes",         default:0.06},
  {key:"resp_pkts",          label:"Resp Pkts",             default:0},
  {key:"resp_ip_bytes",      label:"Resp IP Bytes",         default:0},
  {key:"is_orig_local",      label:"Is Orig Local (0/1)",   default:1},
  {key:"orig_h_count",       label:"Orig H Count",          default:991061},
  {key:"resp_h_count",       label:"Resp H Count",          default:3},
  {key:"is_well_known_port", label:"Well Known Port (0/1)", default:1},
  {key:"hour",               label:"Heure (0-23)",          default:15},
  {key:"minute",             label:"Minute (0-59)",         default:30},
  {key:"day_of_week",        label:"Jour Semaine (0-6)",    default:2},
  {key:"inter_arrival_time", label:"Inter Arrival Time",    default:0.000000003},
  {key:"pkt_ratio",          label:"Pkt Ratio",             default:0.1765},
  {key:"avg_orig_pkt_size",  label:"Avg Orig Pkt Size",     default:45},
  {key:"avg_resp_pkt_size",  label:"Avg Resp Pkt Size",     default:0},
];

function ResultCard({result, selectedModel, selectedScenario}) {
  if (!result) return null;
  const isM = result.label === "Malicious";
  const color = isM ? "#ef4444" : "#22c55e";
  const riskColor = {LOW:"#22c55e",MEDIUM:"#f59e0b",HIGH:"#f97316",CRITICAL:"#ef4444"};
  return (
    <div style={{background:isM?"rgba(239,68,68,0.06)":"rgba(34,197,94,0.06)",border:`2px solid ${color}`,borderRadius:14,padding:"20px 24px"}}>
      <div style={{display:"flex",alignItems:"center",gap:14,marginBottom:16}}>
        <div style={{fontSize:"1.5rem",background:color+"15",borderRadius:"50%",width:50,height:50,display:"flex",alignItems:"center",justifyContent:"center",fontWeight:800,color}}>{isM?"!":"OK"}</div>
        <div style={{flex:1}}>
          <div style={{fontSize:"1.2rem",fontWeight:800,color,fontFamily:"JetBrains Mono, monospace"}}>{isM?"MALICIOUS":"BENIGN"}</div>
          <div style={{fontSize:"0.75rem",color:"#9ca3af"}}>{isM?"Comportement malveillant detecte":"Trafic legitime identifie"}</div>
        </div>
        <div style={{textAlign:"right"}}>
          <div style={{fontSize:"1.6rem",fontWeight:800,color,fontFamily:"JetBrains Mono, monospace"}}>{result.confidence}%</div>
          <div style={{fontSize:"0.68rem",color:"#9ca3af"}}>Confiance</div>
        </div>
      </div>
      <div style={{background:"#1f2937",borderRadius:6,height:6,overflow:"hidden",marginBottom:14}}>
        <div style={{width:`${result.confidence}%`,height:"100%",background:`linear-gradient(90deg,${color}70,${color})`,borderRadius:6,transition:"width 1s ease"}}/>
      </div>
      <div style={{display:"grid",gridTemplateColumns:"repeat(3,1fr)",gap:8}}>
        {[
          {label:"Modele",   value:selectedModel?.name||"RF",              c:selectedModel?.color||"#3b82f6"},
          {label:"Scenario", value:selectedScenario?.label||"Manuel",      c:selectedScenario?.color||"#9ca3af"},
          {label:"Risque",   value:result.risk_level||"LOW",               c:riskColor[result.risk_level]||"#22c55e"},
        ].map(({label,value,c})=>(
          <div key={label} style={{background:"#111827",border:"1px solid #1f2937",borderRadius:8,padding:"8px 10px"}}>
            <div style={{fontSize:"0.62rem",color:"#6b7280",textTransform:"uppercase",marginBottom:2}}>{label}</div>
            <div style={{fontSize:"0.8rem",fontWeight:700,color:c,overflow:"hidden",textOverflow:"ellipsis",whiteSpace:"nowrap"}}>{value}</div>
          </div>
        ))}
      </div>
    </div>
  );
}

function BatchResults({data}) {
  if (!data) return null;
  const {total,malicious,benign,taux_detection,results} = data;
  return (
    <div style={{display:"flex",flexDirection:"column",gap:12}}>
      <div style={{display:"grid",gridTemplateColumns:"repeat(4,1fr)",gap:10}}>
        {[
          {label:"Total",       value:total,              color:"#3b82f6"},
          {label:"Malveillant", value:malicious,          color:"#ef4444"},
          {label:"Benin",       value:benign,             color:"#22c55e"},
          {label:"Taux",        value:`${taux_detection}%`,color:"#f59e0b"},
        ].map(({label,value,color})=>(
          <div key={label} style={{background:"#111827",border:`1px solid ${color}30`,borderRadius:10,padding:"12px 14px",textAlign:"center"}}>
            <div style={{fontSize:"1.4rem",fontWeight:800,color,fontFamily:"JetBrains Mono, monospace"}}>{value}</div>
            <div style={{fontSize:"0.68rem",color:"#9ca3af",textTransform:"uppercase",marginTop:2}}>{label}</div>
          </div>
        ))}
      </div>
      <div style={{maxHeight:280,overflowY:"auto",borderRadius:10,border:"1px solid #1f2937"}}>
        <table style={{width:"100%",borderCollapse:"collapse",fontSize:"0.78rem"}}>
          <thead>
            <tr style={{background:"#1f2937"}}>
              {["#","Classification","Confiance","Risque"].map(h=>(
                <th key={h} style={{padding:"8px 12px",textAlign:"left",color:"#9ca3af",fontSize:"0.68rem",textTransform:"uppercase"}}>{h}</th>
              ))}
            </tr>
          </thead>
          <tbody>
            {results.map((r,i)=>(
              <tr key={i} style={{borderBottom:"1px solid #1f293740",background:i%2===0?"#0a0e1a":"transparent"}}>
                <td style={{padding:"6px 12px",color:"#6b7280"}}>{r.index+1}</td>
                <td style={{padding:"6px 12px",color:r.label==="Malicious"?"#ef4444":"#22c55e",fontWeight:600}}>{r.label}</td>
                <td style={{padding:"6px 12px",color:"#f1f5f9"}}>{r.confidence}%</td>
                <td style={{padding:"6px 12px",color:r.risk_level==="LOW"?"#22c55e":r.risk_level==="MEDIUM"?"#f59e0b":"#ef4444"}}>{r.risk_level}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}

export default function PredictForm({onResult}) {
  const isMobile = useIsMobile();
  const [activeTab,        setActiveTab]        = useState("scenarios");
  const [selectedModel,    setSelectedModel]    = useState(MODELS_INFO[3]);
  const [selectedScenario, setSelectedScenario] = useState(null);
  const [loadingScenario,  setLoadingScenario]  = useState(false);
  const [resultScenario,   setResultScenario]   = useState(null);
  const [batchFile,        setBatchFile]        = useState(null);
  const [selectedBatchModel, setSelectedBatchModel] = useState(MODELS_INFO[3]);
  const [loadingBatch,     setLoadingBatch]     = useState(false);
  const [batchResults,     setBatchResults]     = useState(null);
  const [batchError,       setBatchError]       = useState(null);
  const fileInputRef = useRef(null);
  const initManual = () => Object.fromEntries(MANUAL_FIELDS.map(f=>[f.key,f.default]));
  const [manualForm,    setManualForm]    = useState(initManual);
  const [loadingManual, setLoadingManual] = useState(false);
  const [resultManual,  setResultManual]  = useState(null);
  const [manualError,   setManualError]   = useState(null);
  const [manualModel,   setManualModel]   = useState(MODELS_INFO[3]);

  const runScenario = async () => {
    if (!selectedModel || !selectedScenario) return;
    setLoadingScenario(true); setResultScenario(null);
    try {
      const {data} = await apiService.predict({...selectedScenario.payload, model:selectedModel.key});
      setResultScenario(data); onResult?.();
    } catch(e){console.error(e);}
    setLoadingScenario(false);
  };

  const runBatch = async () => {
    if (!batchFile) return;
    setLoadingBatch(true); setBatchResults(null); setBatchError(null);
    try {
      const formData = new FormData();
      formData.append("file", batchFile);
      const {data} = await apiService.predictBatch(formData, selectedBatchModel?.key || "random_forest");
      setBatchResults(data); onResult?.();
    } catch(e){ setBatchError(e.response?.data?.detail||e.message); }
    setLoadingBatch(false);
  };

  const runManual = async () => {
    setLoadingManual(true); setResultManual(null); setManualError(null);
    try {
      const {data} = await apiService.predict({...manualForm, model:manualModel.key});
      setResultManual(data); onResult?.();
    } catch(e){ setManualError(e.response?.data?.detail||e.message); }
    setLoadingManual(false);
  };

  const tabStyle = (tab) => ({
    padding:"9px 18px", border:`2px solid ${activeTab===tab?"#3b82f6":"#374151"}`,
    borderRadius:10, background:activeTab===tab?"#3b82f620":"transparent",
    color:activeTab===tab?"#3b82f6":"#9ca3af", cursor:"pointer",
    fontFamily:"JetBrains Mono, monospace", fontWeight:700, fontSize:"0.82rem", transition:"all 0.2s"
  });

  const btnStyle = (active,color="#3b82f6") => ({
    background:active?`linear-gradient(135deg,${color},#8b5cf6)`:"#374151",
    border:"none", borderRadius:12, padding:"14px 24px",
    color:active?"#fff":"#6b7280", cursor:active?"pointer":"not-allowed",
    fontFamily:"JetBrains Mono, monospace", fontWeight:700, fontSize:"0.9rem",
    display:"flex", alignItems:"center", justifyContent:"center", gap:10,
    transition:"all 0.2s", boxShadow:active?`0 4px 20px ${color}40`:"none", width:"100%"
  });

  const modelBtn = (m, selected, onSelect) => (
    <button key={m.key} onClick={()=>onSelect(m)} style={{
      background:selected?.key===m.key?m.color+"15":"#1f2937",
      border:`2px solid ${selected?.key===m.key?m.color:"#374151"}`,
      borderRadius:10, padding:"11px 14px", cursor:"pointer", textAlign:"left", transition:"all 0.2s", width:"100%"
    }}>
      <div style={{display:"flex",alignItems:"center",gap:10}}>
        <span style={{fontSize:"0.78rem",fontWeight:700,color:m.color,background:m.color+"20",padding:"2px 6px",borderRadius:4,flexShrink:0}}>{m.icon}</span>
        <div style={{flex:1,minWidth:0}}>
          <div style={{fontWeight:700,fontSize:"0.83rem",color:selected?.key===m.key?m.color:"#f1f5f9",fontFamily:"JetBrains Mono, monospace"}}>{m.name}</div>
          <div style={{fontSize:"0.68rem",color:"#9ca3af"}}>{m.desc}</div>
        </div>
        {selected?.key===m.key&&<span style={{fontSize:"0.62rem",fontWeight:700,padding:"2px 7px",borderRadius:999,background:m.color+"30",color:m.color}}>OK</span>}
      </div>
      <div style={{marginTop:7,display:"flex",gap:12}}>
        <span style={{fontSize:"0.68rem",color:"#9ca3af"}}>Acc: <strong style={{color:m.color}}>{m.acc}%</strong></span>
        <span style={{fontSize:"0.68rem",color:"#9ca3af"}}>F1: <strong style={{color:m.color}}>{m.f1}%</strong></span>
        <span style={{marginLeft:"auto",fontSize:"0.6rem",fontWeight:700,padding:"1px 6px",borderRadius:999,background:"rgba(34,197,94,0.15)",color:"#22c55e"}}>Actif</span>
      </div>
    </button>
  );

  return (
    <div style={{display:"flex",flexDirection:"column",gap:20}}>
      <div>
        <h2 style={{fontFamily:"JetBrains Mono, monospace",fontSize:"1rem",marginBottom:4}}>Systeme d Analyse Avance</h2>
        <p style={{fontSize:"0.8rem",color:"#9ca3af"}}>3 modes : scenarios predefinies, fichier Excel en masse, ou saisie manuelle.</p>
      </div>

      <div style={{display:"flex",gap:10,flexWrap:"wrap"}}>
        <button style={tabStyle("scenarios")} onClick={()=>setActiveTab("scenarios")}>Scenarios Predefinies</button>
        <button style={tabStyle("batch")}     onClick={()=>setActiveTab("batch")}>Upload Excel (Batch)</button>
        <button style={tabStyle("manual")}    onClick={()=>setActiveTab("manual")}>Saisie Manuelle</button>
      </div>

      {activeTab==="scenarios" && (
        <div style={{display:"grid",gridTemplateColumns:isMobile?"1fr":"1fr 1fr",gap:20,alignItems:"start"}}>
          <div className="card">
            <p className="card__title" style={{marginBottom:14}}>
              <span style={{background:"#3b82f620",color:"#3b82f6",borderRadius:"50%",width:20,height:20,display:"inline-flex",alignItems:"center",justifyContent:"center",fontSize:"0.7rem",fontWeight:800,marginRight:8}}>1</span>
              Choisir le modele ML
            </p>
            <div style={{display:"flex",flexDirection:"column",gap:7}}>
              {MODELS_INFO.map(m=>modelBtn(m,selectedModel,setSelectedModel))}
            </div>
          </div>
          <div style={{display:"flex",flexDirection:"column",gap:14}}>
            <div className="card">
              <p className="card__title" style={{marginBottom:12}}>
                <span style={{background:"#ef444420",color:"#ef4444",borderRadius:"50%",width:20,height:20,display:"inline-flex",alignItems:"center",justifyContent:"center",fontSize:"0.7rem",fontWeight:800,marginRight:8}}>2</span>
                Choisir le scenario
              </p>
              <div style={{fontSize:"0.7rem",color:"#9ca3af",padding:"6px 10px",background:"#1f2937",borderRadius:6,borderLeft:"3px solid #3b82f6",marginBottom:10}}>
                Donnees reelles — dataset CTU-IoT-Malware-Capture
              </div>
              <div style={{display:"flex",flexDirection:"column",gap:6}}>
                {ATTACK_SCENARIOS.map(s=>(
                  <button key={s.id} onClick={()=>setSelectedScenario(s)} style={{
                    background:selectedScenario?.id===s.id?s.color+"15":"#1f2937",
                    border:`2px solid ${selectedScenario?.id===s.id?s.color:"#374151"}`,
                    borderRadius:9,padding:"10px 13px",cursor:"pointer",textAlign:"left",transition:"all 0.2s"
                  }}>
                    <div style={{display:"flex",alignItems:"center",gap:9}}>
                      <span style={{fontSize:"0.72rem",fontWeight:700,color:s.color,background:s.color+"20",padding:"2px 6px",borderRadius:4,flexShrink:0}}>{s.icon}</span>
                      <div>
                        <div style={{fontWeight:700,fontSize:"0.82rem",color:selectedScenario?.id===s.id?s.color:"#f1f5f9",fontFamily:"JetBrains Mono, monospace"}}>{s.label}</div>
                        <div style={{fontSize:"0.68rem",color:"#9ca3af"}}>{s.desc}</div>
                      </div>
                      {selectedScenario?.id===s.id&&<span style={{marginLeft:"auto",fontSize:"0.62rem",fontWeight:700,padding:"2px 6px",borderRadius:999,background:s.color+"30",color:s.color,flexShrink:0}}>OK</span>}
                    </div>
                  </button>
                ))}
              </div>
            </div>
            {selectedModel&&selectedScenario&&!resultScenario&&(
              <div style={{background:"#111827",border:"1px solid #1f2937",borderRadius:10,padding:"12px 14px"}}>
                <div style={{fontSize:"0.65rem",color:"#6b7280",textTransform:"uppercase",marginBottom:7}}>Recapitulatif</div>
                <div style={{fontSize:"0.8rem",color:"#9ca3af",marginBottom:3}}>Modele : <strong style={{color:selectedModel.color}}>{selectedModel.name}</strong></div>
                <div style={{fontSize:"0.8rem",color:"#9ca3af"}}>Scenario : <strong style={{color:selectedScenario.color}}>{selectedScenario.label}</strong></div>
              </div>
            )}
            <button onClick={runScenario} disabled={!selectedModel||!selectedScenario||loadingScenario}
              style={btnStyle(selectedModel&&selectedScenario&&!loadingScenario)}>
              {loadingScenario?"Analyse en cours...":!selectedScenario?"Selectionnez un scenario":`Lancer — ${selectedModel?.name}`}
            </button>
            <ResultCard result={resultScenario} selectedModel={selectedModel} selectedScenario={selectedScenario}/>
          </div>
        </div>
      )}

      {activeTab==="batch" && (
        <div style={{display:"flex",flexDirection:"column",gap:16}}>
          <div className="card">
            <p className="card__title" style={{marginBottom:14}}>Upload Fichier Excel — Analyse en Masse</p>
            <div style={{fontSize:"0.75rem",color:"#9ca3af",padding:"10px 14px",background:"#1f2937",borderRadius:8,borderLeft:"3px solid #3b82f6",marginBottom:16}}>
              Le fichier Excel doit contenir les 20 features comme colonnes. Chaque ligne sera analysee independamment.
            </div>
            <div style={{marginBottom:14}}>
              <div style={{fontSize:"0.7rem",color:"#9ca3af",textTransform:"uppercase",marginBottom:8,letterSpacing:"0.05em"}}>Modele ML pour l analyse</div>
              <div style={{display:"flex",gap:8,flexWrap:"wrap"}}>
                {MODELS_INFO.map(m=>(
                  <button key={m.key} onClick={()=>setSelectedBatchModel(m)} style={{
                    padding:"6px 14px",border:`2px solid ${selectedBatchModel?.key===m.key?m.color:"#374151"}`,
                    borderRadius:8,background:selectedBatchModel?.key===m.key?m.color+"15":"transparent",
                    color:selectedBatchModel?.key===m.key?m.color:"#9ca3af",cursor:"pointer",
                    fontFamily:"JetBrains Mono, monospace",fontWeight:600,fontSize:"0.78rem",transition:"all 0.2s"
                  }}>{m.name}</button>
                ))}
              </div>
            </div>
            <div onClick={()=>fileInputRef.current?.click()} style={{
              border:"2px dashed #374151",borderRadius:12,padding:"32px 24px",textAlign:"center",cursor:"pointer",
              transition:"all 0.2s",background:batchFile?"#22c55e08":"transparent"
            }}
              onDragOver={e=>e.preventDefault()}
              onDrop={e=>{e.preventDefault();const f=e.dataTransfer.files[0];if(f)setBatchFile(f);}}>
              <div style={{fontSize:"2rem",marginBottom:10,color:"#3b82f6",fontFamily:"JetBrains Mono, monospace",fontWeight:700}}>XLS</div>
              <div style={{fontWeight:700,color:batchFile?"#22c55e":"#f1f5f9",fontFamily:"JetBrains Mono, monospace",marginBottom:4}}>
                {batchFile?batchFile.name:"Cliquez ou glissez votre fichier Excel"}
              </div>
              <div style={{fontSize:"0.72rem",color:"#9ca3af"}}>
                {batchFile?`Taille : ${(batchFile.size/1024).toFixed(1)} KB`:"Formats acceptes : .xlsx, .xls, .csv"}
              </div>
              <input ref={fileInputRef} type="file" accept=".xlsx,.xls,.csv" style={{display:"none"}}
                onChange={e=>{if(e.target.files[0])setBatchFile(e.target.files[0]);}}/>
            </div>
            <div style={{display:"flex",gap:10,marginTop:14}}>
              <button onClick={runBatch} disabled={!batchFile||loadingBatch} style={btnStyle(batchFile&&!loadingBatch,"#22c55e")}>
                {loadingBatch?"Analyse en cours...":"Analyser le fichier"}
              </button>
              {batchFile&&(
                <button onClick={()=>{setBatchFile(null);setBatchResults(null);setBatchError(null);}}
                  style={{...btnStyle(true,"#ef4444"),width:"auto",padding:"14px 18px"}}>
                  Effacer
                </button>
              )}
            </div>
            {batchError&&(
              <div style={{marginTop:12,background:"rgba(239,68,68,0.08)",border:"1px solid rgba(239,68,68,0.3)",borderRadius:10,padding:"12px 14px",fontSize:"0.8rem",color:"#ef4444"}}>
                Erreur : {batchError}
              </div>
            )}
          </div>
          {batchResults&&(
            <div className="card">
              <p className="card__title" style={{marginBottom:14}}>Resultats — {batchResults.total} connexions analysees</p>
              <BatchResults data={batchResults}/>
            </div>
          )}
        </div>
      )}

      {activeTab==="manual" && (
        <div style={{display:"flex",flexDirection:"column",gap:16}}>
          <div className="card">
            <p className="card__title" style={{marginBottom:14}}>Saisie Manuelle des Features</p>
            <div style={{fontSize:"0.72rem",color:"#9ca3af",padding:"8px 12px",background:"#1f2937",borderRadius:7,borderLeft:"3px solid #8b5cf6",marginBottom:16}}>
              Remplissez les 21 features manuellement puis cliquez sur Analyser.
            </div>
            <div style={{marginBottom:16}}>
              <div style={{fontSize:"0.7rem",color:"#9ca3af",textTransform:"uppercase",marginBottom:8,letterSpacing:"0.05em"}}>Modele ML</div>
              <div style={{display:"flex",gap:8,flexWrap:"wrap"}}>
                {MODELS_INFO.map(m=>(
                  <button key={m.key} onClick={()=>setManualModel(m)} style={{
                    padding:"6px 14px",border:`2px solid ${manualModel?.key===m.key?m.color:"#374151"}`,
                    borderRadius:8,background:manualModel?.key===m.key?m.color+"15":"transparent",
                    color:manualModel?.key===m.key?m.color:"#9ca3af",cursor:"pointer",
                    fontFamily:"JetBrains Mono, monospace",fontWeight:600,fontSize:"0.78rem",transition:"all 0.2s"
                  }}>{m.name}</button>
                ))}
              </div>
            </div>
            <div style={{display:"grid",gridTemplateColumns:isMobile?"1fr":"1fr 1fr 1fr",gap:10,marginBottom:16}}>
              {MANUAL_FIELDS.map(field=>(
                <div key={field.key}>
                  <div style={{fontSize:"0.65rem",color:"#9ca3af",textTransform:"uppercase",letterSpacing:"0.04em",marginBottom:4}}>{field.label}</div>
                  <input type="number" step="any" value={manualForm[field.key]}
                    onChange={e=>setManualForm(prev=>({...prev,[field.key]:parseFloat(e.target.value)||0}))}
                    style={{background:"#1f2937",border:"1px solid #374151",borderRadius:7,padding:"7px 10px",color:"#f1f5f9",width:"100%",fontSize:"0.82rem",fontFamily:"JetBrains Mono, monospace",outline:"none"}}/>
                </div>
              ))}
            </div>
            <div style={{display:"flex",gap:10}}>
              <button onClick={runManual} disabled={loadingManual} style={btnStyle(!loadingManual,"#8b5cf6")}>
                {loadingManual?"Analyse en cours...":`Analyser — ${manualModel?.name}`}
              </button>
              <button onClick={()=>{setManualForm(initManual());setResultManual(null);}}
                style={{...btnStyle(true,"#374151"),width:"auto",padding:"14px 18px",background:"#374151",boxShadow:"none"}}>
                Reset
              </button>
            </div>
            {manualError&&(
              <div style={{marginTop:12,background:"rgba(239,68,68,0.08)",border:"1px solid rgba(239,68,68,0.3)",borderRadius:10,padding:"12px 14px",fontSize:"0.8rem",color:"#ef4444"}}>
                Erreur : {manualError}
              </div>
            )}
          </div>
          {resultManual&&(
            <div className="card">
              <p className="card__title" style={{marginBottom:12}}>Resultat de l Analyse</p>
              <ResultCard result={resultManual} selectedModel={manualModel} selectedScenario={null}/>
            </div>
          )}
        </div>
      )}
    </div>
  );
}
