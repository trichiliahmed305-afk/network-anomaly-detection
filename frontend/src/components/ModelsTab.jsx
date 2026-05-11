import { useState, useEffect } from "react";
import { apiService } from "../services/api";

// ============================================================
// ModelsTab.jsx — affiche les metriques REELLES des modeles
// Les metriques viennent de /models qui retourne les valeurs
// exactes du notebook CICIDS-2017 (MODEL_METRICS dans main.py)
// ============================================================

const MODEL_COLORS = {
  random_forest:    "#3b82f6",
  xgboost:          "#22c55e",
  decision_tree:    "#f59e0b",
  knn:              "#8b5cf6",
  svm:              "#06b6d4",
  isolation_forest: "#6b7280",
};

export default function ModelsTab() {
  const [models,  setModels]  = useState([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    apiService.getModels()
      .then(r => setModels(r.data.available || []))
      .catch(console.error)
      .finally(() => setLoading(false));
  }, []);

  if (loading) return (
    <div style={{ textAlign:"center", padding:40, color:"#9ca3af" }}>
      Chargement des modeles...
    </div>
  );

  return (
    <div>
      <div className="card" style={{ marginBottom:16 }}>
        <p className="card__title">Modeles ML — CICIDS-2017</p>
        <p style={{ fontSize:"0.8rem", color:"#9ca3af", margin:0 }}>
          Metriques reelles obtenues lors de l'entrainement sur le dataset CICIDS-2017.
          Dataset : 2,099,971 connexions — 27 types d'attaques — sklearn 1.6.1
        </p>
      </div>

      <div className="grid grid--2col">
        {models.map(model => {
          const color  = MODEL_COLORS[model.key] || "#6b7280";
          const isIso  = model.key === "isolation_forest";

          return (
            <div key={model.key} className="card"
              style={{ borderLeft:`3px solid ${color}` }}>

              {/* Model header */}
              <div style={{ display:"flex", justifyContent:"space-between",
                            alignItems:"center", marginBottom:14 }}>
                <div>
                  <div style={{ fontWeight:700, fontSize:"0.95rem", color }}>
                    {model.name}
                  </div>
                  <div style={{ fontSize:"0.72rem", color:"#6b7280", marginTop:2 }}>
                    {isIso ? "Non-supervise — Detection zero-day"
                           : "Supervise — Classification binaire"}
                  </div>
                </div>
                <div style={{
                  background: color + "20", color, borderRadius:6,
                  padding:"4px 10px", fontSize:"0.78rem", fontWeight:700
                }}>
                  {isIso ? "ANOMALIE" : "CLASSIF."}
                </div>
              </div>

              {/* Metrics */}
              {isIso ? (
                <div style={{ color:"#9ca3af", fontSize:"0.8rem", padding:"10px 0" }}>
                  L'Isolation Forest est un modele non-supervise.
                  Il ne possede pas de metriques de classification standard.
                  Accuracy sur test set : <strong style={{ color:"#f59e0b" }}>
                    {model.accuracy}%
                  </strong>
                </div>
              ) : (
                <div style={{ display:"grid", gridTemplateColumns:"1fr 1fr", gap:10 }}>
                  {[
                    { label: "Accuracy",  value: model.accuracy  },
                    { label: "Precision", value: model.precision },
                    { label: "Recall",    value: model.recall    },
                    { label: "F1-Score",  value: model.f1_score  },
                  ].map(({ label, value }) => (
                    <div key={label} style={{
                      background:"#1f2937", borderRadius:8, padding:"10px 12px"
                    }}>
                      <div style={{ fontSize:"0.7rem", color:"#9ca3af",
                                    marginBottom:4 }}>
                        {label}
                      </div>
                      <div style={{ fontSize:"1.1rem", fontWeight:700, color }}>
                        {value?.toFixed(3)}%
                      </div>
                      {/* Progress bar */}
                      <div style={{ marginTop:6, height:4, background:"#374151",
                                    borderRadius:2, overflow:"hidden" }}>
                        <div style={{
                          height:"100%", borderRadius:2,
                          background:color,
                          width:`${Math.min(value || 0, 100)}%`,
                          transition:"width 0.6s ease"
                        }} />
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </div>
          );
        })}
      </div>
    </div>
  );
}
