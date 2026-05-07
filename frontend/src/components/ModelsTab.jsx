import {
  BarChart, Bar, XAxis, YAxis, CartesianGrid,
  Tooltip, Legend, ResponsiveContainer
} from "recharts";
import { MODELS_INFO, COLORS } from "../constants/theme";
import { useIsMobile } from "../hooks/useIsMobile";

export default function ModelsTab({ modelData }) {
  const isMobile = useIsMobile();

  return (
    <div style={{ display: "flex", flexDirection: "column", gap: 20 }}>

      {/* ── Titre ── */}
      <div>
        <h2 style={{ fontFamily: "JetBrains Mono, monospace", fontSize: "1rem", marginBottom: 4 }}>
          🤖 Modèles ML entraînés
        </h2>
        <p style={{ fontSize: "0.8rem", color: COLORS.text2 }}>
          6 modèles comparés — Random Forest sélectionné pour la production
        </p>
      </div>

      {/* ── Grille des 6 modèles ── */}
      <div className="grid grid--3col">
        {MODELS_INFO.map((m) => (
          <div key={m.key} className="model-card" style={{ "--model-color": m.color }}>

            {/* Badge status */}
            <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", marginBottom: 8 }}>
              <span style={{ fontSize: "1.6rem" }}>{m.icon}</span>
              <span style={{
                fontSize: "0.65rem", fontWeight: 700, padding: "3px 8px",
                borderRadius: 999, textTransform: "uppercase",
                background: m.status === "active" ? "rgba(34,197,94,0.15)" : "rgba(156,163,175,0.15)",
                color: m.status === "active" ? "#22c55e" : "#9ca3af",
              }}>
                {m.status === "active" ? "● Actif" : "○ Entraîné"}
              </span>
            </div>

            <h3 style={{ color: m.color, marginBottom: 2, fontSize: "0.95rem" }}>{m.name}</h3>
            <p style={{ fontSize: "0.72rem", color: COLORS.text2, marginBottom: 4 }}>{m.desc}</p>

            <span style={{
              display: "inline-block", fontSize: "0.65rem", fontWeight: 700,
              padding: "2px 8px", borderRadius: 999, marginBottom: 12,
              background: m.color + "20", color: m.color
            }}>
              {m.type}
            </span>

            {/* Métriques */}
            {[["Accuracy", m.acc], ["F1 Score", m.f1]].map(([label, val]) => (
              <div key={label} style={{ marginBottom: 8 }}>
                <div style={{ display: "flex", justifyContent: "space-between", marginBottom: 4 }}>
                  <span style={{ fontSize: "0.75rem", color: COLORS.text2 }}>{label}</span>
                  <span style={{ fontSize: "0.75rem", fontWeight: 700, color: m.color }}>{val}%</span>
                </div>
                <div style={{ background: "#1f2937", borderRadius: 4, height: 5 }}>
                  <div style={{
                    width: `${val}%`, height: "100%",
                    background: m.color, borderRadius: 4,
                    transition: "width 1.2s cubic-bezier(0.4,0,0.2,1)"
                  }} />
                </div>
              </div>
            ))}
          </div>
        ))}
      </div>

      {/* ── Graphique comparaison ── */}
      <div className="card">
        <p className="card__title">📊 Comparaison des performances</p>
        <ResponsiveContainer width="100%" height={isMobile ? 220 : 300}>
          <BarChart
            data={MODELS_INFO.map(m => ({
              name: m.name.replace(" ", "\n"),
              Accuracy: m.acc,
              "F1 Score": m.f1,
            }))}
            margin={{ top: 5, right: 16, left: 0, bottom: 5 }}
          >
            <CartesianGrid strokeDasharray="3 3" stroke={COLORS.border} />
            <XAxis dataKey="name" stroke={COLORS.text2} fontSize={isMobile ? 9 : 11} interval={0} />
            <YAxis stroke={COLORS.text2} fontSize={10} domain={[0, 100]} width={32} />
            <Tooltip contentStyle={{ background: "#1f2937", border: `1px solid ${COLORS.border}`, fontSize: 12 }} />
            <Legend wrapperStyle={{ fontSize: 12 }} />
            <Bar dataKey="Accuracy"  fill={COLORS.blue}   radius={[4, 4, 0, 0]} />
            <Bar dataKey="F1 Score"  fill={COLORS.purple} radius={[4, 4, 0, 0]} />
          </BarChart>
        </ResponsiveContainer>
      </div>

      {/* ── Tableau récapitulatif ── */}
      <div className="card">
        <p className="card__title">📋 Tableau récapitulatif</p>
        <div className="data-table-wrapper">
          <table className="data-table">
            <thead className="data-table__head">
              <tr>
                <th>Modèle</th>
                <th>Type</th>
                <th>Accuracy</th>
                <th>F1 Score</th>
                <th>Statut</th>
              </tr>
            </thead>
            <tbody className="data-table__body">
              {MODELS_INFO.map(m => (
                <tr key={m.key}>
                  <td>
                    <span style={{ marginRight: 8 }}>{m.icon}</span>
                    <span style={{ color: m.color, fontWeight: 600 }}>{m.name}</span>
                  </td>
                  <td>
                    <span style={{
                      fontSize: "0.7rem", padding: "2px 8px", borderRadius: 999,
                      background: m.color + "20", color: m.color
                    }}>
                      {m.type}
                    </span>
                  </td>
                  <td style={{ fontWeight: 600, color: m.acc > 90 ? COLORS.benign : COLORS.warning }}>
                    {m.acc}%
                  </td>
                  <td style={{ fontWeight: 600, color: m.f1 > 90 ? COLORS.benign : COLORS.warning }}>
                    {m.f1}%
                  </td>
                  <td>
                    <span style={{
                      fontSize: "0.7rem", padding: "2px 8px", borderRadius: 999, fontWeight: 700,
                      background: m.status === "active" ? "rgba(34,197,94,0.15)" : "rgba(156,163,175,0.15)",
                      color: m.status === "active" ? "#22c55e" : "#9ca3af",
                    }}>
                      {m.status === "active" ? "● Actif" : "○ Entraîné"}
                    </span>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}