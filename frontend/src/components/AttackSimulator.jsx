import { COLORS } from "../constants/theme";

// ============================================================
// AttackSimulator.jsx - SIMPLIFIE
// Les scenarios complexes ont ete supprimes.
// Le workflow principal est desormais le CSV import.
// Ce composant affiche uniquement un message de redirection.
// ============================================================

export default function AttackSimulator({ onResult }) {
  return (
    <div className="card">
      <p className="card__title">Analyse de Trafic Reseau</p>
      <div style={{ padding: "20px 0", color: "#9ca3af", fontSize: "0.85rem",
                    textAlign: "center" }}>
        <div style={{ fontSize: "2rem", marginBottom: 12 }}>📊</div>
        <div style={{ marginBottom: 8, color: "#f1f5f9", fontWeight: 600 }}>
          Utilisez l'onglet Analyse pour tester le systeme
        </div>
        <div style={{ fontSize: "0.78rem", color: "#6b7280" }}>
          Import CSV/Excel avec donnees reelles CICIDS-2017
          ou saisie manuelle des 20 features
        </div>
      </div>
    </div>
  );
}
