export const COLORS = {
  malicious: "#ef4444",
  benign:    "#22c55e",
  blue:      "#3b82f6",
  purple:    "#8b5cf6",
  yellow:    "#f59e0b",
  card:      "#111827",
  border:    "#1f2937",
  text2:     "#9ca3af",
  warning:   "#f97316",
};

export const RISK_LEVELS = {
  LOW:      { label: "Faible",   color: "#22c55e" },
  MEDIUM:   { label: "Moyen",    color: "#f59e0b" },
  HIGH:     { label: "Eleve",    color: "#f97316" },
  CRITICAL: { label: "Critique", color: "#ef4444" },
};

export const MODELS_INFO = [
  { key: "knn",              name: "KNN",              acc: 99.48, f1: 99.48, precision: 99.03, recall: 99.93, color: "#10b981", icon: "KN", type: "Supervise", status: "active", available: true,  desc: "K-Nearest Neighbors" },
  { key: "svm",              name: "SVM",              acc: 96.93, f1: 97.05, precision: 94.31, recall: 99.93, color: "#06b6d4", icon: "SV", type: "Supervise", status: "active", available: true,  desc: "Support Vector Machine" },
  { key: "decision_tree",    name: "Decision Tree",    acc: 99.95, f1: 99.95, precision: 99.95, recall: 99.94, color: "#f59e0b", icon: "DT", type: "Supervise", status: "active", available: true,  desc: "Arbre de decision" },
  { key: "random_forest",    name: "Random Forest",    acc: 99.38, f1: 99.38, precision: 98.89, recall: 99.86, color: "#3b82f6", icon: "RF", type: "Supervise", status: "active", available: true,  desc: "Modele principal deploye" },
  { key: "xgboost",          name: "XGBoost",          acc: 99.90, f1: 99.89, precision: 99.83, recall: 99.95, color: "#8b5cf6", icon: "XG", type: "Supervise", status: "active", available: true,  desc: "Gradient Boosting" },
  { key: "isolation_forest", name: "Isolation Forest", acc: 56.02, f1: 56.17, precision: 55.87, recall: 56.47, color: "#f97316", icon: "IF", type: "Non Supervise", status: "active", available: true, desc: "Detection zero-day" },
];

export const NAV_TABS = [
  { id: "dashboard", label: "Dashboard" },
  { id: "predict",   label: "Analyser"  },
  { id: "alerts",    label: "Alertes"   },
  { id: "models",    label: "Modeles"   },
];
