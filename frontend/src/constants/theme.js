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
  { key: "knn",              name: "KNN",              acc: 95.22, f1: 95.40, precision: 91.82, recall: 99.27, color: "#10b981", icon: "KN", type: "Supervise", status: "active", available: true,  desc: "K-Nearest Neighbors" },
  { key: "svm",              name: "SVM",              acc: 95.52, f1: 95.70, precision: 91.80, recall: 99.95, color: "#06b6d4", icon: "SV", type: "Supervise", status: "active", available: true,  desc: "Support Vector Machine" },
  { key: "decision_tree",    name: "Decision Tree",    acc: 95.45, f1: 95.63, precision: 91.78, recall: 99.81, color: "#f59e0b", icon: "DT", type: "Supervise", status: "active", available: true,  desc: "Arbre de decision" },
  { key: "random_forest",    name: "Random Forest",    acc: 95.51, f1: 95.69, precision: 91.81, recall: 99.91, color: "#3b82f6", icon: "RF", type: "Supervise", status: "active", available: true,  desc: "Modele principal deploye" },
  { key: "xgboost",          name: "XGBoost",          acc: 95.38, f1: 95.56, precision: 91.82, recall: 99.61, color: "#8b5cf6", icon: "XG", type: "Supervise", status: "active", available: true,  desc: "Gradient Boosting" },
  { key: "isolation_forest", name: "Isolation Forest", acc: 70.67, f1: 70.66, precision: 70.54, recall: 70.79, color: "#f97316", icon: "IF", type: "Non Supervise", status: "active", available: true, desc: "Detection zero-day" },
];

export const NAV_TABS = [
  { id: "dashboard", label: "Dashboard" },
  { id: "predict",   label: "Analyser"  },
  { id: "alerts",    label: "Alertes"   },
  { id: "models",    label: "Modeles"   },
];

