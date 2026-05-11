// ============================================================
// api.js - Service API ITGATE v4.0
// Tous les appels vers le backend FastAPI CICIDS-2017
// ============================================================

import axios from "axios";

const BASE_URL = "https://itgate-anomaly-api.onrender.com";

const api = axios.create({
  baseURL: BASE_URL,
  timeout: 30000,
  headers: { "Content-Type": "application/json" },
});

export const apiService = {
  // Prediction unique
  predict: (data) => api.post("/predict", data),

  // Stats — utilise predictions[] cote backend (Benign + Malicious)
  getStats: () => api.get("/stats"),

  // Alertes — Malicious ONLY
  getAlerts: () => api.get("/alerts"),

  // Historique complet — toutes les predictions
  getHistory: () => api.get("/history"),

  // Status
  getStatus: () => api.get("/status"),

  // Modeles avec metriques reelles
  getModels: () => api.get("/models"),

  // Effacer alertes ET predictions
  clearAlerts: () => api.delete("/alerts/clear"),

  // Rapport PDF
  downloadReport: () => api.get("/report", { responseType: "blob" }),
};
