import axios from "axios";

const BASE_URL = "https://itgate-anomaly-api.onrender.com";

const api = axios.create({ baseURL: BASE_URL, timeout: 10000 });

export const apiService = {
  getStatus:      ()            => api.get("/status"),
  getMappings:    ()            => api.get("/debug/mappings"),
  getStats:       ()            => api.get("/stats"),
  getAlerts:      (limit = 100) => api.get(`/alerts?limit=${limit}`),
  clearAlerts:    ()            => api.delete("/alerts"),
  predict:        (payload)     => api.post("/predict", payload),
  downloadReport: ()            => api.get("/report", {
    responseType: "blob",
    headers: { Accept: "application/pdf" }
  }),
};

export default apiService;