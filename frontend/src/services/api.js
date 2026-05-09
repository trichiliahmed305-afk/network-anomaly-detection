import axios from "axios";

const BASE_URL = "https://itgate-anomaly-api.onrender.com";

const api = axios.create({ baseURL: BASE_URL, timeout: 30000 });

export const apiService = {
  getStatus:      ()                    => api.get("/status"),
  getMappings:    ()                    => api.get("/debug/mappings"),
  getStats:       ()                    => api.get("/stats"),
  getAlerts:      (limit = 100)         => api.get(`/alerts?limit=${limit}`),
  clearAlerts:    ()                    => api.delete("/alerts"),
  predict:        (payload)             => api.post("/predict", payload),
  predictBatch:   (formData, modelKey)  => api.post(
    "/predict/batch?model=" + (modelKey || "random_forest"),
    formData,
    { headers: { "Content-Type": "multipart/form-data" } }
  ),
  downloadReport: () => api.get("/report", {
    responseType: "blob",
    headers: { Accept: "application/pdf" }
  }),
};

export default apiService;
