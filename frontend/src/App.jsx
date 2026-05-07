import { useState, useEffect, useCallback } from "react";
import { Activity, AlertTriangle, CheckCircle, Shield } from "lucide-react";
import {
  LineChart, Line, PieChart, Pie, Cell,
  XAxis, YAxis, CartesianGrid, Tooltip,
  ResponsiveContainer, Legend
} from "recharts";

import Header           from "./components/Header";
import NavBar           from "./components/NavBar";
import StatCard         from "./components/StatCard";
import AlertsTable      from "./components/AlertsTable";
import ModelsTab        from "./components/ModelsTab";
import PredictForm      from "./components/PredictForm";
import AttackSimulator  from "./components/AttackSimulator";

import { apiService }  from "./services/api";
import { useIsMobile } from "./hooks/useIsMobile";
import { COLORS }      from "./constants/theme";

export default function App() {
  const isMobile = useIsMobile();
  const [stats,      setStats]      = useState(null);
  const [alerts,     setAlerts]     = useState([]);
  const [history,    setHistory]    = useState([]);
  const [loading,    setLoading]    = useState(false);
  const [tab,        setTab]        = useState("dashboard");
  const [pdfLoading, setPdfLoading] = useState(false);
  const [mappings,   setMappings]   = useState(null);

  useEffect(() => {
    apiService.getMappings()
      .then(res => setMappings(res.data.label_mappings))
      .catch(console.error);
  }, []);

  const refresh = useCallback(async () => {
    setLoading(true);
    try {
      const [s, a] = await Promise.all([
        apiService.getStats(),
        apiService.getAlerts(),
      ]);
      const raw = s.data;
      setStats({
        total_analyzed: raw.total_analyses     ?? 0,
        malicious:      raw.trafic_malveillant ?? 0,
        benign:         raw.trafic_benin       ?? 0,
        detection_rate: raw.taux_detection     ?? 0,
        models:         raw.models             ?? {},
      });
      setAlerts(a.data.alertes || a.data.alerts || []);
    } catch (e) { console.error(e); }
    setLoading(false);
  }, []);

  useEffect(() => { refresh(); }, [refresh]);

  useEffect(() => {
    const t = setInterval(refresh, 5000);
    return () => clearInterval(t);
  }, [refresh]);

  useEffect(() => {
    const buckets = {};
    alerts.forEach(a => {
      const t = a.timestamp?.slice(11, 16) || "?";
      if (!buckets[t]) buckets[t] = { time: t, malicious: 0, benign: 0 };
      a.label === "Malicious" ? buckets[t].malicious++ : buckets[t].benign++;
    });
    setHistory(Object.values(buckets).slice(-12));
  }, [alerts]);

  const handleClearAlerts = async () => {
    await apiService.clearAlerts();
    refresh();
  };

  const handleDownloadPDF = async () => {
    setPdfLoading(true);
    try {
      const response = await apiService.downloadReport();
      const url  = URL.createObjectURL(response.data);
      const link = document.createElement("a");
      link.href     = url;
      link.download = `anomaly_report_${new Date().toISOString().slice(0, 10)}.pdf`;
      document.body.appendChild(link);
      link.click();
      document.body.removeChild(link);
      URL.revokeObjectURL(url);
    } catch (e) {
      alert("Erreur PDF: " + (e.response?.data?.message || e.message));
    }
    setPdfLoading(false);
  };

  const pieData = stats ? [
    { name: "Malveillant", value: stats.malicious, color: COLORS.malicious },
    { name: "Benin",       value: stats.benign,    color: COLORS.benign    },
  ] : [];

  const modelData = stats
    ? Object.entries(stats.models || {}).map(([k, v]) => ({
        name:     k.replace(/_/g, " "),
        accuracy: v.accuracy,
        f1:       v.f1_score ?? v.f1,
      }))
    : [];

  return (
    <div style={{ minHeight: "100vh", background: "#0a0e1a", overflowX: "hidden" }}>

      <Header
        loading={loading}
        pdfLoading={pdfLoading}
        onRefresh={refresh}
        onDownload={handleDownloadPDF}
        onClear={handleClearAlerts}
      />

      <NavBar activeTab={tab} onTabChange={setTab} />

      <main className="page-content">

        {/* ── DASHBOARD ── */}
        {tab === "dashboard" && (
          <>
            <div className="grid grid--4col">
              <StatCard icon={Activity}      label="Total Analysees"  value={stats?.total_analyzed ?? 0}        color={COLORS.blue} />
              <StatCard icon={AlertTriangle} label="Malveillantes"    value={stats?.malicious ?? 0}             color={COLORS.malicious} />
              <StatCard icon={CheckCircle}   label="Benignes"         value={stats?.benign ?? 0}                color={COLORS.benign} />
              <StatCard icon={Shield}        label="Taux Detection"   value={`${stats?.detection_rate ?? 0}%`} color={COLORS.yellow} />
            </div>

            <div className="grid grid--2col">
              <div className="card">
                <p className="card__title">Timeline des Detections</p>
                <ResponsiveContainer width="100%" height={isMobile ? 200 : 220}>
                  <LineChart data={history}>
                    <CartesianGrid strokeDasharray="3 3" stroke={COLORS.border} />
                    <XAxis dataKey="time" stroke={COLORS.text2} fontSize={10} />
                    <YAxis stroke={COLORS.text2} fontSize={10} width={28} />
                    <Tooltip contentStyle={{ background: "#1f2937", border: `1px solid ${COLORS.border}`, fontSize: 12 }} />
                    <Legend wrapperStyle={{ fontSize: 12 }} />
                    <Line type="monotone" dataKey="malicious" stroke={COLORS.malicious} strokeWidth={2} dot={false} name="Malveillant" />
                    <Line type="monotone" dataKey="benign"    stroke={COLORS.benign}    strokeWidth={2} dot={false} name="Benin" />
                  </LineChart>
                </ResponsiveContainer>
              </div>

              <div className="card">
                <p className="card__title">Distribution</p>
                <ResponsiveContainer width="100%" height={isMobile ? 200 : 220}>
                  <PieChart>
                    <Pie
                      data={pieData}
                      cx="50%" cy="50%"
                      innerRadius={isMobile ? 40 : 55}
                      outerRadius={isMobile ? 65 : 85}
                      dataKey="value"
                      label={isMobile ? false : ({ name, percent }) => `${(percent * 100).toFixed(0)}%`}
                      labelLine={false}
                      fontSize={11}
                    >
                      {pieData.map((e, i) => <Cell key={i} fill={e.color} />)}
                    </Pie>
                    <Tooltip contentStyle={{ background: "#1f2937", border: `1px solid ${COLORS.border}`, fontSize: 12 }} />
                    <Legend wrapperStyle={{ fontSize: 12 }} />
                  </PieChart>
                </ResponsiveContainer>
              </div>
            </div>

            <AlertsTable alerts={alerts.slice(0, 8)} />

            <AttackSimulator onResult={() => setTimeout(refresh, 500)} />
          </>
        )}

        {/* ── PREDICT ── */}
        {tab === "predict" && (
          <div style={{ maxWidth: 700, margin: "0 auto" }}>
            <PredictForm
              onResult={() => setTimeout(refresh, 300)}
              mappings={mappings}
            />
          </div>
        )}

        {/* ── ALERTS ── */}
        {tab === "alerts" && <AlertsTable alerts={alerts} />}

        {/* ── MODELS ── */}
        {tab === "models" && <ModelsTab modelData={modelData} />}

      </main>
    </div>
  );
}