import { useState, useEffect, useCallback } from "react";
import { Activity, AlertTriangle, CheckCircle, Shield } from "lucide-react";
import {
  LineChart, Line, PieChart, Pie, Cell,
  XAxis, YAxis, CartesianGrid, Tooltip,
  ResponsiveContainer, Legend
} from "recharts";

import Header          from "./components/Header";
import NavBar          from "./components/NavBar";
import StatCard        from "./components/StatCard";
import AlertsTable     from "./components/AlertsTable";
import ModelsTab       from "./components/ModelsTab";
import AttackSimulator from "./components/AttackSimulator";
import AnalysisPage    from "./components/AnalysisPage";

import { apiService }  from "./services/api";
import { useIsMobile } from "./hooks/useIsMobile";
import { COLORS }      from "./constants/theme";

export default function App() {
  const isMobile                    = useIsMobile();
  const [stats,      setStats]      = useState(null);
  const [alerts,     setAlerts]     = useState([]);   // Malicious only
  const [history,    setHistory]    = useState([]);   // timeline buckets
  const [loading,    setLoading]    = useState(false);
  const [tab,        setTab]        = useState("dashboard");
  const [pdfLoading, setPdfLoading] = useState(false);

  const refresh = useCallback(async () => {
    setLoading(true);
    try {
      const [s, a] = await Promise.all([
        apiService.getStats(),
        apiService.getAlerts(),
      ]);

      const raw = s.data;
      // Correct field mapping for CICIDS-2017 backend v4.0
      setStats({
        total_analyzed: raw.total          ?? 0,
        malicious:      raw.malicious      ?? 0,
        benign:         raw.benign         ?? 0,
        detection_rate: raw.malicious_pct  ?? 0,
        avg_confidence: raw.avg_confidence ?? 0,
      });

      // alerts = Malicious only (from /alerts endpoint)
      setAlerts(a.data.alerts || a.data.alertes || []);

    } catch (e) {
      console.error("Refresh error:", e);
    }
    setLoading(false);
  }, []);

  // Fetch history separately for the timeline chart
  const refreshHistory = useCallback(async () => {
    try {
      const h = await apiService.getHistory();
      const allPredictions = h.data.history || [];

      // Build time buckets from all predictions
      const buckets = {};
      allPredictions.forEach(p => {
        const t = p.timestamp?.slice(11, 16) || "?";
        if (!buckets[t]) buckets[t] = { time: t, malicious: 0, benign: 0 };
        if (p.label === "Malicious") buckets[t].malicious++;
        else                         buckets[t].benign++;
      });
      setHistory(Object.values(buckets).slice(-12));
    } catch {
      // /history may not exist yet — fall back silently
    }
  }, []);

  useEffect(() => {
    refresh();
    refreshHistory();
  }, [refresh, refreshHistory]);

  useEffect(() => {
    const t = setInterval(() => { refresh(); refreshHistory(); }, 5000);
    return () => clearInterval(t);
  }, [refresh, refreshHistory]);

  const handleClearAlerts = async () => {
    try { await apiService.clearAlerts(); refresh(); refreshHistory(); }
    catch (e) { console.error(e); }
  };

  const handleDownloadPDF = async () => {
    setPdfLoading(true);
    try {
      const response = await apiService.downloadReport();
      const url  = URL.createObjectURL(response.data);
      const link = document.createElement("a");
      link.href = url;
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
  ].filter(d => d.value > 0) : [];

  const onResult = () => setTimeout(() => { refresh(); refreshHistory(); }, 600);

  return (
    <div style={{ minHeight:"100vh", background:"#0a0e1a", overflowX:"hidden" }}>
      <Header
        loading={loading} pdfLoading={pdfLoading}
        onRefresh={refresh} onDownload={handleDownloadPDF}
        onClear={handleClearAlerts}
      />
      <NavBar activeTab={tab} onTabChange={setTab} />
      <main className="page-content">

        {/* ── DASHBOARD ─────────────────────────────────── */}
        {tab === "dashboard" && (
          <>
            {/* Stats cards — from /stats which uses all predictions */}
            <div className="grid grid--4col">
              <StatCard icon={Activity}      label="Total Analysees"  value={stats?.total_analyzed ?? 0}        color={COLORS.blue} />
              <StatCard icon={AlertTriangle} label="Malveillantes"    value={stats?.malicious ?? 0}             color={COLORS.malicious} />
              <StatCard icon={CheckCircle}   label="Benignes"         value={stats?.benign ?? 0}                color={COLORS.benign} />
              <StatCard icon={Shield}        label="Taux Detection"   value={`${stats?.detection_rate ?? 0}%`} color={COLORS.yellow} />
            </div>

            {/* Charts */}
            <div className="grid grid--2col">
              <div className="card">
                <p className="card__title">Timeline des Detections</p>
                <ResponsiveContainer width="100%" height={isMobile ? 200 : 220}>
                  <LineChart data={history}>
                    <CartesianGrid strokeDasharray="3 3" stroke={COLORS.border} />
                    <XAxis dataKey="time" stroke={COLORS.text2} fontSize={10} />
                    <YAxis stroke={COLORS.text2} fontSize={10} width={28} />
                    <Tooltip contentStyle={{ background:"#1f2937", border:`1px solid ${COLORS.border}`, fontSize:12 }} />
                    <Legend wrapperStyle={{ fontSize:12 }} />
                    <Line type="monotone" dataKey="malicious" stroke={COLORS.malicious} strokeWidth={2} dot={false} name="Malveillant" />
                    <Line type="monotone" dataKey="benign"    stroke={COLORS.benign}    strokeWidth={2} dot={false} name="Benin" />
                  </LineChart>
                </ResponsiveContainer>
              </div>

              <div className="card">
                <p className="card__title">Distribution</p>
                {pieData.length > 0 ? (
                  <ResponsiveContainer width="100%" height={isMobile ? 200 : 220}>
                    <PieChart>
                      <Pie data={pieData} cx="50%" cy="50%"
                        innerRadius={isMobile?40:55} outerRadius={isMobile?65:85}
                        dataKey="value"
                        label={({ name, percent }) => `${name} ${(percent*100).toFixed(0)}%`}
                        labelLine={true} fontSize={11}>
                        {pieData.map((e, i) => <Cell key={i} fill={e.color} />)}
                      </Pie>
                      <Tooltip contentStyle={{ background:"#1f2937", border:`1px solid ${COLORS.border}`, fontSize:12 }} />
                      <Legend wrapperStyle={{ fontSize:12 }} />
                    </PieChart>
                  </ResponsiveContainer>
                ) : (
                  <div style={{ height:220, display:"flex", alignItems:"center",
                                justifyContent:"center", color:COLORS.text2, fontSize:"0.85rem" }}>
                    Aucune donnee — lancez un test
                  </div>
                )}
              </div>
            </div>

            {/* Recent alerts — Malicious only */}
            <AlertsTable alerts={alerts.slice(0, 8)} title="Alertes Recentes" />

            {/* Scenario simulator */}
            <AttackSimulator onResult={onResult} />
          </>
        )}

        {/* ── ANALYSE ───────────────────────────────────── */}
        {tab === "analysis" && <AnalysisPage onResult={onResult} />}

        {/* ── ALERTES ───────────────────────────────────── */}
        {tab === "alerts" && (
          <AlertsTable alerts={alerts} title={`Toutes les Alertes (${alerts.length})`} />
        )}

        {/* ── MODELES ───────────────────────────────────── */}
        {tab === "models" && <ModelsTab />}

      </main>
    </div>
  );
}
