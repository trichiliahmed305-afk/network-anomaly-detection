import { useState, useEffect, useCallback, useRef } from "react";
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

// Build timeline buckets from a flat list of predictions
function buildTimeline(allPreds) {
  const buckets = {};
  allPreds.forEach(p => {
    const t = (p.timestamp || "").slice(11, 16) || "??:??";
    if (!buckets[t]) buckets[t] = { time: t, malicious: 0, benign: 0 };
    if (p.label === "Malicious") buckets[t].malicious++;
    else                         buckets[t].benign++;
  });
  return Object.values(buckets).slice(-12);
}

export default function App() {
  const isMobile = useIsMobile();

  const [stats,      setStats]      = useState(null);
  const [alerts,     setAlerts]     = useState([]);     // Malicious only
  const [allPreds,   setAllPreds]   = useState([]);     // ALL predictions
  const [loading,    setLoading]    = useState(false);
  const [tab,        setTab]        = useState("dashboard");
  const [pdfLoading, setPdfLoading] = useState(false);

  // Derived: timeline built from allPreds
  const history = buildTimeline(allPreds);

  const refresh = useCallback(async () => {
    setLoading(true);
    try {
      // Always fetch stats + alerts in parallel
      const [sRes, aRes] = await Promise.all([
        apiService.getStats(),
        apiService.getAlerts(),
      ]);

      const raw = sRes.data;
      setStats({
        total_analyzed: raw.total          ?? 0,
        malicious:      raw.malicious      ?? 0,
        benign:         raw.benign         ?? 0,
        detection_rate: raw.malicious_pct  ?? 0,
        avg_confidence: raw.avg_confidence ?? 0,
      });

      // alerts = Malicious only
      const mal = aRes.data.alerts || aRes.data.alertes || [];
      setAlerts(mal);

      // Try /history for all predictions (timeline)
      // Falls back silently if endpoint not available yet
      try {
        const hRes   = await apiService.getHistory();
        const hPreds = hRes.data.history || [];
        if (hPreds.length > 0) {
          setAllPreds(hPreds);
        }
      } catch {
        // /history not available — build timeline from alerts only
        // This is a degraded mode: timeline shows only malicious
      }

    } catch (e) {
      console.error("Refresh error:", e);
    }
    setLoading(false);
  }, []);

  useEffect(() => { refresh(); }, [refresh]);
  useEffect(() => {
    const t = setInterval(refresh, 5000);
    return () => clearInterval(t);
  }, [refresh]);

  // Called after each prediction — append locally for instant timeline update
  const onResult = useCallback((prediction) => {
    if (prediction) {
      setAllPreds(prev => [...prev, {
        timestamp:  new Date().toISOString(),
        label:      prediction.label,
        confidence: prediction.confidence,
        model:      prediction.model,
      }]);
    }
    setTimeout(refresh, 600);
  }, [refresh]);

  const handleClearAlerts = async () => {
    try {
      await apiService.clearAlerts();
      setAlerts([]);
      setAllPreds([]);
      setStats({ total_analyzed:0, malicious:0, benign:0, detection_rate:0 });
    } catch (e) { console.error(e); }
  };

  const handleDownloadPDF = async () => {
    setPdfLoading(true);
    try {
      const response = await apiService.downloadReport();
      const url  = URL.createObjectURL(response.data);
      const link = document.createElement("a");
      link.href     = url;
      link.download = `ITGATE_Report_${new Date().toISOString().slice(0,10)}.pdf`;
      document.body.appendChild(link);
      link.click();
      document.body.removeChild(link);
      URL.revokeObjectURL(url);
    } catch (e) {
      alert("Erreur PDF: " + (e.response?.data?.message || e.message));
    }
    setPdfLoading(false);
  };

  const pieData = stats && (stats.malicious > 0 || stats.benign > 0) ? [
    { name: "Malveillant", value: stats.malicious, color: COLORS.malicious },
    { name: "Benin",       value: stats.benign,    color: COLORS.benign    },
  ].filter(d => d.value > 0) : [];

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
            <div className="grid grid--4col">
              <StatCard icon={Activity}      label="Total Analysees"  value={stats?.total_analyzed ?? 0}        color={COLORS.blue} />
              <StatCard icon={AlertTriangle} label="Malveillantes"    value={stats?.malicious ?? 0}             color={COLORS.malicious} />
              <StatCard icon={CheckCircle}   label="Benignes"         value={stats?.benign ?? 0}                color={COLORS.benign} />
              <StatCard icon={Shield}        label="Taux Detection"   value={`${stats?.detection_rate ?? 0}%`} color={COLORS.yellow} />
            </div>

            <div className="grid grid--2col">
              {/* Timeline — built from allPreds locally */}
              <div className="card">
                <p className="card__title">Timeline des Detections</p>
                {history.length > 0 ? (
                  <ResponsiveContainer width="100%" height={isMobile ? 200 : 220}>
                    <LineChart data={history}>
                      <CartesianGrid strokeDasharray="3 3" stroke={COLORS.border} />
                      <XAxis dataKey="time" stroke={COLORS.text2} fontSize={10} />
                      <YAxis stroke={COLORS.text2} fontSize={10} width={28} />
                      <Tooltip contentStyle={{ background:"#1f2937", border:`1px solid ${COLORS.border}`, fontSize:12 }} />
                      <Legend wrapperStyle={{ fontSize:12 }} />
                      <Line type="monotone" dataKey="malicious" stroke={COLORS.malicious} strokeWidth={2} dot={true} name="Malveillant" />
                      <Line type="monotone" dataKey="benign"    stroke={COLORS.benign}    strokeWidth={2} dot={true} name="Benin" />
                    </LineChart>
                  </ResponsiveContainer>
                ) : (
                  <div style={{ height:220, display:"flex", alignItems:"center",
                                justifyContent:"center", color:COLORS.text2,
                                fontSize:"0.85rem", flexDirection:"column", gap:8 }}>
                    <span style={{ fontSize:"1.5rem" }}>📊</span>
                    Lancez des tests pour voir la timeline
                  </div>
                )}
              </div>

              {/* Pie chart */}
              <div className="card">
                <p className="card__title">Distribution du Trafic</p>
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
                                justifyContent:"center", color:COLORS.text2,
                                fontSize:"0.85rem", flexDirection:"column", gap:8 }}>
                    <span style={{ fontSize:"1.5rem" }}>🥧</span>
                    Aucune donnee disponible
                  </div>
                )}
              </div>
            </div>

            <AlertsTable alerts={alerts.slice(0, 8)} title="Alertes Recentes (Malveillant)" />
            <AttackSimulator onResult={onResult} />
          </>
        )}

        {tab === "analysis" && <AnalysisPage onResult={onResult} />}
        {tab === "alerts"   && <AlertsTable alerts={alerts} title={`Toutes les Alertes (${alerts.length})`} />}
        {tab === "models"   && <ModelsTab />}

      </main>
    </div>
  );
}
