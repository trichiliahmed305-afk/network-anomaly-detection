export default function StatCard({ icon: Icon, label, value, color }) {
  return (
    <div className="stat-card">
      <div
        className="stat-card__icon"
        style={{ background: color + '20' }}
      >
        <Icon size={22} color={color} />
      </div>
      <div style={{ minWidth: 0 }}>
        <div className="stat-card__value" style={{ color }}>
          {value}
        </div>
        <div className="stat-card__label">{label}</div>
      </div>
    </div>
  );
}