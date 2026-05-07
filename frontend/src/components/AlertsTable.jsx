import { useIsMobile } from '../hooks/useIsMobile';

export default function AlertsTable({ alerts }) {
  const isMobile = useIsMobile();

  if (!alerts?.length) {
    return (
      <div className="card">
        <p className="card__title">🚨 Alertes Récentes</p>
        <p style={{ textAlign: 'center', padding: '24px', color: '#6b7280' }}>
          Aucune alerte pour l'instant
        </p>
      </div>
    );
  }

  return (
    <div className="card">
      <p className="card__title">🚨 Alertes Récentes ({alerts.length})</p>
      <div className="data-table-wrapper">
        <table className="data-table">
          <thead className="data-table__head">
            <tr>
              <th>Horodatage</th>
              <th>Statut</th>
              <th>Confiance</th>
              {!isMobile && <th>Modèle</th>}
              <th>Port Dest.</th>
            </tr>
          </thead>
          <tbody className="data-table__body">
            {alerts.map((a, i) => (
              <tr key={i} className="animate-fadeIn">
                <td style={{ fontFamily: 'monospace', fontSize: '0.78rem', color: '#9ca3af' }}>
                  {a.timestamp?.slice(11, 19) || '—'}
                </td>
                <td>
                  <span className={`badge badge--${a.label === 'Malicious' ? 'malicious' : 'benign'}`}>
                    {a.label === 'Malicious' ? '🚨 Malv.' : '✅ Bénin'}
                  </span>
                </td>
                <td>{a.confidence}%</td>
                {!isMobile && <td style={{ color: '#6b7280', fontSize: '0.78rem' }}>{a.model}</td>}
                <td style={{ fontFamily: 'monospace' }}>:{a.dest_port}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}