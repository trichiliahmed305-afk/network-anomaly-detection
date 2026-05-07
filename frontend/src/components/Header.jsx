import { Lock, RefreshCw, Download, Trash2 } from 'lucide-react';
import { useIsMobile } from '../hooks/useIsMobile';

export default function Header({ loading, onRefresh, onDownload, onClear, pdfLoading }) {
  const isMobile = useIsMobile();

  return (
    <header className="header">
      <Lock size={isMobile ? 22 : 26} color="#3b82f6" style={{ flexShrink: 0 }} />
      <div className="header__brand">
        <h1 className="header__title">
          Network Anomaly Detection
        </h1>
        {!isMobile && (
          <p className="header__subtitle">
            Système de détection d'intrusions par Machine Learning — ITGATE PFE 2026
          </p>
        )}
      </div>
      <div className="header__actions">
        <div className="header__status">
          <span className="status-dot status-dot--online" />
          {!isMobile && 'API Online'}
        </div>
        <button
          className="btn btn--ghost btn--icon"
          onClick={onRefresh}
          title="Rafraîchir"
        >
          <RefreshCw
            size={14}
            className={loading ? 'animate-spin' : ''}
          />
        </button>
        <button
          className="btn btn--purple"
          onClick={onDownload}
          disabled={pdfLoading}
          title="Télécharger le rapport PDF"
        >
          <Download size={14} />
          {!isMobile && (pdfLoading ? 'Génération...' : 'Rapport PDF')}
        </button>
        <button
          className="btn btn--danger btn--icon"
          onClick={onClear}
          title="Effacer les alertes"
        >
          <Trash2 size={14} />
        </button>
      </div>
    </header>
  );
}