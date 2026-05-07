import { NAV_TABS } from '../constants/theme';

export default function NavBar({ activeTab, onTabChange }) {
  return (
    <nav className="navbar">
      {NAV_TABS.map(({ id, label }) => (
        <button
          key={id}
          className={`nav-tab ${activeTab === id ? 'active' : ''}`}
          onClick={() => onTabChange(id)}
        >
          {label}
        </button>
      ))}
    </nav>
  );
}