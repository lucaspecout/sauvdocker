import { NavLink, Route, Routes } from 'react-router-dom';
import Dashboard from './pages/Dashboard';
import Resources from './pages/Resources';
import BackupPlans from './pages/BackupPlans';
import Backups from './pages/Backups';
import RestoreWizard from './pages/RestoreWizard';
import Settings from './pages/Settings';
import Users from './pages/Users';
import AuditLog from './pages/AuditLog';
import SetupWizard from './pages/SetupWizard';

const Nav = () => (
  <nav className="nav">
    <h1>DockBack</h1>
    <div className="links">
      <NavLink to="/">Dashboard</NavLink>
      <NavLink to="/resources">Resources</NavLink>
      <NavLink to="/plans">Backup Plans</NavLink>
      <NavLink to="/backups">Backups</NavLink>
      <NavLink to="/restore">Restore Wizard</NavLink>
      <NavLink to="/settings">Settings</NavLink>
      <NavLink to="/users">Users/Roles</NavLink>
      <NavLink to="/audit">Audit Log</NavLink>
    </div>
  </nav>
);

export default function App() {
  return (
    <div className="layout">
      <Nav />
      <main className="content">
        <Routes>
          <Route path="/" element={<Dashboard />} />
          <Route path="/resources" element={<Resources />} />
          <Route path="/plans" element={<BackupPlans />} />
          <Route path="/backups" element={<Backups />} />
          <Route path="/restore" element={<RestoreWizard />} />
          <Route path="/settings" element={<Settings />} />
          <Route path="/users" element={<Users />} />
          <Route path="/audit" element={<AuditLog />} />
          <Route path="/setup" element={<SetupWizard />} />
        </Routes>
      </main>
    </div>
  );
}
