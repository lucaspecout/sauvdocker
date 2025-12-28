export default function Dashboard() {
  return (
    <section>
      <h2>Dashboard</h2>
      <p>Overview of backup health, last runs, and storage usage.</p>
      <div className="grid">
        <div className="card">
          <h3>Backups</h3>
          <p>Last backup: pending</p>
        </div>
        <div className="card">
          <h3>Resources</h3>
          <p>Auto-discovery running every minute.</p>
        </div>
        <div className="card">
          <h3>Alerts</h3>
          <p>SMTP alerts configured: no</p>
        </div>
      </div>
    </section>
  );
}
