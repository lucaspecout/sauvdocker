export default function Settings() {
  return (
    <section>
      <h2>Settings</h2>
      <div className="grid">
        <div className="card">
          <h3>S3 Storage</h3>
          <label>
            Endpoint
            <input placeholder="https://s3.amazonaws.com" />
          </label>
          <label>
            Bucket
            <input placeholder="dockback" />
          </label>
          <label>
            Access Key
            <input placeholder="AKIA..." />
          </label>
          <label>
            Secret Key
            <input type="password" placeholder="•••••" />
          </label>
          <button className="primary">Save</button>
        </div>
        <div className="card">
          <h3>SMTP Alerts</h3>
          <label>
            Host
            <input placeholder="smtp.example.com" />
          </label>
          <label>
            Port
            <input placeholder="587" />
          </label>
          <label>
            From
            <input placeholder="dockback@example.com" />
          </label>
          <label>
            To
            <input placeholder="alerts@example.com" />
          </label>
          <button className="primary">Save</button>
        </div>
      </div>
    </section>
  );
}
