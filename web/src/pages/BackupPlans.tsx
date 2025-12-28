export default function BackupPlans() {
  return (
    <section>
      <h2>Backup Plans</h2>
      <p>Create cron-based plans with retention policies.</p>
      <div className="card">
        <button className="primary">New Plan</button>
        <table>
          <thead>
            <tr>
              <th>Name</th>
              <th>Cron</th>
              <th>Target</th>
              <th>Retention</th>
            </tr>
          </thead>
          <tbody>
            <tr>
              <td>Volumes nightly</td>
              <td>0 2 * * *</td>
              <td>volume:postgres_data</td>
              <td>Keep last 7</td>
            </tr>
          </tbody>
        </table>
      </div>
    </section>
  );
}
