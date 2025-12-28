export default function AuditLog() {
  return (
    <section>
      <h2>Audit Log</h2>
      <div className="card">
        <table>
          <thead>
            <tr>
              <th>Action</th>
              <th>Detail</th>
              <th>Timestamp</th>
            </tr>
          </thead>
          <tbody>
            <tr>
              <td>login</td>
              <td>admin logged in</td>
              <td>just now</td>
            </tr>
          </tbody>
        </table>
      </div>
    </section>
  );
}
