export default function Backups() {
  return (
    <section>
      <h2>Backups</h2>
      <p>Job history and remote sync status.</p>
      <div className="card">
        <table>
          <thead>
            <tr>
              <th>Job</th>
              <th>Status</th>
              <th>Checksum</th>
              <th>Remote</th>
            </tr>
          </thead>
          <tbody>
            <tr>
              <td>#42</td>
              <td>completed</td>
              <td>sha256:...</td>
              <td>Uploaded to S3</td>
            </tr>
          </tbody>
        </table>
      </div>
    </section>
  );
}
