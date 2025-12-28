export default function Resources() {
  return (
    <section>
      <h2>Resources</h2>
      <p>Auto-discovered containers and volumes on the Docker host.</p>
      <div className="card">
        <h3>Containers</h3>
        <table>
          <thead>
            <tr>
              <th>Name</th>
              <th>Status</th>
              <th>Mounts</th>
              <th>Labels</th>
            </tr>
          </thead>
          <tbody>
            <tr>
              <td>example-container</td>
              <td>running</td>
              <td>/var/lib/data</td>
              <td>app=demo</td>
            </tr>
          </tbody>
        </table>
      </div>
      <div className="card">
        <h3>Volumes</h3>
        <table>
          <thead>
            <tr>
              <th>Name</th>
              <th>Driver</th>
              <th>Mountpoint</th>
              <th>Labels</th>
            </tr>
          </thead>
          <tbody>
            <tr>
              <td>example-volume</td>
              <td>local</td>
              <td>/var/lib/docker/volumes/example</td>
              <td>backup=true</td>
            </tr>
          </tbody>
        </table>
      </div>
    </section>
  );
}
