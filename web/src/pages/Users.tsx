export default function Users() {
  return (
    <section>
      <h2>Users & Roles</h2>
      <div className="card">
        <button className="primary">Invite User</button>
        <table>
          <thead>
            <tr>
              <th>Email</th>
              <th>Role</th>
              <th>Status</th>
            </tr>
          </thead>
          <tbody>
            <tr>
              <td>admin</td>
              <td>Admin</td>
              <td>Active</td>
            </tr>
          </tbody>
        </table>
      </div>
    </section>
  );
}
