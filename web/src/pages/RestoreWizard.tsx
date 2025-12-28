export default function RestoreWizard() {
  return (
    <section>
      <h2>Restore Wizard</h2>
      <p>Restore backups with confirmations and safety lock.</p>
      <div className="card">
        <label>
          Target Volume
          <input placeholder="volume name" />
        </label>
        <label>
          Restore Mode
          <select>
            <option>Replace existing volume</option>
            <option>Clone to new volume</option>
          </select>
        </label>
        <label>
          Safety Lock
          <input type="text" placeholder="Type RESTORE to confirm" />
        </label>
        <button className="danger">Start Restore</button>
      </div>
    </section>
  );
}
