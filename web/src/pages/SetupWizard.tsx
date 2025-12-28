export default function SetupWizard() {
  return (
    <section>
      <h2>Setup Wizard</h2>
      <ol className="steps">
        <li>Change admin password</li>
        <li>Set up MFA</li>
        <li>Configure S3 storage</li>
        <li>Optional: configure SMTP alerts</li>
      </ol>
      <div className="card">
        <label>
          New Password
          <input type="password" placeholder="Enter a strong password" />
        </label>
        <button className="primary">Update Password</button>
      </div>
    </section>
  );
}
