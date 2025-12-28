export default function App() {
  return (
    <div className="app">
      <header className="hero">
        <div className="hero-content">
          <span className="badge">Sauvdocker</span>
          <h1>Vos sauvegardes Docker, simples et en français.</h1>
          <p>
            Un tableau clair, sans surcharge, prêt à fonctionner derrière votre reverse
            proxy. Le port 6677 reste votre point d&apos;entrée, nous nous occupons du reste.
          </p>
          <div className="hero-actions">
            <button className="primary">Ouvrir le tableau de bord</button>
            <button className="ghost">Consulter la documentation</button>
          </div>
          <div className="hero-meta">
            <div className="card">
              <p className="meta-title">Statut</p>
              <p className="meta-value">Proxy OK • Port 6677</p>
            </div>
            <div className="card">
              <p className="meta-title">Dernière sauvegarde</p>
              <p className="meta-value">En attente</p>
            </div>
            <div className="card">
              <p className="meta-title">Ressources suivies</p>
              <p className="meta-value">Conteneurs + Volumes</p>
            </div>
          </div>
        </div>
      </header>
      <main className="main">
        <section className="section">
          <h2>Un site plus simple, vraiment utile</h2>
          <p>
            Tout ce qui compte, en un coup d&apos;œil : la santé des sauvegardes, les alertes,
            et les prochaines actions.
          </p>
          <div className="grid">
            <div className="card">
              <h3>Déploiement rapide</h3>
              <p>Interface légère qui démarre vite, même sur des petits serveurs.</p>
            </div>
            <div className="card">
              <h3>Langue française</h3>
              <p>Textes clairs et jargon réduit pour une prise en main immédiate.</p>
            </div>
            <div className="card">
              <h3>Fiabilité</h3>
              <p>Un aperçu des sauvegardes et restaurations sans fioritures.</p>
            </div>
          </div>
        </section>
        <section className="section">
          <div className="card highlight">
            <h2>Prochaines étapes</h2>
            <ol className="steps">
              <li>Vérifiez vos ressources et activez les volumes à sauvegarder.</li>
              <li>Planifiez vos sauvegardes avec la fréquence souhaitée.</li>
              <li>Configurez les notifications si besoin.</li>
            </ol>
          </div>
        </section>
      </main>
    </div>
  );
}
