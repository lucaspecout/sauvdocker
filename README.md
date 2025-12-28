# SauveDocker

Application web de sauvegarde Docker avec détection automatique des conteneurs/images, automatisation des backups, alertes email, transfert Drive et restauration via l'interface.

## Démarrage rapide

```bash
docker compose up --build
```

Accès : http://localhost:5000

### Identifiants par défaut
- **Utilisateur** : `admin`
- **Mot de passe** : `Admin123!`

Vous devrez changer ce mot de passe lors de la première connexion et configurer la MFA.

## Configuration
- Configurez l'intervalle d'automatisation, SMTP et Drive dans l'écran **Paramètres**.
- Pour Drive, utilisez `rclone` et fournissez un remote (`drive:Sauvegardes`).

## Notes de sécurité
- Montez uniquement le socket Docker dans un environnement contrôlé.
- Changez `APP_SECRET` et le mot de passe admin immédiatement.
