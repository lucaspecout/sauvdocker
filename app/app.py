import os
import sqlite3
from datetime import datetime
from pathlib import Path
import subprocess

from flask import Flask, render_template, request, redirect, url_for, flash, session, send_from_directory
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
import docker
import pyotp
from apscheduler.schedulers.background import BackgroundScheduler
import smtplib
from email.mime.text import MIMEText

APP_DIR = Path(__file__).resolve().parent
DATA_DIR = APP_DIR / "data"
BACKUP_DIR = APP_DIR / "backups"
DB_PATH = DATA_DIR / "app.db"

DEFAULT_ADMIN_USERNAME = "admin"
DEFAULT_ADMIN_PASSWORD = "Admin123!"

app = Flask(__name__)
app.secret_key = os.environ.get("APP_SECRET", "change-this-secret")

login_manager = LoginManager()
login_manager.login_view = "login"
login_manager.init_app(app)

docker_client = docker.from_env()

scheduler = BackgroundScheduler()


class User(UserMixin):
    def __init__(self, row):
        self.id = row[0]
        self.username = row[1]
        self.password_hash = row[2]
        self.mfa_secret = row[3]
        self.force_password_change = bool(row[4])


@login_manager.user_loader
def load_user(user_id):
    with sqlite3.connect(DB_PATH) as conn:
        row = conn.execute("SELECT id, username, password_hash, mfa_secret, force_password_change FROM users WHERE id = ?", (user_id,)).fetchone()
    return User(row) if row else None


def init_db():
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    BACKUP_DIR.mkdir(parents=True, exist_ok=True)
    with sqlite3.connect(DB_PATH) as conn:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                mfa_secret TEXT,
                force_password_change INTEGER NOT NULL DEFAULT 1
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS backups (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                target_type TEXT NOT NULL,
                target_name TEXT NOT NULL,
                file_path TEXT NOT NULL,
                created_at TEXT NOT NULL,
                status TEXT NOT NULL,
                error_message TEXT
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS settings (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL
            )
            """
        )
        conn.commit()

    ensure_admin_user()


def ensure_admin_user():
    with sqlite3.connect(DB_PATH) as conn:
        row = conn.execute("SELECT id FROM users WHERE username = ?", (DEFAULT_ADMIN_USERNAME,)).fetchone()
        if row is None:
            password_hash = generate_password_hash(DEFAULT_ADMIN_PASSWORD)
            mfa_secret = pyotp.random_base32()
            conn.execute(
                "INSERT INTO users (username, password_hash, mfa_secret, force_password_change) VALUES (?, ?, ?, 1)",
                (DEFAULT_ADMIN_USERNAME, password_hash, mfa_secret),
            )
            conn.commit()


def get_setting(key, default=None):
    with sqlite3.connect(DB_PATH) as conn:
        row = conn.execute("SELECT value FROM settings WHERE key = ?", (key,)).fetchone()
    return row[0] if row else default


def set_setting(key, value):
    with sqlite3.connect(DB_PATH) as conn:
        conn.execute("INSERT INTO settings (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value", (key, value))
        conn.commit()


def send_alert(subject, message):
    smtp_host = get_setting("smtp_host")
    smtp_port = get_setting("smtp_port")
    smtp_user = get_setting("smtp_user")
    smtp_password = get_setting("smtp_password")
    alert_email = get_setting("alert_email")

    if not all([smtp_host, smtp_port, alert_email]):
        return

    msg = MIMEText(message)
    msg["Subject"] = subject
    msg["From"] = smtp_user or alert_email
    msg["To"] = alert_email

    with smtplib.SMTP(smtp_host, int(smtp_port)) as server:
        if smtp_user and smtp_password:
            server.starttls()
            server.login(smtp_user, smtp_password)
        server.send_message(msg)


def run_drive_transfer(file_path):
    drive_command = get_setting("drive_command")
    drive_target = get_setting("drive_target")
    if not drive_command or not drive_target:
        return
    subprocess.run([drive_command, "copy", file_path, drive_target], check=False)


def record_backup(target_type, target_name, file_path, status, error_message=None):
    with sqlite3.connect(DB_PATH) as conn:
        conn.execute(
            "INSERT INTO backups (target_type, target_name, file_path, created_at, status, error_message) VALUES (?, ?, ?, ?, ?, ?)",
            (target_type, target_name, file_path, datetime.utcnow().isoformat(), status, error_message),
        )
        conn.commit()


def backup_container(container_id, name=None):
    container = docker_client.containers.get(container_id)
    filename = f"container-{name or container.name}-{datetime.utcnow().strftime('%Y%m%d%H%M%S')}.tar"
    file_path = BACKUP_DIR / filename
    try:
        with open(file_path, "wb") as fh:
            for chunk in container.export():
                fh.write(chunk)
        record_backup("container", name or container.name, str(file_path), "success")
        run_drive_transfer(str(file_path))
        send_alert("Sauvegarde container réussie", f"Sauvegarde créée pour {name or container.name}")
        return True
    except Exception as exc:
        record_backup("container", name or container.name, str(file_path), "failed", str(exc))
        send_alert("Sauvegarde container échouée", f"Erreur pour {name or container.name}: {exc}")
        return False


def backup_image(image_id, name=None):
    image = docker_client.images.get(image_id)
    filename = f"image-{name or image.short_id}-{datetime.utcnow().strftime('%Y%m%d%H%M%S')}.tar"
    file_path = BACKUP_DIR / filename
    try:
        image_data = image.save(named=True)
        with open(file_path, "wb") as fh:
            for chunk in image_data:
                fh.write(chunk)
        record_backup("image", name or image.short_id, str(file_path), "success")
        run_drive_transfer(str(file_path))
        send_alert("Sauvegarde image réussie", f"Sauvegarde créée pour {name or image.short_id}")
        return True
    except Exception as exc:
        record_backup("image", name or image.short_id, str(file_path), "failed", str(exc))
        send_alert("Sauvegarde image échouée", f"Erreur pour {name or image.short_id}: {exc}")
        return False


def scheduled_backup():
    containers = docker_client.containers.list(all=True)
    images = docker_client.images.list()
    for container in containers:
        backup_container(container.id, container.name)
    for image in images:
        name = image.tags[0] if image.tags else image.short_id
        backup_image(image.id, name)


def refresh_scheduler():
    scheduler.remove_all_jobs()
    interval_minutes = int(get_setting("backup_interval", "60"))
    scheduler.add_job(scheduled_backup, "interval", minutes=interval_minutes, id="auto_backup")


@app.route("/")
@login_required
def dashboard():
    containers = docker_client.containers.list(all=True)
    images = docker_client.images.list()
    with sqlite3.connect(DB_PATH) as conn:
        backups = conn.execute(
            "SELECT id, target_type, target_name, file_path, created_at, status, error_message FROM backups ORDER BY created_at DESC"
        ).fetchall()
    return render_template(
        "dashboard.html",
        containers=containers,
        images=images,
        backups=backups,
        force_password_change=current_user.force_password_change,
    )


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")
        otp = request.form.get("otp")
        with sqlite3.connect(DB_PATH) as conn:
            row = conn.execute(
                "SELECT id, username, password_hash, mfa_secret, force_password_change FROM users WHERE username = ?",
                (username,),
            ).fetchone()
        if row is None:
            flash("Identifiants invalides", "error")
            return render_template("login.html")
        user = User(row)
        if not check_password_hash(user.password_hash, password):
            flash("Identifiants invalides", "error")
            return render_template("login.html")
        totp = pyotp.TOTP(user.mfa_secret)
        if not otp or not totp.verify(otp):
            flash("Code MFA invalide", "error")
            return render_template("login.html")
        login_user(user)
        if user.force_password_change:
            return redirect(url_for("force_password"))
        return redirect(url_for("dashboard"))
    return render_template("login.html")


@app.route("/force-password", methods=["GET", "POST"])
@login_required
def force_password():
    if not current_user.force_password_change:
        return redirect(url_for("dashboard"))
    if request.method == "POST":
        new_password = request.form.get("new_password")
        confirm_password = request.form.get("confirm_password")
        if new_password != confirm_password:
            flash("Les mots de passe ne correspondent pas.", "error")
            return render_template("force_password.html")
        password_hash = generate_password_hash(new_password)
        new_mfa_secret = pyotp.random_base32()
        with sqlite3.connect(DB_PATH) as conn:
            conn.execute(
                "UPDATE users SET password_hash = ?, force_password_change = 0, mfa_secret = ? WHERE id = ?",
                (password_hash, new_mfa_secret, current_user.id),
            )
            conn.commit()
        session["mfa_secret"] = new_mfa_secret
        flash("Mot de passe mis à jour. Configurez votre MFA.", "success")
        return redirect(url_for("setup_mfa"))
    return render_template("force_password.html")


@app.route("/setup-mfa", methods=["GET", "POST"])
@login_required
def setup_mfa():
    mfa_secret = session.get("mfa_secret") or current_user.mfa_secret
    totp = pyotp.TOTP(mfa_secret)
    provisioning_uri = totp.provisioning_uri(name=current_user.username, issuer_name="SauveDocker")
    if request.method == "POST":
        otp = request.form.get("otp")
        if not totp.verify(otp):
            flash("Code MFA invalide", "error")
            return render_template("setup_mfa.html", secret=mfa_secret, uri=provisioning_uri)
        session.pop("mfa_secret", None)
        flash("MFA configuré avec succès.", "success")
        return redirect(url_for("dashboard"))
    return render_template("setup_mfa.html", secret=mfa_secret, uri=provisioning_uri)


@app.route("/logout")
@login_required
def logout():
    logout_user()
    return redirect(url_for("login"))


@app.route("/backup/container/<container_id>", methods=["POST"])
@login_required
def backup_container_route(container_id):
    container = docker_client.containers.get(container_id)
    success = backup_container(container.id, container.name)
    if success:
        flash("Sauvegarde du conteneur créée.", "success")
    else:
        flash("Échec de la sauvegarde du conteneur.", "error")
    return redirect(url_for("dashboard"))


@app.route("/backup/image/<image_id>", methods=["POST"])
@login_required
def backup_image_route(image_id):
    image = docker_client.images.get(image_id)
    name = image.tags[0] if image.tags else image.short_id
    success = backup_image(image.id, name)
    if success:
        flash("Sauvegarde de l'image créée.", "success")
    else:
        flash("Échec de la sauvegarde de l'image.", "error")
    return redirect(url_for("dashboard"))


@app.route("/restore", methods=["POST"])
@login_required
def restore_backup():
    backup_id = request.form.get("backup_id")
    with sqlite3.connect(DB_PATH) as conn:
        row = conn.execute("SELECT target_type, file_path FROM backups WHERE id = ?", (backup_id,)).fetchone()
    if not row:
        flash("Sauvegarde introuvable.", "error")
        return redirect(url_for("dashboard"))
    target_type, file_path = row
    try:
        if target_type == "image":
            with open(file_path, "rb") as fh:
                docker_client.images.load(fh.read())
        else:
            with open(file_path, "rb") as fh:
                image = docker_client.images.import_image(fh.read())
            docker_client.containers.run(image.id, detach=True)
        flash("Restauration déclenchée.", "success")
    except Exception as exc:
        flash(f"Erreur de restauration: {exc}", "error")
    return redirect(url_for("dashboard"))


@app.route("/download/<path:filename>")
@login_required
def download_backup(filename):
    return send_from_directory(BACKUP_DIR, filename, as_attachment=True)


@app.route("/settings", methods=["GET", "POST"])
@login_required
def settings():
    if request.method == "POST":
        set_setting("backup_interval", request.form.get("backup_interval", "60"))
        set_setting("smtp_host", request.form.get("smtp_host"))
        set_setting("smtp_port", request.form.get("smtp_port"))
        set_setting("smtp_user", request.form.get("smtp_user"))
        set_setting("smtp_password", request.form.get("smtp_password"))
        set_setting("alert_email", request.form.get("alert_email"))
        set_setting("drive_command", request.form.get("drive_command"))
        set_setting("drive_target", request.form.get("drive_target"))
        refresh_scheduler()
        flash("Paramètres mis à jour.", "success")
        return redirect(url_for("settings"))
    context = {
        "backup_interval": get_setting("backup_interval", "60"),
        "smtp_host": get_setting("smtp_host", ""),
        "smtp_port": get_setting("smtp_port", ""),
        "smtp_user": get_setting("smtp_user", ""),
        "smtp_password": get_setting("smtp_password", ""),
        "alert_email": get_setting("alert_email", ""),
        "drive_command": get_setting("drive_command", "rclone"),
        "drive_target": get_setting("drive_target", ""),
    }
    return render_template("settings.html", **context)


@app.route("/drive/transfer", methods=["POST"])
@login_required
def manual_drive_transfer():
    backup_id = request.form.get("backup_id")
    with sqlite3.connect(DB_PATH) as conn:
        row = conn.execute("SELECT file_path FROM backups WHERE id = ?", (backup_id,)).fetchone()
    if not row:
        flash("Sauvegarde introuvable.", "error")
        return redirect(url_for("dashboard"))
    run_drive_transfer(row[0])
    flash("Transfert vers Drive lancé.", "success")
    return redirect(url_for("dashboard"))


def setup():
    init_db()
    refresh_scheduler()
    scheduler.start()


if __name__ == "__main__":
    setup()
    app.run(host="0.0.0.0", port=5000)
