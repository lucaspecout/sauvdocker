import os
import sqlite3
import base64
import io
from datetime import datetime
from pathlib import Path
import subprocess
import logging
from logging.handlers import RotatingFileHandler

from flask import Flask, render_template, request, redirect, url_for, flash, session, send_from_directory
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
import docker
from requests.exceptions import InvalidURL
import pyotp
import qrcode
from apscheduler.schedulers.background import BackgroundScheduler
import smtplib
from email.mime.text import MIMEText

APP_DIR = Path(__file__).resolve().parent
DATA_DIR = APP_DIR / "data"
BACKUP_DIR = APP_DIR / "backups"
DB_PATH = DATA_DIR / "app.db"
LOG_DIR = DATA_DIR / "logs"
LOG_FILE = LOG_DIR / "sauvedocker.log"

DEFAULT_ADMIN_USERNAME = "admin"
DEFAULT_ADMIN_PASSWORD = "Admin123!"

app = Flask(__name__)
app.secret_key = os.environ.get("APP_SECRET", "change-this-secret")

login_manager = LoginManager()
login_manager.login_view = "login"
login_manager.init_app(app)

logger = logging.getLogger("sauvedocker")
logger.setLevel(logging.INFO)


def setup_logging():
    LOG_DIR.mkdir(parents=True, exist_ok=True)
    if logger.handlers:
        return
    handler = RotatingFileHandler(LOG_FILE, maxBytes=1_000_000, backupCount=3)
    formatter = logging.Formatter("%(asctime)s | %(levelname)s | %(message)s")
    handler.setFormatter(formatter)
    logger.addHandler(handler)
    logger.propagate = False


def log_docker_event(message, level=logging.INFO):
    setup_logging()
    logger.log(level, message)

def normalize_docker_host(docker_host):
    if not docker_host:
        return ""
    normalized = docker_host.strip()
    if normalized.lower().startswith("http+docker://"):
        normalized = "unix:///var/run/docker.sock"
    if normalized.lower().startswith("unix://") and not normalized.lower().startswith("unix:///"):
        normalized = f"unix:///{normalized[7:]}"
    return normalized


def build_docker_client(base_url, source=""):
    if not base_url:
        return None
    try:
        client = docker.DockerClient(base_url=base_url)
        client.ping()
        return client
    except (docker.errors.DockerException, InvalidURL) as exc:
        log_docker_event(f"docker_client_error source={source} base_url={base_url} error={exc}", logging.WARNING)
        return None


def socket_host(path):
    return f"unix://{path}" if str(path).startswith("/") else f"unix:///{path}"


def candidate_socket_hosts():
    candidates = []
    env_socket = os.environ.get("DOCKER_SOCKET")
    if env_socket:
        candidates.append(socket_host(env_socket))
    for path in (
        "/var/run/docker.sock",
        "/run/docker.sock",
        f"/run/user/{os.getuid()}/docker.sock",
    ):
        if Path(path).exists():
            candidates.append(socket_host(path))
    return candidates


def get_docker_client():
    docker_host = normalize_docker_host(os.environ.get("DOCKER_HOST", ""))
    errors = []
    log_docker_event(
        "docker_client_init "
        f"env_DOCKER_HOST={os.environ.get('DOCKER_HOST', '')} "
        f"env_DOCKER_SOCKET={os.environ.get('DOCKER_SOCKET', '')}"
    )
    if docker_host:
        os.environ["DOCKER_HOST"] = docker_host
        log_docker_event(f"docker_client_try source=env base_url={docker_host}")
        client = build_docker_client(docker_host, source="env")
        if client:
            return client
        errors.append(f"DOCKER_HOST={docker_host}")

    try:
        client = docker.from_env()
        client.ping()
        return client
    except (docker.errors.DockerException, InvalidURL) as exc:
        log_docker_event(f"docker_client_error source=from_env error={exc}", logging.WARNING)
        errors.append(str(exc))

    for fallback_host in candidate_socket_hosts():
        os.environ["DOCKER_HOST"] = fallback_host
        log_docker_event(f"docker_client_try source=fallback base_url={fallback_host}")
        client = build_docker_client(fallback_host, source="fallback")
        if client:
            return client

    details = f" Détails: {', '.join(errors)}." if errors else ""
    raise docker.errors.DockerException(
        "Impossible de créer un client Docker. Vérifiez que /var/run/docker.sock est monté et accessible, "
        "ou configurez DOCKER_HOST/DOCKER_SOCKET correctement (ex: DOCKER_HOST=unix:///var/run/docker.sock)."
        f"{details}"
    )


docker_client = None
docker_error = None


def reset_docker_client(error):
    global docker_client, docker_error
    docker_client = None
    docker_error = error
    log_docker_event(f"docker_client_reset error={error}", logging.WARNING)


def ensure_docker_client():
    global docker_client, docker_error
    if docker_client:
        return docker_client
    try:
        docker_client = get_docker_client()
        docker_error = None
        return docker_client
    except docker.errors.DockerException as exc:
        docker_error = str(exc)
        log_docker_event(f"docker_client_unavailable error={docker_error}", logging.ERROR)
        return None


def docker_unavailable_message():
    return docker_error or "Docker indisponible."

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
    setup_logging()
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
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS container_schedules (
                container_name TEXT PRIMARY KEY,
                days TEXT NOT NULL,
                time TEXT NOT NULL,
                retention INTEGER NOT NULL
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
            conn.execute(
                "INSERT INTO users (username, password_hash, mfa_secret, force_password_change) VALUES (?, ?, ?, 1)",
                (DEFAULT_ADMIN_USERNAME, password_hash, None),
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


def get_int_setting(key, default):
    try:
        return int(get_setting(key, default))
    except (TypeError, ValueError):
        return int(default)


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


def read_log_lines(max_lines=200):
    setup_logging()
    if not LOG_FILE.exists():
        return []
    with open(LOG_FILE, "r", encoding="utf-8") as fh:
        lines = fh.readlines()
    return lines[-max_lines:]


def record_backup(target_type, target_name, file_path, status, error_message=None):
    with sqlite3.connect(DB_PATH) as conn:
        conn.execute(
            "INSERT INTO backups (target_type, target_name, file_path, created_at, status, error_message) VALUES (?, ?, ?, ?, ?, ?)",
            (target_type, target_name, file_path, datetime.utcnow().isoformat(), status, error_message),
        )
        conn.commit()


def cleanup_old_backups(max_keep, target_type=None, target_name=None):
    if max_keep is None or max_keep <= 0:
        return
    with sqlite3.connect(DB_PATH) as conn:
        query = "SELECT id, file_path FROM backups"
        params = []
        conditions = []
        if target_type:
            conditions.append("target_type = ?")
            params.append(target_type)
        if target_name:
            conditions.append("target_name = ?")
            params.append(target_name)
        if conditions:
            query += " WHERE " + " AND ".join(conditions)
        query += " ORDER BY created_at DESC LIMIT -1 OFFSET ?"
        params.append(max_keep)
        rows = conn.execute(query, params).fetchall()
        if not rows:
            return
        backup_ids = [row[0] for row in rows]
        file_paths = [row[1] for row in rows]
        conn.execute(
            "DELETE FROM backups WHERE id IN ({})".format(",".join("?" * len(backup_ids))),
            backup_ids,
        )
        conn.commit()
    for file_path in file_paths:
        try:
            path_obj = Path(file_path)
            if path_obj.exists():
                path_obj.unlink()
        except OSError as exc:
            log_docker_event(f"backup_cleanup_error path={file_path} error={exc}", logging.WARNING)


def backup_container(container_id, name=None, client=None, retention=None):
    client = client or ensure_docker_client()
    if not client:
        raise docker.errors.DockerException(docker_unavailable_message())
    container = client.containers.get(container_id)
    filename = f"container-{name or container.name}-{datetime.utcnow().strftime('%Y%m%d%H%M%S')}.tar"
    file_path = BACKUP_DIR / filename
    try:
        with open(file_path, "wb") as fh:
            for chunk in container.export():
                fh.write(chunk)
        record_backup("container", name or container.name, str(file_path), "success")
        retention_value = retention if retention is not None else get_int_setting("backup_retention", 20)
        cleanup_old_backups(retention_value, target_type="container", target_name=name or container.name)
        run_drive_transfer(str(file_path))
        send_alert("Sauvegarde container réussie", f"Sauvegarde créée pour {name or container.name}")
        return True
    except Exception as exc:
        record_backup("container", name or container.name, str(file_path), "failed", str(exc))
        send_alert("Sauvegarde container échouée", f"Erreur pour {name or container.name}: {exc}")
        return False


def backup_image(image_id, name=None, client=None):
    client = client or ensure_docker_client()
    if not client:
        raise docker.errors.DockerException(docker_unavailable_message())
    image = client.images.get(image_id)
    filename = f"image-{name or image.short_id}-{datetime.utcnow().strftime('%Y%m%d%H%M%S')}.tar"
    file_path = BACKUP_DIR / filename
    try:
        image_data = image.save(named=True)
        with open(file_path, "wb") as fh:
            for chunk in image_data:
                fh.write(chunk)
        record_backup("image", name or image.short_id, str(file_path), "success")
        cleanup_old_backups(get_int_setting("backup_retention", 20), target_type="image")
        run_drive_transfer(str(file_path))
        send_alert("Sauvegarde image réussie", f"Sauvegarde créée pour {name or image.short_id}")
        return True
    except Exception as exc:
        record_backup("image", name or image.short_id, str(file_path), "failed", str(exc))
        send_alert("Sauvegarde image échouée", f"Erreur pour {name or image.short_id}: {exc}")
        return False


def import_container_backup(file_path, client=None):
    client = client or ensure_docker_client()
    if not client:
        raise docker.errors.DockerException(docker_unavailable_message())
    before_images = {image.id for image in client.images.list()}
    with open(file_path, "rb") as fh:
        client.api.import_image(fh.read())
    after_images = client.images.list()
    new_images = [image for image in after_images if image.id not in before_images]
    if not new_images:
        raise RuntimeError("Import de l'image échoué.")
    return new_images[0]


def remove_existing_container(container_name, client=None):
    client = client or ensure_docker_client()
    if not client:
        raise docker.errors.DockerException(docker_unavailable_message())
    try:
        container = client.containers.get(container_name)
    except docker.errors.NotFound:
        return False
    if container.status == "running":
        container.stop(timeout=10)
    container.remove()
    return True


def scheduled_container_backup(container_name, retention):
    client = ensure_docker_client()
    if not client:
        return
    try:
        container = client.containers.get(container_name)
    except docker.errors.DockerException as exc:
        log_docker_event(f"scheduled_backup_error container={container_name} error={exc}", logging.WARNING)
        return
    backup_container(container.id, container.name, client=client, retention=retention)


def get_container_schedules():
    with sqlite3.connect(DB_PATH) as conn:
        rows = conn.execute(
            "SELECT container_name, days, time, retention FROM container_schedules"
        ).fetchall()
    schedules = {}
    for name, days, time_value, retention in rows:
        schedules[name] = {
            "days": [day for day in days.split(",") if day],
            "time": time_value,
            "retention": retention,
        }
    return schedules


def set_container_schedule(container_name, days, time_value, retention):
    with sqlite3.connect(DB_PATH) as conn:
        conn.execute(
            """
            INSERT INTO container_schedules (container_name, days, time, retention)
            VALUES (?, ?, ?, ?)
            ON CONFLICT(container_name) DO UPDATE SET days = excluded.days, time = excluded.time, retention = excluded.retention
            """,
            (container_name, ",".join(days), time_value, retention),
        )
        conn.commit()


def delete_container_schedule(container_name):
    with sqlite3.connect(DB_PATH) as conn:
        conn.execute("DELETE FROM container_schedules WHERE container_name = ?", (container_name,))
        conn.commit()


def refresh_scheduler():
    scheduler.remove_all_jobs()
    schedules = get_container_schedules()
    for container_name, schedule in schedules.items():
        if not schedule["days"] or not schedule["time"]:
            continue
        try:
            hour_str, minute_str = schedule["time"].split(":")
            scheduler.add_job(
                scheduled_container_backup,
                "cron",
                day_of_week=",".join(schedule["days"]),
                hour=int(hour_str),
                minute=int(minute_str),
                args=[container_name, schedule["retention"]],
                id=f"container_backup_{container_name}",
                replace_existing=True,
            )
        except ValueError:
            log_docker_event(
                f"schedule_invalid_time container={container_name} time={schedule['time']}",
                logging.WARNING,
            )


@app.route("/")
@login_required
def dashboard():
    client = ensure_docker_client()
    if client:
        try:
            containers = client.containers.list(all=True)
            images = client.images.list()
            volumes = client.volumes.list()
        except docker.errors.DockerException as exc:
            reset_docker_client(str(exc))
            containers = []
            images = []
            volumes = []
            flash(docker_unavailable_message(), "error")
    else:
        containers = []
        images = []
        volumes = []
        flash(docker_unavailable_message(), "error")
    schedules = get_container_schedules()
    week_days = [
        {"value": "mon", "label": "Lun"},
        {"value": "tue", "label": "Mar"},
        {"value": "wed", "label": "Mer"},
        {"value": "thu", "label": "Jeu"},
        {"value": "fri", "label": "Ven"},
        {"value": "sat", "label": "Sam"},
        {"value": "sun", "label": "Dim"},
    ]
    with sqlite3.connect(DB_PATH) as conn:
        backups = conn.execute(
            "SELECT id, target_type, target_name, file_path, created_at, status, error_message FROM backups ORDER BY created_at DESC"
        ).fetchall()
    return render_template(
        "dashboard.html",
        containers=containers,
        images=images,
        volumes=volumes,
        backups=backups,
        schedules=schedules,
        week_days=week_days,
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
        if user.force_password_change:
            login_user(user)
            return redirect(url_for("force_password"))
        totp = pyotp.TOTP(user.mfa_secret)
        if not otp or not totp.verify(otp):
            flash("Code MFA invalide", "error")
            return render_template("login.html")
        login_user(user)
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
    qr = qrcode.QRCode(box_size=6, border=2)
    qr.add_data(provisioning_uri)
    qr.make(fit=True)
    qr_image = qr.make_image(fill_color="black", back_color="white")
    qr_buffer = io.BytesIO()
    qr_image.save(qr_buffer, format="PNG")
    qr_code = base64.b64encode(qr_buffer.getvalue()).decode("utf-8")
    if request.method == "POST":
        otp = request.form.get("otp")
        if not totp.verify(otp):
            flash("Code MFA invalide", "error")
            return render_template("setup_mfa.html", secret=mfa_secret, uri=provisioning_uri, qr_code=qr_code)
        session.pop("mfa_secret", None)
        flash("MFA configuré avec succès.", "success")
        return redirect(url_for("dashboard"))
    return render_template("setup_mfa.html", secret=mfa_secret, uri=provisioning_uri, qr_code=qr_code)


@app.route("/logout")
@login_required
def logout():
    logout_user()
    return redirect(url_for("login"))


@app.route("/backup/container/<container_id>", methods=["POST"])
@login_required
def backup_container_route(container_id):
    client = ensure_docker_client()
    if not client:
        flash(docker_unavailable_message(), "error")
        return redirect(url_for("dashboard"))
    try:
        container = client.containers.get(container_id)
        schedule = get_container_schedules().get(container.name, {})
        retention = schedule.get("retention")
        success = backup_container(container.id, container.name, client=client, retention=retention)
    except docker.errors.DockerException as exc:
        reset_docker_client(str(exc))
        flash(docker_unavailable_message(), "error")
        return redirect(url_for("dashboard"))
    if success:
        flash("Sauvegarde du conteneur créée.", "success")
    else:
        flash("Échec de la sauvegarde du conteneur.", "error")
    return redirect(url_for("dashboard"))


@app.route("/backup/image/<image_id>", methods=["POST"])
@login_required
def backup_image_route(image_id):
    client = ensure_docker_client()
    if not client:
        flash(docker_unavailable_message(), "error")
        return redirect(url_for("dashboard"))
    try:
        image = client.images.get(image_id)
        name = image.tags[0] if image.tags else image.short_id
        success = backup_image(image.id, name, client=client)
    except docker.errors.DockerException as exc:
        reset_docker_client(str(exc))
        flash(docker_unavailable_message(), "error")
        return redirect(url_for("dashboard"))
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
        row = conn.execute(
            "SELECT target_type, target_name, file_path FROM backups WHERE id = ?",
            (backup_id,),
        ).fetchone()
    if not row:
        flash("Sauvegarde introuvable.", "error")
        return redirect(url_for("dashboard"))
    target_type, target_name, file_path = row
    client = ensure_docker_client()
    if not client:
        flash(docker_unavailable_message(), "error")
        return redirect(url_for("dashboard"))
    try:
        if target_type == "image":
            with open(file_path, "rb") as fh:
                client.images.load(fh.read())
        else:
            image = import_container_backup(file_path, client=client)
            image_config = image.attrs.get("Config") or {}
            removed_existing = False
            if target_name:
                removed_existing = remove_existing_container(target_name, client=client)
            if image_config.get("Cmd") or image_config.get("Entrypoint"):
                client.containers.run(image.id, detach=True, name=target_name or None)
                flash("Restauration déclenchée.", "success")
            else:
                message = "Image importée. Aucun CMD/Entrypoint détecté, créez le conteneur manuellement."
                if removed_existing:
                    message = "Conteneur existant supprimé. " + message
                flash(message, "success")
        if target_type == "image":
            flash("Restauration déclenchée.", "success")
    except docker.errors.DockerException as exc:
        reset_docker_client(str(exc))
        flash(docker_unavailable_message(), "error")
    except Exception as exc:
        flash(f"Erreur de restauration: {exc}", "error")
    return redirect(url_for("dashboard"))


@app.route("/schedule/container/<container_id>", methods=["POST"])
@login_required
def schedule_container(container_id):
    client = ensure_docker_client()
    if not client:
        flash(docker_unavailable_message(), "error")
        return redirect(url_for("dashboard"))
    try:
        container = client.containers.get(container_id)
    except docker.errors.DockerException as exc:
        reset_docker_client(str(exc))
        flash(docker_unavailable_message(), "error")
        return redirect(url_for("dashboard"))

    if request.form.get("disable"):
        delete_container_schedule(container.name)
        refresh_scheduler()
        flash("Planification désactivée.", "success")
        return redirect(url_for("dashboard"))

    days = request.form.getlist("days")
    time_value = request.form.get("time", "").strip()
    retention_raw = request.form.get("retention", "").strip()
    if not days or not time_value:
        delete_container_schedule(container.name)
        refresh_scheduler()
        flash("Planification désactivée (jour ou heure manquante).", "warning")
        return redirect(url_for("dashboard"))
    try:
        retention = max(0, int(retention_raw or 0))
    except ValueError:
        retention = get_int_setting("backup_retention", 20)
    set_container_schedule(container.name, days, time_value, retention)
    refresh_scheduler()
    flash("Planification enregistrée.", "success")
    return redirect(url_for("dashboard"))


@app.route("/download/<path:filename>")
@login_required
def download_backup(filename):
    return send_from_directory(BACKUP_DIR, filename, as_attachment=True)


@app.route("/settings", methods=["GET", "POST"])
@login_required
def settings():
    if request.method == "POST":
        set_setting("backup_retention", request.form.get("backup_retention", "20"))
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
        "backup_retention": get_setting("backup_retention", "20"),
        "smtp_host": get_setting("smtp_host", ""),
        "smtp_port": get_setting("smtp_port", ""),
        "smtp_user": get_setting("smtp_user", ""),
        "smtp_password": get_setting("smtp_password", ""),
        "alert_email": get_setting("alert_email", ""),
        "drive_command": get_setting("drive_command", "rclone"),
        "drive_target": get_setting("drive_target", ""),
    }
    return render_template("settings.html", **context)


@app.route("/logs")
@login_required
def logs():
    log_lines = read_log_lines()
    if not log_lines:
        log_lines = ["Aucun log disponible pour le moment.\n"]
    return render_template("logs.html", log_lines=log_lines, log_file=str(LOG_FILE))


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
