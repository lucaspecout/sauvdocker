import os
import sqlite3
import base64
import io
from datetime import datetime
from pathlib import Path
import subprocess
import json
import tarfile
import tempfile
import shutil
import logging
import threading
import uuid
import hashlib
import hmac
from logging.handlers import RotatingFileHandler

from flask import Flask, render_template, request, redirect, url_for, flash, session, send_from_directory, jsonify
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
import docker
from requests.exceptions import InvalidURL
from docker import types as docker_types
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
STACK_LABEL_KEYS = ("com.docker.stack.namespace", "com.docker.compose.project")
ENC_HEADER = b"SDENC1"
ENC_IV_SIZE = 16
ENC_HMAC_SIZE = 32
ENC_CHUNK_SIZE = 1024 * 1024

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
task_status = {}
task_lock = threading.Lock()


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
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS stack_schedules (
                stack_name TEXT PRIMARY KEY,
                days TEXT NOT NULL,
                time TEXT NOT NULL,
                retention INTEGER NOT NULL,
                db_safe INTEGER NOT NULL DEFAULT 0
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


def update_task(task_id, **updates):
    if not task_id:
        return
    with task_lock:
        task = task_status.get(task_id, {})
        task.update(updates)
        task_status[task_id] = task


def get_task(task_id):
    with task_lock:
        return task_status.get(task_id, {}).copy()


def get_encryption_key():
    return get_setting("backup_encryption_key")


def encrypt_file(source_path, destination_path, secret):
    try:
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
        from cryptography.hazmat.backends import default_backend
        from cryptography.hazmat.primitives import padding
    except ImportError as exc:
        raise RuntimeError("Le chiffrement nécessite le module cryptography.") from exc
    if not secret:
        raise RuntimeError("Clé de chiffrement manquante.")
    key = hashlib.sha256(secret.encode("utf-8")).digest()
    iv = os.urandom(ENC_IV_SIZE)
    hmac_key = hashlib.sha256((secret + "hmac").encode("utf-8")).digest()
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    padder = padding.PKCS7(128).padder()
    hmac_ctx = hmac.new(hmac_key, digestmod=hashlib.sha256)
    total_size = Path(source_path).stat().st_size
    processed = 0
    with open(source_path, "rb") as source, open(destination_path, "wb") as target:
        target.write(ENC_HEADER)
        target.write(iv)
        while True:
            chunk = source.read(ENC_CHUNK_SIZE)
            if not chunk:
                break
            processed += len(chunk)
            padded = padder.update(chunk)
            if padded:
                encrypted = encryptor.update(padded)
                target.write(encrypted)
                hmac_ctx.update(encrypted)
        padded_final = padder.finalize()
        encrypted_final = encryptor.update(padded_final) + encryptor.finalize()
        if encrypted_final:
            target.write(encrypted_final)
            hmac_ctx.update(encrypted_final)
        target.write(hmac_ctx.digest())
    return total_size, processed


def decrypt_file(source_path, destination_path, secret):
    try:
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
        from cryptography.hazmat.backends import default_backend
        from cryptography.hazmat.primitives import padding
    except ImportError as exc:
        raise RuntimeError("Le déchiffrement nécessite le module cryptography.") from exc
    if not secret:
        raise RuntimeError("Clé de chiffrement manquante.")
    source_size = Path(source_path).stat().st_size
    if source_size < len(ENC_HEADER) + ENC_IV_SIZE + ENC_HMAC_SIZE:
        raise RuntimeError("Fichier chiffré invalide.")
    cipher_size = source_size - len(ENC_HEADER) - ENC_IV_SIZE - ENC_HMAC_SIZE
    hmac_key = hashlib.sha256((secret + "hmac").encode("utf-8")).digest()
    hmac_ctx = hmac.new(hmac_key, digestmod=hashlib.sha256)
    key = hashlib.sha256(secret.encode("utf-8")).digest()
    processed = 0
    with open(source_path, "rb") as source, open(destination_path, "wb") as target:
        header = source.read(len(ENC_HEADER))
        if header != ENC_HEADER:
            raise RuntimeError("Fichier chiffré invalide.")
        iv = source.read(ENC_IV_SIZE)
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        unpadder = padding.PKCS7(128).unpadder()
        remaining = cipher_size
        while remaining > 0:
            chunk = source.read(min(ENC_CHUNK_SIZE, remaining))
            if not chunk:
                break
            remaining -= len(chunk)
            processed += len(chunk)
            hmac_ctx.update(chunk)
            padded = decryptor.update(chunk)
            if padded:
                target.write(unpadder.update(padded))
        file_hmac = source.read(ENC_HMAC_SIZE)
        if not hmac.compare_digest(hmac_ctx.digest(), file_hmac):
            target.close()
            try:
                Path(destination_path).unlink()
            except OSError:
                pass
            raise RuntimeError("Clé de chiffrement invalide ou fichier corrompu.")
        padded_final = decryptor.finalize()
        target.write(unpadder.update(padded_final) + unpadder.finalize())
    return cipher_size, processed


def maybe_encrypt_backup(file_path):
    encryption_key = get_encryption_key()
    if not encryption_key:
        return file_path, False
    encrypted_path = f"{file_path}.enc"
    encrypt_file(file_path, encrypted_path, encryption_key)
    try:
        Path(file_path).unlink()
    except OSError as exc:
        log_docker_event(f"backup_encrypt_cleanup_error path={file_path} error={exc}", logging.WARNING)
    return encrypted_path, True


def is_encrypted_backup_file(file_path):
    path = Path(file_path)
    if not path.exists():
        return False
    try:
        with open(path, "rb") as fh:
            header = fh.read(len(ENC_HEADER))
    except OSError as exc:
        log_docker_event(f"backup_encryption_check_error path={file_path} error={exc}", logging.WARNING)
        return False
    return header == ENC_HEADER


def detect_backup_metadata(file_path):
    working_path, temp_dir = prepare_restore_file(file_path)
    try:
        if tarfile.is_tarfile(working_path):
            with tarfile.open(working_path, "r") as tar:
                try:
                    manifest_member = tar.getmember("manifest.json")
                except KeyError:
                    return "image", None
                manifest_file = tar.extractfile(manifest_member)
                if not manifest_file:
                    return "image", None
                manifest = json.load(manifest_file)
            if "stack" in manifest:
                return "stack", (manifest.get("stack") or {}).get("name")
            if "container" in manifest:
                return "container", (manifest.get("container") or {}).get("name")
            return "container", None
        return "image", None
    finally:
        if temp_dir:
            shutil.rmtree(temp_dir, ignore_errors=True)


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


def backup_container(container_id, name=None, client=None, retention=None, task_id=None):
    client = client or ensure_docker_client()
    if not client:
        raise docker.errors.DockerException(docker_unavailable_message())
    container = client.containers.get(container_id)
    filename = f"container-{name or container.name}-{datetime.utcnow().strftime('%Y%m%d%H%M%S')}.tar"
    file_path = BACKUP_DIR / filename
    try:
        update_task(task_id, status="running", progress=5, message="Préparation de la sauvegarde")
        temp_dir = Path(tempfile.mkdtemp(prefix="sauvedocker-backup-"))
        try:
            update_task(task_id, progress=10, message="Sauvegarde de l'image")
            image = container.image
            image_tar_path = temp_dir / "image.tar"
            with open(image_tar_path, "wb") as fh:
                for chunk in image.save(named=True):
                    fh.write(chunk)
            volumes_dir = temp_dir / "volumes"
            volumes_dir.mkdir(parents=True, exist_ok=True)
            volume_entries = []
            for mount in container.attrs.get("Mounts", []):
                if mount.get("Type") != "volume":
                    continue
                volume_name = mount.get("Name")
                destination = mount.get("Destination")
                if not volume_name or not destination:
                    continue
                update_task(task_id, message=f"Sauvegarde du volume {volume_name}")
                volume_tar_path = volumes_dir / f"{volume_name}.tar"
                archive_path = f"{destination.rstrip('/')}/."
                archive_stream, _ = container.get_archive(archive_path)
                with open(volume_tar_path, "wb") as fh:
                    for chunk in archive_stream:
                        fh.write(chunk)
                volume_entries.append(
                    {
                        "name": volume_name,
                        "destination": destination,
                        "read_only": not mount.get("RW", True),
                    }
                )
            manifest = {
                "version": 2,
                "container": {
                    "name": container.name,
                    "config": container.attrs.get("Config", {}),
                    "host_config": container.attrs.get("HostConfig", {}),
                    "image_id": image.id,
                    "image_tags": image.tags or [],
                },
                "volumes": volume_entries,
                "networks": collect_container_networks(container, client),
            }
            manifest_path = temp_dir / "manifest.json"
            with open(manifest_path, "w", encoding="utf-8") as fh:
                json.dump(manifest, fh, ensure_ascii=False, indent=2)
            with tarfile.open(file_path, "w") as tar:
                tar.add(manifest_path, arcname="manifest.json")
                tar.add(image_tar_path, arcname="image.tar")
                if volume_entries:
                    tar.add(volumes_dir, arcname="volumes")
        finally:
            shutil.rmtree(temp_dir, ignore_errors=True)
        update_task(task_id, progress=85, message="Chiffrement de la sauvegarde")
        encrypted_file_path, encrypted = maybe_encrypt_backup(file_path)
        record_backup("container", name or container.name, str(encrypted_file_path), "success")
        retention_value = retention if retention is not None else get_int_setting("backup_retention", 20)
        cleanup_old_backups(retention_value, target_type="container", target_name=name or container.name)
        run_drive_transfer(str(encrypted_file_path))
        send_alert("Sauvegarde container réussie", f"Sauvegarde créée pour {name or container.name}")
        update_task(
            task_id,
            status="success",
            progress=100,
            message="Sauvegarde terminée",
            details="Sauvegarde chiffrée." if encrypted else "Sauvegarde terminée.",
        )
        return True, None
    except Exception as exc:
        record_backup("container", name or container.name, str(file_path), "failed", str(exc))
        send_alert("Sauvegarde container échouée", f"Erreur pour {name or container.name}: {exc}")
        update_task(task_id, status="failed", progress=100, message="Échec de la sauvegarde", details=str(exc))
        return False, str(exc)


def backup_stack(stack_name, client=None, task_id=None):
    client = client or ensure_docker_client()
    if not client:
        raise docker.errors.DockerException(docker_unavailable_message())
    containers = []
    for container in client.containers.list(all=True):
        container_stack, label_key = get_container_stack(container)
        if container_stack == stack_name:
            containers.append(container)
    if not containers:
        raise RuntimeError("Aucun conteneur trouvé pour cette stack.")
    filename = f"stack-{stack_name}-{datetime.utcnow().strftime('%Y%m%d%H%M%S')}.tar"
    file_path = BACKUP_DIR / filename
    try:
        update_task(task_id, status="running", progress=5, message="Préparation de la sauvegarde stack")
        temp_dir = Path(tempfile.mkdtemp(prefix="sauvedocker-stack-"))
        try:
            images_dir = temp_dir / "images"
            images_dir.mkdir(parents=True, exist_ok=True)
            volumes_dir = temp_dir / "volumes"
            volumes_dir.mkdir(parents=True, exist_ok=True)
            image_entries = {}
            container_entries = []
            for container in containers:
                update_task(task_id, message=f"Sauvegarde image {container.image.short_id}")
                image = container.image
                image_id = image.id
                if image_id not in image_entries:
                    image_filename = f"{image_id.replace(':', '_')}.tar"
                    image_tar_path = images_dir / image_filename
                    with open(image_tar_path, "wb") as fh:
                        for chunk in image.save(named=True):
                            fh.write(chunk)
                    image_entries[image_id] = {
                        "id": image_id,
                        "tags": image.tags or [],
                        "file": f"images/{image_filename}",
                    }
                volume_mappings = []
                for mount in container.attrs.get("Mounts", []):
                    if mount.get("Type") != "volume":
                        continue
                    volume_name = mount.get("Name")
                    destination = mount.get("Destination")
                    if not volume_name or not destination:
                        continue
                    volume_mappings.append(
                        {
                            "name": volume_name,
                            "destination": destination,
                            "read_only": not mount.get("RW", True),
                        }
                    )
                container_entries.append(
                    {
                        "name": container.name,
                        "config": container.attrs.get("Config", {}),
                        "host_config": container.attrs.get("HostConfig", {}),
                        "image_id": image_id,
                        "image_tags": image.tags or [],
                        "volumes": volume_mappings,
                        "networks": collect_container_networks(container, client),
                    }
                )
            volume_entries = []
            stack_volumes = collect_stack_volumes(client, stack_name)
            helper_image = None
            if stack_volumes:
                helper_image = ensure_helper_image(client)
            for volume in stack_volumes:
                volume_name = volume.name
                if not volume_name:
                    continue
                update_task(task_id, message=f"Sauvegarde volume {volume_name}")
                volume_tar_path = volumes_dir / f"{volume_name}.tar"
                backup_volume_archive(volume_name, volume_tar_path, client, helper_image)
                volume_attrs = volume.attrs or {}
                volume_entries.append(
                    {
                        "name": volume_name,
                        "driver": volume_attrs.get("Driver"),
                        "labels": volume_attrs.get("Labels") or {},
                        "options": volume_attrs.get("Options") or {},
                    }
                )
            manifest = {
                "version": 1,
                "stack": {"name": stack_name},
                "containers": container_entries,
                "images": list(image_entries.values()),
                "volumes": volume_entries,
                "networks": collect_stack_networks(client, stack_name),
            }
            manifest_path = temp_dir / "manifest.json"
            with open(manifest_path, "w", encoding="utf-8") as fh:
                json.dump(manifest, fh, ensure_ascii=False, indent=2)
            with tarfile.open(file_path, "w") as tar:
                tar.add(manifest_path, arcname="manifest.json")
                if image_entries:
                    tar.add(images_dir, arcname="images")
                if volume_entries:
                    tar.add(volumes_dir, arcname="volumes")
        finally:
            shutil.rmtree(temp_dir, ignore_errors=True)
        update_task(task_id, progress=85, message="Chiffrement de la sauvegarde stack")
        encrypted_file_path, encrypted = maybe_encrypt_backup(file_path)
        record_backup("stack", stack_name, str(encrypted_file_path), "success")
        cleanup_old_backups(get_int_setting("backup_retention", 20), target_type="stack", target_name=stack_name)
        run_drive_transfer(str(encrypted_file_path))
        send_alert("Sauvegarde stack réussie", f"Sauvegarde créée pour {stack_name}")
        update_task(
            task_id,
            status="success",
            progress=100,
            message="Sauvegarde stack terminée",
            details="Sauvegarde chiffrée." if encrypted else "Sauvegarde terminée.",
        )
        return True, None
    except Exception as exc:
        record_backup("stack", stack_name, str(file_path), "failed", str(exc))
        send_alert("Sauvegarde stack échouée", f"Erreur pour {stack_name}: {exc}")
        update_task(task_id, status="failed", progress=100, message="Échec de la sauvegarde", details=str(exc))
        return False, str(exc)


def get_container_env(container):
    return container.attrs.get("Config", {}).get("Env", []) or []


def is_database_container(container):
    hints = (
        "postgres",
        "postgis",
        "mysql",
        "mariadb",
        "percona",
        "mssql",
        "mongo",
        "redis",
    )
    env_hints = (
        "POSTGRES_DB",
        "POSTGRES_USER",
        "PGDATA",
        "MYSQL_DATABASE",
        "MYSQL_USER",
        "MARIADB_DATABASE",
        "MARIADB_USER",
        "MONGO_INITDB_DATABASE",
        "REDIS_PASSWORD",
    )
    container_name = (container.name or "").lower()
    if any(hint in container_name for hint in hints):
        return True
    image_tags = container.image.tags or []
    if any(hint in tag.lower() for hint in hints for tag in image_tags):
        return True
    env_values = get_container_env(container)
    if any(env_key in env_item for env_key in env_hints for env_item in env_values):
        return True
    return False


def backup_stack_with_db_pause(stack_name, client=None, task_id=None):
    client = client or ensure_docker_client()
    if not client:
        raise docker.errors.DockerException(docker_unavailable_message())
    stack_containers = []
    for container in client.containers.list(all=True):
        container_stack, label_key = get_container_stack(container)
        if container_stack == stack_name:
            stack_containers.append(container)
    if not stack_containers:
        raise RuntimeError("Aucun conteneur trouvé pour cette stack.")
    db_containers = [container for container in stack_containers if is_database_container(container)]
    stopped_containers = []
    try:
        for container in db_containers:
            container.reload()
            if container.status == "running":
                log_docker_event(f"stack_backup_stop_db container={container.name} stack={stack_name}")
                container.stop(timeout=10)
                stopped_containers.append(container)
        return backup_stack(stack_name, client=client, task_id=task_id)
    finally:
        for container in stopped_containers:
            try:
                log_docker_event(f"stack_backup_start_db container={container.name} stack={stack_name}")
                container.start()
            except docker.errors.DockerException as exc:
                log_docker_event(
                    f"stack_backup_restart_db_error container={container.name} stack={stack_name} error={exc}",
                    logging.WARNING,
                )


def backup_image(image_id, name=None, client=None, task_id=None):
    client = client or ensure_docker_client()
    if not client:
        raise docker.errors.DockerException(docker_unavailable_message())
    image = client.images.get(image_id)
    filename = f"image-{name or image.short_id}-{datetime.utcnow().strftime('%Y%m%d%H%M%S')}.tar"
    file_path = BACKUP_DIR / filename
    try:
        update_task(task_id, status="running", progress=10, message="Sauvegarde de l'image")
        image_data = image.save(named=True)
        with open(file_path, "wb") as fh:
            for chunk in image_data:
                fh.write(chunk)
        update_task(task_id, progress=85, message="Chiffrement de la sauvegarde image")
        encrypted_file_path, encrypted = maybe_encrypt_backup(file_path)
        record_backup("image", name or image.short_id, str(encrypted_file_path), "success")
        cleanup_old_backups(get_int_setting("backup_retention", 20), target_type="image")
        run_drive_transfer(str(encrypted_file_path))
        send_alert("Sauvegarde image réussie", f"Sauvegarde créée pour {name or image.short_id}")
        update_task(
            task_id,
            status="success",
            progress=100,
            message="Sauvegarde image terminée",
            details="Sauvegarde chiffrée." if encrypted else "Sauvegarde terminée.",
        )
        return True, None
    except Exception as exc:
        record_backup("image", name or image.short_id, str(file_path), "failed", str(exc))
        send_alert("Sauvegarde image échouée", f"Erreur pour {name or image.short_id}: {exc}")
        update_task(task_id, status="failed", progress=100, message="Échec de la sauvegarde", details=str(exc))
        return False, str(exc)


def import_container_backup(file_path, client=None):
    client = client or ensure_docker_client()
    if not client:
        raise docker.errors.DockerException(docker_unavailable_message())
    before_images = {image.id for image in client.images.list()}
    with open(file_path, "rb") as fh:
        loaded = client.images.load(fh.read())
    loaded_images = []
    if isinstance(loaded, list):
        loaded_images = loaded
    elif isinstance(loaded, tuple) and loaded and isinstance(loaded[0], list):
        loaded_images = loaded[0]
    if loaded_images:
        return loaded_images[0]
    before_images = {image.id for image in client.images.list()}
    after_images = client.images.list()
    new_images = [image for image in after_images if image.id not in before_images]
    if not new_images:
        raise RuntimeError("Import de l'image échoué.")
    return new_images[0]


def normalize_port_bindings(port_bindings):
    if not port_bindings:
        return None
    ports = {}
    for container_port, bindings in port_bindings.items():
        if not bindings:
            ports[container_port] = None
            continue
        binding = bindings[0] or {}
        host_port = binding.get("HostPort")
        host_ip = binding.get("HostIp")
        if host_port:
            try:
                host_port_value = int(host_port)
            except ValueError:
                host_port_value = host_port
        else:
            host_port_value = None
        if host_ip and host_ip != "0.0.0.0":
            ports[container_port] = (host_ip, host_port_value)
        else:
            ports[container_port] = host_port_value
    return ports


def ensure_helper_image(client):
    helper_image = "alpine:3.19"
    try:
        return client.images.get(helper_image)
    except docker.errors.ImageNotFound:
        return client.images.pull(helper_image)


def collect_container_networks(container, client):
    networks = []
    network_settings = container.attrs.get("NetworkSettings", {}).get("Networks", {}) or {}
    for network_name, details in network_settings.items():
        try:
            network = client.networks.get(network_name)
            network_attrs = network.attrs or {}
        except docker.errors.NotFound:
            network_attrs = {}
        ipam = network_attrs.get("IPAM") or {}
        networks.append(
            {
                "name": network_name,
                "aliases": details.get("Aliases") or [],
                "ipv4_address": details.get("IPAddress"),
                "ipv6_address": details.get("GlobalIPv6Address"),
                "driver": network_attrs.get("Driver"),
                "options": network_attrs.get("Options") or {},
                "ipam_config": ipam.get("Config") or [],
                "labels": network_attrs.get("Labels") or {},
                "internal": network_attrs.get("Internal", False),
                "attachable": network_attrs.get("Attachable", False),
                "enable_ipv6": network_attrs.get("EnableIPv6", False),
            }
        )
    return networks


def get_container_stack(container):
    labels = container.labels or {}
    if not labels:
        labels = container.attrs.get("Config", {}).get("Labels", {}) or {}
    for label_key in STACK_LABEL_KEYS:
        value = labels.get(label_key)
        if value:
            return value, label_key
    return None, None


def split_containers_by_stack(containers):
    stacks = {}
    standalone = []
    stack_label_keys = {}
    for container in containers:
        stack_name, label_key = get_container_stack(container)
        if stack_name:
            stacks.setdefault(stack_name, []).append(container)
            if label_key:
                stack_label_keys.setdefault(stack_name, label_key)
        else:
            standalone.append(container)
    return standalone, stacks, stack_label_keys


def collect_stack_networks(client, stack_name):
    networks = []
    seen = set()
    for label_key in STACK_LABEL_KEYS:
        for network in client.networks.list(filters={"label": f"{label_key}={stack_name}"}):
            if network.name in seen:
                continue
            seen.add(network.name)
            attrs = network.attrs or {}
            ipam = attrs.get("IPAM") or {}
            networks.append(
                {
                    "name": network.name,
                    "driver": attrs.get("Driver"),
                    "options": attrs.get("Options") or {},
                    "ipam_config": ipam.get("Config") or [],
                    "labels": attrs.get("Labels") or {},
                    "internal": attrs.get("Internal", False),
                    "attachable": attrs.get("Attachable", False),
                    "enable_ipv6": attrs.get("EnableIPv6", False),
                }
            )
    return networks


def collect_stack_volumes(client, stack_name):
    volumes = []
    seen = set()
    for label_key in STACK_LABEL_KEYS:
        for volume in client.volumes.list(filters={"label": f"{label_key}={stack_name}"}):
            if volume.name in seen:
                continue
            seen.add(volume.name)
            volumes.append(volume)
    return volumes


def backup_volume_archive(volume_name, archive_path, client, helper_image):
    helper_container = client.containers.create(
        helper_image.id,
        command=["sleep", "120"],
        volumes={volume_name: {"bind": "/volume", "mode": "ro"}},
    )
    try:
        archive_stream, _ = helper_container.get_archive("/volume/.")
        with open(archive_path, "wb") as fh:
            for chunk in archive_stream:
                fh.write(chunk)
    finally:
        helper_container.remove(force=True)


def build_ipam_config(config_entries):
    if not config_entries:
        return None
    pools = []
    for entry in config_entries:
        if not entry:
            continue
        pools.append(
            docker_types.IPAMPool(
                subnet=entry.get("Subnet"),
                gateway=entry.get("Gateway"),
                iprange=entry.get("IPRange"),
                aux_addresses=entry.get("AuxiliaryAddresses"),
            )
        )
    if not pools:
        return None
    return docker_types.IPAMConfig(pool_configs=pools)


def ensure_network(client, network_entry):
    network_name = network_entry.get("name")
    if not network_name:
        return None
    try:
        return client.networks.get(network_name)
    except docker.errors.NotFound:
        return client.networks.create(
            name=network_name,
            driver=network_entry.get("driver") or "bridge",
            options=network_entry.get("options") or None,
            labels=network_entry.get("labels") or None,
            internal=network_entry.get("internal", False),
            attachable=network_entry.get("attachable", False),
            enable_ipv6=network_entry.get("enable_ipv6", False),
            ipam=build_ipam_config(network_entry.get("ipam_config")),
        )


def connect_container_network(container, network, network_entry):
    aliases = network_entry.get("aliases") or None
    ipv4_address = network_entry.get("ipv4_address") or None
    ipv6_address = network_entry.get("ipv6_address") or None
    try:
        network.connect(
            container,
            aliases=aliases,
            ipv4_address=ipv4_address,
            ipv6_address=ipv6_address,
        )
    except docker.errors.APIError as exc:
        if ipv4_address or ipv6_address:
            log_docker_event(
                "network_connect_retry "
                f"container={container.name} network={network.name} error={exc}",
                logging.WARNING,
            )
            network.connect(container, aliases=aliases)
        else:
            raise


def reset_volume_contents(client, helper_image, volume_name):
    cleanup_container = client.containers.create(
        helper_image.id,
        command=["sh", "-c", "rm -rf /volume/* /volume/.[!.]* /volume/..?* || true"],
        volumes={volume_name: {"bind": "/volume", "mode": "rw"}},
    )
    try:
        cleanup_container.start()
        cleanup_container.wait(timeout=60)
    finally:
        cleanup_container.remove(force=True)


def remove_images_by_tags(client, image_tags):
    for tag in image_tags or []:
        try:
            image = client.images.get(tag)
        except docker.errors.ImageNotFound:
            continue
        try:
            image.remove(force=True)
        except docker.errors.DockerException as exc:
            log_docker_event(f"image_remove_error tag={tag} error={exc}", logging.WARNING)


def normalize_volume_archive(archive_path, destination, temp_dir):
    destination_name = Path(destination.rstrip("/")).name
    if not destination_name:
        return archive_path
    extract_dir = temp_dir / f"volume-{destination_name}"
    try:
        with tarfile.open(archive_path, "r") as tar:
            members = [member for member in tar.getmembers() if member.name not in (".", "./")]
            if not members:
                return archive_path
            top_levels = {member.name.split("/")[0] for member in members if member.name}
            if len(top_levels) != 1 or destination_name not in top_levels:
                return archive_path
            tar.extractall(path=extract_dir)
        source_dir = extract_dir / destination_name
        if not source_dir.exists():
            return archive_path
        normalized_path = extract_dir / "normalized.tar"
        with tarfile.open(normalized_path, "w") as tar:
            for item in source_dir.rglob("*"):
                tar.add(item, arcname=item.relative_to(source_dir))
        return normalized_path
    except (tarfile.TarError, OSError):
        return archive_path


def restore_container_bundle(file_path, client=None):
    client = client or ensure_docker_client()
    if not client:
        raise docker.errors.DockerException(docker_unavailable_message())
    temp_dir = Path(tempfile.mkdtemp(prefix="sauvedocker-restore-"))
    try:
        with tarfile.open(file_path, "r") as tar:
            tar.extract("manifest.json", path=temp_dir)
            tar.extract("image.tar", path=temp_dir)
            volume_members = [member for member in tar.getmembers() if member.name.startswith("volumes/")]
            if volume_members:
                tar.extractall(path=temp_dir, members=volume_members)
        with open(temp_dir / "manifest.json", "r", encoding="utf-8") as fh:
            manifest = json.load(fh)
        container_info = manifest.get("container", {})
        image_tags = container_info.get("image_tags") or []
        if image_tags:
            remove_images_by_tags(client, image_tags)
        with open(temp_dir / "image.tar", "rb") as fh:
            client.images.load(fh.read())
        volume_entries = manifest.get("volumes", [])
        network_entries = manifest.get("networks", [])
        helper_image = None
        if volume_entries:
            helper_image = ensure_helper_image(client)
        for volume in volume_entries:
            volume_name = volume.get("name")
            destination = volume.get("destination")
            if not volume_name or not destination:
                continue
            try:
                client.volumes.get(volume_name)
                reset_volume_contents(client, helper_image, volume_name)
            except docker.errors.NotFound:
                client.volumes.create(name=volume_name)
            archive_path = temp_dir / "volumes" / f"{volume_name}.tar"
            if not archive_path.exists():
                continue
            normalized_archive_path = normalize_volume_archive(archive_path, destination, temp_dir)
            helper_container = client.containers.create(
                helper_image.id,
                command=["sleep", "120"],
                volumes={volume_name: {"bind": "/volume", "mode": "rw"}},
            )
            try:
                with open(normalized_archive_path, "rb") as fh:
                    helper_container.put_archive("/volume", fh.read())
            finally:
                helper_container.remove(force=True)
        container_name = container_info.get("name")
        config = container_info.get("config", {})
        host_config = container_info.get("host_config", {})
        for network_entry in network_entries:
            ensure_network(client, network_entry)
        image_ref = image_tags[0] if image_tags else container_info.get("image_id")
        if not image_ref:
            raise RuntimeError("Image introuvable dans la sauvegarde.")
        removed_existing = False
        if container_name:
            removed_existing = remove_existing_container(container_name, client=client)
        volumes = {}
        for volume in volume_entries:
            volume_name = volume.get("name")
            destination = volume.get("destination")
            if not volume_name or not destination:
                continue
            mode = "ro" if volume.get("read_only") else "rw"
            volumes[volume_name] = {"bind": destination, "mode": mode}
        ports = normalize_port_bindings(host_config.get("PortBindings"))
        network_mode = host_config.get("NetworkMode")
        restart_policy = host_config.get("RestartPolicy") or None
        container = client.containers.create(
            image_ref,
            name=container_name or None,
            command=config.get("Cmd"),
            entrypoint=config.get("Entrypoint"),
            environment=config.get("Env"),
            working_dir=config.get("WorkingDir") or None,
            labels=config.get("Labels") or None,
            ports=ports,
            volumes=volumes or None,
            restart_policy=restart_policy,
            network_mode=network_mode if network_mode and network_mode != "default" else None,
        )
        container.start()
        for network_entry in network_entries:
            network_name = network_entry.get("name")
            if not network_name or network_name in ("bridge", "host", "none"):
                continue
            if network_mode and network_mode == network_name:
                continue
            try:
                network = client.networks.get(network_name)
            except docker.errors.NotFound:
                continue
            connect_container_network(container, network, network_entry)
        return removed_existing
    finally:
        shutil.rmtree(temp_dir, ignore_errors=True)


def restore_stack_bundle(file_path, client=None):
    client = client or ensure_docker_client()
    if not client:
        raise docker.errors.DockerException(docker_unavailable_message())
    temp_dir = Path(tempfile.mkdtemp(prefix="sauvedocker-stack-restore-"))
    try:
        with tarfile.open(file_path, "r") as tar:
            tar.extract("manifest.json", path=temp_dir)
            image_members = [member for member in tar.getmembers() if member.name.startswith("images/")]
            volume_members = [member for member in tar.getmembers() if member.name.startswith("volumes/")]
            if image_members:
                tar.extractall(path=temp_dir, members=image_members)
            if volume_members:
                tar.extractall(path=temp_dir, members=volume_members)
        with open(temp_dir / "manifest.json", "r", encoding="utf-8") as fh:
            manifest = json.load(fh)
        for image_entry in manifest.get("images", []):
            image_tags = image_entry.get("tags") or []
            if image_tags:
                remove_images_by_tags(client, image_tags)
            image_path = temp_dir / image_entry.get("file", "")
            if not image_path.exists():
                continue
            with open(image_path, "rb") as fh:
                client.images.load(fh.read())
        volume_entries = manifest.get("volumes", [])
        network_entries = manifest.get("networks", [])
        helper_image = None
        if volume_entries:
            helper_image = ensure_helper_image(client)
        for volume in volume_entries:
            volume_name = volume.get("name")
            if not volume_name:
                continue
            try:
                client.volumes.get(volume_name)
                reset_volume_contents(client, helper_image, volume_name)
            except docker.errors.NotFound:
                client.volumes.create(
                    name=volume_name,
                    driver=volume.get("driver"),
                    driver_opts=volume.get("options") or None,
                    labels=volume.get("labels") or None,
                )
            archive_path = temp_dir / "volumes" / f"{volume_name}.tar"
            if not archive_path.exists():
                continue
            helper_container = client.containers.create(
                helper_image.id,
                command=["sleep", "120"],
                volumes={volume_name: {"bind": "/volume", "mode": "rw"}},
            )
            try:
                with open(archive_path, "rb") as fh:
                    helper_container.put_archive("/volume", fh.read())
            finally:
                helper_container.remove(force=True)
        for network_entry in network_entries:
            ensure_network(client, network_entry)
        stack_network_names = {entry.get("name") for entry in network_entries if entry.get("name")}
        for container_entry in manifest.get("containers", []):
            container_name = container_entry.get("name")
            config = container_entry.get("config", {})
            host_config = container_entry.get("host_config", {})
            image_tags = container_entry.get("image_tags") or []
            image_ref = image_tags[0] if image_tags else container_entry.get("image_id")
            if not image_ref:
                raise RuntimeError("Image introuvable pour restaurer la stack.")
            if container_name:
                remove_existing_container(container_name, client=client)
            volumes = {}
            for volume in container_entry.get("volumes", []):
                volume_name = volume.get("name")
                destination = volume.get("destination")
                if not volume_name or not destination:
                    continue
                mode = "ro" if volume.get("read_only") else "rw"
                volumes[volume_name] = {"bind": destination, "mode": mode}
            ports = normalize_port_bindings(host_config.get("PortBindings"))
            network_mode = host_config.get("NetworkMode")
            restart_policy = host_config.get("RestartPolicy") or None
            container = client.containers.create(
                image_ref,
                name=container_name or None,
                command=config.get("Cmd"),
                entrypoint=config.get("Entrypoint"),
                environment=config.get("Env"),
                working_dir=config.get("WorkingDir") or None,
                labels=config.get("Labels") or None,
                ports=ports,
                volumes=volumes or None,
                restart_policy=restart_policy,
                network_mode=network_mode if network_mode and network_mode != "default" else None,
            )
            container.start()
            container_networks = container_entry.get("networks") or []
            if not container_networks and network_entries:
                container_networks = list(network_entries)
            elif stack_network_names:
                container_network_names = {
                    entry.get("name") for entry in container_networks if entry.get("name")
                }
                if not (container_network_names & stack_network_names):
                    for network_entry in network_entries:
                        network_name = network_entry.get("name")
                        if network_name and network_name not in container_network_names:
                            container_networks.append({"name": network_name})
                            container_network_names.add(network_name)
            for network_entry in container_networks:
                network_name = network_entry.get("name")
                if not network_name or network_name in ("bridge", "host", "none"):
                    continue
                if network_mode and network_mode == network_name:
                    continue
                try:
                    network = client.networks.get(network_name)
                except docker.errors.NotFound:
                    continue
                connect_container_network(container, network, network_entry)
        return True
    finally:
        shutil.rmtree(temp_dir, ignore_errors=True)


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


def scheduled_stack_backup(stack_name, retention, db_safe):
    client = ensure_docker_client()
    if not client:
        return
    if db_safe:
        backup_stack_with_db_pause(stack_name, client=client)
    else:
        backup_stack(stack_name, client=client)


def get_stack_schedules():
    with sqlite3.connect(DB_PATH) as conn:
        rows = conn.execute(
            "SELECT stack_name, days, time, retention, db_safe FROM stack_schedules"
        ).fetchall()
    schedules = {}
    for name, days, time_value, retention, db_safe in rows:
        schedules[name] = {
            "days": [day for day in days.split(",") if day],
            "time": time_value,
            "retention": retention,
            "db_safe": bool(db_safe),
        }
    return schedules


def set_stack_schedule(stack_name, days, time_value, retention, db_safe):
    with sqlite3.connect(DB_PATH) as conn:
        conn.execute(
            """
            INSERT INTO stack_schedules (stack_name, days, time, retention, db_safe)
            VALUES (?, ?, ?, ?, ?)
            ON CONFLICT(stack_name) DO UPDATE SET days = excluded.days, time = excluded.time,
            retention = excluded.retention, db_safe = excluded.db_safe
            """,
            (stack_name, ",".join(days), time_value, retention, int(db_safe)),
        )
        conn.commit()


def delete_stack_schedule(stack_name):
    with sqlite3.connect(DB_PATH) as conn:
        conn.execute("DELETE FROM stack_schedules WHERE stack_name = ?", (stack_name,))
        conn.commit()


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
    stack_schedules = get_stack_schedules()
    for stack_name, schedule in stack_schedules.items():
        if not schedule["days"] or not schedule["time"]:
            continue
        try:
            hour_str, minute_str = schedule["time"].split(":")
            scheduler.add_job(
                scheduled_stack_backup,
                "cron",
                day_of_week=",".join(schedule["days"]),
                hour=int(hour_str),
                minute=int(minute_str),
                args=[stack_name, schedule["retention"], schedule["db_safe"]],
                id=f"stack_backup_{stack_name}",
                replace_existing=True,
            )
        except ValueError:
            log_docker_event(
                f"schedule_invalid_time stack={stack_name} time={schedule['time']}",
                logging.WARNING,
            )


@app.route("/")
@login_required
def dashboard():
    client = ensure_docker_client()
    if client:
        try:
            containers = client.containers.list(all=True)
        except docker.errors.DockerException as exc:
            reset_docker_client(str(exc))
            containers = []
            flash(docker_unavailable_message(), "error")
    else:
        containers = []
        flash(docker_unavailable_message(), "error")
    containers, stacks, _ = split_containers_by_stack(containers)
    schedules = get_container_schedules()
    stack_schedules = get_stack_schedules()
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
    encrypted_backups = {backup[0]: is_encrypted_backup_file(backup[3]) for backup in backups}
    container_backups = {}
    stack_backups = {}
    for backup in backups:
        if backup[1] != "container":
            if backup[1] == "stack":
                stack_backups.setdefault(backup[2], []).append(backup)
            continue
        container_backups.setdefault(backup[2], []).append(backup)
    latest_container_backups = {
        name: history[0] for name, history in container_backups.items() if history
    }
    latest_stack_backups = {
        name: history[0] for name, history in stack_backups.items() if history
    }
    return render_template(
        "dashboard.html",
        containers=containers,
        stacks=stacks,
        backups=backups,
        encrypted_backups=encrypted_backups,
        container_backups=container_backups,
        latest_container_backups=latest_container_backups,
        stack_backups=stack_backups,
        latest_stack_backups=latest_stack_backups,
        schedules=schedules,
        stack_schedules=stack_schedules,
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


def start_task(title, target_type, target_name):
    task_id = uuid.uuid4().hex
    update_task(
        task_id,
        status="queued",
        progress=0,
        message=title,
        target_type=target_type,
        target_name=target_name,
        started_at=datetime.utcnow().isoformat(),
    )
    return task_id


def run_container_backup_task(task_id, container_id):
    update_task(task_id, status="running", progress=2, message="Connexion à Docker")
    client = ensure_docker_client()
    if not client:
        update_task(task_id, status="failed", progress=100, message="Docker indisponible", details=docker_unavailable_message())
        return
    try:
        container = client.containers.get(container_id)
        schedule = get_container_schedules().get(container.name, {})
        retention = schedule.get("retention")
        update_task(task_id, target_name=container.name)
        success, error_message = backup_container(
            container.id,
            container.name,
            client=client,
            retention=retention,
            task_id=task_id,
        )
        if not success:
            update_task(task_id, status="failed", progress=100, details=error_message)
    except Exception as exc:
        update_task(task_id, status="failed", progress=100, message="Échec de la sauvegarde", details=str(exc))


def run_stack_backup_task(task_id, stack_name, db_safe=False):
    update_task(task_id, status="running", progress=2, message="Connexion à Docker")
    client = ensure_docker_client()
    if not client:
        update_task(task_id, status="failed", progress=100, message="Docker indisponible", details=docker_unavailable_message())
        return
    try:
        update_task(task_id, target_name=stack_name)
        if db_safe:
            success, error_message = backup_stack_with_db_pause(stack_name, client=client, task_id=task_id)
        else:
            success, error_message = backup_stack(stack_name, client=client, task_id=task_id)
        if not success:
            update_task(task_id, status="failed", progress=100, details=error_message)
    except Exception as exc:
        update_task(task_id, status="failed", progress=100, message="Échec de la sauvegarde", details=str(exc))


def run_image_backup_task(task_id, image_id):
    update_task(task_id, status="running", progress=2, message="Connexion à Docker")
    client = ensure_docker_client()
    if not client:
        update_task(task_id, status="failed", progress=100, message="Docker indisponible", details=docker_unavailable_message())
        return
    try:
        image = client.images.get(image_id)
        name = image.tags[0] if image.tags else image.short_id
        update_task(task_id, target_name=name)
        success, error_message = backup_image(image.id, name, client=client, task_id=task_id)
        if not success:
            update_task(task_id, status="failed", progress=100, details=error_message)
    except Exception as exc:
        update_task(task_id, status="failed", progress=100, message="Échec de la sauvegarde", details=str(exc))


def prepare_restore_file(file_path, task_id=None):
    encrypted = is_encrypted_backup_file(file_path)
    if not encrypted:
        if str(file_path).endswith(".enc"):
            raise RuntimeError("Fichier chiffré invalide.")
        return Path(file_path), None
    update_task(task_id, status="running", progress=10, message="Déchiffrement de la sauvegarde")
    temp_dir = Path(tempfile.mkdtemp(prefix="sauvedocker-restore-dec-"))
    decrypted_path = temp_dir / Path(file_path).with_suffix("").name
    decrypt_file(file_path, decrypted_path, get_encryption_key())
    return decrypted_path, temp_dir


def run_restore_task(task_id, backup_id):
    update_task(task_id, status="running", progress=2, message="Préparation de la restauration")
    with sqlite3.connect(DB_PATH) as conn:
        row = conn.execute(
            "SELECT target_type, target_name, file_path FROM backups WHERE id = ?",
            (backup_id,),
        ).fetchone()
    if not row:
        update_task(task_id, status="failed", progress=100, message="Sauvegarde introuvable")
        return
    target_type, target_name, file_path = row
    update_task(task_id, target_type=target_type, target_name=target_name)
    client = ensure_docker_client()
    if not client:
        update_task(task_id, status="failed", progress=100, message="Docker indisponible", details=docker_unavailable_message())
        return
    temp_dir = None
    try:
        working_path, temp_dir = prepare_restore_file(file_path, task_id=task_id)
        update_task(task_id, progress=40, message="Restauration en cours")
        if target_type == "image":
            with open(working_path, "rb") as fh:
                client.images.load(fh.read())
        elif target_type == "stack":
            restore_stack_bundle(working_path, client=client)
        else:
            if tarfile.is_tarfile(working_path):
                with tarfile.open(working_path, "r") as tar:
                    if "manifest.json" in tar.getnames():
                        restore_container_bundle(working_path, client=client)
                        update_task(task_id, progress=90, message="Restauration du conteneur terminée")
                        update_task(task_id, status="success", progress=100, message="Restauration terminée")
                        return
            image = import_container_backup(working_path, client=client)
            image_config = image.attrs.get("Config") or {}
            if target_name:
                remove_existing_container(target_name, client=client)
            if image_config.get("Cmd") or image_config.get("Entrypoint"):
                client.containers.run(image.id, detach=True, name=target_name or None)
        update_task(task_id, status="success", progress=100, message="Restauration terminée")
    except Exception as exc:
        update_task(task_id, status="failed", progress=100, message="Erreur de restauration", details=str(exc))
    finally:
        if temp_dir:
            shutil.rmtree(temp_dir, ignore_errors=True)


def run_import_task(task_id, destination, target_type):
    update_task(task_id, status="running", progress=5, message="Validation de la sauvegarde")
    try:
        encrypted = is_encrypted_backup_file(destination)
        if not encrypted and str(destination).endswith(".enc"):
            raise RuntimeError("Fichier chiffré invalide.")
        if encrypted and not str(destination).endswith(".enc"):
            renamed = destination.with_name(f"{destination.name}.enc")
            destination.rename(renamed)
            destination = renamed
        update_task(task_id, progress=25, message="Détection du type de sauvegarde")
        detected_type = None
        detected_name = None
        if target_type == "auto":
            detected_type, detected_name = detect_backup_metadata(destination)
            target_type = detected_type
        elif target_type not in {"container", "stack", "image"}:
            raise RuntimeError("Type de sauvegarde invalide.")
        if not target_type:
            raise RuntimeError("Impossible de détecter le type de sauvegarde.")
        if not detected_name:
            detected_name = Path(destination).stem
        update_task(
            task_id,
            target_type=target_type,
            target_name=detected_name,
            progress=70,
            message="Enregistrement de la sauvegarde",
        )
        record_backup(target_type, detected_name, str(destination), "imported")
        update_task(task_id, status="success", progress=100, message="Sauvegarde importée")
    except Exception as exc:
        try:
            destination.unlink()
        except OSError:
            pass
        update_task(task_id, status="failed", progress=100, message="Erreur d'import", details=str(exc))


@app.route("/tasks/<task_id>")
@login_required
def task_status_route(task_id):
    return jsonify(get_task(task_id) or {"status": "unknown"})


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
        success, error_message = backup_container(
            container.id,
            container.name,
            client=client,
            retention=retention,
        )
    except docker.errors.DockerException as exc:
        reset_docker_client(str(exc))
        flash(docker_unavailable_message(), "error")
        return redirect(url_for("dashboard"))
    if success:
        flash("Sauvegarde du conteneur créée.", "success")
    else:
        flash(f"Échec de la sauvegarde du conteneur. {error_message}", "error")
    return redirect(url_for("dashboard"))


@app.route("/tasks/backup/container/<container_id>", methods=["POST"])
@login_required
def backup_container_task_route(container_id):
    task_id = start_task("Sauvegarde conteneur", "container", container_id)
    thread = threading.Thread(target=run_container_backup_task, args=(task_id, container_id), daemon=True)
    thread.start()
    return jsonify({"task_id": task_id})


@app.route("/backup/stack/<stack_name>", methods=["POST"])
@login_required
def backup_stack_route(stack_name):
    client = ensure_docker_client()
    if not client:
        flash(docker_unavailable_message(), "error")
        return redirect(url_for("dashboard"))
    try:
        success, error_message = backup_stack(stack_name, client=client)
    except docker.errors.DockerException as exc:
        reset_docker_client(str(exc))
        flash(docker_unavailable_message(), "error")
        return redirect(url_for("dashboard"))
    if success:
        flash("Sauvegarde de la stack créée.", "success")
    else:
        flash(f"Échec de la sauvegarde de la stack. {error_message}", "error")
    return redirect(url_for("dashboard"))


@app.route("/tasks/backup/stack/<stack_name>", methods=["POST"])
@login_required
def backup_stack_task_route(stack_name):
    task_id = start_task("Sauvegarde stack", "stack", stack_name)
    thread = threading.Thread(target=run_stack_backup_task, args=(task_id, stack_name, False), daemon=True)
    thread.start()
    return jsonify({"task_id": task_id})


@app.route("/backup/stack/<stack_name>/db-safe", methods=["POST"])
@login_required
def backup_stack_db_safe_route(stack_name):
    client = ensure_docker_client()
    if not client:
        flash(docker_unavailable_message(), "error")
        return redirect(url_for("dashboard"))
    try:
        success, error_message = backup_stack_with_db_pause(stack_name, client=client)
    except docker.errors.DockerException as exc:
        reset_docker_client(str(exc))
        flash(docker_unavailable_message(), "error")
        return redirect(url_for("dashboard"))
    if success:
        flash("Sauvegarde stack avec arrêt DB créée.", "success")
    else:
        flash(f"Échec de la sauvegarde stack avec arrêt DB. {error_message}", "error")
    return redirect(url_for("dashboard"))


@app.route("/tasks/backup/stack/<stack_name>/db-safe", methods=["POST"])
@login_required
def backup_stack_db_safe_task_route(stack_name):
    task_id = start_task("Sauvegarde stack (arrêt DB)", "stack", stack_name)
    thread = threading.Thread(target=run_stack_backup_task, args=(task_id, stack_name, True), daemon=True)
    thread.start()
    return jsonify({"task_id": task_id})


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
        success, error_message = backup_image(image.id, name, client=client)
    except docker.errors.DockerException as exc:
        reset_docker_client(str(exc))
        flash(docker_unavailable_message(), "error")
        return redirect(url_for("dashboard"))
    if success:
        flash("Sauvegarde de l'image créée.", "success")
    else:
        flash(f"Échec de la sauvegarde de l'image. {error_message}", "error")
    return redirect(url_for("dashboard"))


@app.route("/tasks/backup/image/<image_id>", methods=["POST"])
@login_required
def backup_image_task_route(image_id):
    task_id = start_task("Sauvegarde image", "image", image_id)
    thread = threading.Thread(target=run_image_backup_task, args=(task_id, image_id), daemon=True)
    thread.start()
    return jsonify({"task_id": task_id})


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
    temp_dir = None
    try:
        working_path, temp_dir = prepare_restore_file(file_path)
        if target_type == "image":
            with open(working_path, "rb") as fh:
                client.images.load(fh.read())
        elif target_type == "stack":
            restore_stack_bundle(working_path, client=client)
            flash("Restauration de la stack déclenchée.", "success")
            return redirect(url_for("dashboard"))
        else:
            if tarfile.is_tarfile(working_path):
                with tarfile.open(working_path, "r") as tar:
                    if "manifest.json" in tar.getnames():
                        removed_existing = restore_container_bundle(working_path, client=client)
                        if removed_existing:
                            flash("Conteneur existant supprimé. Restauration déclenchée.", "success")
                        else:
                            flash("Restauration déclenchée.", "success")
                        return redirect(url_for("dashboard"))
            image = import_container_backup(working_path, client=client)
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
    finally:
        if temp_dir:
            shutil.rmtree(temp_dir, ignore_errors=True)
    return redirect(url_for("dashboard"))


@app.route("/tasks/restore", methods=["POST"])
@login_required
def restore_backup_task_route():
    backup_id = request.form.get("backup_id")
    if not backup_id:
        return jsonify({"error": "backup_id manquant"}), 400
    task_id = start_task("Restauration sauvegarde", "restore", backup_id)
    thread = threading.Thread(target=run_restore_task, args=(task_id, backup_id), daemon=True)
    thread.start()
    return jsonify({"task_id": task_id})


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


@app.route("/schedule/stack/<stack_name>", methods=["POST"])
@login_required
def schedule_stack(stack_name):
    if request.form.get("disable"):
        delete_stack_schedule(stack_name)
        refresh_scheduler()
        flash("Planification stack désactivée.", "success")
        return redirect(url_for("dashboard"))

    days = request.form.getlist("days")
    time_value = request.form.get("time", "").strip()
    retention_raw = request.form.get("retention", "").strip()
    db_safe = bool(request.form.get("db_safe"))
    if not days or not time_value:
        delete_stack_schedule(stack_name)
        refresh_scheduler()
        flash("Planification stack désactivée (jour ou heure manquante).", "warning")
        return redirect(url_for("dashboard"))
    try:
        retention = max(0, int(retention_raw or 0))
    except ValueError:
        retention = get_int_setting("backup_retention", 20)
    set_stack_schedule(stack_name, days, time_value, retention, db_safe)
    refresh_scheduler()
    flash("Planification stack enregistrée.", "success")
    return redirect(url_for("dashboard"))


@app.route("/download/<path:filename>")
@login_required
def download_backup(filename):
    file_path = BACKUP_DIR / filename
    if not file_path.exists():
        flash("Sauvegarde introuvable.", "error")
        return redirect(url_for("dashboard"))
    if str(file_path).endswith(".enc") and not is_encrypted_backup_file(file_path):
        flash("Sauvegarde chiffrée invalide.", "error")
        return redirect(url_for("dashboard"))
    return send_from_directory(BACKUP_DIR, filename, as_attachment=True)


@app.route("/tasks/backup/import", methods=["POST"])
@login_required
def import_backup_task_route():
    uploaded = request.files.get("backup_file")
    target_type = request.form.get("target_type", "auto")
    if not uploaded or not uploaded.filename:
        return jsonify({"error": "Fichier de sauvegarde manquant."}), 400
    BACKUP_DIR.mkdir(parents=True, exist_ok=True)
    filename = secure_filename(uploaded.filename)
    if not filename:
        filename = f"backup-{uuid.uuid4().hex}"
    destination = BACKUP_DIR / filename
    if destination.exists():
        destination = BACKUP_DIR / f"{destination.stem}-{uuid.uuid4().hex}{destination.suffix}"
    try:
        uploaded.save(destination)
    except OSError as exc:
        return jsonify({"error": f"Impossible d'enregistrer le fichier: {exc}"}), 500
    task_id = start_task("Import sauvegarde", "import", filename)
    thread = threading.Thread(target=run_import_task, args=(task_id, destination, target_type), daemon=True)
    thread.start()
    return jsonify({"task_id": task_id})


@app.route("/backup/delete", methods=["POST"])
@login_required
def delete_backup():
    backup_id = request.form.get("backup_id")
    if not backup_id:
        flash("Sauvegarde introuvable.", "error")
        return redirect(url_for("dashboard"))
    with sqlite3.connect(DB_PATH) as conn:
        row = conn.execute("SELECT file_path FROM backups WHERE id = ?", (backup_id,)).fetchone()
        if not row:
            flash("Sauvegarde introuvable.", "error")
            return redirect(url_for("dashboard"))
        conn.execute("DELETE FROM backups WHERE id = ?", (backup_id,))
        conn.commit()
    file_path = row[0]
    if file_path:
        try:
            path_obj = Path(file_path)
            if path_obj.exists():
                path_obj.unlink()
        except OSError as exc:
            log_docker_event(f"backup_delete_error path={file_path} error={exc}", logging.WARNING)
    flash("Sauvegarde supprimée.", "success")
    return redirect(url_for("dashboard"))


@app.route("/settings", methods=["GET", "POST"])
@login_required
def settings():
    if request.method == "POST":
        set_setting("backup_retention", request.form.get("backup_retention", "20"))
        set_setting("backup_encryption_key", request.form.get("backup_encryption_key"))
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
        "backup_encryption_key": get_setting("backup_encryption_key", ""),
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
