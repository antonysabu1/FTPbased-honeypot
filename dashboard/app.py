import os
import binascii
import secrets
import logging
from flask import Flask, render_template, jsonify, request, send_from_directory, abort, Response
from honeypot.config import DASHBOARD_HOST, DASHBOARD_PORT, SECRET_KEY, QUARANTINE_DIR, DASHBOARD_USERNAME, DASHBOARD_PASSWORD
from honeypot.database import db

logger = logging.getLogger("AegisFTP.Dashboard")

app = Flask(__name__, static_folder="static", template_folder="templates")
app.config["SECRET_KEY"] = SECRET_KEY

if DASHBOARD_PASSWORD == "aegisftp-change-me":
    logger.warning(
        "[Dashboard] DASHBOARD_PASSWORD is not set -- using the default "
        "credentials (admin / aegisftp-change-me). Set DASHBOARD_USERNAME "
        "and DASHBOARD_PASSWORD env vars before exposing this dashboard "
        "beyond localhost."
    )


@app.before_request
def enforce_dashboard_auth():
    """Issue 2: the dashboard shows attacker IPs, trapped credentials and
    quarantined malware -- it must not be reachable by anyone who can
    just hit the port. HTTP Basic Auth, checked with a constant-time
    comparison to avoid a timing side-channel on the password."""
    auth = request.authorization
    valid = (
        auth is not None
        and secrets.compare_digest(auth.username or "", DASHBOARD_USERNAME)
        and secrets.compare_digest(auth.password or "", DASHBOARD_PASSWORD)
    )
    if not valid:
        return Response(
            "Authentication required", 401,
            {"WWW-Authenticate": 'Basic realm="AegisFTP Dashboard"'}
        )


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/api/stats")
def get_stats():
    stats = db.get_stats()
    return jsonify(stats)


@app.route("/api/sessions")
def get_sessions():
    limit = request.args.get("limit", 50, type=int)
    sessions = db.get_recent_sessions(limit)
    return jsonify(sessions)


@app.route("/api/auth_attempts")
def get_auth_attempts():
    limit = request.args.get("limit", 100, type=int)
    attempts = db.get_auth_attempts(limit)
    return jsonify(attempts)


@app.route("/api/commands")
def get_commands():
    limit = request.args.get("limit", 100, type=int)
    commands = db.get_command_logs(limit)
    return jsonify(commands)


@app.route("/api/events")
def get_events():
    limit = request.args.get("limit", 100, type=int)
    events = db.get_events(limit)
    return jsonify(events)



@app.route("/api/quarantine")
def get_quarantine():
    limit = request.args.get("limit", 50, type=int)
    files = db.get_quarantined_files(limit)
    return jsonify(files)


@app.route("/api/quarantine/preview/<int:file_id>")
def preview_quarantine_file(file_id):
    q_file = db.get_quarantined_file(file_id)
    if not q_file:
        return jsonify({"error": "File record not found"}), 404

    file_path = os.path.join(QUARANTINE_DIR, q_file["quarantine_filename"])
    if not os.path.exists(file_path):
        return jsonify({"error": "Quarantined file missing from disk"}), 404

    try:
        with open(file_path, "rb") as f:
            content = f.read(4096)  # Read max 4KB preview

        # Check if text/utf-8 readable
        is_text = True
        try:
            text_preview = content.decode('utf-8')
        except UnicodeDecodeError:
            is_text = False
            text_preview = ""

        # Hex dump preview
        hex_preview = binascii.hexlify(content).decode('ascii')
        formatted_hex = " ".join(hex_preview[i:i+2] for i in range(0, len(hex_preview), 2))

        return jsonify({
            "metadata": q_file,
            "is_text": is_text,
            "text_preview": text_preview if is_text else None,
            "hex_preview": formatted_hex
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/quarantine/download/<int:file_id>")
def download_quarantine_file(file_id):
    q_file = db.get_quarantined_file(file_id)
    if not q_file:
        abort(404)

    # Sanitize download filename against HTTP response splitting / header injection
    raw_name = q_file.get("original_filename") or "payload.bin"
    clean_name = "".join(c for c in raw_name if c.isalnum() or c in "._-") or "payload.bin"

    return send_from_directory(
        QUARANTINE_DIR,
        q_file["quarantine_filename"],
        as_attachment=True,
        download_name=clean_name
    )


def run_dashboard():
    app.run(host=DASHBOARD_HOST, port=DASHBOARD_PORT, debug=False, use_reloader=False)


if __name__ == "__main__":
    run_dashboard()
