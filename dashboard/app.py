import os
import binascii
from flask import Flask, render_template, jsonify, request, send_from_directory, abort, Response
from honeypot.config import (
    DASHBOARD_HOST, DASHBOARD_PORT, SECRET_KEY, QUARANTINE_DIR,
    DASHBOARD_USER, DASHBOARD_PASSWORD,
)
from honeypot.database import db

app = Flask(__name__, static_folder="static", template_folder="templates")
app.config["SECRET_KEY"] = SECRET_KEY


# V7: the dashboard exposes harvested credentials, so require HTTP Basic Auth.
# Credentials come from DASHBOARD_USER / DASHBOARD_PASSWORD (env or defaults).
def _check_auth(username, password):
    return username == DASHBOARD_USER and password == DASHBOARD_PASSWORD


@app.before_request
def require_auth():
    auth = request.authorization
    if not auth or not _check_auth(auth.username, auth.password):
        return Response(
            "Authentication required",
            401,
            {"WWW-Authenticate": 'Basic realm="AegisFTP Dashboard"'},
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
    conn = db.get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM quarantined_files WHERE id = ?", (file_id,))
    row = cursor.fetchone()
    conn.close()

    if not row:
        return jsonify({"error": "File record not found"}), 404

    q_file = dict(row)
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
    conn = db.get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM quarantined_files WHERE id = ?", (file_id,))
    row = cursor.fetchone()
    conn.close()

    if not row:
        abort(404)

    q_file = dict(row)
    return send_from_directory(
        QUARANTINE_DIR,
        q_file["quarantine_filename"],
        as_attachment=True,
        download_name=q_file["original_filename"]
    )


def run_dashboard():
    app.run(host=DASHBOARD_HOST, port=DASHBOARD_PORT, debug=False, use_reloader=False)


if __name__ == "__main__":
    run_dashboard()
