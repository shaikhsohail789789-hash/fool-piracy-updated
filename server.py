import hashlib
import json
import sqlite3

from flask import Flask, jsonify, request

app = Flask(__name__)

DATABASE = "licenses.db"


def get_db():
    return sqlite3.connect(DATABASE)


def fingerprint_hash(fp):
    return hashlib.sha256(json.dumps(fp, sort_keys=True).encode()).hexdigest()


def fingerprint_score(stored, current):

    score = 0

    if stored.get("cpu") == current.get("cpu"):
        score += 30

    if stored.get("machine") == current.get("machine"):
        score += 25

    if stored.get("system") == current.get("system"):
        score += 15

    if stored.get("node") == current.get("node"):
        score += 10

    if stored.get("mac") == current.get("mac"):
        score += 20

    return score


@app.route("/activate", methods=["POST"])
def activate():

    data = request.get_json()

    license_key = data.get("license_key")
    exe_hash = data.get("exe_hash")
    hardware = data.get("hardware_profile")

    conn = get_db()
    cur = conn.cursor()

    cur.execute(
        "SELECT exe_hash, activation_key, fingerprint_hash FROM licenses WHERE license_key=?",
        (license_key,),
    )

    row = cur.fetchone()

    if not row:
        conn.close()
        return jsonify({"status": "error", "message": "Invalid license key"})

    db_hash, activation_key, stored_fp_hash = row

    # Verify executable hash
    if exe_hash != db_hash:
        conn.close()
        return jsonify({"status": "error", "message": "Executable mismatch"})

    current_fp_hash = fingerprint_hash(hardware)

    # FIRST ACTIVATION
    if stored_fp_hash is None:
        cur.execute(
            "UPDATE licenses SET fingerprint_hash=? WHERE license_key=?",
            (current_fp_hash, license_key),
        )

        conn.commit()

    # FUTURE ACTIVATIONS
    else:
        if stored_fp_hash != current_fp_hash:
            conn.close()

            return jsonify(
                {"status": "error", "message": "Hardware fingerprint mismatch"}
            )

    # LOG ACTIVATION
    cur.execute(
        """
        INSERT INTO activation_logs (license_key, fingerprint_hash)
        VALUES (?, ?)
        """,
        (license_key, current_fp_hash),
    )

    conn.commit()
    conn.close()

    return jsonify(
        {"status": "activated", "activation_key": activation_key, "expires_in": 3600}
    )


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
