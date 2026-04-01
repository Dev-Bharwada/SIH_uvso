from flask import Flask, jsonify, request
from flask_cors import CORS
import io, sys, contextlib, json
# import your module (menu runs only under __main__, so import is safe)
import usvo_demo as core  # your uploaded file, placed as uvso_demo.py

app = Flask(__name__, static_folder=None)
CORS(app)  # only for dev; for ISO we’ll serve frontend as static via Flask

def _capture(fn, *args, **kwargs):
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        fn(*args, **kwargs)
    return buf.getvalue()

@app.get("/api/health")
def health():
    return {"ok": True}

@app.get("/api/detect")
def detect():
    out = _capture(core.detect_all_media)
    return {"stdout": out}

@app.post("/api/create-fake-disk")
def create_fake_disk():
    size_mb = int(request.json.get("size_mb", 10))
    out = _capture(core.create_fake_disk, size_mb)
    return {"stdout": out}

@app.post("/api/clear")
def clear_overwrite():
    disk = request.json.get("disk", core.FAKE_DISK)
    out = _capture(core.clear_overwrite, disk)
    return {"stdout": out}

@app.post("/api/ce")
def cryptographic_erase():
    disk = request.json.get("disk", core.FAKE_DISK)
    operator = request.json.get("operator", "TeamSIH")
    out = _capture(core.cryptographic_erase, disk, operator)
    return {"stdout": out}

@app.post("/api/verify")
def verify_and_certificate():
    disk = request.json.get("disk", core.FAKE_DISK)
    method = request.json.get("method", "clear")
    operator = request.json.get("operator", "TeamSIH")
    out = _capture(core.verify_and_certificate, disk, method, operator)
    return {"stdout": out, "cert": json.load(open("cert.json"))}

@app.get("/api/ledger")
def ledger():
    try:
        return {"stdout": open(core.LEDGER_FILE).read()}
    except FileNotFoundError:
        return {"stdout": "Ledger is empty."}

@app.post("/api/verify-signature")
def verify_signature():
    ok = core.verify_certificate_and_signature()
    return {"stdout": f"Signature/Ledger verification: {'PASS' if ok else 'FAIL'}"}

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8000)

