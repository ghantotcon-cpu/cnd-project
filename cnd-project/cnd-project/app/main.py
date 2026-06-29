"""
CND Project - Demo Microservice
A simple Python Flask API to demonstrate supply chain security.
"""

from flask import Flask, jsonify, request
import os
import hashlib
import datetime

app = Flask(__name__)

APP_VERSION = os.environ.get("APP_VERSION", "1.0.0")
BUILD_COMMIT = os.environ.get("BUILD_COMMIT", "unknown")
SLSA_LEVEL = os.environ.get("SLSA_LEVEL", "3")


@app.route("/")
def index():
    return jsonify({
        "service": "cnd-demo-app",
        "version": APP_VERSION,
        "build_commit": BUILD_COMMIT,
        "slsa_level": SLSA_LEVEL,
        "timestamp": datetime.datetime.utcnow().isoformat(),
        "status": "healthy"
    })


@app.route("/health")
def health():
    return jsonify({"status": "ok"}), 200


@app.route("/api/data")
def data():
    return jsonify({
        "items": [
            {"id": 1, "name": "Supply Chain Security", "status": "verified"},
            {"id": 2, "name": "SLSA Level 3", "status": "compliant"},
            {"id": 3, "name": "SBOM Generated", "status": "active"},
            {"id": 4, "name": "Cosign Signed", "status": "verified"},
        ]
    })


@app.route("/api/attestation")
def attestation():
    """Returns build attestation metadata (for demo purposes)."""
    return jsonify({
        "builder": "github-actions",
        "slsa_level": SLSA_LEVEL,
        "build_commit": BUILD_COMMIT,
        "version": APP_VERSION,
        "signed_by": "cosign",
        "sbom_format": "CycloneDX",
        "timestamp": datetime.datetime.utcnow().isoformat()
    })


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 8080))
    app.run(host="0.0.0.0", port=port)
