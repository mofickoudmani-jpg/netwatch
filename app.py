"""
NetWatch — Flask Backend
Run: python app.py
"""

from flask import Flask, request, jsonify, render_template, send_file
from analyzer import parse_pcap, analyze_packets, generate_sample_pcap, _fmt_bytes
import traceback
import io
import os

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 100 * 1024 * 1024  # 100 MB max upload


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/api/analyze", methods=["POST"])
def api_analyze():
    try:
        if "file" not in request.files:
            return jsonify({"error": "No file uploaded"}), 400

        f = request.files["file"]
        if not f.filename:
            return jsonify({"error": "No file selected"}), 400

        if not f.filename.lower().endswith(".pcap"):
            return jsonify({"error": "Please upload a .pcap file"}), 400

        data = f.read()
        if len(data) < 24:
            return jsonify({"error": "File too small — not a valid PCAP"}), 400

        packets = parse_pcap(data)
        if not packets:
            return jsonify({"error": "Could not parse PCAP file. Make sure it is a valid libpcap (.pcap) file."}), 400

        result = analyze_packets(packets)
        return jsonify(_serialize(result))

    except Exception as e:
        traceback.print_exc()
        return jsonify({"error": str(e)}), 500


@app.route("/api/sample")
def api_sample():
    """Download a synthetic sample PCAP for demo purposes."""
    try:
        pcap_data = generate_sample_pcap()
        return send_file(
            io.BytesIO(pcap_data),
            mimetype="application/vnd.tcpdump.pcap",
            as_attachment=True,
            download_name="netwatch_sample.pcap",
        )
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/health")
def health():
    return jsonify({"status": "ok", "tool": "NetWatch v1.0"})


def _serialize(result):
    return {
        "total_packets": result.total_packets,
        "total_bytes": result.total_bytes,
        "total_bytes_fmt": _fmt_bytes(result.total_bytes),
        "duration_seconds": result.duration_seconds,
        "protocols": result.protocols,
        "top_talkers": result.top_talkers,
        "top_destinations": result.top_destinations,
        "port_activity": {
            str(k): v for k, v in result.port_activity.items()
        },
        "alerts": [
            {
                "severity": a.severity,
                "category": a.category,
                "description": a.description,
                "source": a.source,
                "destination": a.destination,
                "count": a.count,
                "evidence": a.evidence,
            }
            for a in result.alerts
        ],
        "connections": result.connections[:30],
        "risk_score": result.risk_score,
        "risk_level": result.risk_level,
        "summary": result.summary,
    }


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5001))
    print(f"\n🔍 NetWatch running at http://localhost:{port}\n")
    app.run(debug=True, host="0.0.0.0", port=port)
