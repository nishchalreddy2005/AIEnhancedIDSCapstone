from flask import Flask, request, jsonify
import json
from flask_cors import CORS
import core_ml as ml  # The machine learning model module rewritten below
from scapy.all import sniff, IP, TCP, UDP
import time


app = Flask(__name__)
# CORS(app)
CORS(app, origins=["http://localhost:5173"])

def extract_live_features(packet):
    """
    Convert a live packet into a KDD-like feature dict
    (minimal but compatible with your ML pipeline)
    """
    features = {
        "duration": 0,
        "protocol_type": "tcp",
        "service": "other",
        "flag": "SF",
        "src_bytes": 0,
        "dst_bytes": 0,
        "count": 1,
        "srv_count": 1
    }

    if IP in packet:
        features["src_bytes"] = len(packet)
        features["dst_bytes"] = len(packet.payload)

        if TCP in packet:
            features["protocol_type"] = "tcp"
            flags = packet[TCP].flags
            if flags & 0x02:
                features["flag"] = "S0"
            elif flags & 0x10:
                features["flag"] = "SF"
            else:
                features["flag"] = "REJ"

        elif UDP in packet:
            features["protocol_type"] = "udp"
            features["flag"] = "SF"

    return features

@app.route('/analyse-live', methods=['GET'])
def analyse_live():
    """
    Capture live packets (short window), analyze using ML,
    and return dynamic detection results.
    """
    try:
        results = []

        def process_packet(packet):
            features = extract_live_features(packet)
            prediction = ml.predict(features)

            results.append({
                "timestamp": time.time(),
                "features": features,
                "status": prediction["status"],
                "confidence": prediction["confidence"],
                "details": prediction["details"]
            })

        # Capture packets for 5 seconds (adjustable)
        sniff(prn=process_packet, timeout=5, store=False)

        if not results:
            return jsonify({
                "status": "no-data",
                "confidence": 0,
                "details": "No packets captured during live window"
            })

        # Aggregate results
        anomalies = [r for r in results if r["status"] != "safe"]
        anomaly_ratio = len(anomalies) / len(results)

        if anomaly_ratio == 0:
            final_status = "safe"
            confidence = 95
        elif anomaly_ratio < 0.2:
            final_status = "warning"
            confidence = 70
        else:
            final_status = "danger"
            confidence = 90

        return jsonify({
            "status": final_status,
            "confidence": confidence,
            "details": f"Live analysis complete. {len(anomalies)} anomalies detected out of {len(results)} packets.",
            "samples": results[:10]  # send first 10 detections only
        })

    except Exception as e:
        return jsonify({"error": f"Live analysis failed: {str(e)}"}), 500



@app.route('/analyze-csv', methods=['POST'])
def analyze_csv():
    try:
        if 'file' not in request.files:
            return jsonify({"error": "No file part in the request"}), 400
        file = request.files['file']
        if file.filename == '':
            return jsonify({"error": "No selected file"}), 400
        import pandas as pd
        # werkzeug FileStorage supports .stream
        df = pd.read_csv(file.stream)
        df.columns = df.columns.str.strip()

        # Delegate to ML ensemble; it handles missing columns internally
        result = ml.predict_csv(df)
        return jsonify({
            "status": result.status,
            "confidence": result.confidence,
            "details": result.details
        })
    except Exception as e:
        return jsonify({"error": f"CSV analysis failed: {str(e)}"}), 500

# Optional: Endpoint for analyzing individual log entries sent as JSON
@app.route('/analyze-logs', methods=['POST'])
def analyze_logs():
    try:
        # Accept {"log_data": {...}}, or a raw JSON object with features, or a JSON string
        data = request.get_json(silent=True)
        if data is None:
            raw = request.data.decode('utf-8') if request.data else ''
            try:
                data = json.loads(raw) if raw else None
            except Exception:
                data = None

        if data is None:
            return jsonify({"error": "Invalid or empty JSON body"}), 400

        if isinstance(data, dict) and 'log_data' in data:
            log_data = data['log_data']
        elif isinstance(data, dict):
            # Assume the body itself is the feature object
            log_data = data
        elif isinstance(data, str):
            try:
                log_data = json.loads(data)
            except Exception:
                log_data = data  # keep as raw manual text
        else:
            return jsonify({"error": "Unsupported body format"}), 400
        # If manual textarea text, parse whitespace-separated rows
        if isinstance(log_data, str):
            df = _parse_manual_kdd_text(log_data)
            if df is None or df.empty:
                return jsonify({"error": "Could not parse manual input. Provide JSON or KDD-like rows."}), 400
            if len(df) == 1:
                result = ml.predict(df.iloc[0].to_dict())
                return jsonify({
                    "status": result['status'],
                    "confidence": result['confidence'],
                    "details": result['details']
                })
            res_csv = ml.predict_csv(df)
            return jsonify({
                "status": res_csv.status,
                "confidence": res_csv.confidence,
                "details": res_csv.details
            })
        # Otherwise treat as dict and run ensemble for single row
        result = ml.predict(log_data)
        return jsonify({
            "status": result['status'],
            "confidence": result['confidence'],
            "details": result['details']
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500


def _parse_manual_kdd_text(text: str):
    import pandas as pd
    cols = [
        "duration", "protocol_type", "service", "flag", "src_bytes", "dst_bytes",
        "land", "wrong_fragment", "urgent", "hot", "num_failed_logins",
        "logged_in", "lnum_compromised", "lroot_shell", "lsu_attempted",
        "lnum_root", "lnum_file_creations", "lnum_shells", "lnum_access_files",
        "lnum_outbound_cmds", "is_host_login", "is_guest_login", "count",
        "srv_count", "serror_rate", "srv_serror_rate", "rerror_rate",
        "srv_rerror_rate", "same_srv_rate", "diff_srv_rate", "srv_diff_host_rate",
        "dst_host_count", "dst_host_srv_count", "dst_host_same_srv_rate",
        "dst_host_diff_srv_rate", "dst_host_same_src_port_rate",
        "dst_host_srv_diff_host_rate", "dst_host_serror_rate",
        "dst_host_srv_serror_rate", "dst_host_rerror_rate", "dst_host_srv_rerror_rate",
        "label"
    ]
    rows = []
    for raw in text.splitlines():
        line = raw.strip()
        if not line:
            continue
        parts = line.split()
        if len(parts) == len(cols):
            row = parts
        elif len(parts) == len(cols) - 1:
            row = parts + [""]
        else:
            continue
        record = {}
        for i, key in enumerate(cols):
            val = row[i]
            if key in ("protocol_type", "service", "flag", "label"):
                record[key] = val
            else:
                try:
                    record[key] = float(val)
                except Exception:
                    record[key] = 0.0
        rows.append(record)
    if not rows:
        return None
    df = pd.DataFrame(rows)
    int_like = [
        "duration", "src_bytes", "dst_bytes", "land", "wrong_fragment", "urgent", "hot",
        "num_failed_logins", "logged_in", "lnum_compromised", "lroot_shell", "lsu_attempted",
        "lnum_root", "lnum_file_creations", "lnum_shells", "lnum_access_files",
        "lnum_outbound_cmds", "is_host_login", "is_guest_login", "count", "srv_count",
        "dst_host_count", "dst_host_srv_count"
    ]
    for c in int_like:
        if c in df.columns:
            try:
                df[c] = df[c].astype(int)
            except Exception:
                pass
    return df
    
@app.route('/', methods=['GET'])
def index():
    return "Backend server is running."


if __name__ == '__main__':
    app.run(port=5000, debug=True)
