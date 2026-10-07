from flask import Flask, render_template, jsonify
from packet_sniffer import sniffer

app = Flask(__name__)


@app.route("/")
def home():
    return render_template("index.html")


@app.route("/start", methods=["POST"])
def start_sniffer():

    if not sniffer.running:
        sniffer.start()

    return jsonify({
        "success": True,
        "message": "Packet capture started"
    })


@app.route("/stop", methods=["POST"])
def stop_sniffer():

    sniffer.stop()

    return jsonify({
        "success": True,
        "message": "Packet capture stopped"
    })


@app.route("/data")
def packet_data():

    return jsonify(sniffer.get_data())


@app.route("/reset", methods=["POST"])
def reset_data():

    sniffer.reset()

    return jsonify({
        "success": True,
        "message": "Statistics reset"
    })


if __name__ == "__main__":

    print("=" * 50)
    print("       NETWORK PACKET SNIFFER")
    print("=" * 50)
    print("Open: http://127.0.0.1:5000")
    print("=" * 50)

    app.run(
        host="127.0.0.1",
        port=5000,
        debug=False,
        threaded=True
    )