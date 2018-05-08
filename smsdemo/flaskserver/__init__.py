"""
Flask demo server.
"""

from flask import Flask, request

from smsdemo.constants import POST_PATH, SIGNATURE_HEADER_KEY
from smsdemo.message import SMSMessage
from smsdemo.util import (
    ServerConfig, SMSSendError,
    parse_signature, generate_signature,
    sync_send,
)


app = Flask(__name__)


@app.route(POST_PATH, methods=["POST"])
def receive_and_echo():
    secret = app.config["secret"]

    if request.headers.get("Content-Type") == "application/json":
        payload = request.get_json()
    else:
        payload = request.form

    msg = SMSMessage.from_payload(payload)
    app.logger.info("Received message: %s", msg)

    sig = request.headers.get(SIGNATURE_HEADER_KEY)
    raw_payload = request.data
    timestamp, _ = parse_signature(sig)
    expected_sig = generate_signature(secret=secret,
                                      payload=raw_payload,
                                      timestamp=timestamp)
    if sig != expected_sig:
        app.logger.error("Invalid signature: %s (expected %s)", sig, expected_sig)
        return "Invalid signature", 400

    try:
        echo_msg = msg.echo_message()
        sync_send(echo_msg, secret)
    except SMSSendError as e:
        app.logger.error("Echo failed: %s", e)
        return "Echo failed", 502

    app.logger.info("Echoed message: %s", echo_msg)
    return "Echo OK", 200


def run(conf: ServerConfig):
    """Run the flask-based demo server."""

    app.config["secret"] = conf.secret

    app.logger.info("SMS echo server (Flask) running on %s:%d", conf.host, conf.port)
    app.run(host=conf.host, port=conf.port)
