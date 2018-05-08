"""
aiohttp demo server.
"""

import logging

from aiohttp import web

from smsdemo.constants import POST_PATH, SIGNATURE_HEADER_KEY
from smsdemo.message import SMSMessage
from smsdemo.util import (
    ServerConfig, SMSSendError,
    parse_signature, generate_signature,
    async_send,
)


async def receive_and_echo(request):
    """Accept and validate an SMS delivery."""

    secret = request.app["secret"]

    if request.content_type == "application/json":
        payload = await request.json()
    else:
        payload = await request.post()

    msg = SMSMessage.from_payload(payload)
    logging.info("Received message: %s", msg)

    sig = request.headers.get(SIGNATURE_HEADER_KEY)
    raw_payload = await request.read()
    timestamp, _ = parse_signature(sig)
    expected_sig = generate_signature(secret=secret,
                                      payload=raw_payload,
                                      timestamp=timestamp)
    if sig != expected_sig:
        logging.error("Invalid signature: %s (expected %s)", sig, expected_sig)
        return web.HTTPBadRequest(text="Invalid signature")

    try:
        echo_msg = msg.echo_message()
        await async_send(echo_msg, secret)
    except SMSSendError as e:
        logging.error("Echo failed: %s", e)
        return web.HTTPBadGateway(text="Echo failed")

    logging.info("Echoed message: %s", echo_msg)
    return web.Response(text="Echo OK")


def run(conf: ServerConfig):
    app = web.Application()
    app["secret"] = conf.secret
    app.router.add_post(POST_PATH, receive_and_echo)

    logging.info("SMS echo server (aiohttp) running on %s:%d", conf.host, conf.port)
    web.run_app(app, host=conf.host, port=conf.port)
