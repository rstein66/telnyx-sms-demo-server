"""
Various helpers.

This module contains the actual logic that does message validation and sending.
"""

import hmac
from base64 import b64encode
from collections import namedtuple
from datetime import datetime
from typing import Optional, Tuple, Union

import requests
from aiohttp import ClientSession, ClientError

from smsdemo.constants import (
    MESSAGES_ENDPOINT,
    SECRET_HEADER_KEY,
)
from smsdemo.message import SMSMessage


ServerConfig = namedtuple("ServerConfig", "host port secret")


class SMSSendError(Exception):
    pass


def sync_send(msg: SMSMessage, secret: str) -> str:
    """Synchronously send an SMSMessage, using the requests library.

    Returns:
        The response from the server.
    Raises:
        SMSSendError if sending failed.
    """

    headers = {SECRET_HEADER_KEY: secret}
    data = msg.as_dict()

    r = requests.post(MESSAGES_ENDPOINT, headers=headers, data=data)

    # Check return code and log the action
    if r.status_code != requests.codes.ok:
        raise SMSSendError(r.text)

    return r.text


async def async_send(msg: SMSMessage, secret: str) -> str:
    """Asynchronously send an SMSMessage, using the aiohttp client.

    Returns:
        The response from the server.
    Raises:
        SMSSendError if sending failed.
    """

    headers = {SECRET_HEADER_KEY: secret}
    data = msg.as_dict()

    try:
        async with ClientSession() as session:
            async with session.post(MESSAGES_ENDPOINT, headers=headers, data=data) as resp:
                resp_text = await resp.text()
                if resp.status != 200:
                    raise SMSSendError(resp_text)
                return resp_text

    except ClientError as e:
        raise SMSSendError(e)


def generate_signature(secret: str,
                       payload: Union[bytes, str],
                       timestamp: Optional[str]=None) -> str:
    """Generate header-signature value for webhook. Header value
    consists of concatenation of an epoch timestamp seconds and
    an HMAC-SHA256 signature of the given payload as a JSON string.
    e.g. 't=1510139799,h=kWxvGoHJz3ToJLO1s86cBWu1ZV0hFNmVU45bY5BTlm8='

    :param secret:      Receiving phone number's messaging profile secret.
    :param payload:     Request payload as a JSON string.
    :param timestamp:   Optional. Unix time in seconds.

    :returns:   Webhook signature header value.
    """

    timestamp = timestamp or str(int(datetime.utcnow().timestamp()))
    secret = secret.encode("utf-8")
    payload_bytes = payload if isinstance(payload, bytes) else payload.encode("utf-8")
    hash_input = timestamp.encode("ascii") + b"." + payload_bytes

    hash_bytes = hmac.new(secret, msg=hash_input, digestmod="sha256").digest()
    b64_encoded_hash = b64encode(hash_bytes).decode("ascii")
    signature_value = "t={},h={}".format(timestamp, b64_encoded_hash)

    return signature_value


def parse_signature(signature_value: str) -> Tuple:
    """Extracts Unix time and hash from the webhook signature header value."""

    signature_map = dict(param.split("=", 1) for param in signature_value.split(","))
    timestamp = signature_map["t"]
    b64_encoded_hash = signature_map["h"]

    return timestamp, b64_encoded_hash
