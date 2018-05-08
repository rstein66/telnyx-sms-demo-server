import json

from smsdemo.util import generate_signature, parse_signature


SECRET = "rq789onm321yxzkjihfEdcAm"
PAYLOAD = {
    "sms_id": "834f3d53-8a3c-4aa0-a733-7f2d682a72df",
    "from": "+13129450002",
    "to": "+13125550001",
    "body": "Hello!"
}
CREATED_AT = "1520983646"
HASH_VALUE = "FHbtAkvKvF5r81WLUlZtNy8k/mZi0byhw0G37njXqBs="
SIGNATURE_VALUE = "t=1520983646,h=FHbtAkvKvF5r81WLUlZtNy8k/mZi0byhw0G37njXqBs="


def test_generate_signature():
    signature_generated = generate_signature(secret=SECRET,
                                             payload=json.dumps(PAYLOAD),
                                             timestamp=CREATED_AT)

    assert signature_generated == SIGNATURE_VALUE


def test_parse_signature():
    timestamp, b64_encoded_hash = parse_signature(SIGNATURE_VALUE)
    assert timestamp == CREATED_AT
    assert b64_encoded_hash == HASH_VALUE
