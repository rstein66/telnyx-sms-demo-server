"""
Constants.
"""

# Demo server's default configuration.

CONFIG_KEY = "config"

DEFAULT_IP = "0.0.0.0"
DEFAULT_PORT = 80

POST_PATH = "/sms"


# HTTP request-response constants.

# Request endpoints.
MESSAGES_ENDPOINT = "https://sms.telnyx.com/messages"
MESSAGING_ENDPOINT = "https://api.telnyx.com/messaging"

# Messages: auth header keys.
SECRET_HEADER_KEY = "X-Profile-Secret"
SIGNATURE_HEADER_KEY = "X-Telnyx-Signature"

# Messaging: auth header keys.
API_USER_HEADER_KEY = "X-Api-User"
API_TOKEN_HEADER_KEY = "X-Api-Token"
