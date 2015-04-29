import binascii

# TLS Header
TLS_HEADER_LENGTH = 5
TLS_CONTENT_TYPE = 0
TLS_VERSION_MAJOR = 1
TLS_VERSION_MINOR = 2
TLS_LENGTH_MAJOR = 3
TLS_LENGTH_MINOR = 4

# TLS Content Types
TLS_CHANGE_CIPHER_SPEC = 20
TLS_ALERT = 21
TLS_HANDSHAKE = 22
TLS_APPLICATION_DATA = 23
TLS_HEARTBEAT = 24
TLS_CONTENT = {
        TLS_CHANGE_CIPHER_SPEC: "Change cipher spec (20)", 
        TLS_ALERT: "Alert (21)", 
        TLS_HANDSHAKE: "Handshake (22)", 
        TLS_APPLICATION_DATA: "Application Data (23)", 
        TLS_HEARTBEAT: "Heartbeat (24)"
    }
TLS_VERSION = {
        (3, 0): "SSL 3.0", 
        (3, 1): "TLS 1.0", 
        (3, 2): "TLS 1.1", 
        (3, 3): "TLS 1.2"
    }

# TLS Alert messages
ALERT_MESSAGES = {
            'CLOSE_NOTIFY' : binascii.unhexlify("15030100020200"),
            'UNEXPECTED_MESSAGE' : binascii.unhexlify("1503010002020A"),
            'DECRYPTION_FAILED' : binascii.unhexlify("15030100020217"),
            'HANDSHAKE_FAILURE' : binascii.unhexlify("15030100020228"),
            'ILLEGAL_PARAMETER' : binascii.unhexlify("1503010002022F"),
            'ACCESS_DENIED' : binascii.unhexlify("15030100020231"),
            'DECODE_ERROR' : binascii.unhexlify("15030100020232"),
            'DECRYPT_ERROR' : binascii.unhexlify("15030100020233"),
            'PROTOCOL_VERSION' : binascii.unhexlify("15030100020246")
        }

# Ports and nodes
USER = "" # Listen requests from everyone
USER_PORT = 443
ENDPOINT = "31.13.93.3" # Connect only to selected endpoint
ENDPOINT_PORT = 443

# Buffers
SOCKET_BUFFER = 4096
LOG_BUFFER = 16
