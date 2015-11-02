'''
File: constants.py
Author: Dimitris Karakostas
Description: Constants library.
'''

import binascii

# Protocol tag numbers
IP_TAG = 8
TCP_TAG = 6
ICMP_TAG = 1
UDP_TAG = 17

# Ethernet Header
ETHERNET_HEADER_LENGTH = 14
ETHERNET_HEADER_UNPACK = '!6s6sH'

# IP Header
IP_HEADER_UNPACK = '!BBHHHBBH4s4s'

# TCP Header
TCP_HEADER_UNPACK = '!HHLLBBHHH'

# ICMP Header
ICMP_HEADER_UNPACK = '!BBH'

# UDP Header
UDP_HEADER_UNPACK = '!HHHH'

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
TLS_CONTENT = {TLS_CHANGE_CIPHER_SPEC: 'Change cipher spec (20)',
               TLS_ALERT: 'Alert (21)',
               TLS_HANDSHAKE: 'Handshake (22)',
               TLS_APPLICATION_DATA: 'Application Data (23)',
               TLS_HEARTBEAT: 'Heartbeat (24)'}
TLS_VERSION = {(3, 0): 'SSL 3.0',
               (3, 1): 'TLS 1.0',
               (3, 2): 'TLS 1.1',
               (3, 3): 'TLS 1.2'}

# TLS Alert messages
ALERT_HEADER = '1503010002'
ALERT_MESSAGES = {'CLOSE_NOTIFY': binascii.unhexlify(ALERT_HEADER + '0200'),
                  'UNEXPECTED_MESSAGE': binascii.unhexlify(ALERT_HEADER + '020A'),
                  'DECRYPTION_FAILED': binascii.unhexlify(ALERT_HEADER + '0217'),
                  'HANDSHAKE_FAILURE': binascii.unhexlify(ALERT_HEADER + '0228'),
                  'ILLEGAL_PARAMETER': binascii.unhexlify(ALERT_HEADER + '022F'),
                  'ACCESS_DENIED': binascii.unhexlify(ALERT_HEADER + '0231'),
                  'DECODE_ERROR': binascii.unhexlify(ALERT_HEADER + '0232'),
                  'DECRYPT_ERROR': binascii.unhexlify(ALERT_HEADER + '0233'),
                  'PROTOCOL_VERSION': binascii.unhexlify(ALERT_HEADER + '0246')}

# Ports and nodes
USER = ''  # Listen requests from everyone
TOUCH_FACEBOOK_IP = '31.13.93.3'  # touch.facebook.com
GMAIL_IP = '216.58.208.101'  # mail.google.com
TLS_PORT = 443

# Buffers
SOCKET_BUFFER = 4096
LOG_BUFFER = 16

# Downgrade
ATTEMPT_DOWNGRADE = False
MAX_TLS_POSITION = 10  # Iceweasel's max tls version byte position in Client Hello message
MAX_TLS_ALLOWED = 1

# Possible alphabets of secret
DIGIT = ['0', '1', '2', '3', '4', '5', '6', '7', '8', '9']
LOWERCASE = ['a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z']
UPPERCASE = ['A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z']
DASH = ['-', '_']

# Random nonces
NONCE_1 = 'ladbfsk!'
NONCE_2 = 'znq'

# Point systems for various methods, used in parse.py
SERIAL_POINT_SYSTEM = {1: 20, 2: 16, 3: 12, 4: 10, 5: 8, 6: 6, 7: 4, 8: 3, 9: 2, 10: 1}
PARALLEL_POINT_SYSTEM = {0: 1}
POINT_SYSTEM_MAPPING = {'s': SERIAL_POINT_SYSTEM,
                        'p': PARALLEL_POINT_SYSTEM}

# Times a candidate has to be optimal to attack forward

PARALLEL_REPEAT = 5
