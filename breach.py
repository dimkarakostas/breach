import socket
import select
import logging
import binascii

#TLS Header
TLS_HEADER_LENGTH = 5
TLS_CONTENT_TYPE = 0
TLS_VERSION_MAJOR = 1
TLS_VERSION_MINOR = 2
TLS_LENGTH_MAJOR = 3
TLS_LENGTH_MINOR = 4

#TLS Content Types
TLS_CHANGE_CIPHER_SPEC = 20
TLS_ALERT = 21
TLS_HANDSHAKE = 22
TLS_APPLICATION_DATA = 23
TLS_HEARTBEAT = 24
TLS_CONTENT = {TLS_CHANGE_CIPHER_SPEC: "Change cipher spec (20)", TLS_ALERT: "Alert (21)", TLS_HANDSHAKE: "Handshake (22)", TLS_APPLICATION_DATA: "Application Data (23)", TLS_HEARTBEAT: "Heartbeat (24)"}
TLS_VERSION = {(3, 0) : "SSL 3.0", (3, 1): "TLS 1.0", (3, 2): "TLS 1.1", (3, 3): "TLS 1.2"}

#Ports and hosts
USER = "" #listen requests from everyone
USER_PORT = 443
ENDPOINT = "31.13.93.3" #connect only to selected endpoint
ENDPOINT_PORT = 443

#Data size
data_buff = 4096

#logger setup
logging.basicConfig()
logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)

def log_data(data, b=16):
    pad = 0
    output = []
    buff = ""
    for i in xrange(0, len(data), b):
            buff = data[i:i+b]
            hex = binascii.hexlify(buff) #hex representation of data
            pad = 32 - len(hex)
            txt = "" #ascii representation of data
            for ch in buff:
                if ((ord(ch)>126) or (ord(ch)<33)):
                        txt = txt + "."
                else:
                        txt = txt + chr(ord(ch))
            output.append("%2d\t %s%s\t %s" % (i, hex, pad*" ", txt))
    return "\n".join(output)

def parse(data, response=False):
    lg = ["\n"]
    cont_type = ord(data[TLS_CONTENT_TYPE])
    version = (ord(data[TLS_VERSION_MAJOR]), ord(data[TLS_VERSION_MINOR]))
    length = 256*ord(data[TLS_LENGTH_MAJOR]) + ord(data[TLS_LENGTH_MINOR])
    if (response):
            if (cont_type == 23):
                    print("Endpoint : %d" % len(data))
            lg.append("Source : Endpoint")
    else:
            if (cont_type == 23):
                    print("User : %d" % len(data))
            lg.append("Source : User")
    try:
        lg.append("Content Type : " + TLS_CONTENT[cont_type])
    except:
        lg.append("Content Type: Unassigned %d" % cont_type)
    try:
        lg.append("TLS Version : " + TLS_VERSION[(version[0], version[1])])
    except:
        lg.append("TLS Version: Uknown %d %d" % (version[0], version[1]))
    lg.append("Payload Length: %d\n" % length)
    lg.append(log_data(data[TLS_HEADER_LENGTH:TLS_HEADER_LENGTH+length]))
    lg.append("\n")
    logger.debug("\n".join(lg))

def start():
    #start sockets on user side (proxy as server) and endpoint side (proxy as client)
    logger.info("Starting Proxy")
    user_setup()
    endpoint_setup()
    logger.info("Proxy is set up")

def restart():
    #restart sockets in case of problem
    try:
        user_socket.close()
        endpoint_socket.close()
    except:
        pass
    user_setup()
    endpoint_setup()
    logger.info("Proxy has restarted")

def user_setup():
    global user_socket, user_connection, address
    logger.info("Setting up user socket")
    user_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    user_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1) #reuse socket option
    user_socket.bind((USER, USER_PORT))
    logger.info("User bind complete")
#    user_socket.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1) #include IP headers
    user_socket.listen(1)
    logger.info("User listen complete")
    user_connection, address = user_socket.accept()
    logger.info("User socket is set up")

def endpoint_setup():
    global endpoint_socket
    logger.info("Setting up endpoint socket")
    endpoint_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    logger.info("Connecting endpoint socket")
    endpoint_socket.connect((ENDPOINT, ENDPOINT_PORT))
    endpoint_socket.setblocking(0) #set non-blocking, i.e. raise exception if send/recv is not completed
    logger.info("Endpoint socket is set up")

#proxy loop
start()
logger.info("Starting main loop")
while 1:
    ready_to_read, ready_to_write, in_error = select.select([user_connection, endpoint_socket], [], [], 10)
    
    if user_connection in ready_to_read:
            data = ""
            try:
                data = user_connection.recv(data_buff)
            except:
                logger.error("User connection error")
                logger.error(type(exc) + "\n" + exc.args + "\n" + exc)
                restart()
            if (len(data)==0):
                    logger.info("User connection closed")
                    restart()
            else:
                    parse(data)
                    try:
                        endpoint_socket.sendall(data)
                    except:
                        logger.error("User data forwarding error")
                        logger.error(type(exc) + "\n" + exc.args + "\n" + exc)
                        restart()

    if endpoint_socket in ready_to_read:
            data = ""
            try:
                data = endpoint_socket.recv(data_buff)
            except Exception as exc:
                logger.error("Endpoint connection error")
                logger.error(type(exc) + "\n" + exc.args + "\n" + exc)
                restart()
            if (len(data)==0):
                    logger.info("Endpoint connection closed")
                    restart()
            else:
                    parse(data, True)
                    try:
                        user_connection.sendall(data)
                    except:
                        logger.error("Endpoint data forwarding error")
                        logger.error(type(exc) + "\n" + exc.args + "\n" + exc)
                        restart()

user_connection.close()
endpoint_socket.close()
logger.info("Connection closed")
