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

#Ports and hosts
USER = "" #Listen requests from everyone
USER_PORT = 443
ENDPOINT = "31.13.93.3" #Connect only to selected endpoint
ENDPOINT_PORT = 443

#Data size
data_buff = 4096 #Size of socket buffer
past_bytes_user = 0 #Number of bytes expanding to future packets
past_bytes_endpoint = 0

#Logger setup
#logging.basicConfig(filename="breach.log") #Log in file
logging.basicConfig()
logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)

#Print hexadecimal and ASCII representation of data
def log_data(data, b=16):
    pad = 0
    output = []
    buff = "" #Buffer of 16 chars

    for i in xrange(0, len(data), b):
            buff = data[i:i+b]
            hex = binascii.hexlify(buff) #Hex representation of data
            pad = 32 - len(hex)
            txt = "" #ASCII representation of data
            for ch in buff:
                if ((ord(ch)>126) or (ord(ch)<33)):
                        txt = txt + "."
                else:
                        txt = txt + chr(ord(ch))
            output.append("%2d\t %s%s\t %s" % (i, hex, pad*" ", txt))

    return "\n".join(output)

#Parse data and print header information and payload
def parse(data, past_bytes_endpoint, past_bytes_user, is_response = False):
    lg = ["\n"]
    
    #Check if there are any remaining bytes from previous endpoint record
    if (past_bytes_endpoint):
        if (is_response):
            lg.append("Data from previous TLS record: Endpoint\n")
            lg.append(log_data(data[0:past_bytes_endpoint]))
            data = data[past_bytes_endpoint:]
            past_bytes_endpoint = 0
            lg.append("\n")
            if (len(data) == 0):
                    return ("\n".join(lg), past_bytes_endpoint, past_bytes_user)
    #Same check for user record
    if (past_bytes_user):
        if (not is_response):
            lg.append("Data from previous TLS record: User\n")
            lg.append(log_data(data[0:past_bytes_user]))
            data = data[past_bytes_user:]
            past_bytes_user = 0
            lg.append("\n")
            if (len(data) == 0):
                    return ("\n".join(lg), past_bytes_endpoint, past_bytes_user)

    cont_type = ord(data[TLS_CONTENT_TYPE])
    version = (ord(data[TLS_VERSION_MAJOR]), ord(data[TLS_VERSION_MINOR]))
    length = 256*ord(data[TLS_LENGTH_MAJOR]) + ord(data[TLS_LENGTH_MINOR])

    if (is_response):
            if (cont_type == 23):
                    print("Endpoint application payload: %d" % length)
            lg.append("Source : Endpoint")
    else:
            if (cont_type == 23):
                    print("User application payload: %d" % length)
            lg.append("Source : User")
    try:
        lg.append("Content Type : " + TLS_CONTENT[cont_type])
    except:
        lg.append("Content Type: Unassigned %d" % cont_type)
    try:
        lg.append("TLS Version : " + TLS_VERSION[(version[0], version[1])])
    except:
        lg.append("TLS Version: Uknown %d %d" % (version[0], version[1]))
    lg.append("Payload Length: %d" % length)
    lg.append("Packet Data length: %d\n" % len(data))
    
    #Check if TLS record spans to next TCP segment
    if (len(data)<length):
        if (is_response):
            past_bytes_endpoint = length + TLS_HEADER_LENGTH - len(data)
        else:
            past_bytes_user = length + TLS_HEADER_LENGTH - len(data)

    lg.append(log_data(data[0:TLS_HEADER_LENGTH]))
    lg.append(log_data(data[TLS_HEADER_LENGTH:TLS_HEADER_LENGTH+length]))
    lg.append("\n")
    
    #Check if packet has more than one TLS records
    if ((length<(len(data) - TLS_HEADER_LENGTH)) and (len(data[TLS_HEADER_LENGTH+length:])>0)):
        more_records, past_bytes_endpoint, past_bytes_user = parse(
                                                                   data[TLS_HEADER_LENGTH+length:], 
                                                                   past_bytes_endpoint, 
                                                                   past_bytes_user, 
                                                                   is_response
                                                                  )
        lg.append(more_records)

    return ("\n".join(lg), past_bytes_endpoint, past_bytes_user)

#Start sockets on user side (proxy as server) and endpoint side (proxy as client)
def start():
    logger.info("Starting Proxy")

    user_setup()
    endpoint_setup()

    logger.info("Proxy is set up")

#Restart sockets in case of error
def restart():
    logger.info("Restarting Proxy")

    try:
        user_socket.close()
        endpoint_socket.close()
    except:
        pass

    user_setup()
    endpoint_setup()

    logger.info("Proxy has restarted")

#Create and configure user side socket
def user_setup():
    global user_socket, user_connection, address

    logger.info("Setting up user socket")
    user_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    user_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1) #Set options to reuse socket
    user_socket.bind((USER, USER_PORT))
    logger.info("User socket bind complete")
    user_socket.listen(1)
    logger.info("User socket listen complete")
    user_connection, address = user_socket.accept()
    logger.info("User socket is set up")

#Create and configure endpoint side socket
def endpoint_setup():
    global endpoint_socket

    logger.info("Setting up endpoint socket")
    endpoint_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    logger.info("Connecting endpoint socket")
    endpoint_socket.connect((ENDPOINT, ENDPOINT_PORT))
    endpoint_socket.setblocking(0) #Set non-blocking, i.e. raise exception if send/recv is not completed
    logger.info("Endpoint socket is set up")

#Start proxy and execute main loop
start()
logger.info("Starting main proxy loop")
while 1:
    ready_to_read, ready_to_write, in_error = select.select(
                                                            [user_connection, endpoint_socket], 
                                                            [], 
                                                            [], 
                                                            5
                                                           )

    if user_connection in ready_to_read: #If user side socket is ready to read...
            data = ""

            try:
                data = user_connection.recv(data_buff) #...receive data from user...
            except Exception as exc:
                logger.error("User connection error")
                logger.error(type(exc) + "\n" + exc.args + "\n" + exc)
                restart()

            if (len(data)==0):
                    logger.info("User connection closed")
                    restart()
            else:
                    output, past_bytes_endpoint, past_bytes_user = parse(
                                                                         data, 
                                                                         past_bytes_endpoint, 
                                                                         past_bytes_user
                                                                        ) #...parse it...
                    logger.debug(output)
                    try:
                        endpoint_socket.sendall(data) #...and send it to endpoint
                    except Exception as exc:
                        logger.error("User data forwarding error")
                        logger.error(type(exc) + "\n" + exc.args + "\n" + exc)
                        restart()

    if endpoint_socket in ready_to_read: #Same for the endpoint side
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
                    output, past_bytes_endpoint, past_bytes_user = parse(
                                                                         data, 
                                                                         past_bytes_endpoint, 
                                                                         past_bytes_user,
                                                                         True
                                                                        )
                    logger.debug(output)
                    try:
                        user_connection.sendall(data)
                    except Exception as exc:
                        logger.error("Endpoint data forwarding error")
                        logger.error(type(exc) + "\n" + exc.args + "\n" + exc)
                        restart()

#Close sockets to terminate connection
user_connection.close()
endpoint_socket.close()
logger.info("Connection closed")
