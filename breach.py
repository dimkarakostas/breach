from os import system
import sys
import signal
import datetime
import logging
import parse
from user_input import get_arguments_dict

def signal_handler(signal, frame):
    '''
    Signal handler for killing the execution.
    '''
    print('Exiting breach.py per your command')
    breach.debug_logger.debug('Exiting breach attack with last dictionary: ' + str(breach.args_dict) + '\n')
    system('rm -f out.out request.txt user_input.pyc hillclimbing.pyc constants.pyc connect.pyc parse.pyc')
    system('mv basic_breach.log full_breach.log debug.log attack.log win_count.log ' + args_dict['history_folder'])
    sys.exit(0)
signal.signal(signal.SIGINT, signal_handler)

class Breach():
    '''
    Start and execute breach attack.
    '''
    def __init__(self, args_dict):
        self.args_dict = args_dict
        if 'debug_logger' not in args_dict:
            if args_dict['verbose'] < 2:
                self.setup_logger('debug_logger', 'debug.log', logging.ERROR)
            else:
                self.setup_logger('debug_logger', 'debug.log')
            self.debug_logger = logging.getLogger('debug_logger')
            self.args_dict['debug_logger'] = self.debug_logger
        else:
            self.debug_logger = args_dict['debug_logger']
        return

    def execute_parser(self):
        self.parser = parse.Parser(self.args_dict)
        args_dict = self.parser.parse_input()
        return args_dict

    def setup_logger(self, logger_name, log_file, level=logging.DEBUG):
        '''
        Logger factory.
        '''
        l = logging.getLogger(logger_name)
        l.setLevel(level)
        formatter = logging.Formatter('%(asctime)s : %(message)s')
        fileHandler = logging.FileHandler(log_file)
        fileHandler.setFormatter(formatter)
        l.addHandler(fileHandler)
        if self.args_dict['log_to_screen']:
            streamHandler = logging.StreamHandler()
            streamHandler.setFormatter(formatter)
            l.addHandler(streamHandler)
        return

if __name__ == '__main__':
    global args_dict

    args_dict = get_arguments_dict(sys.argv)
    args_dict['start_time'] = datetime.datetime.now()
    args_dict['win_count'] = {}
    try:
        while 1:
            args_dict['illegal_iterations'] = []
            breach = Breach(args_dict)
            args_dict = breach.execute_parser()
            breach.debug_logger.debug('Found the following illegal iterations: ' + str(args_dict['illegal_iterations']) + '\n')
    except Exception as e:
        print e
