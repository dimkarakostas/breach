import sys
import signal
import datetime
import logging
import parse
from iolibrary import kill_signal_handler, get_arguments_dict, setup_logger

signal.signal(signal.SIGINT, kill_signal_handler)


class Breach():
    '''
    Start and execute breach attack.
    '''
    def __init__(self, args_dict):
        self.args_dict = args_dict
        if 'debug_logger' not in args_dict:
            if args_dict['verbose'] < 2:
                setup_logger('debug_logger', 'debug.log', args_dict, logging.ERROR)
            else:
                setup_logger('debug_logger', 'debug.log', args_dict)
            self.debug_logger = logging.getLogger('debug_logger')
            self.args_dict['debug_logger'] = self.debug_logger
        else:
            self.debug_logger = args_dict['debug_logger']
        return

    def execute_parser(self):
        self.parser = parse.Parser(self.args_dict)
        args_dict = self.parser.parse_input()
        return args_dict


if __name__ == '__main__':
    args_dict = get_arguments_dict(sys.argv)
    args_dict['start_time'] = datetime.datetime.now()
    args_dict['win_count'] = {}
    args_dict['point_count'] = {}
    args_dict['history_folder'] = 'history/'
    try:
        while 1:
            args_dict['illegal_iterations'] = []
            breach = Breach(args_dict)
            args_dict = breach.execute_parser()
            breach.debug_logger.debug('Found the following illegal iterations: ' + str(args_dict['illegal_iterations']) + '\n')
    except Exception as e:
        print e
