'''
File: breach.py
Author: Dimitris Karakostas
Description: BREACH main execution script.
'''

import sys
import signal
import datetime
import logging
import parse
import traceback
import yaml
from iolibrary import kill_signal_handler, get_arguments_dict, setup_logger, setup_command_and_control


signal.signal(signal.SIGINT, kill_signal_handler)


class Breach():
    '''
    Start and execute breach attack.
    '''
    def __init__(self, args):
        self.args = args
        if 'debug_logger' not in args:
            if args['verbose'] < 2:
                setup_logger('debug_logger', 'debug.log', args, logging.ERROR)
            else:
                setup_logger('debug_logger', 'debug.log', args)
            self.debug_logger = logging.getLogger('debug_logger')
            self.args['debug_logger'] = self.debug_logger
        else:
            self.debug_logger = args['debug_logger']
        return

    def execute_parser(self):
        self.parser = parse.Parser(self.args)
        args = self.parser.parse_input()
        return args


if __name__ == '__main__':
    args = {}
    with open('config.yml', 'r') as ymlconf:
        cfg = yaml.load(ymlconf)
    args.update(cfg['execution'])
    args.update(cfg['endpoint'])
    args.update(cfg['local'])
    args.update(cfg['logging'])
    setup_command_and_control(args)
    args.update(get_arguments_dict(sys.argv))
    args.update({'start_time': datetime.datetime.now(),
                 'win_count': {},
                 'point_count': {},
                 'history_folder': 'history/'})
    try:
        while 1:
            args['illegal_iterations'] = []
            breach = Breach(args)
            args = breach.execute_parser()
            breach.debug_logger.debug('Found the following illegal iterations: ' + str(args['illegal_iterations']) + '\n')
    except Exception as e:
        print e
        traceback.print_exc()
