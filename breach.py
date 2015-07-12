from os import system
import sys
import signal
import datetime
import parse
from user_input import get_arguments_dict

def signal_handler(signal, frame):
    '''
    Signal handler for killing the execution.
    '''
    print('Exiting the program per your command')
    system('rm -f out.out request.txt user_input.pyc hillclimbing.pyc constants.pyc connect.pyc parse.pyc')
    system('mv basic_breach.log full_breach.log debug.log attack.log ' + args_dict['history_folder'])
    sys.exit(0)
signal.signal(signal.SIGINT, signal_handler)

class Breach():
    '''
    Start and execute breach attack.
    '''
    def __init__(self, args_dict):
        self.args_dict = args_dict

    def execute_parser(self):
        self.parser = parse.Parser(self.args_dict)
        args_dict = self.parser.parse_input()
        return args_dict

if __name__ == '__main__':
    global args_dict

    args_dict = get_arguments_dict(sys.argv)
    args_dict['start_time'] = datetime.datetime.now()
    try:
        while 1:
            breach = Breach(args_dict)
            args_dict = breach.execute_parser()
    except Exception as e:
        print e
