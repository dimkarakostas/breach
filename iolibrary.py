from os import system, mkdir, path
from shutil import move, copy
import sys
import argparse
import logging


def kill_signal_handler(signal, frame):
    '''
    Signal handler for killing the execution.
    '''
    print('\nExiting the program per your command.')
    system('rm -f out.out request.txt iolibrary.pyc hillclimbing.pyc constants.pyc connect.pyc parse.pyc sniff.pyc')
    if not path.exists('history'):
        mkdir('history')
    if path.exists('basic_breach.log'):
        system('mv basic_breach.log history/')
    if path.exists('full_breach.log'):
        system('mv full_breach.log history/')
    if path.exists('debug.log'):
        system('mv debug.log history/')
    if path.exists('attack.log'):
        system('mv attack.log history/')
    if path.exists('win_count.log'):
        system('mv win_count.log history/')
    if path.exists('sniff.log'):
        system('mv sniff.log history/')
    if path.exists('sniff_full.log'):
        system('mv sniff_full.log history/')
    sys.exit(0)


def get_arguments_dict(args_list):
    '''
    Parse command line arguments that were given to the program that calls this method.
    '''
    parser = argparse.ArgumentParser(description='Parser of breach.py output')
    parser.add_argument('caller_name', metavar='caller_name', help='The program that called the argument parser.')
    parser.add_argument('--execute_breach', action='store_true', help='Initiate breach attack via breach.py')
    args = parser.parse_args(args_list)

    args_dict = {}
    args_dict['execute_breach'] = True if args.execute_breach else False
    return args_dict


def setup_logger(logger_name, log_file, args_dict, level=logging.DEBUG):
    '''
    Logger factory.
    '''
    l = logging.getLogger(logger_name)
    l.setLevel(level)
    formatter = logging.Formatter('%(asctime)s : %(message)s')
    fileHandler = logging.FileHandler(log_file)
    fileHandler.setFormatter(formatter)
    l.addHandler(fileHandler)
    if args_dict['log_to_screen']:
        streamHandler = logging.StreamHandler()
        streamHandler.setFormatter(formatter)
        l.addHandler(streamHandler)


def setup_command_and_control(args):
    '''
    Setup the web application files that execute the command and control.
    '''
    with open('evil.js', 'r') as f:
        with open('tmp', 'w') as tmp:
            for line in f:
                if '%%%endpoint_url%%%' in line:
                    line = line.replace('%%%endpoint_url%%%', args['endpoint_url'])
                elif '%%%request_timeout%%%' in line:
                    line = line.replace('%%%request_timeout%%%', str(args['request_timeout']))
                elif '%%%error_request_timeout%%%' in line:
                    line = line.replace('%%%error_request_timeout%%%', str(args['error_request_timeout']))
                tmp.write(line)
    if not path.exists(args['wdir']):
        mkdir(args['wdir'])
    move('tmp', args['wdir'] + 'evil.js')
    copy('index.html', args['wdir'])
