from __future__ import division
from os import system, path
import datetime
import time
import argparse

def init(num, lowercase, uppercase, dashes, correct_val):
    alphabet = []
    if num:
        for i in xrange(ord('0'), ord('9') + 1):
            iterations[chr(i)] = 0
            output_sum[chr(i)] = 0
            combined[chr(i)] = 0
            alphabet.append(chr(i))
    if lowercase:
        for i in xrange(ord('a'), ord('z') + 1):
            iterations[chr(i)] = 0
            output_sum[chr(i)] = 0
            combined[chr(i)] = 0
            alphabet.append(chr(i))
    if uppercase:
        for i in xrange(ord('A'), ord('Z') + 1):
            iterations[chr(i)] = 0
            output_sum[chr(i)] = 0
            combined[chr(i)] = 0
            alphabet.append(chr(i))
    if dashes:
        for i in ['-', '_']:
            iterations[i] = 0
            output_sum[i] = 0
            combined[i] = 0
            alphabet.append(i)
    return alphabet

def create_dictionary(output_dict, iter_dict):
    for k, v in iter_dict.items():
        if v != 0:
            combined[k] = output_dict[k] / iter_dict[k]
    return combined

def sort_dictionary_values(in_dict, desc = False):
    sorted_dict = [ (v,k) for k, v in in_dict.items() ]
    sorted_dict.sort(reverse=desc)
    return sorted_dict

def sort_dictionary(in_dict, desc = False):
    sorted_dict = [ (v,k) for v, k in in_dict.items() ]
    sorted_dict.sort(reverse=desc)
    return sorted_dict

parser = argparse.ArgumentParser(description='Parser of breach.py output')
parser.add_argument('-a', metavar = 'alphabet', required = True, nargs = '+', help = 'Choose alphabet type (careful to use correct request order): n => digits, l => lowercase letters, u => uppercase letters, d => - and _')
parser.add_argument('-m', metavar = 'mean_length', required = True, type = int, help = 'Input the (observed mean payload) length value of the packet')
parser.add_argument('-lf', metavar = 'latest_file_number', type = int, help = 'Input the latest output file breach.py has created, -1 if first try')
parser.add_argument('-r', metavar = 'minimum_request_length', type = int, help = 'Input the minimum length of the request packet')
parser.add_argument('-c', metavar = 'correct_value', help = 'Input the correct value we attack')
parser.add_argument('-s', metavar = 'sampling', type = int, help = 'Input the sampling ratio')
parser.add_argument('-t', metavar = 'refresh_time', type = int, help = 'Input the refresh time in seconds')
args = parser.parse_args()

alphabet_type = args.a
mean_length_large = args.m

num = False
lowercase = False
uppercase = False
dashes = False
if 'n' in alphabet_type:
    num = True
if 'l' in alphabet_type:
    lowercase = True
if 'u' in alphabet_type:
    uppercase = True
if 'd' in alphabet_type:
    dashes = True
assert num or lowercase or uppercase or dashes, 'Invalid alphabet type'

latest_file = -1
if args.lf >= 0:
    latest_file = args.lf
if path.isfile('out' + str(latest_file + 1)):
    raw = raw_input("Are you sure you want to overwrite file 'out" + str(latest_file + 1) + "'? ")
    assert raw == 'y' or raw == 'yes', "Aborted by user input"

minimum_request_length = None
if args.r:
    minimum_request_length = args.r

correct_val = None
if args.c:
    correct_val = args.c

sampling_ratio = 200000000
if args.s:
    sampling_ratio = args.s

refresh_time = 60
if args.t:
    refresh_time = args.t

while 1:
    iterations = {}
    output_sum = {}
    combined = {}
    samples = {}

    result_file = open("result.log", "w")
    alphabet = init(num, lowercase, uppercase, dashes, correct_val)

    point_system = {1: 20, 2: 16, 3: 12, 4: 10, 5: 8, 6: 6, 7: 4, 8: 3, 9: 2, 10: 1}
    points = {}
    for key, value in iterations.items():
        points[key] = 0

    if correct_val:
        result_file.write("Correct value = %s\n\n" % correct_val)
    result_file.write("Combined output files\n\n")
    system('cp out.out out' + str(latest_file + 1))
    out_iterator = "0"
    total_requests = 0
    with open("parsed_output.log", "w") as f:
        while int(out_iterator) < 100:
            try:
                output_file = open("out" + out_iterator, "r")
                result_file.write("out" + out_iterator + "\n")

                prev_request = 0
                curr_request = 0
                buff = []
                request_buff = []
                found_first_req = False
                found_response_packet = False
                grab_next = False
                for line in output_file.readlines():
                    if prev_request % len(combined) == 0:
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
                                    if int(size) > mean_length_large - 15 and int(size) < mean_length_large + 15:
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
                            if int(size) > mean_length_large - 10 and int(size) < mean_length_large + 10:
                                grab_next = True
                                continue
                            prev_size = int(size)

                output_file.close()
                out_iterator = str(int(out_iterator) + 1)
                f.write("-1: -2\n")
            except Exception as e:
                #print e
                break
    f.close()

    total_requests = total_requests / len(combined)
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
                if correct_val:
                    sample = create_dictionary(output_sum, iterations)
                    sorted_sample = sort_dictionary_values(sample)
                    samples[iterations[alphabet[alpha_counter]]] = sorted_sample
    f.close()

    result_file.write("\nCombined sorted results\n")

    combined = create_dictionary(output_sum, iterations)
    combined_sorted = sort_dictionary_values(combined)
    if correct_val:
        samples[iterations[alphabet[0]]] = combined_sorted
        samples = sort_dictionary(samples)
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
        result_file.write("\n\n")
        result_file.write("Iteration %d\n" % iterations[alphabet[0]])
        result_file.write("Correct Value is '%s' with divergence %f from second best\n\n" % (combined_sorted[0][1], combined_sorted[1][0] - combined_sorted[0][0]))
    for symbol in enumerate(combined_sorted):
        if symbol[0] % 6 == 0:
            result_file.write('\n')
        result_file.write("%s %f\t" % (symbol[1][1], symbol[1][0]))
    result_file.write("\n")
    for symbol in enumerate(points):
        if symbol[0] % 10 == 0:
            result_file.write('\n')
        result_file.write("%s %d\t" % (symbol[1][1], symbol[1][0]))
    result_file.write('\n')
    result_file.close()
    system("cat result.log")
    time.sleep(refresh_time)

    system("rm parsed_output.log")
