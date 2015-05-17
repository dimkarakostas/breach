from __future__ import division
from os import system
import datetime
import time
import argparse

def init(num, lowercase, uppercase, correct_val):
    result_file.write("Correct value = %s\n\n" % correct_val)
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
    return alphabet

def create_dictionary(output_dict, iter_dict):
    for k, v in iter_dict.items():
        if v != 0:
            combined[k] = output_dict[k] / iter_dict[k]
    return combined

def sort_dictionary_values(in_dict):
    sorted_dict = [ (v,k) for k, v in in_dict.items() ]
    sorted_dict.sort(reverse=False)
    return sorted_dict

def sort_dictionary(in_dict):
    sorted_dict = [ (v,k) for v, k in in_dict.items() ]
    sorted_dict.sort(reverse=False)
    return sorted_dict

num = False
lowercase = False
uppercase = False
buff = []
sampling_ratio = 20
refresh_time = 60

parser = argparse.ArgumentParser(description='Parser of breach.py output')
parser.add_argument('-a', metavar = 'alphabet', required = True, nargs = '+', help = 'Choose alphabet type  (in that order): n => digits, l => lowercase letters, u => uppercase letters')
parser.add_argument('-lf', metavar = 'file_num', required = True, type = int, help = 'Input the latest output file breach.py has created, -1 if first try')
parser.add_argument('-r', metavar = 'request_length', required = True, type = int, help = 'Input the (mean payload) length of the request packet')
parser.add_argument('-m', metavar = 'mean_length', required = True, type = int, help = 'Input the (observed mean payload) length value of the packet')
parser.add_argument('-c', metavar = 'correct_value', required = True, help = 'Input the correct value we attack')
parser.add_argument('-s', metavar = 'sampling', type = int, help = 'Input the sampling ratio')
parser.add_argument('-t', metavar = 'refresh_time', type = int, help = 'Input the refresh time in seconds')
args = parser.parse_args()
alphabet_type = args.a
latest_file = args.lf
request_length = args.r
mean_length_large = args.m
correct_val = args.c
if args.s:
    sampling_ratio = args.s
if args.t:
    refresh_time = args.s

if 'n' in alphabet_type:
    num = True
if 'l' in alphabet_type:
    lowercase = True
if 'u' in alphabet_type:
    uppercase = True
assert num or lowercase or uppercase, 'Invalid alphabet type'

while 1:
    iterations = {}
    output_sum = {}
    combined = {}
    samples = {}

    result_file = open("result.log", "w")
    alphabet = init(num, lowercase, uppercase, correct_val)

    system('cp out.out out' + str(latest_file + 1))
    out_iterator = "0"
    with open("parsed_output.log", "w") as f:
        while int(out_iterator) < 55:
            try:
                output_file = open("out" + out_iterator, "r")
                result_file.write("out" + out_iterator + "\n")

                prev_request = 0
                curr_request = 0
                buff = []
                for line in output_file.readlines():
                    if prev_request % len(combined) == 0:
                        #print buff
                        for r in buff:
                            f.write(r)
                            buff = []
                    pref, size = line.split(": ")
                    if pref == "User application payload" and int(size) > request_length - 5 and int(size) < request_length + 5:
                            if (curr_request != prev_request):
                                    buff.append("%d: -1\n" % prev_request)
                                    prev_request = prev_request + 1
                            curr_request = curr_request + 1
                            continue
                    if (pref == "Endpoint application payload"):
                        if int(size) > mean_length_large - 10 and int(size) < mean_length_large + 10:
                            summary = int(size)
                            buff.append("%d: %d\n" % (prev_request, summary))
                            prev_request = prev_request + 1
                output_file.close()
                out_iterator = str(int(out_iterator) + 1)
                f.write("-1: -2\n")
            except Exception as e:
                break
    f.close()

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
                    if iterations[alphabet[alpha_counter]] % sampling_ratio == 0:
                        sample = create_dictionary(output_sum, iterations)
                        sorted_sample = sort_dictionary_values(sample)
                        samples[iterations[alphabet[alpha_counter]]] = sorted_sample
    f.close()

    result_file.write("\nCombined sorted results\n\n")

    combined = create_dictionary(output_sum, iterations)
    combined_sorted = sort_dictionary_values(combined)
    for v,k in combined_sorted:
            result_file.write("%s: %f\n" % (k, v))
    print alphabet[0]
    print iterations[alphabet[0]]
    samples[iterations[alphabet[0]]] = combined_sorted
    samples = sort_dictionary(samples)
    result_file.write("\n")

    found_in_iter = False
    correct_leader = False
    result_file.write("Iteration - Chart Position - Divergence from top - Mean Length\n\n")
    for point in samples:
            pos = 1
            for j in point[1]:
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
                            pos = pos + 1
            if not found_in_iter:
                result_file.write("%d:\t%d\t%d\t%d\n" % (0, 0, 0, 0))
            else:
                result_file.write("%d:\t\t%d\t\t%f\t\t%f\n" % (point[0], correct_pos, divergence, correct_len))
    result_file.write("\n")
    result_file.close()
    system("cat result.log")
    time.sleep(refresh_time)

    system("rm parsed_output.log")