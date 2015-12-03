'''
File: hillclimbing.py
Author: Dimitris Karakostas
Description: Hillclimbing library for JS execution parameters creation.
'''

import sys
from iolibrary import get_arguments_dict
from constants import DIGIT, LOWERCASE, UPPERCASE, DASH, NONCE_1, NONCE_2


def create_alphabet(alpha_types):
    '''
    Create array with the alphabet we are testing.
    '''
    assert alpha_types, 'Empty argument for alphabet types'
    alphabet = []
    for t in alpha_types:
        if t == 'n':
            for i in DIGIT:
                alphabet.append(i)
        if t == 'l':
            for i in LOWERCASE:
                alphabet.append(i)
        if t == 'u':
            for i in UPPERCASE:
                alphabet.append(i)
        if t == 'd':
            for i in DASH:
                alphabet.append(i)
    assert alphabet, 'Invalid alphabet types'
    return alphabet


def huffman_point(alphabet, test_points):
    '''
    Use Huffman fixed point.
    '''
    huffman = ''
    for alpha_item in enumerate(alphabet):
        if alpha_item[1] not in test_points:
                huffman = huffman + alpha_item[1] + '_'
    return huffman


def serial_execution(alphabet, prefix):
    '''
    Create request list for serial method.
    '''
    req_list = []
    for i in xrange(len(alphabet)):
        huffman = huffman_point(alphabet, [alphabet[i]])
        req_list.append(huffman + prefix + alphabet[i])
    reflection_alphabet = alphabet
    return req_list, reflection_alphabet


def parallel_execution(alphabet, prefix):
    '''
    Create request list for parallel method.
    '''
    if len(alphabet) % 2:
        alphabet.append('^')
    first_half = alphabet[::2]
    first_huffman = huffman_point(alphabet, first_half)
    second_half = alphabet[1::2]
    second_huffman = huffman_point(alphabet, second_half)
    head = ''
    tail = ''
    for i in xrange(len(alphabet)/2):
        head = head + prefix + first_half[i] + ' '
        tail = tail + prefix + second_half[i] + ' '
    reflection_alphabet = [head, tail]
    return [first_huffman + head, second_huffman + tail], reflection_alphabet


def create_request_file(args_dict):
    '''
    Create the 'request' file used by evil.js to issue the requests.
    '''
    method_functions = {'serial': serial_execution,
                        'parallel': parallel_execution}

    prefix = args_dict['prefix']
    assert prefix, 'Empty prefix argument'
    method = args_dict['method']
    assert prefix, 'Empty method argument'
    search_alphabet = args_dict['alphabet'] if 'alphabet' in args_dict else create_alphabet(args_dict['alpha_types'])
    with open('request.txt', 'w') as f:
        f.write(prefix + '\n')
        total_tests = []
        alphabet, reflection_alphabet = method_functions[method](search_alphabet, prefix)
        for test in alphabet:
            search_string = NONCE_1 + test + NONCE_2
            total_tests.append(search_string)
        f.write(','.join(total_tests))
        f.close()
    return reflection_alphabet


if __name__ == '__main__':
    args_dict = get_arguments_dict(sys.argv)
    create_request_file(args_dict)
