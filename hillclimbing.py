def initialize():
    '''
    Initialize global variables.
    '''
    global digit, lowercase, uppercase, dashes, nonce_1, nonce_2, method_functions
    digit = ['1', '2', '3', '4', '5', '6', '7', '8', '9']
    lowercase = ['a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z']
    uppercase = ['A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z']
    dashes = ['-', '_']
    nonce_1 = 'ladbfsk!'
    nonce_2 = 'znq'
    method_functions = {
        's': serial_execution,
        'p': parallel_execution
    }

def create_alphabet(types):
    '''
    Create array with the alphabet we are testing.
    '''
    alphabet = []
    if 'n' in types:
        for i in digit:
            alphabet.append(i)
    if 'l' in types:
        for i in lowercase:
            alphabet.append(i)
    if 'u' in types:
        for i in uppercase:
            alphabet.append(i)
    if 'd' in types:
        for i in dashes:
            alphabet.append(i)
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
    req_list = []
    for i in xrange(len(alphabet)):
        huffman = huffman_point(alphabet, [alphabet[i]])
        req_list.append(huffman + prefix + alphabet[i])
    return req_list

def parallel_execution(alphabet, prefix):
    '''
    Create request list for parallel method.
    '''
    if len(alphabet) % 2:
        alphabet.append('%')
    first_half = alphabet[0:len(alphabet)/2]
    first_huffman = huffman_point(alphabet, first_half)
    second_half = alphabet[len(alphabet)/2:]
    second_huffman = huffman_point(alphabet, second_half)
    head = ''
    tail = ''
    for i in xrange(len(alphabet)/2):
        head = head + prefix + first_half[i] + ' '
        tail = tail + prefix + second_half[i] + ' '
    return [first_huffman + head, second_huffman + tail]

def create_request_file(alpha_types, prefix, method):
    '''
    Create the 'request' file used by evil.js to issue the requests.
    '''
    initialize();
    search_alphabet = create_alphabet(alpha_types)
    with open("request.txt", "w") as f:
        f.write(prefix + "\n")
        total_tests = []
        alphabet = method_functions[method](search_alphabet, prefix)
        for test in alphabet:
            huffman_nonce = huffman_point(alphabet, test)
            search_string = nonce_1 + test + nonce_2
            total_tests.append(search_string)
        f.write(','.join(total_tests))
        f.close()

def parse_args():
    '''
    Parse console arguments for standalone use.
    '''
    parser = argparse.ArgumentParser(description='Create hillclimbing parameters file')
    parser.add_argument('-a', metavar = 'alphabet', required = True, nargs = '+', help = 'Choose alphabet type (careful to use correct request order): n => digits, l => lowercase letters, u => uppercase letters, d => - and _')
    parser.add_argument('-p', '--prefix', metavar = 'bootstrap_prefix', required = True, help = 'Input the already known prefix needed for bootstrap')
    parser.add_argument('-m', '--method', metavar = 'request_method', help = 'Choose the request method: s => serial, p => parallel')
    args = parser.parse_args()
    alpha_types = args.a
    prefix = args.prefix
    method = args.method if args.method else 's'
    return alpha_types, prefix, method

if __name__ == "__main__":
    import argparse

    alpha_types, prefix, method = parse_args()
    create_request_file(alpha_types, prefix, method)
