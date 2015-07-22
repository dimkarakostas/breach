import argparse

def get_arguments_dict(args_list):
    '''
    Parse command line arguments that were given to the program that calls this method.
    '''
    parser = argparse.ArgumentParser(description='Parser of breach.py output')
    parser.add_argument('caller_name', metavar = 'caller_name', help = 'The program that called the argument parser.')
    parser.add_argument('-a', '--alpha_types', metavar = 'alphabet', nargs = '+', help = 'Choose alphabet types: n => digits, l => lowercase letters, u => uppercase letters, d => - and _')
    parser.add_argument('-l', '--len_pivot', metavar = 'pivot_length', type = int, help = 'Input the (observed payload) length value of the pivot packet')
    parser.add_argument('-p', '--prefix', metavar = 'bootstrap_prefix', help = 'Input the already known prefix needed for bootstrap')
    parser.add_argument('-m', '--method', metavar = 'request_method', help = 'Choose the request method: s => serial, p => parallel')
    parser.add_argument('-lf', '--latest_file', metavar = 'latest_file_number', type = int, help = 'Input the latest output file breach.py has created, -1 if first try')
    parser.add_argument('-r', '--request_len', metavar = 'minimum_request_length', type = int, help = 'Input the minimum length of the request packet')
    parser.add_argument('-c', '--correct', metavar = 'correct_value', help = 'Input the correct value we attack')
    parser.add_argument('-s', '--sample', metavar = 'sample', type = int, help = 'Input the sampling ratio')
    parser.add_argument('-i', '--iterations', metavar = 'number_of_iterations', type = int, help = 'Input the number of iterations per symbol.')
    parser.add_argument('-t', '--refresh_time', metavar = 'refresh_time', type = int, help = 'Input the refresh time in seconds')
    parser.add_argument('--wdir', metavar = 'web_application_directory', help = 'The directory where you have added evil.js')
    parser.add_argument('--history_folder', metavar = 'history_directory', help = 'The directory where you want execution logs and results to be stored')
    parser.add_argument('--execute_breach', action = 'store_true', help = 'Initiate breach attack via breach.py')
    parser.add_argument('--verbose', metavar = 'verbosity_level', type = int, help = 'Choose verbosity level: 0 => no logs, 1 => attack logs, 2 => debug logs, 3 => basic breach logs, 4 => full logs')
    parser.add_argument('--log_to_screen', action = 'store_true', help = 'Print logs to stdout')
    args = parser.parse_args(args_list)

    args_dict = {}
    args_dict['alpha_types'] = args.alpha_types if args.alpha_types else None
    args_dict['prefix'] = args.prefix if args.prefix else None
    args_dict['method'] = args.method if args.method else 's'
    args_dict['pivot_length'] = args.len_pivot if args.len_pivot else None
    args_dict['minimum_request_length'] = args.request_len if args.request_len else None
    args_dict['correct_val'] = args.correct if args.correct else None
    args_dict['sampling_ratio'] = args.sample if args.sample else 200000000
    args_dict['iterations'] = args.iterations if args.iterations else 500
    args_dict['refresh_time'] = args.refresh_time if args.refresh_time else 60
    args_dict['wdir'] = args.wdir if args.wdir else '/var/www/breach/'
    args_dict['execute_breach'] = True if args.execute_breach else False
    args_dict['log_to_screen'] = True if args.log_to_screen else False
    args_dict['verbose'] = args.verbose if args.verbose else 0
    args_dict['latest_file'] = args.latest_file if args.latest_file else 0
    args_dict['history_folder'] = args.history_folder if args.history_folder else 'history/'
    return args_dict
