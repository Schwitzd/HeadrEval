import argparse
from HeadrEval.SecurityHeaderChecker import SecurityHeaderChecker

print('''
 _   _                _      _____           _ 
| | | |              | |    |  ___|         | |
| |_| | ___  __ _  __| |_ __| |____   ____ _| |
|  _  |/ _ \/ _` |/ _` | '__|  __\ \ / / _` | |
| | | |  __/ (_| | (_| | |  | |___\ V / (_| | |
\_| |_/\___|\__,_|\__,_|_|  \____/ \_/ \__,_|_|
                                         v0.3.2                                               

''')

def get_args():
    parser = argparse.ArgumentParser()
    parser.add_argument('-U', '--url', type=str, dest='url', required=True,
                        help='Url to scan')
    parser.add_argument('-L', '--list', action='store_true', dest='list',
                        help='list headers without do a security evaluation')

    args = parser.parse_args()
    if not (args.url or args.file):
        parser.error(
            'Please specify an URL or a file path.')

    return args

def main():
    args = get_args()
    checker = SecurityHeaderChecker(args.url)

    if args.list:
        checker.list_only()
    else:
        checker.evaluate_headers()

if __name__ == '__main__':
    main()
