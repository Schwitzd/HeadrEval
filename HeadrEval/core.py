import argparse
from HeadrEval.utils import print_banner
from HeadrEval.SecurityHeaderChecker import SecurityHeaderChecker


def get_args():
    """Parses command-line arguments and returns the argument values."""
    parser = argparse.ArgumentParser()
    parser.add_argument(
        '-U', '--url', type=str, dest='url', required=True,
        help='Url to scan'
    )

    parser.add_argument(
        '-L', '--list', action='store_true', dest='list',
        help='list headers without do a security evaluation'
    )

    args = parser.parse_args()
    if not (args.url or args.file):
        parser.error(
            'Please specify an URL or a file path.')

    return args


def main():
    print_banner()
    args = get_args()
    checker = SecurityHeaderChecker(args.url)

    if args.list:
        checker.list_only()
    else:
        checker.evaluate_headers()


if __name__ == '__main__':
    main()
