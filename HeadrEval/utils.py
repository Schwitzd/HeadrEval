import random
import os
from termcolor import colored


def get_random_user_agent():
    """Randomly selects a user agent from the user_agents.txt file"""
    file_path = os.path.join('data', 'user_agents.txt')
    with open(file_path, 'r', encoding='utf-8') as file:
        user_agents = file.readlines()

    user_agent = {'User-Agent': random.choice(user_agents).strip()}
    return user_agent


def print_msg(code: str, message: str) -> None:
    """Prints a formatted message with the provided code and message"""
    open_bracket = colored('[', 'white')
    closed_bracket = colored(']', 'white')

    code_colors = {
        'INFO': ('INF', 'white', []),
        'OK': ('OK', 'green', []),
        'DEP': ('DEPRECATED', 'yellow', []),
        'WARN': ('WARNING', 'yellow', ['bold']),
        'HIGH': ('HIGH', 'red', ['bold'])
    }

    if code in code_colors:
        code_text, color, attrs = code_colors[code]
        code_colored = colored(code_text, color, attrs=attrs)
        print(f'{open_bracket}{code_colored}{closed_bracket} {message}')
    else:
        print(f'{open_bracket}{code}{closed_bracket} {message}')

def print_title(name: str) -> None:
    """Prints a title with a horizontal line underneath."""
    print(colored(name, 'white', attrs=['bold']))
    print('-' * len(name))


def csp_parser(csp_policy: str) -> dict:
    """Parses a CSP policy string and returns a dictionary representation"""
    csp = {}
    directives = csp_policy.split(";")
    for directive in directives:
        directive = directive.strip().split()

        if directive:
            directive_name = directive[0]
            directive_values = directive[1:] if len(directive) > 1 else []
            csp[directive_name] = directive_values

    return csp
