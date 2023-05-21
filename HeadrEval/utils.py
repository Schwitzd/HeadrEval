import shutil
from termcolor import colored

def print_msg(type:str, message: str) -> None:
    open_bracket = colored('[', 'white')
    closed_bracket = colored(']', 'white')

    type_colors = {
        'OK': ('OK', 'green', []),
        'DEP': ('DEPRECATED', 'yellow', []),
        'WARN': ('WARNING', 'yellow', ['bold']),
        'HIGH': ('HIGH', 'red', ['bold'])
    }

    if type in type_colors:
        type_text, color, attrs = type_colors[type]
        type_colored = colored(type_text, color, attrs=attrs)
        print(f'{open_bracket}{type_colored}{closed_bracket} {message}')
    else:
        print(f'{open_bracket}{type}{closed_bracket} {message}')

def print_title(name: str) -> None:
    print(colored(name, 'white', attrs=['bold', 'underline']))
    print()


def csp_parser(csp_policy: str) -> dict:
    csp = {}
    directives = csp_policy.split(";")
    for directive in directives:
        directive = directive.strip().split()
        
        if directive:
            directive_name = directive[0]
            directive_values = directive[1:] if len(directive) > 1 else []
            csp[directive_name] = directive_values

    return csp


def print_separator() -> None:
    console_width = shutil.get_terminal_size().columns
    line = '-' * console_width
    print(line)