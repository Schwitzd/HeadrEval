from termcolor import colored

def print_msg(code: str, message: str) -> None:
    open_bracket = colored('[', 'white')
    closed_bracket = colored(']', 'white')

    code_colors = {
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
    print(colored(name, 'white', attrs=['bold']))
    print('-' * len(name))


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
