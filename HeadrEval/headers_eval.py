import re
from HeadrEval.utils import print_msg, print_title, print_separator, csp_parser


def eval_xss_protection(content: str) -> None:
    print_title(f'X-XSS-Protection: {content}')
    print_msg('DEP', 'instead should be used CSP')

    if content.lower() == '1; mode=block':
        print_msg(
            'OK', f"Setting to {content} helps protect against cross-site scripting (XSS) attacks by enabling the browser's built-in XSS protection mechanism")

    if content.lower() == '0':
        print_msg(
            'HIGH', 'Setting it to 0 may disable XSS protection, increasing the risk of cross-site scripting attacks')

    print_separator()


def eval_strict_transport_security(content: str):
    print_title('HSTS - Strict-Transport-Security')
    print_msg('OK', 'The presence of the HSTS header ensures secure connections by instructing the browser to only communicate with the website over HTTPS')
    directives = content.split(';')
    result = {
        'max_age': None,
        'include_subdomains': False,
        'preload': False
    }

    for directive in directives:
        directive = directive.strip()

        if directive.lower() == 'preload':
            result['preload'] = True

        if directive.lower().startswith('max-age='):
            try:
                max_age = int(directive.split('=')[1])
                result['max_age'] = max_age
            except ValueError:
                print_msg(
                    'WARN', "'max-age' is invalid, it allows a bad actor to downgrade the connection to HTTP, risking users exposure to man-in-the-middle attacks")

        if directive.lower() == 'includeSubDomains':
            result['include_subdomains'] = True

    print(f'Max-Age: {result["max_age"]}')
    print(f'Include Subdomains: {result["include_subdomains"]}')
    print(f'Preload: {result["preload"]}')
    print_separator()


def eval_permissions_policy(content: str) -> None:
    print_title('Permissions-Policy')

    permissions = re.split(r', *|; *', content)

    all_values = [
        'accelerometer',
        'ambient-light-sensor',
        'autoplay',
        'battery',
        'camera',
        'display-capture',
        'document-domain',
        'encrypted-media',
        'execution-while-not-rendered',
        'execution-while-out-of-viewport',
        'fullscreen',
        'geolocation',
        'gyroscope',
        'layout-animations',
        'legacy-image-formats',
        'magnetometer',
        'microphone',
        'midi',
        'navigation-override',
        'oversized-images',
        'payment',
        'picture-in-picture',
        'publickey-credentials-get',
        'screen-wake-lock',
        'serial',
        'sync-xhr',
        'usb',
        'wake-lock',
        'web-share',
        'xr-spatial-tracking',
        'browsing-topics'
    ]

    for value in all_values:
        matching_permissions = [p for p in permissions if p.startswith(value + '=')]
        if matching_permissions:
            for permission in matching_permissions:
                policy_value = permission.split('=')[1]
                if policy_value == 'none':
                    print_msg('HIGH', f'{value} access is disabled')
                elif policy_value == 'self':
                    print_msg('OK', f'{value} access is limited to the same origin')
                else:
                    print_msg('OK', f'{permission} access is enabled')

    print_separator()

def eval_x_frame_options(content: str) -> None:
    pass


def eval_csp(content: str) -> None:
    print_title('Content-Security-Policy')
    csp = csp_parser(content)

    print_msg('HIGH', 'Found weakness in the CSP policy')
    print()
    print(f'\033[1mPolicy:\033[0m {content}')
    print()

    unsafe_directives = {
        'default-src': [
            ("'unsafe-inline'", 'Allows inline scripts, which can be exploited for cross-site scripting (XSS) attacks.'),
            ("'unsafe-eval'", 'Enables the use of eval() and similar functions, which can lead to code injection and other security vulnerabilities.'),
            ('data:', 'Allows the execution of code from data URIs, which can be used to execute malicious scripts.'),
            ('https:', 'Allows the execution of code from data URIs, which can be used to execute malicious scripts.')
        ],
        'script-src': [
            ("'unsafe-inline'", 'Enables inline scripts, which can be exploited for cross-site scripting (XSS) attacks.'),
            ("'unsafe-eval'", 'Allows the use of eval() and similar functions, which can lead to code injection and other security vulnerabilities.'),
            ('data:', 'Allows the execution of code from data URIs, which can be used to execute malicious scripts.'),
            ('https:', 'Allows the execution of code from data URIs, which can be used to execute malicious scripts.')
        ],
        'style-src': [
            ("'unsafe-inline'", 'Enables inline styles, which can be exploited for cross-site scripting (XSS) attacks.'),
            ('data:', 'Allows the use of styles from data URIs, which can be used to execute malicious scripts.')
        ],
        'img-src': [
            ('data:', 'Allows the use of images from data URIs, which can be used to execute malicious scripts.')
        ],
        'font-src': [
            ('data:', 'Allows the use of fonts from data URIs, which can be used to execute malicious scripts.')
        ],
        'frame-src': [
            ("'*'", 'Allows embedding content from any origin, which can lead to clickjacking and other attacks.')
        ],
        'object-src': [
            ("'*'", 'Allows embedding objects from any origin, which can lead to security vulnerabilities.')
        ],
        'form-action': [
            ("'*'", 'Allows form submissions to any destination, which can lead to cross-site request forgery (CSRF) attacks.')
        ],
        'frame-ancestors': [
            ("'*'", 'Allows embedding the page in frames from any origin, which can lead to clickjacking and other attacks.')
        ],
        'connect-src': [
            ("'*'", 'Allows connections to any origin, which can lead to information leakage and security vulnerabilities.')
        ]
    }

    weak_directives = set()

    for directive, values in csp.items():
        if directive in unsafe_directives:
            for rule, explanation in unsafe_directives[directive]:
                if rule in values:
                    weak_directives.add(directive)

    if weak_directives:
        for directive in weak_directives:
            print(f'\033[1mDirective:\033[0m {directive}')
            for rule, explanation in unsafe_directives[directive]:
                if rule in csp.get(directive, []):
                    print(f'   \033[1mRule:\033[0m {rule}')
                    print(f'   \033[1mExplanation:\033[0m {explanation}\n')
    else:
        print_msg('OK', 'No weak directives found in the CSP policy.')

    print_separator()


def eval_cspro(value):
    pass


def eval_cors_opener_policy(value):
    pass


def eval_content_type_options(content: str) -> None:
    print_title('X-Content-Type-Options')

    if content.lower() == 'nosniff':
        print_msg('OK', 'When the header value is set to "nosniff", it instructs the browser to prevent MIME-sniffing attacks by strictly interpreting the content type without performing content sniffing')
    else:
        print_msg('ERR', 'Header is different from "nosniff"')

    print_separator()


def eval_referrer_policy(content: str) -> None:
    print_title(f'Referrer-Policy: {content}')

    if content.lower() == 'no-referrer':
        print_msg(
            'OK', 'No referrer information is sent, potentially limiting the ability to track and analyze legitimate referrals')

    elif content.lower() == 'no-referrer-when-downgrade':
        print_msg('OK', 'Referrer information is not sent during HTTPS to HTTP navigation, preventing the exposure of sensitive data in the Referer header')

    elif content.lower() == 'origin':
        print_msg('OK', 'Only the origin (scheme, host, and port) is sent as the referrer, excluding the path and query parameters, which helps protect sensitive information during cross-origin requests')

    elif content.lower() == 'origin-when-cross-origin':
        print_msg('OK', 'The full referrer is sent within the same origin, while only the origin is sent during cross-origin navigation, balancing security and usability')

    elif content.lower() == 'same-origin':
        print_msg('OK', 'The full referrer is sent only for requests within the same origin, preventing referrer information leakage to external sites during cross-origin requests.')

    elif content.lower() == 'strict-origin':
        print_msg('OK', 'The full referrer is sent only for requests within the same origin, preventing referrer information leakage to external sites during cross-origin requests')

    elif content.lower() == 'strict-origin-when-cross-origin':
        print_msg('OK', 'The origin is sent for same-origin requests, while during cross-origin navigation, only the origin is sent, minimizing the exposure of sensitive information')

    else:
        print_msg(
            'ERR', f'The specified Referrer-Policy header has an invalid value: {content}')


def eval_feature_policy(value):
    pass
