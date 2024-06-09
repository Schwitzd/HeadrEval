import re
from .utils import print_msg, print_title, csp_parser


def eval_xss_protection(header_value: str, cross_headers: dict = None) -> None:
    """Evaluates the X-XSS-Protection header value and provides security assessments"""
    print_title(f'X-XSS-Protection: {header_value}')

    if cross_headers:
        csp_policy = cross_headers.get('Content-Security-Policy')
        if csp_policy:
            print_msg('OK', 'CSP header is present. XSS protection is handled '
                            'by the Content Security Policy.')
    else:
        print_msg('DEP', 'instead should be used CSP')

        if header_value.lower() == '1; mode=block':
            print_msg('OK', f"Setting to {header_value} helps protect against cross-site scripting (XSS) "
                            "attacks by enabling the browser's built-in XSS protection mechanism")


        if header_value.lower() == '0':
            print_msg('HIGH', 'Setting it to 0 may disable XSS protection, '
                              'increasing the risk of cross-site scripting attacks')

    print()


def eval_strict_transport_security(header_value: str) -> None:
    """Evaluates the HSTS header value and provides security assessments"""
    print_title('HSTS - Strict-Transport-Security')
    print_msg('OK', 'The presence of the HSTS header ensures secure connections '
                    'by instructing the browser to only communicate with the '
                    'website over HTTPS')
    directives = header_value.split(';')
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
                if max_age < 2592000:
                    print_msg('WARN', 'The "max-age" directive is too small. '
                                      'The minimum recommended value is 2592000 (30 days).')
            except ValueError:
                print_msg('WARN', "'max-age' is invalid, it allows a bad actor to downgrade "
                                "the connection to HTTP, risking users' exposure to "
                                "man-in-the-middle attacks")

        if directive.lower() == 'includeSubDomains':
            result['include_subdomains'] = True

    print(f'Max-Age: {result["max_age"]}')
    print(f'Include Subdomains: {result["include_subdomains"]}')
    print(f'Preload: {result["preload"]}')
    print()


def eval_permissions_policy(header_value: str) -> None:
    """Evaluates the Permissions-Policy header value and provides security assessments"""
    print_title('Permissions-Policy')

    permissions = re.split(r', *|; *', header_value)

    for permission in permissions:
        policy_parts = permission.split('=')
        if policy_parts:
            value = policy_parts[0].strip()
            policy_value = policy_parts[1].strip() if len(policy_parts) > 1 else ''

            if value == 'browsing-topics':
                # Special case for 'browsing-topics'
                if policy_value == 'none':
                    print_msg('WARN', 'browsing-topics access is disabled')
                else:
                    print_msg('OK', 'browsing-topics access is enabled')
            else:
                # General case for other permissions
                if policy_value == 'none':
                    print_msg('WARN', f'{value} access is disabled')
                elif policy_value == 'self':
                    print_msg('OK', f'{value} access is limited to the same origin')
                else:
                    print_msg('OK', f'{permission} access is enabled')

    print()


def eval_x_frame_options(header_value: str) -> None:
    """Evaluates the X-Frame-Options header value and provides security assessments"""
    print_title('X-Frame-Options')
    header_value = header_value.lower().strip()

    if header_value == 'deny':
        print_msg('OK', 'X-Frame-Options is set to "deny" (prevents framing of the web page)')
    elif header_value == 'sameorigin':
        print_msg('OK', 'X-Frame-Options is set to "sameorigin" '
                 '(allows framing by pages from the same origin)')

    elif header_value.startswith('allow-from'):
        url = header_value[11:].strip()
        print_msg('OK', f'X-Frame-Options is set to "allow-from: {url}" '
                        '(allows framing from the specified URL)')

    else:
        print_msg('WARN', f'Invalid X-Frame-Options value: {header_value}')

    print()


def eval_csp(header_value: str) -> None:
    """Evaluates the CSP header value and provides security assessments"""
    print_title('Content-Security-Policy')
    csp = csp_parser(header_value)

    print(f'\033[1mPolicy:\033[0m {header_value}')
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
            ("'*'", 'Allows connections to any origin, which can lead to information leakage '
                    'and security vulnerabilities.')
        ]

    }

    weak_directives = set()

    for directive, values in csp.items():
        if directive in unsafe_directives:
            for rule, explanation in unsafe_directives[directive]:
                if rule in values:
                    weak_directives.add(directive)

    if weak_directives:
        print_msg('HIGH', 'Found weakness in the CSP policy')
        for directive in weak_directives:
            print(f'\033[1mDirective:\033[0m {directive}')
            for rule, explanation in unsafe_directives[directive]:
                if rule in csp.get(directive, []):
                    print(f'   \033[1mRule:\033[0m {rule}')
                    print(f'   \033[1mExplanation:\033[0m {explanation}\n')
    else:
        print_msg('OK', 'No weak directives found in the CSP policy.')

    print()


def eval_access_control_allow_origin(header_value: str) -> None:
    """Evaluates the Access-Control-Allow-Origin header value and provides security assessments"""
    print_title('Access-Control-Allow-Origin')

    if header_value == '*':
        print_msg('WARN', 'Access-Control-Allow-Origin is set to "*" '
                  '(allows requests from any origin)')

    else:
        origins = header_value.split(',')
        origins = [origin.strip() for origin in origins]
        allowed_origins = ', '.join(origins)
        print_msg('OK', f'Access-Control-Allow-Origin is set to "{allowed_origins}" '
                 '(allows requests from specified origins)')

    print()


def eval_access_control_allow_methods(header_value: str) -> None:
    pass

def eval_access_control_allow_credentials(header_value: str) -> None:
    pass

def eval_access_control_max_age(header_value: str) -> None:
    pass

def eval_access_control_expose_headers(header_value: str) -> None:
    pass

def eval_access_control_request_method(header_value: str) -> None:
    pass

def eval_access_control_request_headers(header_value: str) -> None:
    pass


def eval_cors_opener_policy(header_value: str) -> None:
    """Evaluates the Cross-Origin-Opener-Policy header value and provides security assessments"""
    print_title('Cross-Origin-Opener-Policy')

    if header_value.lower() == 'same-origin':
        print_msg('OK', 'The opener browsing context is restricted to the same origin, '
                 'preventing cross-origin interactions')

    elif header_value.lower() == 'same-origin-allow-popups':
        print_msg('OK', 'The opener browsing context is restricted to the same origin, '
                 'allowing popups')

    elif header_value.lower() == 'unsafe-none':
        print_msg('WARN', 'The opener browsing context is not restricted and can be cross-origin')

    elif header_value.lower() == 'same-origin-plus-coep':
        print_msg('OK', 'The opener browsing context is restricted to the same origin '
                 'and requires Cross-Origin-Embedder-Policy (COEP) enforcement')


    elif header_value.lower() == 'same-origin-allow-popups-plus-coep':
        print_msg('OK', 'The opener browsing context is restricted to the same origin, '
                 'allowing popups, and requires COEP enforcement')


    else:
        print_msg('HIGH', 'The specified Cross-Origin-Opener-Policy header has an '
                  f'invalid value: {header_value}')


    print()


def eval_cors_embedded_policy(header_value: str) -> None:
    """Evaluates the Cross-Origin-Embedder-Policy header value and provides security assessments"""
    print_title('Cross-Origin-Embedder-Policy')

    if header_value.lower() == 'none':
        print_msg('OK', 'No cross-origin embedding restrictions are enforced')

    elif header_value.lower() == 'credentialless':
        print_msg('OK', 'Cross-origin embedding is allowed without credentials')

    elif header_value.lower() == 'require-corp':
        print_msg('OK', 'Cross-origin embedding is allowed only if the response has '
                 'the `Cross-Origin-Resource-Policy` header set to `same-site` '
                 'or `same-origin`')

    elif header_value.lower() == 'require-corp-credentialless':
        print_msg('OK', 'Cross-origin embedding is allowed without credentials only '
                 'if the response has the `Cross-Origin-Resource-Policy` header '
                 'set to `same-site` or `same-origin`')

    elif header_value.lower() == 'unsafe-none':
        print_msg('WARN', 'No cross-origin embedding restrictions are enforced, '
                   'which can lead to security risks')

    else:
        print_msg('HIGH', f'The specified Cross-Origin-Embedder-Policy header has '
                   f'an invalid value: {header_value}')

    print()


def eval_cors_resource_policy(header_value: str) -> None:
    """Evaluates the Cross-Origin-Resource-Policy header value and provides security assessments"""
    print_title('Cross-Origin-Resource-Policy')

    if header_value.lower() == 'same-site':
        print_msg('OK', 'Cross-origin requests are only allowed from the same site')

    elif header_value.lower() == 'same-origin':
        print_msg('OK', 'Cross-origin requests are only allowed from the same origin')

    elif header_value.lower() == 'cross-origin':
        print_msg('OK', 'Cross-origin requests are allowed')

    elif header_value.lower() == 'same-site-strict':
        print_msg('OK', 'Cross-origin requests are only allowed from the same site '
                 'and must use CORS headers')

    elif header_value.lower() == 'same-origin-allow-popups':
        print_msg('OK', 'Cross-origin requests are only allowed from the same origin '
                 'and are allowed for popups')

    else:
        print_msg('ERR', f'The specified Cross-Origin-Resource-Policy header has an '
                  f'invalid value: {header_value}')

    print()


def eval_content_type_options(header_value: str) -> None:
    """Evaluates the X-Content-Type-Options header value and provides security assessments"""
    print_title('X-Content-Type-Options')

    if header_value.lower() == 'nosniff':
        print_msg('OK', 'When the header value is set to "nosniff", it instructs '
                 'the browser to prevent MIME-sniffing attacks by strictly '
                 'interpreting the content type without performing content sniffing')
    else:
        print_msg('ERR', 'Header is different from "nosniff"')

    print()


def eval_referrer_policy(header_value: str) -> None:
    """Evaluates the Referrer-Policy header value and provides security assessments"""
    print_title(f'Referrer-Policy: {header_value}')

    if header_value.lower() == 'no-referrer':
        print_msg('OK', 'No referrer information is sent, potentially limiting '
                        'the ability to track and analyze legitimate referrals')

    elif header_value.lower() == 'no-referrer-when-downgrade':
        print_msg('OK', 'Referrer information is not sent during HTTPS to HTTP '
                        'navigation, preventing the exposure of sensitive data '
                        'in the Referer header')

    elif header_value.lower() == 'origin':
        print_msg('OK', 'Only the origin (scheme, host, and port) is sent as the '
                        'referrer, excluding the path and query parameters, '
                        'which helps protect sensitive information during '
                        'cross-origin requests')

    elif header_value.lower() == 'origin-when-cross-origin':
        print_msg('OK', 'The full referrer is sent within the same origin, while '
                        'only the origin is sent during cross-origin navigation, '
                        'balancing security and usability')

    elif header_value.lower() == 'same-origin':
        print_msg('OK', 'The full referrer is sent only for requests within the '
                        'same origin, preventing referrer information leakage to '
                        'external sites during cross-origin requests.')

    elif header_value.lower() == 'strict-origin':
        print_msg('OK', 'The full referrer is sent only for requests within the '
                        'same origin, preventing referrer information leakage to '
                        'external sites during cross-origin requests')

    elif header_value.lower() == 'strict-origin-when-cross-origin':
        print_msg('WARN', 'The full URL is sent as the referrer, including the '
                        'path, query parameters, and fragment identifier. This '
                        'can potentially expose sensitive information in the '
                        'referrer header.')
    else:
        print_msg('HIGH', f'The specified Referrer-Policy header has an invalid '
                        f'value: {header_value}')
     
    print()


def eval_feature_policy(header_value: str) -> None:
    """Evaluates the Feature-Policy header value and provides security assessments"""
    print_title('Feature-Policy')
    print_msg('WARN', 'Feature Policy has been renamed to Permissions Policy')

    print()
