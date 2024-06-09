from dataclasses import dataclass
from urllib.parse import urlparse
import sys
import requests
from .utils import print_msg, print_title, get_random_user_agent
from .headers_eval import *


class SecurityHeaderChecker:
    """A class for checking security headers and leaked headers of a given URL"""
    @dataclass
    class SecurityHeaders:
        """Represents a security header"""
        header_name: str
        header_value: bool

    @dataclass
    class LeakedHeaders:
        """Represents a leaked header"""
        header_name: str
        header_value: bool

    SECURITY_HEADERS = {
        'Strict-Transport-Security': {
            'eval_function': eval_strict_transport_security,
            'tags': '',
            'cross_eval': ()
        },
        'Permissions-Policy': {
            'eval_function': eval_permissions_policy,
            'tags': '',
            'cross_eval': ()
        },
        'X-XSS-Protection': {
            'eval_function': eval_xss_protection,
            'tags': 'deprecated',
            'cross_eval': ('Content-Security-Policy')
        },
        'Content-Security-Policy': {
            'eval_function': eval_csp,
            'tags': '',
            'cross_eval': ()
        },
        'Cross-Origin-Resource-Policy': {
            'eval_function': eval_cors_resource_policy,
            'tags': 'cors',
            'cross_eval': ()
        },
        'Cross-Origin-Opener-Policy': {
            'eval_function': eval_cors_opener_policy,
            'tags': 'cors',
            'cross_eval': ()
        },
        'Cross-Origin-Embedder-Policy': {
            'eval_function': eval_cors_embedded_policy,
            'tags': 'cors',
            'cross_eval': ()
        },
        'Access-Control-Allow-Origin': {
            'eval_function': eval_access_control_allow_origin,
            'tags': 'cors',
            'cross_eval': ()
        },
        'Access-Control-Allow-Methods': {
            'eval_function': eval_access_control_allow_methods,
            'tags': 'cors',
            'cross_eval': ()
        },
        'Access-Control-Allow-Credentials': {
            'eval_function': eval_access_control_allow_credentials,
            'tags': 'cors',
            'cross_eval': ()
        },
        'Access-Control-Max-Age': {
            'eval_function': eval_access_control_max_age,
            'tags': 'cors',
            'cross_eval': ()
        },
        'Access-Control-Expose-Headers': {
            'eval_function': eval_access_control_expose_headers,
            'tags': 'cors',
            'cross_eval': ()
        },
        'Access-Control-Request-Method': {
            'eval_function': eval_access_control_request_method,
            'tags': 'cors',
            'cross_eval': ()
        },
        'Access-Control-Request-Headers': {
            'eval_function': eval_access_control_request_headers,
            'tags': 'cors',
            'cross_eval': ()
        },
        'X-Frame-Options': {
            'eval_function': eval_x_frame_options,
            'tags': '',
            'cross_eval': ()
        },
        'X-Content-Type-Options': {
            'eval_function': eval_content_type_options,
            'tags': '',
            'cross_eval': ()
        },
        'Referrer-Policy': {
            'eval_function': eval_referrer_policy,
            'tags': '',
            'cross_eval': ()
        },
        'Feature-Policy': {
            'eval_function': eval_feature_policy,
            'tags': 'deprecated',
            'cross_eval': ()
        }
    }

    LEAK_HEADERS = (
    'Server',
    'X-Powered-By',
    'X-AspNet-Version',
    'X-AspNetMvc-Version',
    'X-PHP-Version',
    'X-Powered-CMS',
    'X-Runtime',
    'X-Node-ID',
    'X-Host',
    'X-Version',
    'X-Backend-Server',
    'X-Varnish',
    'X-Node',
    'X-Hostname',
    'X-Instance-ID',
    'X-Turbo-Charged-By'
)

    def __init__(self, url):
        self.raw_url = url
        self.url = self.__parse_url()
        self.user_agent = get_random_user_agent()
        self.connection = self.__open_connection()
        self.security_headers = self.__fetch_headers()
        self.leaked_headers = self.__leaking_headers()

    def __parse_url(self) -> str:
        parsed_url = urlparse(self.raw_url)
        if not parsed_url.scheme:
            return f'https://{self.raw_url}'

        return self.raw_url

    def __open_connection(self):
        try:
            response = requests.get(
                self.url, timeout=1.0, headers=self.user_agent)
            response.raise_for_status()
            return response
        except requests.exceptions.RequestException:
            print_msg('HIGH',f'Failed to connect to {self.url}')
            sys.exit(1)


    def __fetch_headers(self) -> SecurityHeaders:
        headers = self.connection.headers
        security_headers = [
            self.SecurityHeaders(header_name, headers.get(header_name, False))
            for header_name in self.SECURITY_HEADERS
        ]

        return security_headers


    def __leaking_headers(self) -> LeakedHeaders:
        headers = self.connection.headers
        leaked_headers = [
            self.LeakedHeaders(header_name, headers.get(header_name))
            for header_name in self.LEAK_HEADERS
            if headers.get(header_name) is not None
        ]

        return leaked_headers


    def list_only(self) -> None:
        """
        Lists the security headers with their values and identifies missing headers.
        Prints the headers with values as 'OK', and missing headers as 'WARN'.
        Additionally, prints the possibly leaked headers.
        """
        headers_with_values = []
        headers_without_values = []

        print_msg('INF', f'Getting headers from {self.url}')
        print()
        for security_header in self.security_headers:
            header_name = security_header.header_name
            header_value = security_header.header_value

            if header_name in self.SECURITY_HEADERS and self.SECURITY_HEADERS[header_name].get('tags') == 'cors':
                continue

            if header_value:
                headers_with_values.append((header_name, header_value))
            else:
                headers_without_values.append((header_name))

        for field, value in headers_with_values:
            print_msg('OK', f'{field}: {value}')

        for header in headers_without_values:
            print_msg('WARN', f'missing header {header}')

        print()
        print_title('Possibile Leaked Headers')
        for leaked_header in self.leaked_headers:
            print(f'{leaked_header.header_name}: {leaked_header.header_value}')


    def evaluate_headers(self):
        """
        Evaluates the security headers based on their values.
        Calls the corresponding evaluation function for each header and 
        performs cross-evaluation if required. Prints the evaluation results.
        Additionally, prints the possibly leaked headers.
        """
        headers_to_evaluate = {
            header.header_name: header.header_value
            for header in self.security_headers
            if header.header_value is not False
        }

        print_msg('INF', f'Getting headers from {self.url}')
        print()
        for header_name, header_value in headers_to_evaluate.items():
            eval_func = self.SECURITY_HEADERS.get(header_name, {}).get('eval_function')
            cross_eval = self.SECURITY_HEADERS.get(header_name, {}).get('cross_eval')

            if cross_eval:

                if isinstance(cross_eval, str):
                    cross_eval = (cross_eval,)

                cross_values = {}
                for cross_header_name in cross_eval:
                    cross_header_value = headers_to_evaluate.get(cross_header_name)
                    if cross_header_value is None:
                        continue
                    cross_values[cross_header_name] = cross_header_value

                eval_func(header_value, cross_values)
            else:
                eval_func(header_value)

        print_title('Possibile Leaked Headers')
        for leaked_header in self.leaked_headers:
            print(f'{leaked_header.header_name}: {leaked_header.header_value}')
