from dataclasses import dataclass
from urllib.parse import urlparse
import requests
from HeadrEval.utils import print_msg
from HeadrEval.headers_eval import *


class SecurityHeaderChecker:
    @dataclass
    class SecurityHeaders:
        header_name: str
        header_value: bool

    SECURITY_HEADERS = {
        'Strict-Transport-Security': eval_strict_transport_security,
        'Permissions-Policy': eval_permissions_policy,
        'X-XSS-Protection': eval_xss_protection,
        'Content-Security-Policy': eval_csp,
        'Content-Security-Policy-Report-Only': eval_cspro,
        'Cross-Origin-Opener-Policy': eval_cors_opener_policy,
        'X-Frame-Options': eval_x_frame_options,
        'X-Content-Type-Options': eval_content_type_options,
        'Referrer-Policy': eval_referrer_policy,
        'Feature-Policy': eval_feature_policy
    }

    HEADERS = {
        'User-Agent': 'Mozilla/5.0 (X11; U; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/80.0.3987.81 Safari/537.36'
    }

    def __init__(self, url):
        self.raw_url = url
        self.url = self.__parse_url()
        self.connection = self.__open_connection()
        self.security_headers = self.__fetch_headers()

    def __parse_url(self) -> str:
        parsed_url = urlparse(self.raw_url)
        if not parsed_url.scheme:
            return f'https://{self.raw_url}'

        return self.raw_url

    def __open_connection(self):
        try:
            response = requests.get(
                self.url, timeout=1.0, headers=self.HEADERS)
            response.raise_for_status()
            return response
        except (requests.RequestException, ConnectionError) as e:
            raise ConnectionError(f"Failed to connect to {self.url}: {e}")

    def __fetch_headers(self) -> SecurityHeaders:
        headers = self.connection.headers
        security_headers = [
            self.SecurityHeaders(header_name, headers.get(header_name, False))
            for header_name in self.SECURITY_HEADERS
        ]

        return security_headers

    def list_only(self) -> None:
        headers_with_values = []
        headers_without_values = []

        for security_header in self.security_headers:
            header_name = security_header.header_name
            header_value = security_header.header_value

            if header_value:
                headers_with_values.append((header_name, header_value))
            else:
                headers_without_values.append((header_name))

        for field, value in headers_with_values:
            print_msg('OK', f'{field}: {value}')

        for header in headers_without_values:
            print_msg('WARN', f'missing header {header}')

    def evaluate_headers(self):
        for security_header in self.security_headers:
            header_name = security_header.header_name
            header_value = security_header.header_value

            if header_value is not False:
                eval_func = self.SECURITY_HEADERS.get(header_name)
                eval_func(header_value)
