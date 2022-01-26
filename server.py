from datetime import datetime
from enum import IntEnum
from pathlib import Path
import mimetypes
import platform
import socketserver
from typing import Optional, Tuple
from charset_normalizer import logging
from urllib.parse import ParseResult, urlparse, unquote
#  coding: utf-8

# Copyright 2022 Dillon Allan
# Copyright 2013 Abram Hindle, Eddie Antonio Santos
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
#
# Furthermore it is derived from the Python documentation examples thus
# some of the code is Copyright © 2001-2013 Python Software
# Foundation; All Rights Reserved
#
# http://docs.python.org/2/library/socketserver.html
#
# run: python freetests.py

# try: curl -v -X GET http://127.0.0.1:8080/


class HttpStatus(IntEnum):
    '''
    The few HTTP Status codes supported by HttpServer.

    Design inspired by http.HTTPStatus.

    class http.HTTPStatus by the Python Software foundation is licensed under the Python Software Foundation License Version 2.
    https://docs.python.org/3/library/http.html#http.HTTPStatus
    Accessed 2022-01-26.
    '''
    def __new__(cls, value, phrase):
        obj = int.__new__(cls, value)
        obj._value_ = value
        obj.phrase = phrase
        return obj

    OK = (200, 'OK')

    MOVED_PERMANENTLY = (301, 'Moved Permanently')

    BAD_REQUEST = (400, 'Bad Request')
    NOT_FOUND = (404, 'File not found')
    METHOD_NOT_ALLOWED = (405, 'Method Not Allowed')
    IM_A_TEAPOT = (418, "I'm a teapot")

    HTTP_VERSION_NOT_SUPPORTED = (505, 'HTTP Version Not Supported')


class HttpServer():
    '''A web server supporting a subset of the RFC 2616 HTTP/1.1 specification.'''
    ENCODING = 'UTF-8'
    SERVER_ROOT = 'www'
    HTTP_VERSION = b'HTTP/1.1'
    SUPPORTED_HTTP_VERSIONS = (b'HTTP/1.0', b'HTTP/1.1')

    # RFC 1123 Date Representation in Python? posted by Sebastian Rittau and answered by Florian Bösch is licensed under CC-BY-SA 2.5
    # https://stackoverflow.com/a/225106
    # Accessed 2022-01-26
    RFC_1123_DATE_FORMAT = '%a, %d %b %Y %H:%M:%S GMT'

    # Common MIME types by Mozilla Contributors is licensed under CC-BY-SA 2.5
    # https://developer.mozilla.org/en-US/docs/Web/HTTP/Basics_of_HTTP/MIME_types/Common_types,
    # Accessed 2022-01-25
    DEFAULT_MIME_TYPE = b'application/octet-stream'
    DEFAULT_CHARSET = b'charset=utf-8'

    CRLF = b'\r\n'
    CRLF_CRLF = CRLF*2
    SP = b' '
    COLON = b':'
    SEP = b'/'

    INDEX_FILE = Path('index.html')
    READ_CHUNKSIZE = 4092

    class HttpResponse:
        '''Helper class for crafting responses based on the design of HttpServer.'''

        def __init__(self):
            self.__logger = logging.getLogger(HttpServer.HttpResponse.__name__)
            self.__encoding = HttpServer.ENCODING
            self.__header = {b'Connection': b'close',
                             b'Server': bytes(f'{HttpServer.__name__}/0.1 Python/{platform.python_version()}', encoding=self.__encoding)}
            self.__body = b''

        def set_status(self, status: HttpStatus) -> 'HttpResponse':
            self.__status_parts = [
                bytes(str(status.value), self.__encoding),
                bytes(status.phrase, self.__encoding)
            ]
            return self

        def update_header(self, fields_to_add: dict) -> 'HttpResponse':
            self.__header.update(fields_to_add)
            return self

        def set_body(self, body: bytes) -> 'HttpResponse':
            self.__body = body
            return self

        def to_bytes(self) -> bytes:
            response_line = HttpServer.SP.join(
                [HttpServer.HTTP_VERSION, *self.__status_parts])

            header_bytes = HttpServer.CRLF.join(
                [b': '.join([name, val]) for name, val in self.__header.items()])
            header_bytes += HttpServer.CRLF

            response_bytes = HttpServer.CRLF.join(
                [response_line, header_bytes, self.__body])

            self.__logger.info(f'Response:\n{response_bytes}')
            return response_bytes

    def __init__(self, client_data: bytes):
        self.__logger = logging.getLogger(HttpServer.__name__)
        try:
            self.__server_root = (
                Path(__file__).parent / Path(HttpServer.SERVER_ROOT)).resolve(strict=True)
        except Exception as e:
            self.__logger.exception(e)
            raise ValueError from e

        self.__client_data = client_data
        self.__method_handlers = {
            b'GET': self.__handle_get
        }
        self.__response = self.HttpResponse()

    def handle(self) -> bytes:
        '''
        Responds to the HTTP request contained in the client data it was initialized with. The server may not be able to process a client request if it is
        a) invalid, or
        b) not compatible with the server (which is not fully HTTP/1.1 compliant.)
        '''
        # Empty requests are ignored
        if not self.__client_data:
            return b''

        request_and_possibly_body = self.__client_data.lstrip(
            self.CRLF).split(self.CRLF_CRLF)

        # Improper use of CRLF is not allowed
        if len(request_and_possibly_body) > 2:
            return self.__response.set_status(HttpStatus.BAD_REQUEST).to_bytes()

        return self.__handle_request(*request_and_possibly_body).to_bytes()

    def __handle_request(self, request: bytes, body: Optional[bytes] = None) -> 'HttpResponse':
        request_line = b''
        header = None
        request_line_and_possibly_headers = request.split(
            self.CRLF, maxsplit=1)

        # Check header
        if len(request_line_and_possibly_headers) == 2:
            request_line, header_raw = request_line_and_possibly_headers

            ok, self.__response, header = self.__parse_header(header_raw)
            if not ok:
                return self.__response

        # No header
        else:
            request_line = request_line_and_possibly_headers[0]

        self.__logger.info(
            f'Request line:\n{request_line}\nHeader:\n{header}\nBody (if any):\n{body}')

        ok, self.__response, method, request_uri, http_version = self.__parse_request_line(
            request_line)
        if not ok:
            return self.__response

        # Only handle supported methods
        if method not in self.__method_handlers:
            return self.__response.set_status(HttpStatus.METHOD_NOT_ALLOWED)

        return self.__method_handlers[method](request_uri, http_version, header, body)

    def __parse_request_line(self, request_line: bytes) -> Tuple:
        expected_line_parts_length = 3
        request_line_parts = request_line.split(self.SP)

        if len(request_line_parts) != expected_line_parts_length:
            return False, self.__response.set_status(HttpStatus.BAD_REQUEST), None, None, None

        method, request_uri, http_version = request_line_parts

        # Validate URI
        parsed_uri = None
        try:
            parsed_uri = urlparse(request_uri)
        except Exception as e:
            self.__logger.exception(e)
            return False, self.__response.set_status(HttpStatus.BAD_REQUEST), None, None, None

        # Validate HTTP version
        if http_version not in self.SUPPORTED_HTTP_VERSIONS:
            return False, self.__response.set_status(HttpStatus.HTTP_VERSION_NOT_SUPPORTED), None, None, None

        return True, self.__response, method, parsed_uri, http_version

    def __parse_header(self, header: bytes) -> Tuple:
        parsed_header_entries = []
        for entry in header.split(self.CRLF):
            entry_parts = [part.strip()
                           for part in entry.split(self.COLON, maxsplit=1)]

            # Each header name must have a corresponding value
            if len(entry_parts) != 2:
                return False, self.__response.set_status(HttpStatus.BAD_REQUEST), None

            parsed_header_entries.append(entry_parts)

        return True, self.__response, dict(parsed_header_entries)

    def __validate_request_uri(self, uri: ParseResult, header: dict) -> Tuple:
        unquoted_uri_path = unquote(
            str(uri.path, encoding=self.ENCODING), encoding=self.ENCODING)
        uri_has_trailing_slash = len(unquoted_uri_path) > 0 and \
            bytes(unquoted_uri_path[-1], encoding=self.ENCODING) == self.SEP
        uri_path_relative_to_server_root = self.__server_root / \
            Path(unquoted_uri_path.lstrip(str(self.SEP, encoding=self.ENCODING)))

        # Test that request URI is both
        # a. a descendent of the server root, and
        # b. pointing to an actual resource.
        uri_path_absolute = None
        try:
            uri_path_absolute = uri_path_relative_to_server_root.resolve(
                strict=True)
        except (FileNotFoundError, RuntimeError) as e:
            self.__logger.exception(e)
        finally:
            if uri_path_absolute is None or \
                    (self.__server_root != uri_path_absolute and self.__server_root not in uri_path_absolute.parents):
                return False, self.__response.set_status(HttpStatus.NOT_FOUND), None

        if uri_path_absolute.is_dir():
            # serve default file in a directory
            if uri_has_trailing_slash:
                uri_path_absolute /= self.INDEX_FILE

            # Missing trailing separator: redirect to proper URL
            else:
                new_uri = uri._replace(scheme=b'http', netloc=header.get(b'Host'),
                                       path=uri.path + self.SEP).geturl()
                location_header = {b'Location': new_uri}
                return False, self.__response.set_status(HttpStatus.MOVED_PERMANENTLY).update_header(location_header), None

        if not uri_path_absolute.exists():
            return False, self.__response.set_status(HttpStatus.NOT_FOUND), None

        return True, self.__response, uri_path_absolute

    def __set_resource_headers(self, uri_path: Path) -> 'HttpResponse':
        mime_type, file_charset = mimetypes.guess_type(uri_path)
        resource_stats = uri_path.stat()
        content_type = {b'Content-Type': b';'.join(
            [bytes(mime_type, self.ENCODING) if mime_type else self.DEFAULT_MIME_TYPE,
             bytes(file_charset, self.ENCODING) if file_charset else self.DEFAULT_CHARSET])}
        content_length = {
            b'Content-Length': bytes(
                str(resource_stats.st_size), encoding=self.ENCODING
            )}
        last_modified = {
            b'Last-Modified': bytes(
                datetime.utcfromtimestamp(resource_stats.st_mtime).strftime(
                    self.RFC_1123_DATE_FORMAT),
                encoding=self.ENCODING
            )}
        date_field = {
            b'Date': bytes(datetime.utcnow().strftime(self.RFC_1123_DATE_FORMAT), encoding=self.ENCODING)
        }

        return self.__response.update_header({**content_type, **content_length, **last_modified, **date_field})

    def __set_body(self, uri_path: Path) -> 'HttpResponse':
        # Load resource into body
        body_buffer = b''
        with open(uri_path, mode='rb') as resource:
            chunk = resource.read(self.READ_CHUNKSIZE)
            while chunk:
                body_buffer = b''.join([body_buffer, chunk])
                chunk = resource.read(self.READ_CHUNKSIZE)
        return self.__response.set_body(body_buffer)

    def __handle_get(self, request_uri: ParseResult, request_http_version: bytes, header: dict, body: Optional[bytes] = None) -> 'HttpResponse':
        ok, self.__response, uri_path_absolute = self.__validate_request_uri(
            request_uri, header)
        if not ok:
            return self.__response

        self.__response = self.__set_resource_headers(uri_path_absolute)
        self.__response = self.__set_body(uri_path_absolute)

        return self.__response.set_status(HttpStatus.OK)


class MyWebServer(socketserver.BaseRequestHandler):
    MAX_CLIENT_MESSAGE_LENGTH_BYTES = 1024

    def handle(self):
        client_data = self.request.recv(
            self.MAX_CLIENT_MESSAGE_LENGTH_BYTES).strip()
        httpServer = HttpServer(client_data)
        self.request.sendall(httpServer.handle())


if __name__ == "__main__":
    HOST, PORT = "localhost", 8080

    socketserver.TCPServer.allow_reuse_address = True
    # Create the server, binding to HOST on port PORT
    server = socketserver.TCPServer((HOST, PORT), MyWebServer)

    # Set log level to desired verbosity
    logging.basicConfig(
        level=logging.INFO, format='[%(levelname)s - %(asctime)s - %(name)s] %(message)s')

    # Activate the server; this will keep running until you
    # interrupt the program with Ctrl-C
    server.serve_forever()
