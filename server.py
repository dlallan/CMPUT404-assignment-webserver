import socketserver
from http import HTTPStatus
from typing import Optional, Tuple
from charset_normalizer import logging
from urllib.parse import urlparse
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


class HttpServer():
    '''A web server supporting a subset of the RFC 2616 HTTP/1.1 specification.'''
    ENCODING = 'UTF-8'
    HTTP_VERSION = b'HTTP/1.1'
    SUPPORTED_HTTP_VERSIONS = (HTTP_VERSION, b'HTTP/1.0')
    CRLF = b'\r\n'
    CRLF_CRLF = CRLF*2
    SP = b' '
    COLON = b':'

    class HttpResponse:
        '''Helper class for crafting responses based on the design of HttpServer.'''

        def __init__(self):
            self.__logger = logging.getLogger(HttpServer.HttpResponse.__name__)
            self.__encoding = HttpServer.ENCODING
            self.__header = {'Connection': 'close'}
            self.__body = b''

        def set_status(self, status: HTTPStatus) -> 'HttpResponse':
            self.__status_parts = [
                bytes(str(status.value), self.__encoding),
                bytes(status.phrase, self.__encoding)
            ]
            return self

        def to_bytes(self) -> bytes:
            response_line = HttpServer.SP.join(
                [HttpServer.HTTP_VERSION, *self.__status_parts])

            header_bytes = HttpServer.CRLF.join(
                [bytes(f'{name}: {val}', encoding=HttpServer.ENCODING)
                 for name, val in self.__header.items()]
            )

            response_bytes = HttpServer.CRLF.join(
                [response_line, header_bytes, self.__body])

            self.__logger.debug(f'Response:\n{response_bytes}')
            return response_bytes

    def __init__(self, client_data: bytes):
        self.__logger = logging.getLogger(HttpServer.__name__)
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
            return self.__response.set_status(HTTPStatus.BAD_REQUEST).to_bytes()

        return self.__handle_request(*request_and_possibly_body).to_bytes()

    def __handle_request(self, request: bytes, body: Optional[bytes] = None) -> 'HttpResponse':
        request_line = b''
        header = {}
        request_line_and_possibly_headers = request.split(
            self.CRLF, maxsplit=1)

        # Check header
        if len(request_line_and_possibly_headers) == 2:
            request_line, header_raw = request_line_and_possibly_headers

            ok, header = self.__parse_header(header_raw)
            if not ok:
                return self.__response

        # No header
        else:
            request_line = request_line_and_possibly_headers

        self.__logger.debug(
            f'Request line:\n{request_line}\nHeader:\n{header}\nBody (if any):\n{body}')

        ok, method, request_uri, http_version = self.__parse_request_line(
            request_line)
        if not ok:
            return self.__response

        # Only handle supported methods
        if method not in self.__method_handlers:
            return self.__response.set_status(HTTPStatus.METHOD_NOT_ALLOWED)

        return self.__method_handlers[method](request_uri, http_version, header, body)

    def __parse_request_line(self, request_line: bytes) -> Tuple:
        expected_line_parts_length = 3
        request_line_parts = request_line.split(self.SP)

        if len(request_line_parts) != expected_line_parts_length:
            self.__response.set_status(HTTPStatus.BAD_REQUEST)
            return False, None, None, None

        method, request_uri, http_version = request_line_parts

        # Validate URI
        parsed_uri = None
        try:
            parsed_uri = urlparse(request_uri)
        except Exception as e:
            self.__logger.exception(e)
            self.__response.set_status(HTTPStatus.BAD_REQUEST)
            return False, None, None, None

        # Validate HTTP version
        if http_version not in self.SUPPORTED_HTTP_VERSIONS:
            self.__response.set_status(HTTPStatus.HTTP_VERSION_NOT_SUPPORTED)
            return False, None, None, None

        return True, method, parsed_uri, http_version

    def __parse_header(self, header: bytes) -> Tuple:
        parsed_header_entries = []
        for entry in header.split(self.CRLF):
            entry_parts = [part.strip()
                           for part in entry.split(self.COLON, maxsplit=1)]

            # Each header name must have a corresponding value
            if len(entry_parts) != 2:
                self.__response.set_status(HTTPStatus.BAD_REQUEST)
                return False, None

            parsed_header_entries.append(entry_parts)

        return True, dict(parsed_header_entries)

    def __handle_get(self, request_uri: bytes, request_http_version: bytes, header: dict, body: Optional[bytes] = None) -> bytes:
        ...


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
    # Create the server, binding to localhost on port 8080
    server = socketserver.TCPServer((HOST, PORT), MyWebServer)

    logging.basicConfig(
        level=logging.DEBUG, format='[%(levelname)s - %(asctime)s - %(name)s] %(message)s')

    # Activate the server; this will keep running until you
    # interrupt the program with Ctrl-C
    server.serve_forever()
