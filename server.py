import socketserver
from typing import Optional

from charset_normalizer import logging
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
    CRLF = b'\r\n'
    CRLF_CRLF = CRLF*2
    SP = b' '
    COLON = b':'
    METHOD = b'OPTIONS|GET|HEAD|POST|PUT|DELETE|TRACE|CONNECT'
    REQUEST_URI = ""
    # HTTP_VERSION = ...
    # REQUEST_LINE = bytes(METHOD, SP, REQUEST_URI, SP, HTTP_VERSION, CRLF)

    def __init__(self, client_data: bytes):
        self.__logger = logging.getLogger(HttpServer.__name__)
        self.__client_data = client_data

    def handle(self) -> bytes:
        '''
        Responds to the HTTP request contained in the client data it was initialized with. The server may not be able to process a client request if it is
        a) invalid, or
        b) not compatible with the server (which is not fully HTTP/1.1 compliant.)
        '''
        response = b''

        # Empty requests are invalid
        if not self.__client_data:
            response = self.CRLF.join(
                (b'HTTP/1.1 400 Bad message syntax', self.CRLF))
            return response

        request_and_possibly_body = self.__client_data.lstrip(
            self.CRLF).split(self.CRLF_CRLF)

        # Improper use of CRLF is not allowed
        if len(request_and_possibly_body) > 2:
            response = self.CRLF.join(
                (b'HTTP/1.1 400 Bad message syntax', self.CRLF))
            return response

        return self.__handle_request(*request_and_possibly_body)

    def __handle_request(self, request: bytes, body: Optional[bytes] = None) -> bytes:
        self.__logger.debug(
            f'Handling request:\n{request}\nwith body:\n{body}')
        response = b''
        request_line = b''
        header = {}
        request_line_and_possibly_headers = request.split(
            self.CRLF, maxsplit=1)

        # Parse header (if any)
        if len(request_line_and_possibly_headers) == 2:
            request_line, header_entries = request_line_and_possibly_headers

            parsed_header_entries = []
            for entry in header_entries.split(self.CRLF):
                entry_parts = entry.split(self.COLON, maxsplit=1)

                # Each header name must have a corresponding value
                if len(entry_parts) != 2:
                    return self.CRLF.join((b'HTTP/1.1 400 Bad message syntax', self.CRLF))

                parsed_header_entries.append(entry_parts)

            header = dict(parsed_header_entries)
            self.__logger.debug(f'Header:\n{header}')

        else:
            request_line = request_line_and_possibly_headers

        return response


class MyWebServer(socketserver.BaseRequestHandler):
    MAX_CLIENT_MESSAGE_LENGTH_BYTES = 1024

    def handle(self):
        client_data = self.request.recv(
            self.MAX_CLIENT_MESSAGE_LENGTH_BYTES).strip()
        httpServer = HttpServer(client_data)
        self.request.sendall(httpServer.handle())
        # self.request.sendall(bytearray("OK", 'utf-8'))


if __name__ == "__main__":
    HOST, PORT = "localhost", 8080

    socketserver.TCPServer.allow_reuse_address = True
    # Create the server, binding to localhost on port 8080
    server = socketserver.TCPServer((HOST, PORT), MyWebServer)

    logging.basicConfig(
        level=logging.DEBUG, format='[%(levelname)s - %(asctime)s - %(name)s - %(lineno)d] %(message)s')

    # Activate the server; this will keep running until you
    # interrupt the program with Ctrl-C
    server.serve_forever()
