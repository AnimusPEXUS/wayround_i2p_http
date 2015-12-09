
import pprint
import logging

import wayround_org.http.message


class HTTPServer:

    def __init__(
            self,
            func=None,
            header_size_limit=(1 * 1024 ** 2),
            output_into_socket_encoding='utf-8'
            ):
        """
        pass method `callable_for_socket_server' of this class instance to
        socket server

        this class (and it's instances) does not uses threading, as threading
        functionality ought to be provided by calling socket server. in other
        words, this class simply parses header body (raises exception in case
        if header size bytes limit is reached) and passes results to `func'
        callable.

        func - must be callable and accept arguments:
            request - instance of wayround_org.http.message.HTTPRequest

        func - must return instance of wayround_org.http.message.HTTPResponse
        """
        if not callable(func):
            raise ValueError("`func' must be callable")

        self._func = func

        self._output_into_socket_encoding = output_into_socket_encoding
        self._header_size_limit = header_size_limit

        return

    def callable_for_socket_server(
            self,
            transaction_id,
            serv,
            serv_stop_event,
            sock,
            addr,
            header_already_parsed=None,
            header_already_readen=None
            ):
        """

        on header_already_parsed and header_already_readen params
        read description for read_and_parse_header() function - those params
        simply passed to it
        """

        sock.setblocking(False)

        (header_bytes, line_terminator,
            request_line_parsed, header_fields,
            error) = wayround_org.http.message.read_and_parse_header(
                sock,
                self._header_size_limit,
                header_already_parsed=header_already_parsed,
                header_already_readen=header_already_readen
            )

        if not error:

            req = wayround_org.http.message.HTTPRequest(
                transaction_id,
                serv,
                serv_stop_event,
                sock,
                addr,
                request_line_parsed,
                header_fields
                )

            res = self._func(req)

            if not isinstance(res, wayround_org.http.message.HTTPResponse):
                raise TypeError(
                    "only wayround_org.http.message.HTTPResponse type is "
                    "acceptable as response"
                    )

            res.send_into_socket(
                sock,
                encoding=self._output_into_socket_encoding
                )

            sock.close()

        return
