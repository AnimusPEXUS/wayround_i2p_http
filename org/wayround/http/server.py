
import pprint
import logging

import org.wayround.http.message


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
            request - instance of org.wayround.http.message.HTTPRequest

        func - must return instance of org.wayround.http.message.HTTPResponse
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
            addr
            ):

        try:
            header_bytes, line_terminator = \
                org.wayround.http.message.read_header(
                    sock,
                    self._header_size_limit
                    )
        except:
            logging.exception(
                "Error splitting HTTP header from the rest of the body"
                )
        else:

            try:
                request_line_parsed, header_fields = \
                    org.wayround.http.message.parse_header(
                        header_bytes,
                        line_terminator
                        )
            except:
                logging.exception(
                    "Error parsing header. Maybe it's not an HTTP"
                    )
            else:

                req = org.wayround.http.message.HTTPRequest(
                    transaction_id,
                    serv,
                    serv_stop_event,
                    sock,
                    addr,
                    request_line_parsed,
                    header_fields
                    )

                res = self._func(req)

                if not isinstance(res, org.wayround.http.message.HTTPResponse):
                    raise TypeError(
                        "only org.wayround.http.message.HTTPResponse type is "
                        "acceptable as response"
                        )

                res.send_into_socket(
                    sock,
                    encoding=self._output_into_socket_encoding
                    )

        return
