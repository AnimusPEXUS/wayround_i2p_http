
import pprint
import re
import urllib.parse
import http.client
import logging
import ssl
import datetime

import wayround_org.utils.socket


HTTP_MESSAGE_REQUEST_REGEXP = re.compile(
    rb'(?P<method>\w+) (?P<requesttarget>.+?) (?P<httpversion>.*)'
    )


class InputDataLimitReached(Exception):
    pass


class RequestLineDoesNotMatch(Exception):
    pass


class MessageCantFindColumnInLine(Exception):
    pass


class HTTPRequest:
    """
    I'm preferring to use classes over dicts, cause classes are easier to debug

    so this class is only for forming centralised HTTP requests

    it's content isn't mean to be changed by users. read input data from it's
    instances and throw them away.

    this class instances only formed by http server implimentations, like
    wayround_org.server.http_server
    """

    def __init__(
            self,
            transaction_id,
            socket_server,
            serv_stop_event,
            sock,
            addr,
            request_line_parsed,
            header_fields
            ):

        self.transaction_id = transaction_id
        self.socket_server = socket_server
        self.serv_stop_event = serv_stop_event
        self.sock = sock
        self.addr = addr
        self.request_line_parsed = request_line_parsed
        self.header_fields = header_fields
        return

    @property
    def method(self):
        return self.request_line_parsed['method']

    @property
    def requesttarget(self):
        return self.request_line_parsed['requesttarget']

    @property
    def httpversion(self):
        return self.request_line_parsed['httpversion']

    def __repr__(self):
        return pprint.pformat(
            {
                'transaction_id': self.transaction_id,
                'socket_server': self.socket_server,
                'serv_stop_event': self.serv_stop_event,
                'sock': self.sock,
                'addr': self.addr,
                'request_line_parsed': self.request_line_parsed,
                'header_fields': self.header_fields
                }
            )

    def get_decoded_request(self, encoding='utf-8'):
        """
        this only decodes self.request_line_parsed to string values.
        to unquote use other functions.
        """

        ret = {}
        for k, v in self.request_line_parsed:
            ks = k
            if isinstance(ks, bytes):
                ks = str(ks, encoding=encoding)
            vs = v
            if isinstance(vs, bytes):
                vs = str(vs, encoding=encoding)
            ret[ks] = vs

        return ret

    def get_decoded_header_fields(self, encoding='utf-8'):
        """
        this only decodes self.header_fields to string values.
        to unquote use other functions.
        """
        ret = []
        for k, v in self.header_fields:
            ks = k
            if isinstance(ks, bytes):
                ks = str(ks, encoding=encoding)
            vs = v
            if isinstance(vs, bytes):
                vs = str(vs, encoding=encoding)
            ret.append((ks, vs))
        return ret


class HTTPResponse:

    def __init__(
            self,
            code,
            header_fields,
            iterable_body,
            reasonphrase=None,
            httpversion='HTTP/1.1'
            ):
        """
        It is preferable `iterable_body' to return bytes. If not bytes returned
        then what is returned is forcibly converted to bytes with bytes()
        function using encoding parameter. If an error will araise as a
        consequence, - exception will be logged into loggin module and then
        exception will be reraised
        """
        self.code = code
        self.header_fields = header_fields
        self.iterable_body = iterable_body
        self.reasonphrase = reasonphrase
        self.httpversion = httpversion

        return

    def format_status_line(self):
        ret = format_status_line(
            self.code,
            self.reasonphrase,
            self.httpversion
            )
        return ret

    def format_header(self, encoding='utf-8'):
        """
        retruns bytes
        """

        ret = b''

        ret += bytes(
            self.format_status_line(),
            encoding
            )

        ret += b'\r\n'

        for k, v in self.header_fields:
            kb = k
            if isinstance(kb, str):
                kb = bytes(kb, encoding=encoding)
            vb = v
            if isinstance(vb, str):
                vb = bytes(vb, encoding=encoding)
            ret += kb + b': ' + vb + b'\r\n'

        return ret

    def send_into_socket(
            self,
            sock,
            bs=1024,
            stop_event=None,
            encoding='utf-8'
            ):
        """
        Header is writted into socket not earlier when first body iteration is
        returned

        stop_event is for threading.Event instance, for forcibly stopping
        output method
        """

        header_bytes = self.format_header(encoding)

        header_sent = False

        for i in self.iterable_body:

            if not header_sent:
                header_sent = True
                self.send_header(sock, header_bytes, bs, stop_event)

            if stop_event is not None and stop_event.is_set():
                break

            if not isinstance(i, bytes):
                if not isinstance(i, str):
                    i = str(i)
                i = bytes(i, encoding=encoding)

            self.send_iteration(sock, i, bs, stop_event)

        if not header_sent:
            self.send_header(sock, header_bytes, bs, stop_event)

        return

    def send_header(self, sock, header_bytes, bs, stop_event=None):
        """
        usually you don't need to call this method manually
        """
        self.send_iteration(sock, header_bytes, bs, stop_event)
        self.send_iteration(sock, b'\r\n', bs, stop_event)
        return

    def send_iteration(self, sock, data, bs, stop_event=None):
        """
        usually you don't need to call this method manually
        """
        if not isinstance(data, bytes):
            raise TypeError("`data' must be bytes")

        while True:

            if stop_event is not None and stop_event.is_set():
                break

            if len(data) == 0:
                break

            # TODO: use wayround_org.utils.stream module here
            to_send = data[:bs]
            data = data[bs:]

            # print("sending data to socket: {}".format(to_send))

            while len(to_send) != 0:
                sent_number = sock.send(to_send)
                if sent_number == len(to_send):
                    # print('sent: {}'.format(to_send[:sent_number]))
                    break
                else:
                    to_send = to_send[sent_number:]

        return


class ClientHTTPRequest(HTTPResponse):

    # NOTE: server response and client request are mostly the same

    def __init__(
            self,
            method,
            requesttarget,
            header_fields,
            iterable_body,
            httpversion='HTTP/1.1'
            ):
        self.method = method
        self.requesttarget = requesttarget
        self.header_fields = header_fields
        self.iterable_body = iterable_body
        self.httpversion = httpversion
        return

    def format_status_line(self):
        # NOTE: only this method actions is different
        ret = client_format_status_line(
            self.method,
            self.requesttarget,
            self.httpversion
            )
        return ret


class HTTPError(HTTPResponse):
    """
    Truncated shortcut for HTTPResponse

    Implemented as driop in replacement for same named class of other http
    implimentations.
    """

    def __init__(self, code, message):
        super().__init__(
            code,
            {
                'Content-Type': 'text/plain; charset=UTF-8'
                },
            str(message)
            )
        return


def format_status(statuscode, reasonphrase=None, encoding='utf-8'):
    statuscode = int(statuscode)
    if reasonphrase is None:
        reasonphrase = http.client.responses[statuscode]

    if type(reasonphrase) == bytes:
        reasonphrase = str(reasonphrase, encoding)

    return '{} {}'.format(statuscode, reasonphrase)


def format_status_line(
        statuscode,
        reasonphrase=None,
        httpversion='HTTP/1.1',
        encoding='utf-8'
        ):
    """
    No quoting done by this function
    """
    if type(httpversion) == bytes:
        httpversion = bytes(httpversion, encoding)

    return '{} {}'.format(httpversion, format_status(statuscode, reasonphrase))


def client_format_status_line(
        method,
        requesttarget,
        httpversion='HTTP/1.1',
        encoding='utf-8'
        ):
    """
    No quoting done by this function
    """
    if type(method) == bytes:
        method = str(method, encoding)

    if type(requesttarget) == bytes:
        requesttarget = str(requesttarget, encoding)

    if type(httpversion) == bytes:
        httpversion = str(httpversion, encoding)

    return '{} {} {}'.format(method, requesttarget, httpversion)


def determine_line_terminator(text):

    if not isinstance(text, bytes):
        raise TypeError("`text' value type must be bytes")

    ret = None

    f = text.find(b'\n')

    if f != -1:
        if f == 0 or text[f - 1] != 13:
            ret = b'\n'
        else:
            ret = b'\r\n'

    return ret


def read_header_first_line(sock, limit=(1 * 1024 ** 2)):
    """
    Returns first line and it's terminator: tuple(terminator, bytes)

    if resulted (None, None), then must be socket closed before all
    first line was recived
    """

    first_line_with_terminators = b''

    line_terminator = None

    ret = None, None

    while True:
        res = wayround_org.utils.socket.nb_recv(sock, bs=1)

        if len(res) == 0:
            ret = None, None
            break

        first_line_with_terminators += res

        if len(first_line_with_terminators) > limit:
            raise InputDataLimitReached("header exited size limit")

        if first_line_with_terminators[-1] == 10:

            line_terminator = determine_line_terminator(
                first_line_with_terminators
                )

            ret = line_terminator, first_line_with_terminators
            break

    return ret


def read_header(sock, limit=(1 * 1024 ** 2)):
    """
    if resulted (None, None), then must be socket closed before complete header
    was recived
    """

    ret = None, None

    line_terminator, first_line = read_header_first_line(sock)

    if line_terminator is None or first_line is None:
        pass

    else:

        header_bytes = first_line

        while True:

            res = wayround_org.utils.socket.nb_recv(sock, bs=1)

            if len(res) == 0:
                ret = None, None
                break

            header_bytes += res
            if len(header_bytes) > limit:
                raise InputDataLimitReached("header exited size limit")

            if line_terminator == b'\n':
                if header_bytes[-2:] == b'\n\n':
                    break

            elif line_terminator == b'\r\n':
                if header_bytes[-4:] == b'\r\n\r\n':
                    break

            else:
                raise Exception("programming error")

            ret = header_bytes, line_terminator

    return ret


def split_lines(bytes_data, line_terminator):
    lines = []
    line_terminator_len = len(line_terminator)

    while True:
        fr = bytes_data.find(line_terminator)
        if fr == -1:
            break

        lines.append(bytes_data[:fr])

        bytes_data = bytes_data[fr + line_terminator_len:]

    ret = lines

    return ret


def parse_header(bytes_data, line_terminator=b'\r\n'):
    """
    HTTP has no line lenght limitations in difference to email messages.
    HTTP also does not assume line wrappings, but this function will unwrap
    messages anyway, just for any case.

    the two values is returned:
        1. dict with struct {'method' => bytes,
                             'requesttarget' => bytes,
                             'httpversion' => bytes
                             }
        2, list of 2-tuples with bytes in them
    """

    lines = split_lines(bytes_data, line_terminator)

    # print('bites_data: \n{}'.format(pprint.pformat(lines)))

    # this isn't needed anymore
    del bytes_data

    if len(lines) == 0:
        raise RequestLineDoesNotMatch("Absent at all")

    request_line = lines[0]

    # it not needed farther
    del lines[0]

    request_line_parsed = HTTP_MESSAGE_REQUEST_REGEXP.match(request_line)

    if not request_line_parsed:
        raise RequestLineDoesNotMatch("Doesn't match standard regexp")

    request_line_parsed = {
        'method': request_line_parsed.group('method'),
        'requesttarget': request_line_parsed.group('requesttarget'),
        'httpversion': request_line_parsed.group('httpversion')
        }

    lines_l = len(lines)

    header_fields = []

    i = -1
    while True:

        if i + 1 >= lines_l:
            break

        i += 1

        line_i = lines[i]

        if line_i == b'':
            break

        column_index = line_i.find(b':')
        if column_index == -1:
            raise MessageCantFindColumnInLine(
                "can't find `:' in line no: {}".format(i)
                )

        name = line_i[:column_index]
        value = [line_i[column_index + 1:]]

        ii = i
        while True:
            if ii + 1 >= lines_l:
                i = ii
                break
            if lines[ii + 1].startswith(b' '):
                value.append(lines[ii + 1])
                ii += 1
            else:
                i = ii
                break

        value = b''.join(value)

        if value[0] == 32:
            value = value[1:]

        header_fields.append((name, value,))

    return request_line_parsed, header_fields


def read_and_parse_header(
        sock,
        limit=(1 * 1024 ** 2),
        header_already_parsed=None,
        header_already_readen=None
        ):
    """

    if header_already_readen and/or header_already_parsed defined, they
    should be results of wayround_org.http.message.read_header() and
    wayround_org.http.message.parse_header() respectively.

    Note 1: if header_already_parsed is given, then:
            header_already_readen is not used

    Note 2: obviously, if header_already_readen or
            header_already_parsed is given, then:
            socket input data position should be after header part
    """

    error = False

    header_bytes, line_terminator = None, None
    request_line_parsed, header_fields = None, None

    if header_already_parsed is None:
        if header_already_readen is None:

            try:
                header_bytes, line_terminator = read_header(sock, limit)
            except:
                logging.exception(
                    "Error splitting HTTP header from the rest of the body"
                    )
                error = True

        else:
            header_bytes, line_terminator = header_already_readen
    else:
        # TODO: probably this must be not (None, None), but conditional
        #       values copy of header_already_readen
        header_bytes, line_terminator = None, None

    if not error:

        if header_bytes is not None and line_terminator is not None:

            if header_already_parsed is None:

                try:
                    request_line_parsed, header_fields = parse_header(
                        header_bytes,
                        line_terminator
                        )
                except:
                    logging.exception(
                        "Error parsing header. Maybe it's not an HTTP"
                        )
                    error = True

            else:
                request_line_parsed, header_fields = header_already_parsed
        else:
            error = True

    return (
        header_bytes,
        line_terminator,
        request_line_parsed,
        header_fields,
        error
        )
