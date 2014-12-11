
import pprint
import re
import urllib.parse
import http.client

import org.wayround.mail.message

HTTP_MESSAGE_REQUEST_REGEXP = re.compile(
    rb'(?P<method>\w+) (?P<requesttarget>.+?) (?P<httpversion>)'
    )

HTTP_STATUS_LINE_TEMPLATE = '{httpversion} {statuscode} {reasonphrase}'


class InputDataLimitReached(Exception):
    pass


class RequestLineDoesNotMatch(Exception):
    pass


class HTTPRequest:

    """
    I'm preferring to use classes over dicts, cause classes are easier to debug

    so this class is only for forming centralised HTTP requests

    it's content isn't mean to be changed by users. read input data from it's
    instances and throw them away.

    this class instances only formed by http server implimentations, like
    org.wayround.server.http_server
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

    def _format_response_header(self, encoding):
        """
        retruns bytes
        """

        ret = b''

        ret += bytes(
            format_status_line(
                self.code,
                self.reasonphrase,
                self.httpversion
                ),
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
            socket,
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

        header_bytes = self._format_response_header(encoding)

        header_sent = False

        for i in self.iterable_body:

            if not header_sent:
                header_sent = True
                self._send_header(socket, header_bytes, bs, stop_event)

            if stop_event is not None and stop_event.is_set():
                break

            if not isinstance(i, bytes):
                if not isinstance(i, str):
                    i = str(i)
                i = bytes(i, encoding=encoding)

            self._send_iteration(socket, i, bs, stop_event)

        if not header_sent:
            self._send_header(socket, header_bytes, bs, stop_event)

        return

    def _send_header(self, socket, header_bytes, bs, stop_event=None):
        self._send_iteration(socket, header_bytes, bs, stop_event)
        self._send_iteration(socket, b'\r\n', bs, stop_event)
        return

    def _send_iteration(self, socket, data, bs, stop_event=None):
        if not isinstance(data, bytes):
            raise TypeError("`data' must be bytes")

        while True:

            if stop_event is not None and stop_event.is_set():
                break

            if len(data) == 0:
                break

            # TODO: use org.wayround.utils.stream module here
            to_send = data[:bs]
            data = data[bs:]

            while len(to_send) != 0:
                sent_number = socket.send(to_send)
                if sent_number == len(to_send):
                    break
                else:
                    to_send = to_send[sent_number:]

        return


def format_status_line(statuscode, reasonphrase=None, httpversion='HTTP/1.1'):
    """
    No quoting done by this function
    """
    statuscode = int(statuscode)
    if reasonphrase is None:
        reasonphrase = http.client.responses[statuscode]
    ret = HTTP_STATUS_LINE_TEMPLATE.format(
        httpversion=httpversion,
        statuscode=statuscode,
        reasonphrase=reasonphrase)
    return ret


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


def determine_line_terminator_in_stream(sock):
    """
    Returns first line and it's terminator: tuple(terminator, bytes)
    """

    first_line_with_terminators = b''

    line_terminator = None

    while True:
        res = sock.recv(1)

        first_line_with_terminators += res

        if res == b'\n':
            line_terminator = determine_line_terminator(
                first_line_with_terminators
                )
            break

    return line_terminator, first_line_with_terminators


def read_header(sock, limit=(1 * 1024 ** 2)):

    line_terminator, first_line = determine_line_terminator_in_stream(sock)

    header_bytes = first_line

    while True:
        res = sock.recv(1)
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

    return header_bytes, line_terminator


def parse_header(bites_data, line_terminator=b'\r\n'):
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

    lines = bites_data.split(line_terminator)

    # this isn't needed anymore
    del bites_data

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

        # print('value == {}'.format(value))
        # print('value[0] == {}'.format(value[0]))

        if value[0] == 32:
            value = value[1:]

        # print('value == {}'.format(value))

        header_fields.append((name, value,))

    return request_line_parsed, header_fields
