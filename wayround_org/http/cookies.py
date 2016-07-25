

import http.cookies
import regex

import wayround_org.http.message
import wayround_org.utils.domain
import wayround_org.utils.datetime_rfc5322


COOKIE_FIELD_NAMES = [
    'Set-Cookie',
    'Cookie'
    ]


def check_cookie_field_name(value, var_name):
    if value not in COOKIE_FIELD_NAMES:
        raise ValueError("invalid value of `{}'".format(var_name))
    return


CTL_RE = r'([\x00-\x1f]|\x7f)'

SEPARATORS_RE = (
    r'('
    r'\('
    r'|\)'
    r'|\<'
    r'|\>'
    r'|\@'
    r'|\,'
    r'|\;'
    r'|\:'
    r'|\\'
    r'|\"'
    r'|\/'
    r'|\['
    r'|\]'
    r'|\?'
    r'|\='
    r'|\{'
    r'|\}'
    r'|\x20'
    r'|\x09'
    r')'
    )

TOKEN_RE = r'(.*)(?<!.*({CTL_RE}|{SEPARATORS_RE}).*)'.format(
    CTL_RE=CTL_RE,
    SEPARATORS_RE=SEPARATORS_RE
    )

COOKIE_NAME_RE = TOKEN_RE
COOKIE_NAME_RE_C = regex.compile(COOKIE_NAME_RE)

COOKIE_OCTET_RE = r'(\x21|[\x23-\x2B]|[\x2D-\x3A]|[\x3C-\x5B]|[\x5D-\x7E])'
COOKIE_OCTET_RE_C = regex.compile(COOKIE_OCTET_RE)

'''
COOKIE_VALUE_RE = r'((\"({cookie-octet})*\")|(({cookie-octet})*))'.format_map(
    {
        'cookie-octet': COOKIE_OCTET_RE
        }
    )
'''

COOKIE_VALUE_RE = r'(?P<dquote>\"?)({cookie-octet})*(?P=dquote)'.format_map(
    {
        'cookie-octet': COOKIE_OCTET_RE
        }
    )

COOKIE_VALUE_RE_C = regex.compile(COOKIE_VALUE_RE)

'''
COOKIE_VALUE_RE_T = "^{COOKIE_VALUE_RE}$".format(
    COOKIE_VALUE_RE=COOKIE_VALUE_RE
    )

COOKIE_VALUE_RE_T_C = regex.compile(COOKIE_VALUE_RE_T)
'''

COOKIE_PAIR_RE = r'{cookie-name}\={cookie-value}'.format_map(
    {
        'cookie-name': COOKIE_NAME_RE,
        'cookie-value': COOKIE_VALUE_RE
        }
    )

EXPIRES_AV_RE = r'Expires\=({sane-cookie-date})'.format_map(
    {
        'sane-cookie-date': wayround_org.utils.datetime_rfc5322.
        DATETIME_EXPRESSION
        }
    )

MAX_AGE_VALUE_RE = r'[1-9]\d*'
MAX_AGE_VALUE_RE_C = regex.compile(MAX_AGE_VALUE_RE)

MAX_AGE_AV_RE = r'Max-Age=({MAX_AGE_VALUE_RE})'.format(
    MAX_AGE_VALUE_RE=MAX_AGE_VALUE_RE
    )

DOMAIN_AV_RE = r'Domain=({DOMAIN_RE})'.format(
    DOMAIN_RE=wayround_org.utils.domain.DOMAIN_RE
    )

PATH_VALUE_RE = r'(.*)(?<!.*(({CTL_RE}|\;).*))'.format(CTL_RE=CTL_RE)
PATH_VALUE_RE_C = regex.compile(PATH_VALUE_RE)

PATH_AV_RE = r'Path=({PATH_VALUE_RE})'.format(PATH_VALUE_RE=PATH_VALUE_RE)

SECURE_AV_RE = r'Secure'

HTTPONLY_AV_RE = r'HttpOnly'

EXTENSION_AV_RE = PATH_VALUE_RE

COOKIE_AV_RE = (
    r'('
    r'{expires-av}'
    r'|{max-age-av}'
    r'|{domain-av}'
    r'|{path-av}'
    r'|{secure-av}'
    r'|{httponly-av}'
    r'|{extension-av}'
    r')'
    ).format_map(
        {
            'expires-av': EXPIRES_AV_RE,
            'max-age-av': MAX_AGE_AV_RE,
            'domain-av': DOMAIN_AV_RE,
            'path-av': PATH_AV_RE,
            'secure-av': SECURE_AV_RE,
            'httponly-av': HTTPONLY_AV_RE,
            'extension-av': EXTENSION_AV_RE,
            }
        )

SP_RE = r'\x20'

SET_COOKIE_STRING_RE = r'{cookie-pair}(;{SP}{cookie-av})*'.format_map(
    {
        'cookie-pair': COOKIE_PAIR_RE,
        'SP': SP_RE,
        'cookie-av': COOKIE_AV_RE
        }
    )

ATTRIBUTE_NAMES_RE_C = regex.compile(
    r'(Expires=|Max-Age=|Domain=|Path=|Secure|HttpOnly)'
    )


def parse_cookie_string(data):

    ended = len(data) == 0
    error = False

    ret = {
        'name': None,
        'value': None,
        'expires': None,
        'max-age': None,
        'domain': None,
        'path': None,
        'secure': None,
        'httponly': None
        }

    if not ended and not error:

        data = data.lstrip()
        print('data 1: {}'.format(data))
        re_res = COOKIE_NAME_RE_C.match(data)

        if re_res is None:
            print('error 1')
            error = True
        else:

            print(
                're_res name: start {}, end {}'.format(
                    re_res.start(),
                    re_res.end()))

            ret['name'] = data[re_res.start():re_res.end()]

            data = data[re_res.end():]
            print('data 2: {}'.format(data))

    if not ended and not error:
        if len(data) == 0:
            print('error 2')
            ended = True
            error = True

    if not ended and not error:
        if data[0] == '=':
            data = data[1:]
            print('data 3: {}'.format(data))
        else:
            print('error 2.5')
            error = True

    if not ended and not error:
        if len(data) == 0:
            ended = True
            error = False

    if not ended and not error:
        re_res = COOKIE_VALUE_RE_C.match(data)
        print('re_res value: {}'.format(re_res))

        if re_res is None or (re_res.end() == re_res.start()):
            print('error 3.5')
            error = True
        else:
            ret['value'] = data[re_res.start():re_res.end()]
            if (
                    len(ret['value']) > 1
                    and ret['value'][0] == '"'
                    and ret['value'][-1] == '"'
                    ):
                ret['value'] = ret['value'][1:-1]
            data = data[re_res.end():]
            print('data 4: {}'.format(data))

    if not ended and not error:
        if len(data) == 0:
            ended = True
            error = False

    if not ended and not error:
        while True:

            if data.startswith('; '):
                data = data[2:]
                print('data 5: {}'.format(data))

            else:
                ended = False
                print('error 5')
                error = True

            if error:
                break

            re_res = ATTRIBUTE_NAMES_RE_C.match(data)

            if re_res is None:
                ended = False
                print('error 6')
                error = True

            if error:
                break

            re_res_attr_name = data[re_res.start():re_res.end()]

            data = data[re_res.end():]
            print('data 6: {}'.format(data))

            print('re_res_attr_name: {}'.format(re_res_attr_name))

            if re_res_attr_name == 'Expires=':
                re_res  = wayround_org.utils.datetime_rfc5322.\
                    match_DATETIME_EXPRESSION_C(
                        data
                        )

                if re_res is None:
                    error = True
                    print('error 7')
                    break

                _t = data[re_res.start():re_res.end()]
                data = data[re_res.end():]
                print('error 7')
                ret['expires'] =  wayround_org.utils.datetime_rfc5322.\
                    str_to_datetime(
                        None,
                        already_parsed=re_res
                        )
                del _t

            elif re_res_attr_name == 'Max-Age=':

                re_res = MAX_AGE_VALUE_RE_C.match(data)
                if re_res is None:
                    error = True
                    print('error 8')
                    break

                ret['max-age'] = int(data[re_res.start():re_res.end()])
                data = data[re_res.end():]
                print('error 8')

            elif re_res_attr_name == 'Domain=':
                re_res = wayround_org.utils.domain.DOMAIN_RE_C.match(data)
                if re_res is None:
                    error = True
                    print('error 9')
                    break

                ret['domain'] = data[re_res.start():re_res.end()]
                data = data[re_res.end():]
                print('error 9')

            elif re_res_attr_name == 'Path=':
                re_res = PATH_VALUE_RE_C.match(data)
                if re_res is None:
                    error = True
                    print('error 10')
                    break

                ret['path'] = data[re_res.start():re_res.end()]
                data = data[re_res.end():]
                print('error 10')

            elif re_res_attr_name == 'Secure':
                ret['secure'] = True

            elif re_res_attr_name == 'HttpOnly':
                ret['httponly'] = True

            else:
                raise Exception("programming error")

            if len(data) == 0:
                ended = True
                error = False
                break

    return ret, error


class Cookie:

    """
    This is https://tools.ietf.org/html/rfc2109.html implimentation
    as http.cookies.Morsel is fuckin shit by state on
    Thu Jul 21 10:31:19 MSK 2016
    """

    @classmethod
    def new_from_text(cls, text):
        if not isinstance(text, str):
            raise TypeError("`text' must be of inst of str")
        res, error = parse_cookie_string(text)
        ret = None
        if not error:
            ret = cls(
                name=res['name'],
                value=res['value'],
                expires=res['expires'],
                max_age=res['max-age'],
                domain=res['domain'],
                path=res['path'],
                secure=res['secure'],
                httponly=res['httponly']
                )

        return ret

    @classmethod
    def new_from_dict(cls, d):

        ret = cls(
            name=d['name'],
            value=d['value'],
            expires=d['expires'],
            max_age=d['max-age'],
            domain=d['domain'],
            path=d['path'],
            secure=d['secure'],
            httponly=d['httponly']
            )

        return ret

    @classmethod
    def new_from_morsel(cls, python_morsel):

        if not isinstance(python_morsel, http.cookies.Morsel):
            raise TypeError(
                "`python_morsel' must be of inst of http.cookies.Morsel"
                )

        ret = cls(
            name=python_morsel.name,
            value=python_morsel.value,
            expires=python_morsel['expires'],
            max_age=python_morsel['max-age'],
            domain=python_morsel['domain'],
            path=python_morsel['path'],
            secure=python_morsel['secure'],
            httponly=python_morsel['httponly']
            )

        return ret

    def __init__(
            self,
            name,
            value='',
            expires=None,
            max_age=None,
            domain=None,
            path=None,
            secure=None,
            httponly=None
            ):

        self._name = None
        self._value = ''
        self._expires = None
        self._max_age = None
        self._domain = None
        self._path = None
        self._secure = None
        self._httponly = None

        self.name = name
        self.value = value
        self.expires = expires
        self.max_age = max_age
        self.domain = domain
        self.path = path
        self.secure = secure
        self.httponly = httponly
        return

    def render(self, field_name=None):
        ret = ''

        if field_name is not None:
            check_cookie_field_name(field_name)

            ret += '{}: '.format(field_name)

        if len(ret) != 0:
            ret += ' '

        ret += '{}={}'.format(self.key, self.value)

        if self.expires is not None:
            ret += '; Expires={}'.format(
                wayround_org.utils.datetime_rfc5322.datetime_to_str(
                    self.expires
                    )
                )

        if self.max_age is not None:
            ret += '; Max-Age={}'.format(self.max_age)

        if self.domain is not None:
            ret += '; Domain={}'.format(self.domain)

        if self.path is not None:
            ret += '; Path={}'.format(self.path)

        if self.secure is not None and self.secure == True:
            ret += '; Secure'

        if self.httponly is not None and self.httponly == True:
            ret += '; HttpOnly'

        return ret

    @property
    def name(self):
        ret = self._name
        return ret

    @name.setter
    def name(self, value):
        if type(value) != str:
            raise TypeError("`name' value must be of str type")
        self._name = value
        return

    @property
    def value(self):
        ret = self._value
        return ret

    @value.setter
    def value(self, value):
        if type(value) != str:
            raise TypeError("`value' value must be of str type")
        for i in value:
            if not COOKIE_OCTET_RE_C.match(i):
                raise ValueError("supplied cookie value is unsafe")
        self._value = value
        return

    @property
    def value(self):
        ret = self._value
        return ret

    @value.setter
    def value(self, value):
        if type(value) != str:
            raise TypeError("`value' value must be of str type")
        self._value = value
        return

    @property
    def expires(self):
        ret = self._expires
        return ret

    @expires.setter
    def expores(self, value):
        if value is not None and not isinstance(value, datetime.DateTime):
            raise TypeError("`expires' must be None or DateTime")
        self._expires = value
        return

    @property
    def max_age(self):
        ret = self._max_age
        return ret

    @max_age.setter
    def max_age(self, value):
        if value is not None and not isinstance(value, datetime.DateTime):
            raise TypeError("`max_age' must be None or DateTime")
        self._max_age = value
        return

    @property
    def path(self):
        ret = self._path
        return ret

    @path.setter
    def path(self, value):
        if value is not None and type(value) != str:
            raise TypeError("`path' value must be None or of str type")
        self._path = value
        return

    @property
    def secure(self):
        ret = self._secure
        return ret

    @secure.setter
    def secure(self, value):
        if value is not None and type(value) != bool:
            raise TypeError("`secure' value must be None or of bool type")
        self._secure = value
        return

    @property
    def httponly(self):
        ret = self._httponly
        return ret

    @httponly.setter
    def httponly(self, value):
        if value is not None and type(value) != bool:
            raise TypeError("`httponly' value must be None or of bool type")
        self._httponly = value
        return


class Cookies:

    def __init__(self):
        self._cookies_dict = {}
        return

    def __getitem__(self, name):
        ret = self._cookies_dict['name']
        return ret

    def __len__(self):
        return len(self._cookies_dict)

    def __contains__(self, key):
        return key in self._cookies_dict

    def add(self, cookie):
        if not isinstance(cookie, Cookie):
            raise TypeError("`cookie' must be inst of Cookie")
        self._cookies_dict[cookie.name] = cookie
        return

    def add_from_str(self, txt):
        res = Cookie.new_from_text(text)
        ret = 1
        if res is not None:
            self.add(res)
            ret = 0
        return ret

    def add_from_morsel(self, python_morsel):
        res = Cookie.new_from_morsel(python_morsel)
        ret = 1
        if res is not None:
            self.add(res)
            ret = 0
        return ret

    def add_from_dict(self, d):
        res = Cookie.new_from_dict(d)
        ret = 1
        if res is not None:
            self.add(res)
            ret = 0
        return ret

    def add_from_reqres(self, obj, src_field_name='Set-Cookie'):

        check_cookie_field_name(src_field_name, 'src_field_name')

        type_obj = type(obj)

        if type_obj in [
                wayround_org.http.message.HTTPRequest,
                wayround_org.http.message.HTTPResponse
                ]:
            for i in range(len(obj.header_fields) - 1, -1, -1):

                header_field = obj.header_fields[i]
                header_field_name = \
                    wayround_org.http.message.normalize_header_field_name(
                        header_field[0]
                        )

                if header_field_name == src_field_name:
                    self.add_from_text(header_field[1])

        else:
            raise TypeError("invalid `obj' type")

        return 
        
    def put_cookies_into_reqres(self, obj, tgt_header_name='Cookie'):

        check_cookie_field_name(tgt_header_name, 'tgt_header_name')

        if type(obj) not in [
                wayround_org.http.message.HTTPRequest,
                wayround_org.http.message.HTTPResponse
                ]:
            raise TypeError("Invalid type of `obj'")

        for i in reversed(sorted(list(self._cookies_dict.keys()))):
            obj.header_fields.insert(
                0,
                (
                    tgt_header_name,
                    self._cookies_dict[i].render()
                    )
                )

        return


def parser_test():

    for i in [
            'lang=; Expires=Sun, 06 Nov 1994 08:49:37 GMT',
            ' lang=; Expires=Sun, 06 Nov 1994 08:49:37 GMT',
            'SID=31d4d96e407aad42',
            'SID=31d4d96e407aad42; Path=/; Domain=example.com',
            'spacy="wow spaces in value"; Secure'
            ]:
        print('{}{}'.format('    ', i))
        res, error = parse_cookie_string(i)
        print('{}error: {}'.format(' ' * 4 * 2, error))
        if True:  # not error:
            for j in [
                    'name', 'value', 'expires', 'max-age',
                    'domain', 'path', 'secure', 'httponly'
                    ]:
                print('{}{:10}:{:>20}'.format(' ' * 4 * 3, j, str(res[j])))
        if not error:
            print("rendered: {}".format(Cookie.new_from_dict(res).render()))
        print('-' * 79)

    return
