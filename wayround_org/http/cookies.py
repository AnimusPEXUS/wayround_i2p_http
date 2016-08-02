

import copy
import http.cookies
import regex
import yaml
import base64
import datetime
import json

import wayround_org.utils.domain
import wayround_org.utils.datetime_rfc5322
import wayround_org.utils.class_applicator

import wayround_org.http.message


COOKIE_FIELD_NAMES = [
    'Set-Cookie',
    'Cookie'
    ]


def check_cookie_field_name(value, var_name):
    if value not in COOKIE_FIELD_NAMES:
        raise ValueError("invalid value of `{}'".format(var_name))
    return


def check_mode_value(value):
    if value not in ['c2s', 's2c']:
        raise ValueError("invalid mode value")
    return


def mode_to_field_name(mode):
    check_mode_value(mode)
    ret = None
    if mode == 'c2s':
        ret = 'Cookie'
    else:
        ret = 'Set-Cookie'
    return ret


def check_add_method(value):
    if value not in ['append', 'prepend']:
        raise ValueError("invalid mode value")
    return


def check_raw_value(raw_value):
    if not isinstance(raw_value, bool):
        raise TypeError("`raw_value' must be bool")
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

COOKIE_VALUE_RE = r'(?P<dquote>\"?)({cookie-octet})*(?P=dquote)'.format_map(
    {
        'cookie-octet': COOKIE_OCTET_RE
        }
    )

COOKIE_VALUE_RE_C = regex.compile(COOKIE_VALUE_RE)

COOKIE_PAIR_RE = r'({cookie-name})\=({cookie-value})'.format_map(
    {
        'cookie-name': COOKIE_NAME_RE,
        'cookie-value': COOKIE_VALUE_RE
        }
    )

COOKIE_STRING_RE = r'({cookie-pair})(\; ({cookie-pair}))*'.format_map(
    {'cookie-pair': COOKIE_PAIR_RE}
    )

EXPIRES_AV_RE = r'Expires=({sane-cookie-date})'.format_map(
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

DOMAIN_AV_RE = r'Domain=\.?({domain})'.format(
    domain=wayround_org.utils.domain.DOMAIN_RE
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


def parse_cookie_string_c2s(data):

    data = data.lstrip()

    ended = len(data) == 0
    error = False

    ret = []

    if ended:
        error = True

    if not ended and not error:

        while True:

            name = None
            value = None

            re_res = COOKIE_NAME_RE_C.match(data)

            if re_res is None:
                error = True
            else:

                name = data[re_res.start():re_res.end()]
                data = data[re_res.end():]

            if not ended and not error:
                if len(data) == 0:
                    ended = True
                    error = True

            if ended or error:
                break

            if not ended and not error:
                if data[0] == '=':
                    data = data[1:]
                else:
                    error = True

            if not ended and not error:
                if len(data) == 0:
                    ended = True
                    error = False

            if ended or error:
                break

            re_res = COOKIE_VALUE_RE_C.match(data)

            if re_res is None or (re_res.end() == re_res.start()):
                error = True
            else:
                value = data[re_res.start():re_res.end()]
                if (
                        len(value) > 1
                        and value[0].startswith('"')
                        and value[-1].endswith('"')
                        ):
                    value = value[1:-1]
                data = data[re_res.end():]

            ret.append((name, value))

            if ended or error:
                break

            if not ended and not error:
                if len(data) == 0:
                    ended = True
                    error = False

            if ended or error:
                break

            if not data.startswith('; '):
                error = True

            if ended or error:
                break

            data = data[2:]

    return ret, error


def parse_cookie_string_s2c(data):

    data = data.lstrip()

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

        re_res = COOKIE_NAME_RE_C.match(data)

        if re_res is None:
            error = True
        else:

            ret['name'] = data[re_res.start():re_res.end()]

            data = data[re_res.end():]

    if not ended and not error:
        if len(data) == 0:
            ended = True
            error = True

    if not ended and not error:
        if data[0] == '=':
            data = data[1:]
        else:
            error = True

    if not ended and not error:
        if len(data) == 0:
            ended = True
            error = False

    if not ended and not error:
        re_res = COOKIE_VALUE_RE_C.match(data)

        if re_res is None or (re_res.end() == re_res.start()):
            error = True
        else:
            ret['value'] = data[re_res.start():re_res.end()]
            if (
                    len(ret['value']) > 1
                    and ret['value'].startswith('"')
                    and ret['value'].endswith('"')
                    ):
                ret['value'] = ret['value'][1:-1]
            data = data[re_res.end():]

    if not ended and not error:
        if len(data) == 0:
            ended = True
            error = False

    if not ended and not error:
        while True:

            if data.startswith('; '):
                data = data[2:]

            else:
                ended = False
                error = True

            if error:
                break

            re_res = ATTRIBUTE_NAMES_RE_C.match(data)

            if re_res is None:
                ended = False
                error = True

            if error:
                break

            re_res_attr_name = data[re_res.start():re_res.end()]

            data = data[re_res.end():]

            if re_res_attr_name == 'Expires=':
                re_res  = wayround_org.utils.datetime_rfc5322.\
                    match_DATETIME_EXPRESSION_C(
                        data
                        )

                if re_res is None:
                    error = True
                    break

                _t = data[re_res.start():re_res.end()]
                data = data[re_res.end():]
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
                    break

                ret['max-age'] = int(data[re_res.start():re_res.end()])
                data = data[re_res.end():]

            elif re_res_attr_name == 'Domain=':
                ret['domain'] = ''
                if data.startswith('.'):
                    ret['domain'] += '.'
                    data = data[1:]
                re_res = wayround_org.utils.domain.DOMAIN_RE_C.match(data)
                if re_res is None:
                    error = True
                    break

                ret['domain'] += data[re_res.start():re_res.end()]
                data = data[re_res.end():]
                print('error 9')

            elif re_res_attr_name == 'Path=':
                re_res = PATH_VALUE_RE_C.match(data)
                if re_res is None:
                    error = True
                    break

                ret['path'] = data[re_res.start():re_res.end()]
                data = data[re_res.end():]

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


class CookieInvalidValue(Exception):
    pass


class CookieInvalidC2SString(Exception):
    pass


class CookieFields:

    def __init__(self):

        self.name = None
        self.value = None
        self.expires = None
        self.max_age = None
        self.domain = None
        self.path = None
        self.secure = None
        self.httponly = None
        return


class CookiesFields(dict):
    pass


class Cookie:

    @classmethod
    def new_by_values(
            cls,
            name,
            value='',
            expires=None,
            max_age=None,
            domain=None,
            path=None,
            secure=None,
            httponly=None
            ):

        ret = None

        cf = CookieFields()

        ret = cls(cf)

        try:
            ret.name = name
            ret.value = value
            ret.expires = expires
            ret.max_age = max_age
            ret.domain = domain
            ret.path = path
            ret.secure = secure
            ret.httponly = httponly
        except CookieInvalidValue:
            ret = None

        return ret

    @classmethod
    def new_from_tuple(cls, value):

        if not isinstance(value, tuple):
            raise TypeError("`value' must be inst of tuple")

        ret = cls.new_by_values(*value)

        return ret

    @classmethod
    def new_from_str_c2s(cls, value):
        """
        WARNING: this method assumes there is axactly one cookie name-value
                 pair in string, else exception will be raised
        """

        if not isinstance(value, str):
            raise TypeError("`value' must be inst of str")

        res, error = parse_cookie_string_c2s(value)

        ret = None
        if not error:

            if len(res) != 1:
                raise CookieInvalidC2SString(
                    "invalid value. key-value pair is not single"
                    )

            ret = cls.new_from_tuple((res[0][0], res[0][1]))

        return ret

    @classmethod
    def new_from_str_s2c(cls, value):

        if not isinstance(value, str):
            raise TypeError("`value' must be inst of str")

        value, error = parse_cookie_string_s2c(value)

        ret = None
        if not error:
            ret = cls.new_from_dict(value)

        return ret

    @classmethod
    def new_from_dict(cls, value):

        ret = cls.new_from_tuple(
            (
                value.get('name', None),
                value.get('value', None),
                value.get('expires', None),
                value.get('max-age', None),
                value.get('domain', None),
                value.get('path', None),
                value.get('secure', None),
                value.get('httponly', None)
                )
            )

        return ret

    @classmethod
    def new_from_morsel(cls, value):

        if not isinstance(value, http.cookies.Morsel):
            raise TypeError(
                "`value' must be of inst of http.cookies.Morsel"
                )

        ret = cls.new_from_tuple(
            value.name,
            value.value,
            value['expires'],
            value['max-age'],
            value['domain'],
            value['path'],
            value['secure'],
            value['httponly']
            )

        return ret

    def __init__(self, fields=None):

        if fields is None:
            fields = CookieFields()

        if isinstance(fields, CookieFields):
            self._fields = fields
        elif isinstance(fields, (Cookie, CookieSafe, CookieJSON, CookieYAML)):
            self._fields = fields.fields
        else:
            raise TypeError("invalid `fields' type: {}".format(type(fields)))
        return

    @property
    def fields(self):
        return self._fields

    def copy(self):
        # TODO: datetime has no __copy__ method.
        #        need to somehow insure in copy safety of .expires
        ret = type(self)(copy.deepcopy(self._fields))
        return ret

    @property
    def cookie(self):
        return Cookie(self._fields)

    @property
    def cookieSafe(self):
        return CookieSafe(self._fields)

    @property
    def cookieJSON(self):
        return CookieJSON(self._fields)

    @property
    def cookieYAML(self):
        return CookieYAML(self._fields)

    def render_str(self, field_name=None, mode='s2c'):
        check_mode_value(mode)

        if field_name is not None:
            check_cookie_field_name(field_name, 'field_name')

        ret = ''

        if field_name is not None:
            ret += '{}: '.format(field_name)

        if len(ret) != 0:
            ret += ' '

        ret += '{}='.format(self.name)

        ret += '{}'.format(self.value)

        if mode == 's2c':

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

    def render_tuple(self, mode='s2c'):
        ret = []

        check_mode_value(mode)

        ret.append(self.name)

        ret.append(self.value)

        if mode == 's2c':

            ret.append(self.expires)
            ret.append(self.max_age)
            ret.append(self.domain)
            ret.append(self.path)
            ret.append(self.secure)
            ret.append(self.httponly)

        if isinstance(ret, list):
            ret = tuple(ret)

        return ret

    @property
    def name(self):
        ret = self.fields.name
        return ret

    @name.setter
    def name(self, value):
        if type(value) != str:
            raise TypeError("`name' value must be of str type")
        self.fields.name = value
        return

    @property
    def value(self):
        ret = self.fields.value
        return ret

    @value.setter
    def value(self, value):
        if type(value) != str:
            raise TypeError("`value' value must be of str type")
        for i in value:
            if not COOKIE_OCTET_RE_C.match(i):
                raise CookieInvalidValue("supplied cookie value is unsafe")
        self.fields.value = value
        return

    @property
    def expires(self):
        ret = self.fields.expires
        return ret

    @expires.setter
    def expires(self, value):
        if isinstance(value, str):
            value = wayround_org.utils.datetime_rfc5322.str_to_datetime(value)
        if value is not None and not isinstance(value, datetime.datetime):
            raise TypeError("`expires' must be None or datetime.datetime")
        if value is not None:
            wayround_org.utils.datetime_rfc5322.check_datetime_has_tzinfo(
                value
                )
        self.fields.expires = value
        return

    @property
    def max_age(self):
        ret = self.fields.max_age
        return ret

    @max_age.setter
    def max_age(self, value):
        if value is not None and not isinstance(value, datetime.datetime):
            raise TypeError("`max_age' must be None or DateTime")
        self.fields.max_age = value
        return

    @property
    def domain(self):
        ret = self.fields.domain
        return ret

    @domain.setter
    def domain(self, value):
        if value is not None and type(value) != str:
            raise TypeError("`domain' value must be None or of str type")
        self.fields.domain = value
        return

    @property
    def path(self):
        ret = self.fields.path
        return ret

    @path.setter
    def path(self, value):
        if value is not None and type(value) != str:
            raise TypeError("`path' value must be None or of str type")
        self.fields.path = value
        return

    @property
    def secure(self):
        ret = self.fields.secure
        return ret

    @secure.setter
    def secure(self, value):
        if value is not None and type(value) != bool:
            raise TypeError("`secure' value must be None or of bool type")
        self.fields.secure = value
        return

    @property
    def httponly(self):
        ret = self.fields.httponly
        return ret

    @httponly.setter
    def httponly(self, value):
        if value is not None and type(value) != bool:
            raise TypeError("`httponly' value must be None or of bool type")
        self.fields.httponly = value
        return


class Cookies:

    def cookie_class(self):
        return Cookie

    @classmethod
    def new_from_str_s2c(cls, value):
        ret = cls()
        if not ret.add_from_str_s2c(value):
            ret = None
        return ret

    @classmethod
    def new_from_str_c2s(cls, value):
        ret = cls()
        if not ret.add_from_str_c2s(value):
            ret = None
        return ret

    @classmethod
    def new_from_morsel(cls, value):
        ret = cls()
        if not ret.add_from_morsel(value):
            ret = None
        return ret

    @classmethod
    def new_from_dict(cls, value):
        ret = cls()
        if not ret.add_from_dict(value):
            ret = None
        return ret

    @classmethod
    def new_from_reqres(cls, value, mode='c2s'):
        ret = cls()
        if not ret.add_from_reqres(value, mode=mode):
            ret = None
        return ret

    @classmethod
    def new_from_wsgi_request(cls, value):
        ret = cls()
        if not ret.add_from_wsgi_request(value):
            ret = None
        return ret

    @classmethod
    def new_from_cookies(cls, value):
        ret = cls()
        if not ret.add_from_cookies(value):
            ret = None
        return ret

    def __init__(self, fields=None):
        if fields is None:
            fields = CookiesFields()

        if not isinstance(fields, CookiesFields):
            raise TypeError(
                "`fields' must be None or CookiesFields type"
                )
        self._cookies_dict = fields
        return

    def __getitem__(self, key):
        ret = self.cookie_class()(self._cookies_dict[key])
        return ret

    def __setitem__(self, key, value):
        if key not in self._cookies_dict:
            c = self.cookie_class().new_by_values(key, value)
            self.add(c)
        else:
            self._cookies_dict[key].value = value
        return

    def __delitem__(self, value):
        del self._cookies_dict[value]
        return

    def __len__(self):
        return len(self._cookies_dict)

    def __contains__(self, key):
        return key in self._cookies_dict

    def __iter__(self):
        return iter(self._cookies_dict)

    # @property
    # def fields(self):
    #    return self._cookies_dict

    @property
    def cookies(self):
        return Cookies(self._cookies_dict)

    @property
    def cookiesSafe(self):
        return CookiesSafe(self._cookies_dict)

    @property
    def cookiesJSON(self):
        return CookiesJSON(self._cookies_dict)

    @property
    def cookiesYAML(self):
        return CookiesYAML(self._cookies_dict)

    def keys(self):
        return self._cookies_dict.keys()

    def copy(self):
        ret = type(self).new_from_cookies(self)
        return ret

    def add(self, value):
        if type(value) != self.cookie_class():
            raise TypeError(
                "`value' must be of type {}".format(self.cookie_class())
                )
        self._cookies_dict[value.name] = value
        return

    def remove(self, name):
        """
        This method is not for removing Cookie from Cookies
        (for this use ``del cookies[name]``). This method is for removing
        cookie from cookie client.
        """
        self.add(self.cookie_class(name, ''))
        return

    def add_from_tuple(self, value):
        res = self.cookie_class().new_from_tuple(value)
        ret = False
        if res is not None:
            self.add(res)
            ret = True
        return ret

    def add_from_str_s2c(self, value):
        res = self.cookie_class().new_from_str_s2c(value)
        ret = False
        if res is not None:
            self.add(res)
            ret = True
        return ret

    def add_from_str_c2s(self, value):
        res, error = parse_cookie_string_c2s(value)
        ret = False
        if not error:

            for i in res:
                res2 = self.cookie_class().new_from_tuple(i)
                if res2 is None:
                    break
                self.add(res2)

            ret = True

        return ret

    def add_from_morsel(self, python_morsel):
        res = self.cookie_class().new_from_morsel(python_morsel)
        ret = False
        if res is not None:
            self.add(res)
            ret = True
        return ret

    def add_from_dict(self, d):
        res = self.cookie_class().new_from_dict(d)
        ret = False
        if res is not None:
            self.add(res)
            ret = True
        return ret

    def add_from_field_tuple_list(
            self,
            obj,
            mode='c2s',
            src_field_name=None
            ):

        if src_field_name is None:
            src_field_name = mode_to_field_name(mode)

        check_mode_value(mode)
        check_cookie_field_name(src_field_name, 'src_field_name')

        ret = False
        error = False

        for i in range(len(obj) - 1, -1, -1):

            header_field = obj[i]
            header_field_name = \
                wayround_org.http.message.normalize_header_field_name(
                    header_field[0]
                    )

            if header_field_name == src_field_name:
                if mode == 'c2s':
                    if not self.add_from_str_c2s(header_field[1]):
                        error = True
                        break
                else:
                    if not self.add_from_str_s2c(header_field[1]):
                        error = True
                        break

        else:
            raise TypeError("invalid `obj' type")

        if error:
            ret = False

        return ret

    def add_from_http_reqres(self, obj, mode='c2s'):

        check_mode_value(mode)

        src_field_name = mode_to_field_name(mode)

        ret = False
        error = False

        type_obj = type(obj)

        if type_obj in [
                wayround_org.http.message.HTTPRequest,
                wayround_org.http.message.HTTPResponse
                ]:
            ret = self.add_from_field_tuple_list(
                obj,
                mode=mode,
                src_field_name=src_field_name
                )

        else:
            raise TypeError("invalid `obj' type")

        if error:
            ret = False

        return ret

    def add_from_wsgi_request(self, wsgi_request):

        ret = False

        if not 'HTTP_COOKIE' in wsgi_request:
            ret = True

        else:

            ret = self.add_from_str_c2s(wsgi_request['HTTP_COOKIE'])

        return ret

    def add_from_cookies(self, value):
        """
        Complete cookie copies are created, not just links
        """
        ret = False

        type_self = type(self)

        if type(value) != type_self:
            raise TypeError("`value' must be of type {}".format(type_self))

        for i in value:
            self.add(value[i].copy())

        return ret

    def render_tuple_list(self, mode='s2c'):
        check_mode_value(mode)

        ret = []

        for i in sorted(list(self.keys())):
            ret.append(
                i.render_tuple(mode='s2c')
                )

        return ret

    def render_field_tuple_list(self, mode='s2c'):
        check_mode_value(mode)

        field_name = mode_to_field_name(mode)

        ret = []

        for i in sorted(list(self.keys())):
            ret.append(
                (
                    field_name,
                    self[i].render_str(mode=mode)
                    )
                )

        return ret

    def render_s2c_field_tuple_list(self):
        ret = self.render_field_tuple_list(mode='s2c')
        return ret

    def render_c2s_field_tuple_list(self):
        ret = self.render_field_tuple_list(mode='c2s')
        return ret

    def add_to_tuple_list(
            self,
            obj,
            mode='s2c',
            field_name=None,
            method='append'
            ):

        check_mode_value(mode)
        check_add_method(method)

        if not isinstance(obj, list):
            raise TypeError("`obj' must be list")

        if field_name is not None:
            check_cookie_field_name(field_name)

        if field_name is not None:
            tl = self.render_field_tuple_list(
                mode=mode,
                field_name=field_name
                )
        else:
            tl = self.render_tuple_list(mode=mode)

        for i in tl:
            if mode == 'append':
                obj.append(i)
            elif mode == 'prepend':
                obj.insert(0, i)
            else:
                raise Exception("programming error")

        return

    def append_to_s2c_tuple_list(self, obj):
        ret = self.add_to_tuple_list(
            obj,
            method='append',
            mode='s2c'
            )
        return ret

    def append_to_c2s_tuple_list(self, obj):
        ret = self.add_to_tuple_list(
            obj,
            method='append',
            mode='c2s'
            )
        return ret

    def prepend_to_s2c_tuple_list(self, obj):
        ret = self.add_to_tuple_list(
            obj,
            method='prepend',
            mode='s2c'
            )
        return ret

    def prepend_to_c2s_tuple_list(self, obj):
        ret = self.add_to_tuple_list(
            obj,
            method='prepend',
            mode='c2s'
            )
        return ret

    def append_to_s2c_field_tuple_list(self, obj):
        mode = 's2c'
        ret = self.add_to_tuple_list(
            obj,
            mode=mode,
            field_name=mode_to_field_name(),
            method='append'
            )
        return ret

    def append_to_c2s_field_tuple_list(self, obj):
        mode = 'c2s'
        ret = self.add_to_tuple_list(
            obj,
            mode=mode,
            field_name=mode_to_field_name(),
            method='append'
            )
        return ret

    def prepend_to_s2c_field_tuple_list(self, obj):
        mode = 's2c'
        ret = self.add_to_tuple_list(
            obj,
            mode=mode,
            field_name=mode_to_field_name(),
            method='prepend'
            )
        return ret

    def prepend_to_c2s_field_tuple_list(self, obj):
        mode = 'c2s'
        ret = self.add_to_tuple_list(
            obj,
            mode=mode,
            field_name=mode_to_field_name(),
            method='prepend'
            )
        return ret

    def append_to_http_response(self, obj):

        if not isinstance(obj, wayround_org.http.message.HTTPResponse):
            raise TypeError("Invalid type of `obj'")

        self.append_to_s2c_field_tuple_list(obj.header_fields)

        return


class CookieSafe(Cookie):

    @property
    def value(self):
        # NOTE: super objects does not proxify properties
        # value = super().value
        value = Cookie.value.fget(self)

        value = bytes(value, 'utf-8')
        value = base64.b64decode(value)
        value = str(value, 'utf-8')

        return value

    @value.setter
    def value(self, value):
        if type(value) != str:
            raise TypeError("`value' value must be of str type")

        value = bytes(value, 'utf-8')
        value = base64.b64encode(value)
        value = str(value, 'utf-8')

        # NOTE: super objects does not proxify properties
        # super().value = value
        Cookie.value.fset(self, value)
        return


class CookieJSON(CookieSafe):

    @property
    def value(self):
        # NOTE: super objects does not proxify properties
        # value = super().value
        value = CookieSafe.value.fget(self)

        value = json.loads(value)
        return value

    @value.setter
    def value(self, value):
        value = json.dumps(value)

        # NOTE: super objects does not proxify properties
        # super().value = value
        CookieSafe.value.fset(self, value)
        return


class CookieYAML(CookieSafe):

    @property
    def value(self):
        # NOTE: super objects does not proxify properties
        # value = super().value
        value = CookieSafe.value.fget(self)

        value = yaml.load(value)
        return value

    @value.setter
    def value(self, value):
        value = yaml.dump(value)

        # NOTE: super objects does not proxify properties
        # super().value = value
        CookieSafe.value.fset(self, value)
        return


class CookiesSafe(Cookies):

    def cookie_class(self):
        return CookieSafe


class CookiesJSON(CookiesSafe):

    def cookie_class(self):
        return CookieJSON


class CookiesYAML(CookiesSafe):

    def cookie_class(self):
        return CookieYAML


def parser_test():

    for i in [
            'lang=; Expires=Sun, 06 Nov 1994 08:49:37 GMT',
            ' lang=; Expires=Sun, 06 Nov 1994 08:49:37 GMT',
            'SID=31d4d96e407aad42',
            'SID=31d4d96e407aad42; Path=/; Domain=example.com',
            'spacy="wow spaces in value"; Secure'
            ]:
        print('{}{}'.format('    ', i))
        res, error = parse_cookie_string_s2c(i)
        print('{}error: {}'.format(' ' * 4 * 2, error))

        for j in [
                'name', 'value', 'expires', 'max-age',
                'domain', 'path', 'secure', 'httponly'
                ]:
            print('{}{:10}:{:>20}'.format(' ' * 4 * 3, j, str(res[j])))

        if not error:
            print("rendered: {}".format(Cookie.new_from_dict(res).render()))
        print('-' * 79)

    return
