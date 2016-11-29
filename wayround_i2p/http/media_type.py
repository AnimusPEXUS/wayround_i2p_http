
"""
rfc7231.txt

this module intendet as parser and formatter of Content-Type HTTP
field. in RFC's ABNF this is called 'media-type'
"""

SP_RE = r'\x20'

HTAB_RE = r'\x09'


OWS_RE = r'(({SP})|({HTAB}))*'.format_map(
    {
        'HTAB': HTAB_RE,
        'SP': SP_RE
        }
    )

TCHAR_RE = 

TOKEN_RE = '({tchar})+'.format_map({'tchar': TCHAR_RE})

PARAMETER_RE = r'{(token})\=(({token})|({quoted-string}))'.format_map(
    {
        'token': TOKEN_RE,
        'quoted-string': QUOTED_STRING_RE
        }
    )

MEDIA_TYPE_RE = (
    r'({type})\/({subtype})(({OWS})\;({OWS})({parameter}))*'
    ).format_map(
        {
            'type': TYPE_RE,
            'subtype': SUBTYPE_RE,
            'OWS': OWS_RE,
            'parameter': PARAMETER_RE
            }
        )


class MediaType:

    def __init__(self):
        return
