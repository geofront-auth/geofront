import builtins
import datetime
import os
import re
from typing import Optional, Type

from paramiko.pkey import PKey
from typeguard import check_type
from werkzeug.contrib.cache import BaseCache

from geofront.keystore import KeyStore
from geofront.masterkey import MasterKeyStore
from geofront.remote import PermissionPolicy, RemoteSet
from geofront.team import Team


fields = {
    # Geofront
    'TEAM': (Team, True),
    'REMOTE_SET': (RemoteSet, True),
    'TOKEN_STORE': (BaseCache, True),
    'KEY_STORE': (KeyStore, True),
    'MASTER_KEY_STORE': (MasterKeyStore, True),
    'PERMISSION_POLICY': (PermissionPolicy, False),
    'MASTER_KEY_TYPE': (Type[PKey], False),
    'MASTER_KEY_BITS': (Optional[int], False),
    'MASTER_KEY_RENEWAL': (datetime.timedelta, False),
    'TOKEN_EXPIRE': (datetime.timedelta, False),
    'ENABLE_HSTS': (bool, False),
    # Flask
    'PREFERRED_URL_SCHEME': (str, False),
}



EXPR_RE = re.compile(
    r'^(?P<module>(?:(?:^|\.)[^\d\W]\w*)+)?:'
    r'(?P<expr>.*)$',
    re.UNICODE
)


def evaluate(expression: str, field: str):
    m = EXPR_RE.match(expression)
    if not m:
        raise EnvironmentError(
            '{}: `{}` cannot be evaluated since it is not a valid '
            'configuration expression.  A configuration expression has to be '
            '`module.path:name(and_optional_python_expression)`.'.format(
                field, expression
            )
        )
    module_path = m.group('module')
    expr = m.group('expr')
    try:
        code = compile(expr, '$' + field, 'eval')
    except SyntaxError:
        raise EnvironmentError(
            '{}: `{}` cannot be evaluated since it is not a valid '
            'configuration expression.  The latter part must be a valid Python '
            'expression, but `{}` is invalid.'.format(field, expression, expr)
        )
    ctx = dict(builtins.__dict__)
    if module_path:
        try:
            mod = __import__(module_path)
        except ImportError:
            raise EnvironmentError(
                '{}: `{}` cannot be evaluated since it is not a valid '
                'configuration expression.  The former part must be a valid '
                'Python import path, but `{}` is failed to import..'.format(
                    field, expression, module_path
                )
            )
        for n in module_path.split('.')[1:]:
            mod = getattr(mod, n)
        ctx.update(mod.__dict__)
    return eval(code, ctx, ctx)


for field, (type_, required) in fields.items():
    try:
        expr = os.environ[field]
    except KeyError:
        if required:
            raise EnvironmentError(
                'The required configuration {0} is missing.  Specify -e {0}='
                '... option to `docker run` command.'.format(field)
            )
        continue
    else:
        value = evaluate(expr, field)
        check_type(field, value, type_, None)
        globals()[field] = value
