# -*- coding: utf-8 -*-
'''
Provide authentication using simple LDAP binds

:depends:   - ldap Python module
'''

# Import python libs
from __future__ import absolute_import
import logging

# Import salt libs
from salt.exceptions import CommandExecutionError, SaltInvocationError

log = logging.getLogger(__name__)

# Import third party libs
from jinja2 import Environment
try:
    import ldap
    import ldap.modlist
    import ldapurl
    HAS_LDAP = True
except ImportError:
    HAS_LDAP = False

# Defaults, override in master config
__defopts__ = {'auth.ldap.port': '389',
               'auth.ldap.tls': False,
               'auth.ldap.uri': 'ldap://localhost:389',
               'auth.ldap.no_verify': False,
               'auth.ldap.anonymous': False,
               'auth.ldap.scope': 2,
               'auth.ldap.filter': '(objectclass=*)',
               }


def _config(key, mandatory=True, variables={}):
    '''
    Return a value for 'key' from master config file options or defaults.
    mandatory=True/False determines, whether config value not existing is critical or not
    variables provides input for possible interpolation of templated config values
    '''
    try:
        value = __opts__['auth.ldap.{0}'.format(key)]
    except KeyError:
        try:
            value = __defopts__['auth.ldap.{0}'.format(key)]
        except KeyError:
            if mandatory:
                msg = 'missing auth.ldap.{0} in master config'.format(key)
                raise SaltInvocationError(msg)
            return False
    # render possible template placeholders in value
    if not isinstance(value, int):
        value = _render_template(value, variables)
    return value


def _render_template(param, variables):
    '''
    Render config template, substituting username where found.
    '''
    env = Environment()
    template = env.from_string(param)
    return template.render(variables)


class _LDAPConnection(object):
    '''
    Setup an LDAP connection.
    '''

    def __init__(self, **kwargs):
        '''
        Initialize an LDAP object (validate server data and if provided, credentials).
        '''
        self.binddn = kwargs['binddn']
        self.bindpw = kwargs['bindpw']
        schema = 'ldap'
        # only expect a server in config, when not using an URI, thus mandatory=False
        server = _config('server', mandatory=False)
        # always expect port/tls/no_verify in config, as at least the default value should be returned
        port = _config('port')
        tls = _config('tls')
        no_verify = _config('no_verify')
        anonymous = _config('anonymous')

        if not HAS_LDAP:
            raise CommandExecutionError('Failed to connect to LDAP, module '
                                        'not loaded')

        if server:
            if tls:
                schema = 'ldaps'
            self.uri = '{0}://{1}:{2}'.format(schema, server, port)
        else:
            uri = _config('uri')
            # validate the URI
            log.debug('Validating the LDAP URI {0}'.format(uri))
            if not ldapurl.isLDAPUrl(uri):
                msg = '{0} is no valid LDAP URL'.format(uri)
                log.warn(msg)
                raise CommandExecutionError(msg)
            self.uri = uri

        if no_verify:
            ldap.set_option(ldap.OPT_X_TLS_REQUIRE_CERT,
                            ldap.OPT_X_TLS_NEVER)
        log.debug(
                'Initializing LDAP object with URI: {0}'.format(self.uri)
        )
        try:
            self.ldap = ldap.initialize(self.uri)
        except ldap.LDAPError as ldap_error:
            errmsg = 'Failed initializing LDAP object with URI: {0} - {1}'.format(
                    self.uri, ldap_error
                )
            log.warn(errmsg)
            raise CommandExecutionError(errmsg)
        else:
            log.debug(
                    'Succeeded initializing LDAP object with URI: {0}'.format(self.uri)
            )

        self.ldap.protocol_version = 3  # ldap.VERSION3
        self.ldap.set_option(ldap.OPT_REFERRALS, 0)  # Needed for AD

        if self.bindpw and not anonymous:
            log.debug(
                    'Attempting initial bind to URI {0} as {1}'.format(
                        self.uri, self.binddn
                        )
            )
            try:
                self.ldap.simple_bind_s(self.binddn, self.bindpw)
            except ldap.LDAPError as ldap_error:
                errmsg = 'Failed to bind to LDAP URI {0} as {1}: {2}'.format(
                        self.uri, self.binddn, ldap_error
                    )
                log.warn(errmsg)
                raise CommandExecutionError(errmsg)
            else:
                log.debug('Initial bind succeeded')


def auth(username, password):
    '''
    Authenticate via an LDAP bind
    '''
    # Get config params; create connection dictionary
    basedn       = _config('basedn', mandatory=False)
    scope        = _config('scope')
    anonymous    = _config('anonymous')
    searchfilter = _config('filter', variables={'username': username})
    searchscope  = _config('scope')
    connargs     = {
        'binddn': _config('binddn', mandatory=False, variables={'username': username}),
        'bindpw': _config('bindpw', mandatory=False),
    }

    if not anonymous and connargs['bindpw']:
        # search for the user's DN to be used for the actual authentication
        _ldap = _LDAPConnection(**connargs).ldap
        log.debug(
            'Running LDAP user dn search with filter:{0}, dn:{1}, '
            'scope:{2}'.format(
                searchfilter, basedn, scope
            )
        )
        result = _ldap.search_s(basedn, int(searchscope), searchfilter)
        if len(result) < 1:
            log.warn('Unable to find user {0}'.format(username))
            return False
        elif len(result) > 1:
            log.warn('Found multiple results for user {0}'.format(username))
            return False
        connargs['binddn'] = result[0][0]

    # Update connection dictionary with the user's password
    connargs['bindpw'] = password
    # Attempt bind with user dn and password
    log.debug('Attempting LDAP bind with user dn: {0}'.format(connargs['binddn']))
    try:
        _LDAPConnection(**connargs).ldap
    except Exception:
        logargs=connargs
        logargs['bindpw']='hidden'
        log.warn('Failed to authenticate user dn via LDAP: {0}'.format(logargs))
        return False
    log.debug(
        'Successfully authenticated user dn via LDAP: {0}'.format(
            connargs['binddn']
        )
    )
    return True
