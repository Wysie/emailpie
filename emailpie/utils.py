import re

import gevent

from DNS.Base import ServerError

from emailpie import settings

# All we are really doing is comparing the input string to one
# gigantic regular expression.  But building that regexp, and
# ensuring its correctness, is made much easier by assembling it
# from the "tokens" defined by the RFC.  Each of these tokens is
# tested in the accompanying unit test file.
#
# The section of RFC 2822 from which each pattern component is
# derived is given in an accompanying comment.
#
# (To make things simple, every string below is given as 'raw',
# even when it's not strictly necessary.  This way we don't forget
# when it is necessary.)

WSP = r'[ \t]'                                        # see 2.2.2. Structured Header Field Bodies
CRLF = r'(?:\r\n)'                                    # see 2.2.3. Long Header Fields
NO_WS_CTL = r'\x01-\x08\x0b\x0c\x0f-\x1f\x7f'         # see 3.2.1. Primitive Tokens
QUOTED_PAIR = r'(?:\\.)'                              # see 3.2.2. Quoted characters
FWS = r'(?:(?:' + WSP + r'*' + CRLF + r')?' + \
      WSP + r'+)'                                     # see 3.2.3. Folding white space and comments
CTEXT = r'[' + NO_WS_CTL + \
        r'\x21-\x27\x2a-\x5b\x5d-\x7e]'               # see 3.2.3
CCONTENT = r'(?:' + CTEXT + r'|' + \
           QUOTED_PAIR + r')'                         # see 3.2.3 (NB: The RFC includes COMMENT here
                                                      # as well, but that would be circular.)
COMMENT = r'\((?:' + FWS + r'?' + CCONTENT + \
          r')*' + FWS + r'?\)'                        # see 3.2.3
CFWS = r'(?:' + FWS + r'?' + COMMENT + ')*(?:' + \
       FWS + '?' + COMMENT + '|' + FWS + ')'          # see 3.2.3
ATEXT = r'[\w!#$%&\'\*\+\-/=\?\^`\{\|\}~]'            # see 3.2.4. Atom
ATOM = CFWS + r'?' + ATEXT + r'+' + CFWS + r'?'       # see 3.2.4
DOT_ATOM_TEXT = ATEXT + r'+(?:\.' + ATEXT + r'+)*'    # see 3.2.4
DOT_ATOM = CFWS + r'?' + DOT_ATOM_TEXT + CFWS + r'?'  # see 3.2.4
QTEXT = r'[' + NO_WS_CTL + \
        r'\x21\x23-\x5b\x5d-\x7e]'                    # see 3.2.5. Quoted strings
QCONTENT = r'(?:' + QTEXT + r'|' + \
           QUOTED_PAIR + r')'                         # see 3.2.5
QUOTED_STRING = CFWS + r'?' + r'"(?:' + FWS + \
                r'?' + QCONTENT + r')*' + FWS + \
                r'?' + r'"' + CFWS + r'?'
LOCAL_PART = r'(?:' + DOT_ATOM + r'|' + \
             QUOTED_STRING + r')'                     # see 3.4.1. Addr-spec specification
DTEXT = r'[' + NO_WS_CTL + r'\x21-\x5a\x5e-\x7e]'     # see 3.4.1
DCONTENT = r'(?:' + DTEXT + r'|' + \
           QUOTED_PAIR + r')'                         # see 3.4.1
DOMAIN_LITERAL = CFWS + r'?' + r'\[' + \
                 r'(?:' + FWS + r'?' + DCONTENT + \
                 r')*' + FWS + r'?\]' + CFWS + r'?'   # see 3.4.1
DOMAIN = r'(?:' + DOT_ATOM + r'|' + \
         DOMAIN_LITERAL + r')'                        # see 3.4.1
ADDR_SPEC = LOCAL_PART + r'@' + DOMAIN                # see 3.4.1

# A valid address will match exactly the 3.4.1 addr-spec.
VALID_ADDRESS_REGEXP = re.compile(r'^' + ADDR_SPEC + r'$')

def mxlookup(domain):
    from DNS import Base

    def dnslookup(name, qtype):
        """convenience routine to return just answer data for any query type"""
        if Base.defaults['server'] == []: Base.DiscoverNameServers()
        result = Base.DnsRequest(name=name, qtype=qtype, timout=5).req()
        if result.header['status'] != 'NOERROR':
            raise ServerError("DNS query status: %s" % result.header['status'],
                result.header['rcode'])
        elif len(result.answers) == 0 and Base.defaults['server_rotate']:
            # check with next DNS server
            result = Base.DnsRequest(name=name, qtype=qtype, timout=5).req()
        if result.header['status'] != 'NOERROR':
            raise ServerError("DNS query status: %s" % result.header['status'],
                result.header['rcode'])
        return [x['data'] for x in result.answers]

    def _mxlookup(name):
        """
        convenience routine for doing an MX lookup of a name. returns a
        sorted list of (preference, mail exchanger) records
        """
        l = dnslookup(name, qtype='mx')
        l.sort()
        return l

    return _mxlookup(domain)


class EmailChecker(object):
    """
    Given an email address, run a variety of checks on that email address.

    A check is any method starting with `check_` that returns a list of errors.
    Errors are dictionaries with a message (str) and severity (int) key.
    """

    def __init__(self, email, _gevent=settings.GEVENT_CHECKS):
        self.email = email
        self.errors = []
        self.mx_records = None

        self._gevent = _gevent

    @property
    def username(self):
        return self.email.split('@')[0]

    @property
    def domain(self):
        try:
            return self.email.split('@')[1]
        except IndexError:
            return None

    def didyoumean(self):
        from emailpie.spelling import correct

        if self.domain:
            items = self.domain.split('.')

            suggestion = '{0}@{1}'.format(
                self.username,
                '.'.join(map(correct, items))
            )

            if suggestion == self.email:
                return None
            return suggestion

        return None

    @property
    def checks(self):
        """
        Collects all functions that start with `check_`.
        """
        out = []
        for name in dir(self):
            if name.startswith('check_'):
                out.append(getattr(self, name))
        return out

    def validate(self):
        """
            1. Run each check, fill up self.jobs.
            2. Join all jobs together.
            3. Each job returns a list of errors.
            4. Condense and return each error.
        """
        if self._gevent:
            results = [gevent.spawn(check) for check in self.checks]
            gevent.joinall(results, timeout=7)

            for result in results:
                if result.value:
                    self.errors += result.value
        else:
            for result in [check() for check in self.checks]:
                self.errors += result

        return self.errors


    ############
    ## CHECKS ##
    ############
    
    def check_valid_email_string(self):
        """
        A simple regex based checker.

        Based on https://github.com/heropunch/validate-email-address
        """

        if re.match(VALID_ADDRESS_REGEXP, self.email) is not None:
            return []
        else:
            return [dict(
                severity=10,
                message='Invalid email address.'
            )]

    def check_valid_mx_records(self):
        """
        Ensures that there are MX records for this domain.
        """
        error = dict(
            severity=7,
            message='No MX records found for the domain.'
        )

        if not self.domain:
            return [error]

        try:
            self.mx_records = mxlookup(self.domain)
            if len(self.mx_records) == 0:
                return [error]
        except ServerError:
            return [error]

        return []

    def check_nothing(self):
        return []