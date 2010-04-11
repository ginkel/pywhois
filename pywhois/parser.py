# parser.py - Module for parsing whois response data
# Copyright (c) 2008 Andrey Petrov
#
# This module is part of pywhois and is released under
# the MIT license: http://www.opensource.org/licenses/mit-license.php

import re
import time


class PywhoisError(Exception):
    pass


def cast_date(date_str):
    """Convert any date string found in WHOIS to a time object.
    """
    known_formats = [
        '%d-%b-%Y', # 02-jan-2000
        '%Y-%m-%d', # 2000-01-02
    ]

    r = None
    for fmt in known_formats:
        try:
            r = time.strptime(date_str.strip(), fmt)
        except ValueError, e:
            pass # Wrong format, keep trying

    return r


class WhoisEntry(object):
    """Base class for parsing a Whois entries.
    Child classes will implement special features of each registrar.
    """
    _whois_regs = {
        'domain_name':      'Domain Name:\s?(.+)',
        'registrar':        'Registrar:\s?(.+)',
        'whois_server':     'Whois Server:\s?(.+)',
        'referral_url':     'Referral URL:\s?(.+)', # http url of whois_server
        'updated_date':     'Updated Date:\s?(.+)',
        'creation_date':    'Creation Date:\s?(.+)',
        'expiration_date':  'Expiration Date:\s?(.+)',
        'name_servers':     'Name Server:\s?(.+)', # list of name servers
        'status':           'Status:\s?(.+)', # list of statuses
        'emails':           '[\w.-]+@[\w.-]+\.[\w]{2,4}', # list of email addresses
    }

    def __init__(self, domain, text):
        self.domain = domain
        self.text = text


    def __getattr__(self, attr):
        """The first time an attribute is called it will be calculated here.
        The attribute is then set to be accessed directly by subsequent calls.
        """
        whois_reg = self._whois_regs.get(attr)
        if whois_reg:
            setattr(self, attr, re.findall(whois_reg, self.text))
            return getattr(self, attr)
        else:
            raise KeyError("Unknown attribute: %s" % attr)

    def __str__(self):
        """Print all whois properties of domain
        """
        return '\n'.join('%s: %s' % (attr, str(getattr(self, attr))) for attr in self._whois_regs)


    @staticmethod
    def load(domain, text):
        """Given whois output in ``text``, return an instance of ``WhoisEntry`` that represents its parsed contents.
        """
        if text.strip() == 'No whois server is known for this kind of object.':
            raise PywhoisError(text)

        if '.com' in domain:
            return WhoisCom(domain, text)
        elif '.net' in domain:
            return WhoisNet(domain, text)
        elif '.org' in domain:
            return WhoisOrg(domain, text)
        elif '.ru' in domain:
            return WhoisRu(domain, text)
        else:
            return WhoisEntry(domain, text)



class WhoisCom(WhoisEntry):
    """Whois parser for .com domains
    """
    def __init__(self, domain, text):
        if 'No match for "' in text:
            raise PywhoisError(text)
        else:
            WhoisEntry.__init__(self, domain, text) 

class WhoisNet(WhoisEntry):
    """Whois parser for .net domains
    """
    def __init__(self, domain, text):
        if 'No match for "' in text:
            raise PywhoisError(text)
        else:
            WhoisEntry.__init__(self, domain, text) 

class WhoisOrg(WhoisEntry):
    """Whois parser for .org domains
    """
    def __init__(self, domain, text):
        if text.strip() == 'NOT FOUND':
            raise PywhoisError(text)
        else:
            WhoisEntry.__init__(self, domain, text) 

class WhoisRu(WhoisEntry):
    """Whois parser for .ru domains
    """
    _whois_regs = {
        'domain_name': 'domain:\s*(.+)',
        'registrar': 'registrar:\s*(.+)',
        'creation_date': 'created:\s*(.+)',
        'expiration_date': 'paid-till:\s*(.+)',
        'name_servers': 'nserver:\s*(.+)',  # list of name servers
        'status': 'state:\s*(.+)',  # list of statuses
        'emails': '[\w.-]+@[\w.-]+\.[\w]{2,4}',  # list of email addresses
    }

    def __init__(self, domain, text):
        if text.strip() == 'No entries found':
            raise PywhoisError(text)
        else:
            WhoisEntry.__init__(self, domain, text)
