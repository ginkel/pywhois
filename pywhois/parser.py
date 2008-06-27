# parser.py - Module for parsing whois response data
# Copyright (c) 2008 Andrey Petrov
#
# This module is part of pywhois and is released under
# the MIT license: http://www.opensource.org/licenses/mit-license.php

import re

# TODO: Add a global-ish method which will automatically determine which
# whois type to use and return an instance of it.

class WhoisEntry(object):
    """
    Parent class for parsing a Whois entries. Whois entries of different types
    will implement the interface provided by this class.
    """
    _keys = ['domain_name',
             'registrar',
             'whois_server',
             'referral_url', # http url of whois_server
             'name_servers', # list of name servers
             'status',       # list of statuses
             'updated_date',
             'creation_date',
             'expiration_date']
    _parsing_re = {}

    @staticmethod
    def load(self, text):
        """
        Given whois output in ``text``, return an instance of ``WhoisEntry`` that represents its parsed contents.
        """
        pass


class WhoisDotCom(WhoisEntry):
    "Whois parser for .com domains"
    _parsing_re = {
            # NOTE: These should all be found following the domain_name match.
            'domain_name':  'Domain Name:\s?(.+)$',
            'registrar':    'Registrar:\s?(.+)$',
            'whois_server': 'Whois Server:\s?(.+)$',
            'referral_url': 'Referral URL:\s?(.+)$',
            'updated_date': 'Updated Date:\s?(.+)$',
            'creation_date':   'Creation Date:\s?(.+)$',
            'expiration_date': 'Expiration Date:\s?(.+)$',
            'name_servers': 'Domain Name:\s?(.+)$', # There can be many of these
            'status': 'Status:\s?(.+)$', # There can be many of these
        }

    # Compile the regular expressions
    for key in _parsing_re:
        _parsing_re[key] = re.compile(_parsing_re[key])
