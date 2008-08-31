import unittest

import os
import sys
sys.path.append('../')

import simplejson
from glob import glob

from pywhois.parser import WhoisEntry

class TestParser(unittest.TestCase):
    def test_com_expiration(self):
        data = """
            Status: ok
            Updated Date: 14-apr-2008
            Creation Date: 14-apr-2008
            Expiration Date: 14-apr-2009
            
            >>> Last update of whois database: Sun, 31 Aug 2008 00:18:23 UTC <<<
        """
        w = WhoisEntry.load('urlowl.com', data)
        expires = w.get('expiration_date')
        self.assertEquals(expires, ['14-apr-2009'])

    def test_com_allsamples(self):
        keys_to_test = ['expiration_date']
        fail = 0
        for path in glob('test/samples/whois/*.com'):
            # Parse whois data
            domain = os.path.basename(path)
            whois_fp = open(path)
            data = whois_fp.read()
            
            w = WhoisEntry.load(domain, data)
            results = {}
            for key in keys_to_test:
                results[key] = w.get(key)

            # Load expected result
            expected_fp = open(os.path.join('test/samples/expected/', domain))
            expected_results = simplejson.load(expected_fp)
            
            # Compare each key
            for key in results:
                result = results.get(key)
                expected = expected_results.get(key)
                if expected != result:
                    print "%s \t %s != %s" % (domain, result, expected)
                    fail += 1
            
        if fail:
            self.fail("%d sample whois files were not parsed properly!" % fail)