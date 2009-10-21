from parser import WhoisEntry

import subprocess

def whois(domain):
    domain = domain
    r = subprocess.Popen(['whois', domain.lstrip('http://').lstrip('www')], stdout=subprocess.PIPE)
    text = r.stdout.read()
    return WhoisEntry.load(domain, text)
