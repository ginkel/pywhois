from parser import WhoisEntry

import subprocess

def whois(domain):
    domain = strip_prefix(domain,'http://')
    domain = strip_prefix(domain,'www.')
    r = subprocess.Popen(['whois', domain], stdout=subprocess.PIPE)
    text = r.stdout.read()
    return WhoisEntry.load(domain, text)

def strip_prefix(text, prefix):
    if not text.startswith(prefix):
        return text
    return text[len(prefix):]
