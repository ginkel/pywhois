from parser import WhoisEntry

import subprocess

def whois(domain):
    r = subprocess.Popen(['whois', domain], stdout=subprocess.PIPE)
    text = r.stdout.read()
    return WhoisEntry.load(domain, text)
