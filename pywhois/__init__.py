from parser import cast_date, WhoisEntry

import subprocess

def whois(domain):
    r = subprocess.Popen(['whois', domain], stdout=subprocess.PIPE)
    data = r.stdout.read()
    return WhoisEntry.load(domain, data)
