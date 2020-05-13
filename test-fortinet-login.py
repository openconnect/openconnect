#!/usr/bin/python3

from __future__ import print_function
from sys import stderr, version_info, platform
if (version_info >= (3, 0)):
    from urllib.parse import urlparse, urlencode
    raw_input = input
    import http.client as httplib
else:
    from urlparse import urlparse
    from urllib import urlencode
    import httplib
import sys
import requests
import argparse
import getpass
from shlex import quote

p = argparse.ArgumentParser()
p.add_argument('-v','--verbose', default=0, action='count')
p.add_argument('endpoint', help='Fortinet server (or complete URL, e.g. https://forti.vpn.com/remote/login)')
p.add_argument('extra', nargs='*', help='Extra field to pass to include in the login query string (e.g. "foo=bar")')
g = p.add_argument_group('Login credentials')
g.add_argument('-u','--username', help='Username (will prompt if unspecified)')
g.add_argument('-p','--password', help='Password (will prompt if unspecified)')
g.add_argument('-r','--realm', default='', help='Realm (empty if unspecified)')
g.add_argument('-c','--cert', help='PEM file containing client certificate (and optionally private key)')
g.add_argument('--key', help='PEM file containing client private key (if not included in same file as certificate)')
p.add_argument('--no-verify', dest='verify', action='store_false', default=True, help='Ignore invalid server certificate')
args = p.parse_args()

if args.verbose > 1:
    httplib.HTTPConnection.debuglevel = 1

extra = dict(x.split('=', 1) for x in args.extra)
endpoint = urlparse(('https://{}/remote/login'.format(args.endpoint) if '//' not in args.endpoint else args.endpoint), 'https:')

if args.cert and args.key:
    cert = (args.cert, args.key)
elif args.cert:
    cert = (args.cert, None)
elif args.key:
    p.error('--key specified without --cert')
else:
    cert = None

s = requests.Session()
s.cert = cert
s.verify = args.verify
s.headers['User-Agent'] = 'Open AnyConnect VPN Agent v8.x' # seems to result in a more machine-parseable response format than 'Mozilla/5.0 SV1'
s.headers['Accept-Encoding'] = 'identity'                  # these servers appear to bork 'Transfer-Encoding: chunked'

print("Initial GET /remote/login to populate cookies...", file=stderr)
res = s.get(endpoint.geturl(), allow_redirects=False)

# Send login credentials
if args.username == None:
    args.username = raw_input('Username: ')
if args.password == None:
    args.password = getpass.getpass('Password: ')
data=dict(username=args.username, credential=args.password, realm=args.realm,
	  ajax=1, redir='%2Fremote%2Findex', just_logged_in=1,
          **extra)
print("POST /remote/logincheck to submit login credentials...", file=stderr)
res = s.post(endpoint._replace(path='/remote/logincheck').geturl(), data=data)

res.raise_for_status()

# Build openconnect --cookie argument from the result:
url = urlparse(res.url)
if any(c.name=='SVPNCOOKIE' and c.value for c in s.cookies):
    cookie = next(c.value for c in s.cookies if c.name=='SVPNCOOKIE')
    if args.verbose:
        if cert:
            cert_and_key = ' \\\n        ' + ' '.join('%s "%s"' % (opt, quote(fn)) for opt, fn in zip(('-c','-k'), cert) if fn)
        else:
            cert_and_key = ''

        print('''
Extracted connection cookie. Use this to connect:

    echo %s | openconnect --protocol=fortinet %s --cookie-on-stdin %s

''' % (quote(cookie), cert_and_key, quote(endpoint.netloc)), file=stderr)

    varvals = {
        'HOST': quote(url.netloc),
        'COOKIE': quote(cookie),
    }
    print('\n'.join('%s=%s' % pair for pair in varvals.items()))

# Just print the result
else:
    if args.verbose:
        print(res.headers, file=stderr)
    print(res.text)
