#!/usr/bin/python3
# -*- coding: utf-8 -*-

# Juniper/Pulse TNCC emulator
#
# Copyright © 2015-2018 Russ Dill
#
# Author: Russ Dill <russdill@gmail.com>
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU Lesser General Public License
# version 2.1, as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# Lesser General Public License for more details.

########################################
#
# Required modules:
#   - Mechanize (https://pypi.org/project/mechanize). Tested with v0.4.5
#   - For client certificate support and server certificate validation, asn1crypto
#     is required (https://github.com/wbond/asn1crypto). Tested with v0.24.0 and v1.3.0
#   - For autodetection of network interfaces' hardware/MAC addresses,
#     netifaces is required (https://pypi.org/project/netifaces). Tested with v0.10.9
#
# OpenConnect will automatically set the TNCC_HOSTNAME variable when calling this
# script, and will set TNCC_SHA256 to the pin-sha256 hash of the server certificates
# public key (currently not verified).
#
# Environment variables that may need customization (excerpted from
# https://github.com/russdill/juniper-vpn-py/blame/master/README.host_checker):
#
# TNCC_DEVICE_ID: May need to be overriden to match a known value from a computer
#   running the official Windows client software (obtained from the registry key
#   \HKEY_CURRENT_USER\Software\Juniper Networks\Device Id)
#
# TNCC_FUNK: Set TNCC_FUNK=1 to force the use of client machine identification
#   (known as "funk" to Juniper). This identification will include host platform,
#   a list of network hardware/MAC addresses, and client certificates requested
#   by the server.
#
#   TNCC_PLATFORM: override system value (e.g. "Windows 7").
#   TNCC_HOSTNAME: override system value (e.g. "laptop1234.bigcorp.com").
#   TNCC_HWADDR: override with a comma-separated list of network hardware/MAC
#     addresses to report to the server (e.g. "aa:bb:cc:dd:00:21,ee:ff:12:34:45:78").
#     The default behavior is to include the all the MAC addresses returned by the
#     netifaces module, or to leave blank if this module is not available.
#   TNCC_CERTS: a comma-separated list of absolute paths to PEM-formatted client
#     certificates to offer to the server
#
########################################

import sys
import os
import logging
from io import StringIO
from http.cookiejar import Cookie, CookieJar
import struct
import ssl
import base64
import collections
import zlib
import html.parser as HTMLParser
import socket
import platform
import datetime
import hashlib
import xml.etree.ElementTree

import mechanize
try:
    import asn1crypto.pem, asn1crypto.x509
except ImportError:
    asn1crypto = None
try:
    import netifaces
except ImportError:
    netifaces = None

ssl._create_default_https_context = ssl._create_unverified_context

debug = False
logging.basicConfig(stream=sys.stderr, level=logging.DEBUG if debug else logging.INFO)

MSG_POLICY = 0x58316
MSG_FUNK_PLATFORM = 0x58301
MSG_FUNK = 0xa4c01


# 0013 - Message
def decode_0013(buf, indent):
    logging.debug('%scmd 0013 (Message) %d bytes', indent, len(buf))
    ret = collections.defaultdict(list)
    while (len(buf) >= 12):
        length, cmd, out = decode_packet(buf, indent + "  ")
        buf = buf[length:]
        ret[cmd].append(out)
    return ret

# 0012 - u32
def decode_0012(buf, indent):
    logging.debug('%scmd 0012 (u32) %d bytes', indent, len(buf))
    return struct.unpack(">I", buf)

# 0016 - zlib compressed message
def decode_0016(buf, indent):
    logging.debug('%scmd 0016 (compressed message) %d bytes', indent, len(buf))
    _, compressed = struct.unpack(">I" + str(len(buf) - 4) + "s", buf)
    buf = zlib.decompress(compressed)
    ret = collections.defaultdict(list)
    while (len(buf) >= 12):
        length, cmd, out = decode_packet(buf, indent + "  ")
        buf = buf[length:]
        ret[cmd].append(out)
    return ret

# 0ce4 - encapsulation
def decode_0ce4(buf, indent):
    logging.debug('%scmd 0ce4 (encapsulation) %d bytes', indent, len(buf))
    ret = collections.defaultdict(list)
    while (len(buf) >= 12):
        length, cmd, out = decode_packet(buf, indent + "  ")
        buf = buf[length:]
        ret[cmd].append(out)
    return ret

# 0ce5 - string without hex prefixer
def decode_0ce5(buf, indent):
    s = struct.unpack(str(len(buf)) + "s", buf)[0]
    logging.debug('%scmd 0ce5 (string) %d bytes', indent, len(buf))
    s = s.rstrip(b'\0')
    logging.debug('%s', s)
    return s

# 0ce7 - string with hex prefixer
def decode_0ce7(buf, indent):
    id, s = struct.unpack(">I" + str(len(buf) - 4) + "s", buf)
    logging.debug('%scmd 0ce7 (id %08x string) %d bytes', indent, id, len(buf))

    if s.startswith(b'COMPRESSED:'):
        typ, length, data = s.split(':', 2)
        s = zlib.decompress(data)

    s = s.rstrip(b'\0')
    logging.debug('%s', s)
    return (id, s)

# 0cf0 - encapsulation
def decode_0cf0(buf, indent):
    logging.debug('%scmd 0cf0 (encapsulation) %d bytes', indent, len(buf))
    ret = dict()
    cmd, _, out = decode_packet(buf, indent + "  ")
    ret[cmd] = out
    return ret

# 0cf1 - string without hex prefixer
def decode_0cf1(buf, indent):
    s = struct.unpack(str(len(buf)) + "s", buf)[0]
    logging.debug('%scmd 0cf1 (string) %d bytes', indent, len(buf))
    s = s.rstrip(b'\0')
    logging.debug('%s', s)
    return s

# 0cf3 - u32
def decode_0cf3(buf, indent):
    ret = struct.unpack(">I", buf)
    logging.debug('%scmd 0cf3 (u32) %d bytes - %d', indent, len(buf), ret[0])
    return ret

def decode_packet(buf, indent=""):
    cmd, _1, _2, length, _3 = struct.unpack(">IBBHI", buf[:12])
    if length < 12:
        raise Exception("Invalid packet, cmd %04x, _1 %02x, _2 %02x, length %d" % (cmd, _1, _2, length))

    data = buf[12:length]

    if length % 4:
        length += 4 - (length % 4)

    if cmd == 0x0013:
        data = decode_0013(data, indent)
    elif cmd == 0x0012:
        data = decode_0012(data, indent)
    elif cmd == 0x0016:
        data = decode_0016(data, indent)
    elif cmd == 0x0ce4:
        data = decode_0ce4(data, indent)
    elif cmd == 0x0ce5:
        data = decode_0ce5(data, indent)
    elif cmd == 0x0ce7:
        data = decode_0ce7(data, indent)
    elif cmd == 0x0cf0:
        data = decode_0cf0(data, indent)
    elif cmd == 0x0cf1:
        data = decode_0cf1(data, indent)
    elif cmd == 0x0cf3:
        data = decode_0cf3(data, indent)
    else:
        logging.debug('%scmd %04x(%02x:%02x) is unknown, length %d', indent, cmd, _1, _2, length)
        data = None

    return length, cmd, data

def encode_packet(cmd, align, buf):
    align = 4
    orig_len = len(buf)
    if align > 1 and (len(buf) + 12) % align:
        buf += struct.pack(str(align - len(buf) % align) + "x")

    return struct.pack(">IBBHI", cmd, 0xc0, 0x00, orig_len + 12, 0x0000583) + buf

# 0013 - Message
def encode_0013(buf):
    return encode_packet(0x0013, 4, buf)

# 0012 - u32
def encode_0012(i):
    return encode_packet(0x0012, 1, struct.pack("<I", i))

# 0ce4 - encapsulation
def encode_0ce4(buf):
    return encode_packet(0x0ce4, 4, buf)

# 0ce5 - string without hex prefixer
def encode_0ce5(s):
    return encode_packet(0x0ce5, 1, struct.pack(str(len(s)) + "s", s))

# 0ce7 - string with hex prefixer
def encode_0ce7(s, prefix):
    s += b'\0'
    return encode_packet(0x0ce7, 1, struct.pack(">I" + str(len(s)) + "sx",
                                prefix, s))

# 0cf0 - encapsulation
def encode_0cf0(buf):
    return encode_packet(0x0cf0, 4, buf)

# 0cf1 - string without hex prefixer
def encode_0cf1(s):
    s += b'\0'
    return encode_packet(0x0ce5, 1, struct.pack(str(len(s)) + "s", s))

# 0cf3 - u32
def encode_0cf3(i):
    return encode_packet(0x0013, 1, struct.pack("<I", i))

class x509cert(object):

    @staticmethod
    def decode_names(names):
        ret = dict()
        for name in names.chosen:
            for attr in name:
                type = attr['type'].dotted    # dotted-quad value (e.g. '2.5.4.10' = organization)
                value = attr['value'].native  # literal string value (e.g. 'Bigcorp Inc.')
                ret.setdefault(type, []).append(value)
        return ret

    def __init__(self, cert_file):
        with open(cert_file, 'r') as f:
            self.data = f.read()
        type_name, headers, der_bytes = asn1crypto.pem.unarmor(self.data.encode())
        cert = asn1crypto.x509.Certificate.load(der_bytes)
        tbs = cert['tbs_certificate']
        self.issuer = self.decode_names(tbs['issuer'])
        self.not_before = tbs['validity']['not_before'].native.astimezone(datetime.timezone.utc).replace(tzinfo=None)
        self.not_after = tbs['validity']['not_after'].native.astimezone(datetime.timezone.utc).replace(tzinfo=None)
        self.subject = self.decode_names(tbs['subject'])

class tncc(object):
    def __init__(self, vpn_host, device_id=None, funk=None, platform=None, hostname=None, mac_addrs=[], certs=[], interval=None):
        self.vpn_host = vpn_host
        self.path = '/dana-na/'

        self.funk = funk
        self.platform = platform
        self.hostname = hostname
        self.mac_addrs = mac_addrs
        self.avail_certs = certs
        self.interval = interval

        self.deviceid = device_id

        self.br = mechanize.Browser()

        self.cj = CookieJar()
        self.br.set_cookiejar(self.cj)

        # Browser options
        self.br.set_handle_equiv(True)
        self.br.set_handle_redirect(True)
        self.br.set_handle_referer(True)
        self.br.set_handle_robots(False)

        # Follows refresh 0 but not hangs on refresh > 0
        self.br.set_handle_refresh(mechanize._http.HTTPRefreshProcessor(),
                              max_time=1)

        # Want debugging messages?
        if debug:
            self.br.set_debug_http(True)
            self.br.set_debug_redirects(True)
            self.br.set_debug_responses(True)

        self.user_agent = 'Neoteris HC Http'
        self.br.addheaders = [('User-agent', self.user_agent)]

    def find_cookie(self, name):
        for cookie in self.cj:
            if cookie.name == name:
                return cookie
        return None

    def set_cookie(self, name, value):
        cookie = Cookie(version=0, name=name, value=value,
                port=None, port_specified=False, domain=self.vpn_host,
                domain_specified=True, domain_initial_dot=False, path=self.path,
                path_specified=True, secure=True, expires=None, discard=True,
                comment=None, comment_url=None, rest=None, rfc2109=False)
        self.cj.set_cookie(cookie)

    def parse_response(self):
        # Read in key/token fields in HTTP response
        response = dict()
        last_key = ''
        for line in self.r.readlines():
            line = line.strip().decode()
            # Note that msg is too long and gets wrapped, handle it special
            if last_key == 'msg' and len(line):
                response['msg'] += line
            else:
                key = ''
                try:
                    key, val = line.split('=', 1)
                    response[key] = val
                except ValueError:
                    pass
                last_key = key
        logging.debug('Parsed response:\n\t%s', '\n\t'.join('%r: %r,' % pair for pair in response.items()))
        return response

    def parse_policy_response(self, msg_data):
        # The decompressed data is HTMLish, decode it. The value="" of each
        # tag is the data we want.
        objs = []
        class ParamHTMLParser(HTMLParser.HTMLParser):
            def handle_starttag(self, tag, attrs):
                if tag.lower() == 'param':
                    for key, value in attrs:
                        if key.lower() == 'value':
                            # It's made up of a bunch of key=value pairs separated
                            # by semicolons
                            d = dict()
                            for field in value.split(';'):
                                field = field.strip()
                                try:
                                    key, value = field.split('=', 1)
                                    d[key] = value
                                except ValueError:
                                    pass
                            objs.append(d)
        p = ParamHTMLParser()
        p.feed(msg_data)
        p.close()
        return objs

    def parse_funk_response(self, msg_data):
        e = xml.etree.ElementTree.fromstring(msg_data)
        req_certs = dict()
        for cert in e.find('AttributeRequest').findall('CertData'):
            dns = dict()
            cert_id = cert.attrib['Id']
            for attr in cert.findall('Attribute'):
                name = attr.attrib['Name']
                value = attr.attrib['Value']
                attr_type = attr.attrib['Type']
                if attr_type == 'DN':
                    dns[name] = dict(n.strip().split('=') for n in value.split(','))
                else:
                    # Unknown attribute type
                    pass
            req_certs[cert_id] = dns
        return req_certs

    def gen_funk_platform(self):
        # We don't know if the xml parser on the other end is fully complaint,
        # just format a string like it expects.

        msg = "<FunkMessage VendorID='2636' ProductID='1' Version='1' Platform='%s' ClientType='Agentless'> " % self.platform
        msg += "<ClientAttributes SequenceID='-1'> "

        def add_attr(key, val):
            return "<Attribute Name='%s' Value='%s' />" % (key, val)

        msg += add_attr('Platform', self.platform)
        if self.hostname:
            msg += add_attr(self.hostname, 'NETBIOSName') # Reversed

        for mac in self.mac_addrs:
            msg += add_attr(mac, 'MACAddress') # Reversed

        msg += "</ClientAttributes>  </FunkMessage>"

        return encode_0ce7(msg.encode(), MSG_FUNK_PLATFORM)

    def gen_funk_present(self):
        msg = "<FunkMessage VendorID='2636' ProductID='1' Version='1' Platform='%s' ClientType='Agentless'> " % self.platform
        msg += "<Present SequenceID='0'></Present>  </FunkMessage>"
        return encode_0ce7(msg.encode(), MSG_FUNK)

    def gen_funk_response(self, certs):

        msg = "<FunkMessage VendorID='2636' ProductID='1' Version='1' Platform='%s' ClientType='Agentless'> " % self.platform
        msg += "<ClientAttributes SequenceID='0'> "
        msg += "<Attribute Name='Platform' Value='%s' />" % self.platform
        for name, value in certs.items():
            msg += "<Attribute Name='%s' Value='%s' />" % (name, value.data.strip())
            msg += "<Attribute Name='%s' Value='%s' />" % (name, value.data.strip())
        msg += "</ClientAttributes>  </FunkMessage>"

        return encode_0ce7(msg.encode(), MSG_FUNK)

    def gen_policy_request(self):
        policy_blocks = collections.OrderedDict({
            'policy_request': {
                'message_version': '3'
            },
            'esap': {
                'esap_version': 'NOT_AVAILABLE',
                'fileinfo': 'NOT_AVAILABLE',
                'has_file_versions': 'YES',
                'needs_exact_sdk': 'YES',
                'opswat_sdk_version': '3'
            },
            'system_info': {
                'os_version': '2.6.2',
                'sp_version': '0',
                'hc_mode': 'userMode'
            }
        })

        msg = ''
        for policy_key, policy_val in policy_blocks.items():
            v = ''.join([ '%s=%s;' % (k, v) for k, v in policy_val.items()])
            msg += '<parameter name="%s" value="%s">' % (policy_key, v)

        return encode_0ce7(msg.encode(), 0xa4c18)

    def gen_policy_response(self, policy_objs):
        # Make a set of policies
        policies = set()
        for entry in policy_objs:
            if 'policy' in entry:
                policies.add(entry['policy'])

        # Try to determine on policy name whether the response should be OK
        # or NOTOK. Default to OK if we don't know, this may need updating.
        msg = ''
        for policy in policies:
            msg += '\npolicy:%s\nstatus:' % policy
            if 'Unsupported' in policy or 'Deny' in policy:
                msg += 'NOTOK\nerror:Unknown error'
            elif 'Required' in policy:
                msg += 'OK\n'
            else:
                # Default action
                msg += 'OK\n'

        return encode_0ce7(msg.encode(), MSG_POLICY)

    def get_cookie(self, dspreauth=None, dssignin=None):

        if dspreauth is None or dssignin is None:
            self.r = self.br.open('https://' + self.vpn_host)
        else:
            try:
                self.cj.set_cookie(dspreauth)
            except:
                self.set_cookie('DSPREAUTH', dspreauth)
            try:
                self.cj.set_cookie(dssignin)
            except:
                self.set_cookie('DSSIGNIN', dssignin)

        inner = self.gen_policy_request()
        inner += encode_0ce7(b'policy request\x00v4', MSG_POLICY)
        if self.funk:
            inner += self.gen_funk_platform()
            inner += self.gen_funk_present()

        msg_raw = encode_0013(encode_0ce4(inner) + encode_0ce5(b'Accept-Language: en') + encode_0cf3(1))
        logging.debug('Sending packet -')
        decode_packet(msg_raw)

        post_attrs = {
            'connID': '0',
            'timestamp': '0',
            'msg': base64.b64encode(msg_raw).decode(),
            'firsttime': '1'
        }
        if self.deviceid:
            post_attrs['deviceid'] = self.deviceid

        post_data = ''.join([ '%s=%s;' % (k, v) for k, v in post_attrs.items()])
        self.r = self.br.open('https://' + self.vpn_host + self.path + 'hc/tnchcupdate.cgi', post_data)

        # Parse the data returned into a key/value dict
        response = self.parse_response()

        if 'interval' in response:
            m = int(response['interval'])
            logging.debug('Got interval of %d minutes' % m)
            if self.interval is None or self.interval > m*60:
                self.interval = m*60

        # msg has the stuff we want, it's base64 encoded
        logging.debug('Receiving packet -')
        msg_raw = base64.b64decode(response['msg'])
        _1, _2, msg_decoded = decode_packet(msg_raw)

        # Within msg, there is a field of data
        sub_strings = msg_decoded[0x0ce4][0][0x0ce7]

        # Pull the data out of the 'value' key in the htmlish stuff returned
        policy_objs = []
        req_certs = dict()
        for str_id, sub_str in sub_strings:
            if str_id == MSG_POLICY:
                policy_objs += self.parse_policy_response(sub_str.decode())
            elif str_id == MSG_FUNK:
                req_certs = self.parse_funk_response(sub_str.decode())

        if debug:
            for obj in policy_objs:
                if 'policy' in obj:
                    logging.debug('policy %s', obj['policy'])
                    for key, val in obj.items():
                        if key != 'policy':
                            logging.debug('\t%s %s', key, val)

        # Try to locate the required certificates
        certs = dict()
        for cert_id, req_dns in req_certs.items():
            for cert in self.avail_certs:
                fail = False
                for dn_name, dn_vals in req_dns.items():
                    for name, val in dn_vals.items():
                        try:
                            if dn_name == 'IssuerDN':
                                assert val in cert.issuer[name]
                            else:
                                logging.warn('Unknown DN type %s', str(dn_name))
                                raise Exception()
                        except:
                            fail = True
                            break
                    if fail:
                        break
                if not fail:
                    certs[cert_id] = cert
                    break
            if cert_id not in certs:
                logging.warn('Could not find certificate for %s', str(req_dns))

        inner = b''
        if certs:
            inner += self.gen_funk_response(certs)
        inner += self.gen_policy_response(policy_objs)

        msg_raw = encode_0013(encode_0ce4(inner) + encode_0ce5(b'Accept-Language: en'))
        logging.debug('Sending packet -')
        decode_packet(msg_raw)

        post_attrs = {
            'connID': '1',
            'msg': base64.b64encode(msg_raw).decode(),
            'firsttime': '1'
        }

        post_data = ''.join([ '%s=%s;' % (k, v) for k, v in post_attrs.items()])
        self.r = self.br.open('https://' + self.vpn_host + self.path + 'hc/tnchcupdate.cgi', post_data)

        # We have a new DSPREAUTH cookie
        return self.find_cookie('DSPREAUTH')

class tncc_server(object):
    def __init__(self, s, t):
        self.sock = s
        self.tncc = t

    def process_cmd(self):
        buf = sock.recv(1024).decode('ascii')
        if not len(buf):
            sys.exit(0)
        cmd, buf = buf.split('\n', 1)
        cmd = cmd.strip()
        args = dict()
        for n in buf.split('\n'):
            n = n.strip()
            if len(n):
                key, val = n.strip().split('=', 1)
                args[key] = val
        if cmd == 'start':
            cookie = self.tncc.get_cookie(args['Cookie'], args['DSSIGNIN'])
            resp = ['200', '3', cookie.value]
            if self.tncc.interval is not None:
                resp.append(str(self.tncc.interval))
            sock.send(('\n'.join(resp) + '\n\n').encode('ascii'))
        elif cmd == 'setcookie':
            cookie = self.tncc.get_cookie(args['Cookie'],
                                          self.tncc.find_cookie('DSSIGNIN'))
        else:
            logging.warn('Unknown command %r' % cmd)

def fingerprint_checking_SSLSocket(_fingerprint):
    class SSLSocket(ssl.SSLSocket):
        fingerprint = _fingerprint
        def do_handshake(self, *args, **kw):
            res = super().do_handshake(*args, **kw)
            der_bytes = self.getpeercert(True)
            cert = asn1crypto.x509.Certificate.load(der_bytes)
            pubkey = cert.public_key.dump()
            pin_sha256 = base64.b64encode(hashlib.sha256(pubkey).digest()).decode()
            if pin_sha256 != self.fingerprint:
                raise Exception("Server fingerprint %s does not match expected pin-sha256:%s" % (pin_sha256, self.fingerprint))
    return SSLSocket

if __name__ == "__main__":
    vpn_host = sys.argv[1]

    funk = 'TNCC_FUNK' in os.environ and os.environ['TNCC_FUNK'] != '0'

    interval = int(os.environ.get('TNCC_INTERVAL', 0)) or None

    platform = os.environ.get('TNCC_PLATFORM', platform.system() + ' ' + platform.release())

    if 'TNCC_HWADDR' in os.environ:
        mac_addrs = [n.strip() for n in os.environ['TNCC_HWADDR'].split(',')]
    else:
        mac_addrs = []
        if netifaces is None:
            logging.warn("No netifaces module; mac_addrs will be empty.")
        else:
            for iface in netifaces.interfaces():
                try:
                    mac = netifaces.ifaddresses(iface)[netifaces.AF_LINK][0]['addr']
                    assert mac != '00:00:00:00:00:00'
                    mac_addrs.append(mac)
                except:
                    pass

    hostname = os.environ.get('TNCC_HOSTNAME', socket.gethostname())

    fingerprint = os.environ.get('TNCC_SHA256')
    if not fingerprint:
        logging.warn("TNCC_SHA256 not set, will not validate server certificate")
    elif not asn1crypto:
        logging.warn("asn1crypto module not available, will not validate server certificate")
    else:
        # For Python <3.7, we monkey-patch ssl.SSLSocket directly, because ssl.SSLContext.sslsocket_class
        # isn't available until Python 3.7. For Python 3.7+, we set ssl.SSLContext.sslsocket_class
        # to our modified version (which is sort of monkey-patching too).
        # (see https://gist.github.com/dlenski/fc42156c00a615f4aa18a6d19d67e208)
        if sys.version_info >= (3, 7):
            ssl.SSLContext.sslsocket_class = fingerprint_checking_SSLSocket(fingerprint)
        else:
            ssl.SSLSocket = fingerprint_checking_SSLSocket(fingerprint)

    certs = []
    if asn1crypto:
        if 'TNCC_CERTS' in os.environ:
            now = datetime.datetime.utcnow()
            for f in os.environ['TNCC_CERTS'].split(','):
                cert = x509cert(f.strip())
                if now < cert.not_before:
                    logging.warn('WARNING: %s is not yet valid', f)
                if now > cert.not_after:
                    logging.warn('WARNING: %s is expired', f)
                certs.append(cert)
    else:
        raise Exception('TNCC_CERTS environment variable set, but asn1crypto module is not available')

    # \HKEY_CURRENT_USER\Software\Juniper Networks\Device Id
    device_id = os.environ.get('TNCC_DEVICE_ID')

    t = tncc(vpn_host, device_id, funk, platform, hostname, mac_addrs, certs, interval)
    sock = socket.fromfd(0, socket.AF_UNIX, socket.SOCK_SEQPACKET)
    server = tncc_server(sock, t)
    while True:
        server.process_cmd()
