# OpenConnect

OpenConnect is an SSL VPN client initially created to support [Cisco's AnyConnect SSL VPN](http://www.cisco.com/go/asm).
It has since been ported to support the Juniper SSL VPN (which is now known as [Pulse Connect Secure](https://www.pulsesecure.net/products/connect-secure/)),
and the [Palo Alto Networks GlobalProtect SSL VPN](https://www.paloaltonetworks.com/features/vpn).

An openconnect VPN server (ocserv), which implements an improved version of the Cisco AnyConnect protocol, has also been written.
You can find it on Gitlab at [https://gitlab.com/openconnect/ocserv](https://gitlab.com/openconnect/ocserv).

If you're looking for the standard `vpnc-script`, which is invoked by OpenConnect for routing and DNS setup,
you can find it on Gitlab at [https://gitlab.com/openconnect/vpnc-scripts](https://gitlab.com/openconnect/vpnc-scripts).

## Licence

OpenConnect is released under the [GNU Lesser Public License, version 2.1](https://www.infradead.org/openconnect/licence.html).

## Documentation

Documentation for OpenConnect is built from the `www/` directory in this repository, and lives in rendered form at [https://www.infradead.org/openconnect](https://www.infradead.org/openconnect).

Commonly-sought documentation:

* [Manual](https://www.infradead.org/openconnect/manual.html)
* [Getting Started / Building](https://www.infradead.org/openconnect/building.html) (includes build instructions)
* [Contribute](https://www.infradead.org/openconnect/contribute.html)
* [Mailing list / Help](https://www.infradead.org/openconnect/mail.html)
* [GUIs / Front Ends](https://www.infradead.org/openconnect/gui.html)
* [VPN Server / ocserv](http://www.infradead.org/ocserv/)
