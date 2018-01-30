This program converts an elliptic curve private key from using explicit
parameters to using a named curve. The OpenSSL command line tools do not
support doing this.

I knew enough about the key format to know that this was theoretically
possible and decided to write a tool that does it. This builds against
OpenSSL 1.0.x and OpenSSL 1.1.x. I may try to get this integrated into the
OpenSSL command line tools some day.

The program supports input in both PEM and DER format although the output
will always be in PEM format because it just prints to stdout and DER is a
binary format that will corrupt your terminal.

Why would you want to do this?

Well CentOS/RHEL 6's OpenSSH package has slightly broken backported ECDSA
support.  Specifically it generates private keys with explicit parameters
instead of named curves. Stock OpenSSH only supports keys with named curves. I
didn't want to regenerate one of my server's SSH hostkeys after upgrading.
I'm sure other use cases exist.

Also yes, this repository delibrately contains private key material.
I generated 3 ECDSA SSH keys on a CentOS 6 host for test purposes. These
keys have never been used and exist to confirm that this program works.
