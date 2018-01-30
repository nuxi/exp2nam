These all came from the CentOS/RHEL 6 ssh-keygen since that was the
primary focus of the program. You can easily generate your own test
data with the OpenSSL command line tools.

Yes, there is private key material in this directory. I explicitly
generated them for testing this and they have never been used.

foo.exp - private key with explicit parameters in PEM format
foo.der - private key with explicit parameters in DER format
foo.nam - private key with named curve in PEM format
foo.pub - public key in OpenSSH format

nistp256 = NIST P-256 (aka prime256v1)
nistp384 = NIST P-384 (aka secp384r1)
nistp521 = NIST P-521 (aka secp521r1)
