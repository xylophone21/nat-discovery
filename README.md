## Cross-platform NAT behavior discovery (algorithms defined in RFC3489 and RFC5780)

### When it is useful?


### Features

  - Ready to use on your platform, no requirements, no installing, no administrative privileges
  - <a href="http://www.netmanias.com/en/post/techdocs/6066/nat-stun/nat-behavior-discovery-using-classic-stun-rfc-3489">Discovers following types (RFC3489):</a>
    - ```Full Cone```
    - ```Restricted Cone```
    - ```Port Restricted Cone```
    - ```Symmetric```
    - ```No NAT``` (Open Internet, Blocked, Symmetric UDP Firewall)

  - <a href="https://datatracker.ietf.org/doc/html/rfc5780#section-4.3">Determining NAT Mapping Behavior (RFC5780):</a>
    - ```Endpoint Independent Mapping```
    - ```Address Dependent Mapping```
    - ```Address and Port Dependent Mapping```
    - ```No NAT``` (Open Internet, Blocked, Symmetric UDP 

  - <a href="https://datatracker.ietf.org/doc/html/rfc5780#section-4.4">Determining NAT Filtering Behavior (RFC5780):</a>
    - ```Endpoint-Independent Filtering```
    - ```Address-Dependent Filtering```
    - ```Address and Port-Dependent Filtering```
    - ```No NAT``` (Open Internet, Blocked, Symmetric UDP 


### Configuration

```
> nat-discovery --help

usage: nat-discovery [-h] [-d] [-j] [-e] [-H STUN_HOST] [-P STUN_PORT] [-i SOURCE_IP] [-p SOURCE_PORT] [--version]

optional arguments:
  -h, --help            show this help message and exit
  -d, --debug           enable debug logging (default: False)
  -H STUN_HOST, --stun-host STUN_HOST
                        STUN host to use (default: None)
  -P STUN_PORT, --stun-port STUN_PORT
                        STUN host port to use (default: 3478)
  -i SOURCE_IP, --source-ip SOURCE_IP
                        network interface for client (default: 0.0.0.0)
  -p SOURCE_PORT, --source-port SOURCE_PORT
                        port to listen on for client (default: 54320)
  --version             show program's version number and exit

```
