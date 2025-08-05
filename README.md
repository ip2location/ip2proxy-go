[![Go Report Card](https://goreportcard.com/badge/github.com/ip2location/ip2proxy-go/v4)](https://goreportcard.com/report/github.com/ip2location/ip2proxy-go/v4)
[![PkgGoDev](https://pkg.go.dev/badge/github.com/ip2location/ip2proxy-go/v4)](https://pkg.go.dev/github.com/ip2location/ip2proxy-go/v4)

# IP2Proxy Go Package

This package allows user to query an IP address if it was being used as VPN anonymizer, open proxies, web proxies, Tor exits, data center, web hosting (DCH) range, search engine robots (SES), residential proxies (RES), consumer privacy networks (CPN), and enterprise private networks (EPN). It lookup the proxy IP address from **IP2Proxy BIN Data** file. This data file can be downloaded at

* Free IP2Proxy BIN Data: https://lite.ip2location.com
* Commercial IP2Proxy BIN Data: https://www.ip2location.com/database/ip2proxy

## Developer Documentation
To learn more about installation, usage, and code examples, please visit the developer documentation at [https://ip2proxy-go.readthedocs.io/en/latest/index.html.](https://ip2proxy-go.readthedocs.io/en/latest/index.html)

### Proxy Type

|Proxy Type|Description|
|---|---|
|VPN|Anonymizing VPN services|
|TOR|Tor Exit Nodes|
|PUB|Public Proxies|
|WEB|Web Proxies|
|DCH|Hosting Providers/Data Center|
|SES|Search Engine Robots|
|RES|Residential Proxies [PX10+]|
|CPN|Consumer Privacy Networks. [PX11+]|
|EPN|Enterprise Private Networks. [PX11+]|

### Usage Type

|Usage Type|Description|
|---|---|
|COM|Commercial|
|ORG|Organization|
|GOV|Government|
|MIL|Military|
|EDU|University/College/School|
|LIB|Library|
|CDN|Content Delivery Network|
|ISP|Fixed Line ISP|
|MOB|Mobile ISP|
|DCH|Data Center/Web Hosting/Transit|
|SES|Search Engine Spider|
|RSV|Reserved|

### Threat Type

|Threat Type|Description|
|---|---|
|SPAM|Email and forum spammers|
|SCANNER|Security Scanner or Attack|
|BOTNET|Spyware or Malware|
|BOGON|Unassigned or illegitimate IP addresses announced via BGP|