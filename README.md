[![Go Report Card](https://goreportcard.com/badge/github.com/ip2location/ip2proxy-go)](https://goreportcard.com/report/github.com/ip2location/ip2proxy-go)

# IP2Proxy Go Package

This package allows user to query an IP address if it was being used as VPN anonymizer, open proxies, web proxies, Tor exits, data center, web hosting (DCH) range, search engine robots (SES) and residential (RES). It lookup the proxy IP address from **IP2Proxy BIN Data** file. This data file can be downloaded at

* Free IP2Proxy BIN Data: https://lite.ip2location.com
* Commercial IP2Proxy BIN Data: https://www.ip2location.com/database/ip2proxy


## Installation

To install this module type the following:

```bash

go get github.com/ip2location/ip2proxy-go

```

## Methods
Below are the methods supported in this package.

|Method Name|Description|
|---|---|
|Open|Open the IP2Proxy BIN data for lookup.|
|Close|Close and clean up the file pointer.|
|PackageVersion|Get the package version (1 to 11 for PX1 to PX11 respectively).|
|ModuleVersion|Get the module version.|
|DatabaseVersion|Get the database version.|
|IsProxy|Check whether if an IP address was a proxy. Returned value:<ul><li>-1 : errors</li><li>0 : not a proxy</li><li>1 : a proxy</li><li>2 : a data center IP address or search engine robot</li></ul>|
|GetAll|Return the proxy information in an array.|
|GetProxyType|Return the proxy type. Please visit <a href="https://www.ip2location.com/database/px10-ip-proxytype-country-region-city-isp-domain-usagetype-asn-lastseen-threat-residential" target="_blank">IP2Location</a> for the list of proxy types supported.|
|GetCountryShort|Return the ISO3166-1 country code (2-digits) of the proxy.|
|GetCountryLong|Return the ISO3166-1 country name of the proxy.|
|GetRegion|Return the ISO3166-2 region name of the proxy. Please visit <a href="https://www.ip2location.com/free/iso3166-2" target="_blank">ISO3166-2 Subdivision Code</a> for the information of ISO3166-2 supported.|
|GetCity|Return the city name of the proxy.|
|GetIsp|Return the ISP name of the proxy.|
|GetDomain|Return the domain name of the proxy.|
|GetUsageType|Return the usage type classification of the proxy. Please visit <a href="https://www.ip2location.com/database/px10-ip-proxytype-country-region-city-isp-domain-usagetype-asn-lastseen-threat-residential" target="_blank">IP2Location</a> for the list of usage types supported.|
|GetAsn|Return the autonomous system number of the proxy.|
|GetAs|Return the autonomous system name of the proxy.|
|GetLastSeen|Return the number of days that the proxy was last seen.|
|GetThreat|Return the threat type of the proxy.|
|GetProvider|Return the provider of the proxy.|

## Usage

```go
package main

import (
	"fmt"
	"github.com/ip2location/ip2proxy-go"
)

func main() {
	db, err := ip2proxy.OpenDB("./IP2PROXY-IP-PROXYTYPE-COUNTRY-REGION-CITY-ISP-DOMAIN-USAGETYPE-ASN-LASTSEEN-THREAT-RESIDENTIAL-PROVIDER.BIN")
	
	if err != nil {
		return
	}
	ip := "199.83.103.79"
	all, err := db.GetAll(ip)
	
	if err != nil {
		fmt.Print(err)
		return
	}
	
	fmt.Printf("ModuleVersion: %s\n", ip2proxy.ModuleVersion())
	fmt.Printf("PackageVersion: %s\n", db.PackageVersion())
	fmt.Printf("DatabaseVersion: %s\n", db.DatabaseVersion())
	
	fmt.Printf("isProxy: %s\n", all["isProxy"])
	fmt.Printf("ProxyType: %s\n", all["ProxyType"])
	fmt.Printf("CountryShort: %s\n", all["CountryShort"])
	fmt.Printf("CountryLong: %s\n", all["CountryLong"])
	fmt.Printf("Region: %s\n", all["Region"])
	fmt.Printf("City: %s\n", all["City"])
	fmt.Printf("ISP: %s\n", all["ISP"])
	fmt.Printf("Domain: %s\n", all["Domain"])
	fmt.Printf("UsageType: %s\n", all["UsageType"])
	fmt.Printf("ASN: %s\n", all["ASN"])
	fmt.Printf("AS: %s\n", all["AS"])
	fmt.Printf("LastSeen: %s\n", all["LastSeen"])
	fmt.Printf("Threat: %s\n", all["Threat"])
	fmt.Printf("Provider: %s\n", all["Provider"])
	
	db.Close()
}
```
