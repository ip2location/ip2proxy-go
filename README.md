[![Go Report Card](https://goreportcard.com/badge/github.com/ip2location/ip2proxy-go)](https://goreportcard.com/report/github.com/ip2location/ip2proxy-go)

# IP2Proxy Go Package

This package allows user to query an IP address if it was being used as open proxy, web proxy, VPN anonymizer and TOR exits. It lookup the proxy IP address from **IP2Proxy BIN Data** file. This data file can be downloaded at

* Free IP2Proxy BIN Data: http://lite.ip2location.com
* Commercial IP2Proxy BIN Data: http://www.ip2location.com/proxy-database


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
|PackageVersion|Get the package version (1 to 4 for PX1 to PX4 respectively).|
|ModuleVersion|Get the module version.|
|DatabaseVersion|Get the database version.|
|IsProxy|Check whether if an IP address was a proxy. Returned value:<ul><li>-1 : errors</li><li>0 : not a proxy</li><li>1 : a proxy</li><li>2 : a data center IP address</li></ul>|
|GetAll|Return the proxy information in an array.|
|GetProxyType|Return the proxy type. Please visit <a href="https://www.ip2location.com/databases/px4-ip-proxytype-country-region-city-isp" target="_blank">IP2Location</a> for the list of proxy types supported|
|GetCountryShort|Return the ISO3166-1 country code (2-digits) of the proxy.|
|GetCountryLong|Return the ISO3166-1 country name of the proxy.|
|GetRegion|Return the ISO3166-2 region name of the proxy. Please visit <a href="https://www.ip2location.com/free/iso3166-2" target="_blank">ISO3166-2 Subdivision Code</a> for the information of ISO3166-2 supported|
|GetCity|Return the city name of the proxy.|
|GetIsp|Return the ISP name of the proxy.|

## Usage

```go
package main

import (
	"fmt"
	"github.com/ip2location/ip2proxy-go"
)

func main() {
	if ip2proxy.Open("./IP2PROXY-IP-PROXYTYPE-COUNTRY-REGION-CITY-ISP.BIN") == 0 {
		ip := "199.83.103.79"
		
		fmt.Printf("ModuleVersion: %s\n", ip2proxy.ModuleVersion())
		fmt.Printf("PackageVersion: %s\n", ip2proxy.PackageVersion())
		fmt.Printf("DatabaseVersion: %s\n", ip2proxy.DatabaseVersion())
		
		// functions for individual fields
		fmt.Printf("IsProxy: %d\n", ip2proxy.IsProxy(ip))
		fmt.Printf("ProxyType: %s\n", ip2proxy.GetProxyType(ip))
		fmt.Printf("CountryShort: %s\n", ip2proxy.GetCountryShort(ip))
		fmt.Printf("CountryLong: %s\n", ip2proxy.GetCountryLong(ip))
		fmt.Printf("Region: %s\n", ip2proxy.GetRegion(ip))
		fmt.Printf("City: %s\n", ip2proxy.GetCity(ip))
		fmt.Printf("ISP: %s\n", ip2proxy.GetIsp(ip))
		
		// function for all fields
		all := ip2proxy.GetAll(ip)
		fmt.Printf("isProxy: %s\n", all["isProxy"])
		fmt.Printf("ProxyType: %s\n", all["ProxyType"])
		fmt.Printf("CountryShort: %s\n", all["CountryShort"])
		fmt.Printf("CountryLong: %s\n", all["CountryLong"])
		fmt.Printf("Region: %s\n", all["Region"])
		fmt.Printf("City: %s\n", all["City"])
		fmt.Printf("ISP: %s\n", all["ISP"])
	} else {
		fmt.Printf("Error reading BIN file.\n")
	}
	ip2proxy.Close()
}
```
