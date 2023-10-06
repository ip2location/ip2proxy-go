# Quickstart

## Dependencies

This library requires IP2Proxy BIN database to function. You may download the BIN database at

-   IP2Proxy LITE BIN Data (Free): <https://lite.ip2location.com>
-   IP2Proxy Commercial BIN Data (Comprehensive):
    <https://www.ip2location.com>

## Installation

To install this module type the following:

```bash

go get github.com/ip2location/ip2proxy-go/v4

```

## Sample Codes

### Query geolocation information from BIN database

You can query the geolocation information from the IP2Proxy BIN database as below:

```go
package main

import (
	"fmt"
	"strconv"
	"github.com/ip2location/ip2proxy-go/v4"
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
	
	fmt.Printf("IsProxy: %s\n", strconv.Itoa(int(all.IsProxy)));
	fmt.Printf("ProxyType: %s\n", all.ProxyType);
	fmt.Printf("CountryShort: %s\n", all.CountryShort);
	fmt.Printf("CountryLong: %s\n", all.CountryLong);
	fmt.Printf("Region: %s\n", all.Region);
	fmt.Printf("City: %s\n", all.City);
	fmt.Printf("Isp: %s\n", all.Isp);
	fmt.Printf("Domain: %s\n", all.Domain);
	fmt.Printf("UsageType: %s\n", all.UsageType);
	fmt.Printf("Asn: %s\n", all.Asn);
	fmt.Printf("As: %s\n", all.As);
	fmt.Printf("LastSeen: %s\n", all.LastSeen);
	fmt.Printf("Threat: %s\n", all.Threat)
	fmt.Printf("Provider: %s\n", all.Provider)
	
	db.Close()
}
```