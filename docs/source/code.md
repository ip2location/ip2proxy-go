# IP2Proxy Go API

## IP2Proxy Class
```{py:function} OpenDB(binPath)
Load the IP2Proxy BIN database for lookup.

:param str binPath: (Required) The file path links to IP2Proxy BIN databases.
```

```{py:function} Close()
Close and clean up the file pointer.
```

```{py:function} PackageVersion()
Return the database's type, 1 to 12 respectively for PX1 to PX12. Please visit https://www.ip2location.com/databases/ip2proxy for details.

:return: Returns the package version.
:rtype: string
```

```{py:function} ModuleVersion()
Return the version of module.

:return: Returns the module version.
:rtype: string
```

```{py:function} DatabaseVersion()
Return the database's compilation date as a string of the form 'YYYY-MM-DD'.

:return: Returns the database version.
:rtype: string
```

```{py:function} GetAll(ipAddress)
Retrieve geolocation information for an IP address.

:param string ipAddress: (Required) The IP address (IPv4 or IPv6).
:return: Returns the geolocation information in an object. Refer below table for the fields avaliable in the object
:rtype: object

**RETURN FIELDS**

| Field Name       | Description                                                  |
| ---------------- | ------------------------------------------------------------ |
| IsProxy         |     Determine whether if an IP address was a proxy or not. Returns 0 is not proxy, 1 if proxy, and 2 if it's data center IP |
| CountryShort    |     Two-character country code based on ISO 3166. |
| CountryLong    |     Country name based on ISO 3166. |
| Region     |     Region or state name. |
| City       |     City name. |
| Isp            |     Internet Service Provider or company\'s name. |
| Domain         |     Internet domain name associated with IP address range. |
| UsageType      |     Usage type classification of ISP or company. |
| Asn            |     Autonomous system number (ASN). |
| As             |     Autonomous system (AS) name. |
| LastSeen       |     Proxy last seen in days. |
| Threat         |     Security threat reported. |
| ProxyType      |     Type of proxy. |
| Provider       |     Name of VPN provider if available. |
| FraudScore       |     Potential risk score (0 - 99) associated with IP address. |
```