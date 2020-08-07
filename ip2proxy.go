// This ip2proxy package allows user to query an IP address if it was being used as
// VPN anonymizer, open proxies, web proxies, Tor exits, data center,
// web hosting (DCH) range, search engine robots (SES) and residential (RES)
// by using the IP2Proxy database.
package ip2proxy

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"math"
	"math/big"
	"net"
	"os"
	"strconv"
)

type ip2proxymeta struct {
	databasetype      uint8
	databasecolumn    uint8
	databaseday       uint8
	databasemonth     uint8
	databaseyear      uint8
	ipv4databasecount uint32
	ipv4databaseaddr  uint32
	ipv6databasecount uint32
	ipv6databaseaddr  uint32
	ipv4indexbaseaddr uint32
	ipv6indexbaseaddr uint32
	ipv4columnsize    uint32
	ipv6columnsize    uint32
}

// The IP2Proxyrecord struct stores all of the available
// proxy info found in the IP2Proxy database.
type IP2Proxyrecord struct {
	Country_short string
	Country_long  string
	Region        string
	City          string
	Isp           string
	Proxy_type    string
	Domain        string
	Usage_type    string
	Asn           string
	As            string
	Last_seen     string
	Threat        string
	Is_proxy      int8
}

type DB struct {
	f    *os.File
	meta ip2proxymeta

	country_position_offset   uint32
	region_position_offset    uint32
	city_position_offset      uint32
	isp_position_offset       uint32
	proxytype_position_offset uint32
	domain_position_offset    uint32
	usagetype_position_offset uint32
	asn_position_offset       uint32
	as_position_offset        uint32
	lastseen_position_offset  uint32
	threat_position_offset    uint32

	country_enabled   bool
	region_enabled    bool
	city_enabled      bool
	isp_enabled       bool
	proxytype_enabled bool
	domain_enabled    bool
	usagetype_enabled bool
	asn_enabled       bool
	as_enabled        bool
	lastseen_enabled  bool
	threat_enabled    bool

	metaok bool
}

var defaultDB = &DB{}

var country_position = [11]uint8{0, 2, 3, 3, 3, 3, 3, 3, 3, 3, 3}
var region_position = [11]uint8{0, 0, 0, 4, 4, 4, 4, 4, 4, 4, 4}
var city_position = [11]uint8{0, 0, 0, 5, 5, 5, 5, 5, 5, 5, 5}
var isp_position = [11]uint8{0, 0, 0, 0, 6, 6, 6, 6, 6, 6, 6}
var proxytype_position = [11]uint8{0, 0, 2, 2, 2, 2, 2, 2, 2, 2, 2}
var domain_position = [11]uint8{0, 0, 0, 0, 0, 7, 7, 7, 7, 7, 7}
var usagetype_position = [11]uint8{0, 0, 0, 0, 0, 0, 8, 8, 8, 8, 8}
var asn_position = [11]uint8{0, 0, 0, 0, 0, 0, 0, 9, 9, 9, 9}
var as_position = [11]uint8{0, 0, 0, 0, 0, 0, 0, 10, 10, 10, 10}
var lastseen_position = [11]uint8{0, 0, 0, 0, 0, 0, 0, 0, 11, 11, 11}
var threat_position = [11]uint8{0, 0, 0, 0, 0, 0, 0, 0, 0, 12, 12}

const module_version string = "3.0.0"

var max_ipv4_range = big.NewInt(4294967295)
var max_ipv6_range = big.NewInt(0)
var from_v4mapped = big.NewInt(281470681743360)
var to_v4mapped = big.NewInt(281474976710655)
var from_6to4 = big.NewInt(0)
var to_6to4 = big.NewInt(0)
var from_teredo = big.NewInt(0)
var to_teredo = big.NewInt(0)
var last_32bits = big.NewInt(4294967295)

const countryshort uint32 = 0x00001
const countrylong uint32 = 0x00002
const region uint32 = 0x00004
const city uint32 = 0x00008
const isp uint32 = 0x00010
const proxytype uint32 = 0x00020
const isproxy uint32 = 0x00040
const domain uint32 = 0x00080
const usagetype uint32 = 0x00100
const asn uint32 = 0x00200
const as uint32 = 0x00400
const lastseen uint32 = 0x00800
const threat uint32 = 0x01000

const all uint32 = countryshort | countrylong | region | city | isp | proxytype | isproxy | domain | usagetype | asn | as | lastseen | threat

const msg_not_supported string = "NOT SUPPORTED"
const msg_invalid_ip string = "INVALID IP ADDRESS"
const msg_missing_file string = "MISSING FILE"
const msg_ipv6_unsupported string = "IPV6 ADDRESS MISSING IN IPV4 BIN"

// get IP type and calculate IP number; calculates index too if exists
func (d *DB) checkip(ip string) (iptype uint32, ipnum *big.Int, ipindex uint32) {
	iptype = 0
	ipnum = big.NewInt(0)
	ipnumtmp := big.NewInt(0)
	ipindex = 0
	ipaddress := net.ParseIP(ip)

	if ipaddress != nil {
		v4 := ipaddress.To4()

		if v4 != nil {
			iptype = 4
			ipnum.SetBytes(v4)
		} else {
			v6 := ipaddress.To16()

			if v6 != nil {
				iptype = 6
				ipnum.SetBytes(v6)

				if ipnum.Cmp(from_v4mapped) >= 0 && ipnum.Cmp(to_v4mapped) <= 0 {
					// ipv4-mapped ipv6 should treat as ipv4 and read ipv4 data section
					iptype = 4
					ipnum.Sub(ipnum, from_v4mapped)
				} else if ipnum.Cmp(from_6to4) >= 0 && ipnum.Cmp(to_6to4) <= 0 {
					// 6to4 so need to remap to ipv4
					iptype = 4
					ipnum.Rsh(ipnum, 80)
					ipnum.And(ipnum, last_32bits)
				} else if ipnum.Cmp(from_teredo) >= 0 && ipnum.Cmp(to_teredo) <= 0 {
					// Teredo so need to remap to ipv4
					iptype = 4
					ipnum.Not(ipnum)
					ipnum.And(ipnum, last_32bits)
				}
			}
		}
	}
	if iptype == 4 {
		if d.meta.ipv4indexbaseaddr > 0 {
			ipnumtmp.Rsh(ipnum, 16)
			ipnumtmp.Lsh(ipnumtmp, 3)
			ipindex = uint32(ipnumtmp.Add(ipnumtmp, big.NewInt(int64(d.meta.ipv4indexbaseaddr))).Uint64())
		}
	} else if iptype == 6 {
		if d.meta.ipv6indexbaseaddr > 0 {
			ipnumtmp.Rsh(ipnum, 112)
			ipnumtmp.Lsh(ipnumtmp, 3)
			ipindex = uint32(ipnumtmp.Add(ipnumtmp, big.NewInt(int64(d.meta.ipv6indexbaseaddr))).Uint64())
		}
	}
	return
}

// read byte
func (d *DB) readuint8(pos int64) (uint8, error) {
	var retval uint8
	data := make([]byte, 1)
	_, err := d.f.ReadAt(data, pos-1)
	if err != nil {
		return 0, err
	}
	retval = data[0]
	return retval, nil
}

// read unsigned 32-bit integer from slices
func (d *DB) readuint32_row(row []byte, pos uint32) uint32 {
	var retval uint32
	data := row[pos : pos+4]
	retval = binary.LittleEndian.Uint32(data)
	return retval
}

// read unsigned 32-bit integer
func (d *DB) readuint32(pos uint32) (uint32, error) {
	pos2 := int64(pos)
	var retval uint32
	data := make([]byte, 4)
	_, err := d.f.ReadAt(data, pos2-1)
	if err != nil {
		return 0, err
	}
	buf := bytes.NewReader(data)
	err = binary.Read(buf, binary.LittleEndian, &retval)
	if err != nil {
		fmt.Printf("binary read failed: %v", err)
	}
	return retval, nil
}

// read unsigned 128-bit integer
func (d *DB) readuint128(pos uint32) (*big.Int, error) {
	pos2 := int64(pos)
	retval := big.NewInt(0)
	data := make([]byte, 16)
	_, err := d.f.ReadAt(data, pos2-1)
	if err != nil {
		return nil, err
	}

	// little endian to big endian
	for i, j := 0, len(data)-1; i < j; i, j = i+1, j-1 {
		data[i], data[j] = data[j], data[i]
	}
	retval.SetBytes(data)
	return retval, nil
}

// read string
func (d *DB) readstr(pos uint32) (string, error) {
	pos2 := int64(pos)
	var retval string
	lenbyte := make([]byte, 1)
	_, err := d.f.ReadAt(lenbyte, pos2)
	if err != nil {
		return "", err
	}
	strlen := lenbyte[0]
	data := make([]byte, strlen)
	_, err = d.f.ReadAt(data, pos2+1)
	if err != nil {
		return "", err
	}
	retval = string(data[:strlen])
	return retval, nil
}

// read float from slices
func (d *DB) readfloat_row(row []byte, pos uint32) float32 {
	var retval float32
	data := row[pos : pos+4]
	bits := binary.LittleEndian.Uint32(data)
	retval = math.Float32frombits(bits)
	return retval
}

// read float
func (d *DB) readfloat(pos uint32) (float32, error) {
	pos2 := int64(pos)
	var retval float32
	data := make([]byte, 4)
	_, err := d.f.ReadAt(data, pos2-1)
	if err != nil {
		return 0, err
	}
	buf := bytes.NewReader(data)
	err = binary.Read(buf, binary.LittleEndian, &retval)
	if err != nil {
		fmt.Printf("binary read failed: %v", err)
	}
	return retval, nil
}

func fatal(db *DB, err error) (*DB, error) {
	_ = db.f.Close()
	return nil, err
}

// OpenDB takes the path to the IP2Proxy BIN database file. It will read all the metadata required to
// be able to extract the embedded proxy data, and return the underlining DB object.
func OpenDB(dbpath string) (*DB, error) {
	var db = &DB{}

	max_ipv6_range.SetString("340282366920938463463374607431768211455", 10)
	from_6to4.SetString("42545680458834377588178886921629466624", 10)
	to_6to4.SetString("42550872755692912415807417417958686719", 10)
	from_teredo.SetString("42540488161975842760550356425300246528", 10)
	to_teredo.SetString("42540488241204005274814694018844196863", 10)

	var err error
	db.f, err = os.Open(dbpath)
	if err != nil {
		return nil, err
	}

	db.meta.databasetype, err = db.readuint8(1)
	if err != nil {
		return fatal(db, err)
	}
	db.meta.databasecolumn, err = db.readuint8(2)
	if err != nil {
		return fatal(db, err)
	}
	db.meta.databaseyear, err = db.readuint8(3)
	if err != nil {
		return fatal(db, err)
	}
	db.meta.databasemonth, err = db.readuint8(4)
	if err != nil {
		return fatal(db, err)
	}
	db.meta.databaseday, err = db.readuint8(5)
	if err != nil {
		return fatal(db, err)
	}
	db.meta.ipv4databasecount, err = db.readuint32(6)
	if err != nil {
		return fatal(db, err)
	}
	db.meta.ipv4databaseaddr, err = db.readuint32(10)
	if err != nil {
		return fatal(db, err)
	}
	db.meta.ipv6databasecount, err = db.readuint32(14)
	if err != nil {
		return fatal(db, err)
	}
	db.meta.ipv6databaseaddr, err = db.readuint32(18)
	if err != nil {
		return fatal(db, err)
	}
	db.meta.ipv4indexbaseaddr, err = db.readuint32(22)
	if err != nil {
		return fatal(db, err)
	}
	db.meta.ipv6indexbaseaddr, err = db.readuint32(26)
	if err != nil {
		return fatal(db, err)
	}
	db.meta.ipv4columnsize = uint32(db.meta.databasecolumn << 2)              // 4 bytes each column
	db.meta.ipv6columnsize = uint32(16 + ((db.meta.databasecolumn - 1) << 2)) // 4 bytes each column, except IPFrom column which is 16 bytes

	dbt := db.meta.databasetype

	if country_position[dbt] != 0 {
		db.country_position_offset = uint32(country_position[dbt]-2) << 2
		db.country_enabled = true
	}
	if region_position[dbt] != 0 {
		db.region_position_offset = uint32(region_position[dbt]-2) << 2
		db.region_enabled = true
	}
	if city_position[dbt] != 0 {
		db.city_position_offset = uint32(city_position[dbt]-2) << 2
		db.city_enabled = true
	}
	if isp_position[dbt] != 0 {
		db.isp_position_offset = uint32(isp_position[dbt]-2) << 2
		db.isp_enabled = true
	}
	if proxytype_position[dbt] != 0 {
		db.proxytype_position_offset = uint32(proxytype_position[dbt]-2) << 2
		db.proxytype_enabled = true
	}
	if domain_position[dbt] != 0 {
		db.domain_position_offset = uint32(domain_position[dbt]-2) << 2
		db.domain_enabled = true
	}
	if usagetype_position[dbt] != 0 {
		db.usagetype_position_offset = uint32(usagetype_position[dbt]-2) << 2
		db.usagetype_enabled = true
	}
	if asn_position[dbt] != 0 {
		db.asn_position_offset = uint32(asn_position[dbt]-2) << 2
		db.asn_enabled = true
	}
	if as_position[dbt] != 0 {
		db.as_position_offset = uint32(as_position[dbt]-2) << 2
		db.as_enabled = true
	}
	if lastseen_position[dbt] != 0 {
		db.lastseen_position_offset = uint32(lastseen_position[dbt]-2) << 2
		db.lastseen_enabled = true
	}
	if threat_position[dbt] != 0 {
		db.threat_position_offset = uint32(threat_position[dbt]-2) << 2
		db.threat_enabled = true
	}

	db.metaok = true

	return db, nil
}

// Open takes the path to the IP2Proxy BIN database file. It will read all the metadata required to
// be able to extract the embedded proxy data.
//
// Deprecated: No longer being updated.
func Open(dbpath string) int8 {
	db, err := OpenDB(dbpath)
	if err != nil {
		return -1
	}
	defaultDB = db
	return 0
}

// Close will close the file handle to the BIN file and reset.
//
// Deprecated: No longer being updated.
func Close() int8 {
	defaultDB.meta.databasetype = 0
	defaultDB.meta.databasecolumn = 0
	defaultDB.meta.databaseyear = 0
	defaultDB.meta.databasemonth = 0
	defaultDB.meta.databaseday = 0
	defaultDB.meta.ipv4databasecount = 0
	defaultDB.meta.ipv4databaseaddr = 0
	defaultDB.meta.ipv6databasecount = 0
	defaultDB.meta.ipv6databaseaddr = 0
	defaultDB.meta.ipv4indexbaseaddr = 0
	defaultDB.meta.ipv6indexbaseaddr = 0
	defaultDB.meta.ipv4columnsize = 0
	defaultDB.meta.ipv6columnsize = 0
	defaultDB.metaok = false
	defaultDB.country_position_offset = 0
	defaultDB.region_position_offset = 0
	defaultDB.city_position_offset = 0
	defaultDB.isp_position_offset = 0
	defaultDB.proxytype_position_offset = 0
	defaultDB.domain_position_offset = 0
	defaultDB.usagetype_position_offset = 0
	defaultDB.asn_position_offset = 0
	defaultDB.as_position_offset = 0
	defaultDB.lastseen_position_offset = 0
	defaultDB.country_enabled = false
	defaultDB.region_enabled = false
	defaultDB.city_enabled = false
	defaultDB.isp_enabled = false
	defaultDB.proxytype_enabled = false
	defaultDB.domain_enabled = false
	defaultDB.usagetype_enabled = false
	defaultDB.asn_enabled = false
	defaultDB.as_enabled = false
	defaultDB.lastseen_enabled = false

	err := defaultDB.Close()

	if err != nil {
		return -1
	} else {
		return 0
	}
}

// ModuleVersion returns the version of the component.
func ModuleVersion() string {
	return module_version
}

// PackageVersion returns the database type.
//
// Deprecated: No longer being updated.
func PackageVersion() string {
	return strconv.Itoa(int(defaultDB.meta.databasetype))
}

// DatabaseVersion returns the database version.
//
// Deprecated: No longer being updated.
func DatabaseVersion() string {
	return "20" + strconv.Itoa(int(defaultDB.meta.databaseyear)) + "." + strconv.Itoa(int(defaultDB.meta.databasemonth)) + "." + strconv.Itoa(int(defaultDB.meta.databaseday))
}

// PackageVersion returns the database type.
func (d *DB) PackageVersion() string {
	return strconv.Itoa(int(d.meta.databasetype))
}

// DatabaseVersion returns the database version.
func (d *DB) DatabaseVersion() string {
	return "20" + strconv.Itoa(int(d.meta.databaseyear)) + "." + strconv.Itoa(int(d.meta.databasemonth)) + "." + strconv.Itoa(int(d.meta.databaseday))
}

// populate record with message
func loadmessage(mesg string) IP2Proxyrecord {
	var x IP2Proxyrecord

	x.Country_short = mesg
	x.Country_long = mesg
	x.Region = mesg
	x.City = mesg
	x.Isp = mesg
	x.Proxy_type = mesg
	x.Domain = mesg
	x.Usage_type = mesg
	x.Asn = mesg
	x.As = mesg
	x.Last_seen = mesg
	x.Threat = mesg
	x.Is_proxy = -1

	return x
}

func handleError(rec IP2Proxyrecord, err error) IP2Proxyrecord {
	if err != nil {
		fmt.Print(err)
	}
	return rec
}

// GetAll will return all proxy fields based on the queried IP address.
//
// Deprecated: No longer being updated.
func GetAll(ipaddress string) map[string]string {
	data := handleError(defaultDB.query(ipaddress, all))

	var x = make(map[string]string)
	s := strconv.Itoa(int(data.Is_proxy))
	x["isProxy"] = s
	x["ProxyType"] = data.Proxy_type
	x["CountryShort"] = data.Country_short
	x["CountryLong"] = data.Country_long
	x["Region"] = data.Region
	x["City"] = data.City
	x["ISP"] = data.Isp
	x["Domain"] = data.Domain
	x["UsageType"] = data.Usage_type
	x["ASN"] = data.Asn
	x["AS"] = data.As
	x["LastSeen"] = data.Last_seen

	return x
}

// GetCountryShort will return the ISO-3166 country code based on the queried IP address.
//
// Deprecated: No longer being updated.
func GetCountryShort(ipaddress string) string {
	data := handleError(defaultDB.query(ipaddress, countryshort))
	return data.Country_short
}

// GetCountryLong will return the country name based on the queried IP address.
//
// Deprecated: No longer being updated.
func GetCountryLong(ipaddress string) string {
	data := handleError(defaultDB.query(ipaddress, countrylong))
	return data.Country_long
}

// GetRegion will return the region name based on the queried IP address.
//
// Deprecated: No longer being updated.
func GetRegion(ipaddress string) string {
	data := handleError(defaultDB.query(ipaddress, region))
	return data.Region
}

// GetCity will return the city name based on the queried IP address.
//
// Deprecated: No longer being updated.
func GetCity(ipaddress string) string {
	data := handleError(defaultDB.query(ipaddress, city))
	return data.City
}

// GetIsp will return the Internet Service Provider name based on the queried IP address.
//
// Deprecated: No longer being updated.
func GetIsp(ipaddress string) string {
	data := handleError(defaultDB.query(ipaddress, isp))
	return data.Isp
}

// GetProxyType will return the proxy type based on the queried IP address.
//
// Deprecated: No longer being updated.
func GetProxyType(ipaddress string) string {
	data := handleError(defaultDB.query(ipaddress, proxytype))
	return data.Proxy_type
}

// GetDomain will return the domain name based on the queried IP address.
//
// Deprecated: No longer being updated.
func GetDomain(ipaddress string) string {
	data := handleError(defaultDB.query(ipaddress, domain))
	return data.Domain
}

// GetUsageType will return the usage type based on the queried IP address.
//
// Deprecated: No longer being updated.
func GetUsageType(ipaddress string) string {
	data := handleError(defaultDB.query(ipaddress, usagetype))
	return data.Usage_type
}

// GetAsn will return the autonomous system number based on the queried IP address.
//
// Deprecated: No longer being updated.
func GetAsn(ipaddress string) string {
	data := handleError(defaultDB.query(ipaddress, asn))
	return data.Asn
}

// GetAs will return the autonomous system name based on the queried IP address.
//
// Deprecated: No longer being updated.
func GetAs(ipaddress string) string {
	data := handleError(defaultDB.query(ipaddress, as))
	return data.As
}

// GetLastSeen will return the number of days that the proxy was last seen based on the queried IP address.
//
// Deprecated: No longer being updated.
func GetLastSeen(ipaddress string) string {
	data := handleError(defaultDB.query(ipaddress, lastseen))
	return data.Last_seen
}

// IsProxy checks whether the queried IP address was a proxy. Returned value: -1 (errors), 0 (not a proxy), 1 (a proxy), 2 (a data center IP address or search engine robot).
//
// Deprecated: No longer being updated.
func IsProxy(ipaddress string) int8 {
	data := handleError(defaultDB.query(ipaddress, isproxy))
	return data.Is_proxy
}

// GetAll will return all proxy fields based on the queried IP address.
func (d *DB) GetAll(ipaddress string) (map[string]string, error) {
	data, err := d.query(ipaddress, all)

	var x = make(map[string]string)
	s := strconv.Itoa(int(data.Is_proxy))
	x["isProxy"] = s
	x["ProxyType"] = data.Proxy_type
	x["CountryShort"] = data.Country_short
	x["CountryLong"] = data.Country_long
	x["Region"] = data.Region
	x["City"] = data.City
	x["ISP"] = data.Isp
	x["Domain"] = data.Domain
	x["UsageType"] = data.Usage_type
	x["ASN"] = data.Asn
	x["AS"] = data.As
	x["LastSeen"] = data.Last_seen
	x["Threat"] = data.Threat

	return x, err
}

// GetCountryShort will return the ISO-3166 country code based on the queried IP address.
func (d *DB) GetCountryShort(ipaddress string) (string, error) {
	data, err := d.query(ipaddress, countryshort)
	return data.Country_short, err
}

// GetCountryLong will return the country name based on the queried IP address.
func (d *DB) GetCountryLong(ipaddress string) (string, error) {
	data, err := d.query(ipaddress, countrylong)
	return data.Country_long, err
}

// GetRegion will return the region name based on the queried IP address.
func (d *DB) GetRegion(ipaddress string) (string, error) {
	data, err := d.query(ipaddress, region)
	return data.Region, err
}

// GetCity will return the city name based on the queried IP address.
func (d *DB) GetCity(ipaddress string) (string, error) {
	data, err := d.query(ipaddress, city)
	return data.City, err
}

// GetIsp will return the Internet Service Provider name based on the queried IP address.
func (d *DB) GetIsp(ipaddress string) (string, error) {
	data, err := d.query(ipaddress, isp)
	return data.Isp, err
}

// GetProxyType will return the proxy type based on the queried IP address.
func (d *DB) GetProxyType(ipaddress string) (string, error) {
	data, err := d.query(ipaddress, proxytype)
	return data.Proxy_type, err
}

// GetDomain will return the domain name based on the queried IP address.
func (d *DB) GetDomain(ipaddress string) (string, error) {
	data, err := d.query(ipaddress, domain)
	return data.Domain, err
}

// GetUsageType will return the usage type based on the queried IP address.
func (d *DB) GetUsageType(ipaddress string) (string, error) {
	data, err := d.query(ipaddress, usagetype)
	return data.Usage_type, err
}

// GetAsn will return the autonomous system number based on the queried IP address.
func (d *DB) GetAsn(ipaddress string) (string, error) {
	data, err := d.query(ipaddress, asn)
	return data.Asn, err
}

// GetAs will return the autonomous system name based on the queried IP address.
func (d *DB) GetAs(ipaddress string) (string, error) {
	data, err := d.query(ipaddress, as)
	return data.As, err
}

// GetLastSeen will return the number of days that the proxy was last seen based on the queried IP address.
func (d *DB) GetLastSeen(ipaddress string) (string, error) {
	data, err := d.query(ipaddress, lastseen)
	return data.Last_seen, err
}

// GetThreat will return the threat type of the proxy.
func (d *DB) GetThreat(ipaddress string) (string, error) {
	data, err := d.query(ipaddress, threat)
	return data.Threat, err
}

// IsProxy checks whether the queried IP address was a proxy. Returned value: -1 (errors), 0 (not a proxy), 1 (a proxy), 2 (a data center IP address or search engine robot).
func (d *DB) IsProxy(ipaddress string) (int8, error) {
	data, err := d.query(ipaddress, isproxy)
	return data.Is_proxy, err
}

// main query
func (d *DB) query(ipaddress string, mode uint32) (IP2Proxyrecord, error) {
	x := loadmessage(msg_not_supported) // default message

	// read metadata
	if !d.metaok {
		x = loadmessage(msg_missing_file)
		return x, nil
	}

	// check IP type and return IP number & index (if exists)
	iptype, ipno, ipindex := d.checkip(ipaddress)

	if iptype == 0 {
		x = loadmessage(msg_invalid_ip)
		return x, nil
	}

	var err error
	var colsize uint32
	var baseaddr uint32
	var low uint32
	var high uint32
	var mid uint32
	var rowoffset uint32
	var rowoffset2 uint32
	var countrypos uint32
	ipfrom := big.NewInt(0)
	ipto := big.NewInt(0)
	maxip := big.NewInt(0)

	if iptype == 4 {
		baseaddr = d.meta.ipv4databaseaddr
		high = d.meta.ipv4databasecount
		maxip = max_ipv4_range
		colsize = d.meta.ipv4columnsize
	} else {
		if d.meta.ipv6databasecount == 0 {
			x = loadmessage(msg_ipv6_unsupported)
			return x, nil
		}
		baseaddr = d.meta.ipv6databaseaddr
		high = d.meta.ipv6databasecount
		maxip = max_ipv6_range
		colsize = d.meta.ipv6columnsize
	}

	// reading index
	if ipindex > 0 {
		low, err = d.readuint32(ipindex)
		if err != nil {
			return x, err
		}
		high, err = d.readuint32(ipindex + 4)
		if err != nil {
			return x, err
		}
	}

	if ipno.Cmp(maxip) >= 0 {
		ipno.Sub(ipno, big.NewInt(1))
	}

	for low <= high {
		mid = ((low + high) >> 1)
		rowoffset = baseaddr + (mid * colsize)
		rowoffset2 = rowoffset + colsize

		if iptype == 4 {
			ipfrom32, err := d.readuint32(rowoffset)
			if err != nil {
				return x, err
			}
			ipfrom = big.NewInt(int64(ipfrom32))

			ipto32, err := d.readuint32(rowoffset2)
			if err != nil {
				return x, err
			}
			ipto = big.NewInt(int64(ipto32))
		} else {
			ipfrom, err = d.readuint128(rowoffset)
			if err != nil {
				return x, err
			}

			ipto, err = d.readuint128(rowoffset2)
			if err != nil {
				return x, err
			}
		}

		if ipno.Cmp(ipfrom) >= 0 && ipno.Cmp(ipto) < 0 {
			var firstcol uint32 = 4 // 4 bytes for ip from
			if iptype == 6 {
				firstcol = 16 // 16 bytes for ipv6
				// rowoffset = rowoffset + 12 // coz below is assuming all columns are 4 bytes, so got 12 left to go to make 16 bytes total
			}

			row := make([]byte, colsize-firstcol) // exclude the ip from field
			_, err := d.f.ReadAt(row, int64(rowoffset+firstcol-1))
			if err != nil {
				return x, err
			}

			if d.proxytype_enabled {
				if mode&proxytype != 0 || mode&isproxy != 0 {
					// x.Proxy_type = readstr(readuint32(rowoffset + proxytype_position_offset))
					// x.Proxy_type = readstr(readuint32_row(row, proxytype_position_offset))
					if x.Proxy_type, err = d.readstr(d.readuint32_row(row, d.proxytype_position_offset)); err != nil {
						return x, err
					}
				}
			}

			if d.country_enabled {
				if mode&countryshort != 0 || mode&countrylong != 0 || mode&isproxy != 0 {
					// countrypos = readuint32(rowoffset + country_position_offset)
					// countrypos = readuint32_row(row, country_position_offset)
					countrypos = d.readuint32_row(row, d.country_position_offset)
				}
				if mode&countryshort != 0 || mode&isproxy != 0 {
					// x.Country_short = readstr(countrypos)
					if x.Country_short, err = d.readstr(countrypos); err != nil {
						return x, err
					}
				}
				if mode&countrylong != 0 {
					// x.Country_long = readstr(countrypos + 3)
					if x.Country_long, err = d.readstr(countrypos + 3); err != nil {
						return x, err
					}
				}
			}

			if mode&region != 0 && d.region_enabled {
				// x.Region = readstr(readuint32(rowoffset + region_position_offset))
				// x.Region = readstr(readuint32_row(row, region_position_offset))
				if x.Region, err = d.readstr(d.readuint32_row(row, d.region_position_offset)); err != nil {
					return x, err
				}
			}

			if mode&city != 0 && d.city_enabled {
				// x.City = readstr(readuint32(rowoffset + city_position_offset))
				// x.City = readstr(readuint32_row(row, city_position_offset))
				if x.City, err = d.readstr(d.readuint32_row(row, d.city_position_offset)); err != nil {
					return x, err
				}
			}

			if mode&isp != 0 && d.isp_enabled {
				// x.Isp = readstr(readuint32(rowoffset + isp_position_offset))
				// x.Isp = readstr(readuint32_row(row, isp_position_offset))
				if x.Isp, err = d.readstr(d.readuint32_row(row, d.isp_position_offset)); err != nil {
					return x, err
				}
			}

			if mode&domain != 0 && d.domain_enabled {
				// x.Domain = readstr(readuint32(rowoffset + domain_position_offset))
				// x.Domain = readstr(readuint32_row(row, domain_position_offset))
				if x.Domain, err = d.readstr(d.readuint32_row(row, d.domain_position_offset)); err != nil {
					return x, err
				}
			}

			if mode&usagetype != 0 && d.usagetype_enabled {
				// x.Usage_type = readstr(readuint32(rowoffset + usagetype_position_offset))
				// x.Usage_type = readstr(readuint32_row(row, usagetype_position_offset))
				if x.Usage_type, err = d.readstr(d.readuint32_row(row, d.usagetype_position_offset)); err != nil {
					return x, err
				}
			}

			if mode&asn != 0 && d.asn_enabled {
				// x.Asn = readstr(readuint32(rowoffset + asn_position_offset))
				// x.Asn = readstr(readuint32_row(row, asn_position_offset))
				if x.Asn, err = d.readstr(d.readuint32_row(row, d.asn_position_offset)); err != nil {
					return x, err
				}
			}

			if mode&as != 0 && d.as_enabled {
				// x.As = readstr(readuint32(rowoffset + as_position_offset))
				// x.As = readstr(readuint32_row(row, as_position_offset))
				if x.As, err = d.readstr(d.readuint32_row(row, d.as_position_offset)); err != nil {
					return x, err
				}
			}

			if mode&lastseen != 0 && d.lastseen_enabled {
				// x.Last_seen = readstr(readuint32(rowoffset + lastseen_position_offset))
				// x.Last_seen = readstr(readuint32_row(row, lastseen_position_offset))
				if x.Last_seen, err = d.readstr(d.readuint32_row(row, d.lastseen_position_offset)); err != nil {
					return x, err
				}
			}

			if mode&threat != 0 && d.threat_enabled {
				// x.Threat = readstr(readuint32(rowoffset + threat_position_offset))
				// x.Threat = readstr(readuint32_row(row, threat_position_offset))
				if x.Threat, err = d.readstr(d.readuint32_row(row, d.threat_position_offset)); err != nil {
					return x, err
				}
			}

			if x.Country_short == "-" || x.Proxy_type == "-" {
				x.Is_proxy = 0
			} else {
				if x.Proxy_type == "DCH" || x.Proxy_type == "SES" {
					x.Is_proxy = 2
				} else {
					x.Is_proxy = 1
				}
			}

			return x, nil
		} else {
			if ipno.Cmp(ipfrom) < 0 {
				high = mid - 1
			} else {
				low = mid + 1
			}
		}
	}
	return x, nil
}

func (d *DB) Close() error {
	err := d.f.Close()
	return err
}

// Printrecord is used to output the proxy data for debugging purposes.
func Printrecord(x IP2Proxyrecord) {
	fmt.Printf("country_short: %s\n", x.Country_short)
	fmt.Printf("country_long: %s\n", x.Country_long)
	fmt.Printf("region: %s\n", x.Region)
	fmt.Printf("city: %s\n", x.City)
	fmt.Printf("isp: %s\n", x.Isp)
	fmt.Printf("proxy_type: %s\n", x.Proxy_type)
	fmt.Printf("domain: %s\n", x.Domain)
	fmt.Printf("usage_type: %s\n", x.Usage_type)
	fmt.Printf("asn: %s\n", x.Asn)
	fmt.Printf("as: %s\n", x.As)
	fmt.Printf("last_seen: %s\n", x.Last_seen)
	fmt.Printf("threat: %s\n", x.Threat)
	fmt.Printf("is_proxy: %d\n", x.Is_proxy)
}
