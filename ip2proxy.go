// Package ip2proxy allows user to query an IP address if it was being used as
// VPN anonymizer, open proxies, web proxies, Tor exits, data center,
// web hosting (DCH) range, search engine robots (SES) and residential (RES)
// by using the IP2Proxy database.
package ip2proxy

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"os"
	"strconv"
)

// Implement db reader interface
type dbReader interface {
	io.ReadCloser
	io.ReaderAt
}

type ip2proxyMeta struct {
	databaseType      uint8
	databaseColumn    uint8
	databaseDay       uint8
	databaseMonth     uint8
	databaseYear      uint8
	ipV4DatabaseCount uint32
	ipV4DatabaseAddr  uint32
	ipV6DatabaseCount uint32
	ipV6DatabaseAddr  uint32
	ipV4Indexed       bool
	ipV6Indexed       bool
	ipV4IndexBaseAddr uint32
	ipV6IndexBaseAddr uint32
	ipV4ColumnSize    uint32
	ipV6ColumnSize    uint32
	productCode       uint8
	productType       uint8
	fileSize          uint32
}

// The ip2proxyRecord struct stores all of the available
// proxy info found in the IP2Proxy database.
type ip2proxyRecord struct {
	countryShort string
	countryLong  string
	region       string
	city         string
	isp          string
	proxyType    string
	domain       string
	usageType    string
	asn          string
	as           string
	lastSeen     string
	threat       string
	provider     string
	isProxy      int8
}

// The DB struct is the main object used to query the IP2Proxy BIN file.
type DB struct {
	f    dbReader
	meta ip2proxyMeta

	countryPositionOffset   uint32
	regionPositionOffset    uint32
	cityPositionOffset      uint32
	ispPositionOffset       uint32
	proxyTypePositionOffset uint32
	domainPositionOffset    uint32
	usageTypePositionOffset uint32
	asnPositionOffset       uint32
	asPositionOffset        uint32
	lastSeenPositionOffset  uint32
	threatPositionOffset    uint32
	providerPositionOffset  uint32

	countryEnabled   bool
	regionEnabled    bool
	cityEnabled      bool
	ispEnabled       bool
	proxyTypeEnabled bool
	domainEnabled    bool
	usageTypeEnabled bool
	asnEnabled       bool
	asEnabled        bool
	lastSeenEnabled  bool
	threatEnabled    bool
	providerEnabled  bool

	metaOK bool
}

var defaultDB = &DB{}

var countryPosition = [12]uint8{0, 2, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3}
var regionPosition = [12]uint8{0, 0, 0, 4, 4, 4, 4, 4, 4, 4, 4, 4}
var cityPosition = [12]uint8{0, 0, 0, 5, 5, 5, 5, 5, 5, 5, 5, 5}
var ispPosition = [12]uint8{0, 0, 0, 0, 6, 6, 6, 6, 6, 6, 6, 6}
var proxyTypePosition = [12]uint8{0, 0, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2}
var domainPosition = [12]uint8{0, 0, 0, 0, 0, 7, 7, 7, 7, 7, 7, 7}
var usageTypePosition = [12]uint8{0, 0, 0, 0, 0, 0, 8, 8, 8, 8, 8, 8}
var asnPosition = [12]uint8{0, 0, 0, 0, 0, 0, 0, 9, 9, 9, 9, 9}
var asPosition = [12]uint8{0, 0, 0, 0, 0, 0, 0, 10, 10, 10, 10, 10}
var lastSeenPosition = [12]uint8{0, 0, 0, 0, 0, 0, 0, 0, 11, 11, 11, 11}
var threatPosition = [12]uint8{0, 0, 0, 0, 0, 0, 0, 0, 0, 12, 12, 12}
var providerPosition = [12]uint8{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 13}

const moduleVersion string = "3.4.0"

var maxIPV4Range = big.NewInt(4294967295)
var maxIPV6Range = big.NewInt(0)
var fromV4Mapped = big.NewInt(281470681743360)
var toV4Mapped = big.NewInt(281474976710655)
var from6To4 = big.NewInt(0)
var to6To4 = big.NewInt(0)
var fromTeredo = big.NewInt(0)
var toTeredo = big.NewInt(0)
var last32Bits = big.NewInt(4294967295)

const countryShort uint32 = 0x00001
const countryLong uint32 = 0x00002
const region uint32 = 0x00004
const city uint32 = 0x00008
const isp uint32 = 0x00010
const proxyType uint32 = 0x00020
const isProxy uint32 = 0x00040
const domain uint32 = 0x00080
const usageType uint32 = 0x00100
const asn uint32 = 0x00200
const as uint32 = 0x00400
const lastSeen uint32 = 0x00800
const threat uint32 = 0x01000
const provider uint32 = 0x02000

const all uint32 = countryShort | countryLong | region | city | isp | proxyType | isProxy | domain | usageType | asn | as | lastSeen | threat | provider

const msgNotSupported string = "NOT SUPPORTED"
const msgInvalidIP string = "INVALID IP ADDRESS"
const msgMissingFile string = "MISSING FILE"
const msgIPV6Unsupported string = "IPV6 ADDRESS MISSING IN IPV4 BIN"
const msgInvalidBin string = "Incorrect IP2Proxy BIN file format. Please make sure that you are using the latest IP2Proxy BIN file."

// get IP type and calculate IP number; calculates index too if exists
func (d *DB) checkIP(ip string) (ipType uint32, ipNum *big.Int, ipIndex uint32) {
	ipType = 0
	ipNum = big.NewInt(0)
	ipNumTmp := big.NewInt(0)
	ipIndex = 0
	ipAddress := net.ParseIP(ip)

	if ipAddress != nil {
		v4 := ipAddress.To4()

		if v4 != nil {
			ipType = 4
			ipNum.SetBytes(v4)
		} else {
			v6 := ipAddress.To16()

			if v6 != nil {
				ipType = 6
				ipNum.SetBytes(v6)

				if ipNum.Cmp(fromV4Mapped) >= 0 && ipNum.Cmp(toV4Mapped) <= 0 {
					// ipv4-mapped ipv6 should treat as ipv4 and read ipv4 data section
					ipType = 4
					ipNum.Sub(ipNum, fromV4Mapped)
				} else if ipNum.Cmp(from6To4) >= 0 && ipNum.Cmp(to6To4) <= 0 {
					// 6to4 so need to remap to ipv4
					ipType = 4
					ipNum.Rsh(ipNum, 80)
					ipNum.And(ipNum, last32Bits)
				} else if ipNum.Cmp(fromTeredo) >= 0 && ipNum.Cmp(toTeredo) <= 0 {
					// Teredo so need to remap to ipv4
					ipType = 4
					ipNum.Not(ipNum)
					ipNum.And(ipNum, last32Bits)
				}
			}
		}
	}
	if ipType == 4 {
		if d.meta.ipV4Indexed {
			ipNumTmp.Rsh(ipNum, 16)
			ipNumTmp.Lsh(ipNumTmp, 3)
			ipIndex = uint32(ipNumTmp.Add(ipNumTmp, big.NewInt(int64(d.meta.ipV4IndexBaseAddr))).Uint64())
		}
	} else if ipType == 6 {
		if d.meta.ipV6Indexed {
			ipNumTmp.Rsh(ipNum, 112)
			ipNumTmp.Lsh(ipNumTmp, 3)
			ipIndex = uint32(ipNumTmp.Add(ipNumTmp, big.NewInt(int64(d.meta.ipV6IndexBaseAddr))).Uint64())
		}
	}
	return
}

// read byte
func (d *DB) readUint8(pos int64) (uint8, error) {
	var retVal uint8
	data := make([]byte, 1)
	_, err := d.f.ReadAt(data, pos-1)
	if err != nil {
		return 0, err
	}
	retVal = data[0]
	return retVal, nil
}

// read row
func (d *DB) readRow(pos uint32, size uint32) ([]byte, error) {
	pos2 := int64(pos)
	data := make([]byte, size)
	_, err := d.f.ReadAt(data, pos2-1)
	if err != nil {
		return nil, err
	}
	return data, nil
}

// read unsigned 32-bit integer from slices
func (d *DB) readUint32Row(row []byte, pos uint32) uint32 {
	var retVal uint32
	data := row[pos : pos+4]
	retVal = binary.LittleEndian.Uint32(data)
	return retVal
}

// read unsigned 32-bit integer
func (d *DB) readUint32(pos uint32) (uint32, error) {
	pos2 := int64(pos)
	var retVal uint32
	data := make([]byte, 4)
	_, err := d.f.ReadAt(data, pos2-1)
	if err != nil {
		return 0, err
	}
	buf := bytes.NewReader(data)
	err = binary.Read(buf, binary.LittleEndian, &retVal)
	if err != nil {
		fmt.Printf("binary read failed: %v", err)
	}
	return retVal, nil
}

// read unsigned 128-bit integer from slices
func (d *DB) readUint128Row(row []byte, pos uint32) *big.Int {
	retVal := big.NewInt(0)
	data := row[pos : pos+16]

	// little endian to big endian
	for i, j := 0, len(data)-1; i < j; i, j = i+1, j-1 {
		data[i], data[j] = data[j], data[i]
	}
	retVal.SetBytes(data)
	return retVal
}

// read unsigned 128-bit integer
func (d *DB) readUint128(pos uint32) (*big.Int, error) {
	pos2 := int64(pos)
	retVal := big.NewInt(0)
	data := make([]byte, 16)
	_, err := d.f.ReadAt(data, pos2-1)
	if err != nil {
		return nil, err
	}

	// little endian to big endian
	for i, j := 0, len(data)-1; i < j; i, j = i+1, j-1 {
		data[i], data[j] = data[j], data[i]
	}
	retVal.SetBytes(data)
	return retVal, nil
}

// read string
func (d *DB) readStr(pos uint32) (string, error) {
	pos2 := int64(pos)
	readLen := 256 // max size of string field + 1 byte for the length
	var retVal string
	data := make([]byte, readLen)
	_, err := d.f.ReadAt(data, pos2)
	if err != nil {
		return "", err
	}
	strLen := data[0]
	retVal = string(data[1:(strLen + 1)])
	return retVal, nil
}

func fatal(db *DB, err error) (*DB, error) {
	_ = db.f.Close()
	return nil, err
}

// OpenDB takes the path to the IP2Proxy BIN database file. It will read all the metadata required to
// be able to extract the embedded proxy data, and return the underlining DB object.
func OpenDB(dbPath string) (*DB, error) {
	f, err := os.Open(dbPath)
	if err != nil {
		return nil, err
	}

	return OpenDBWithReader(f)
}

// OpenDBWithReader takes a dbReader to the IP2Proxy BIN database file. It will read all the metadata required to
// be able to extract the embedded proxy data, and return the underlining DB object.
func OpenDBWithReader(reader dbReader) (*DB, error) {
	var db = &DB{}

	maxIPV6Range.SetString("340282366920938463463374607431768211455", 10)
	from6To4.SetString("42545680458834377588178886921629466624", 10)
	to6To4.SetString("42550872755692912415807417417958686719", 10)
	fromTeredo.SetString("42540488161975842760550356425300246528", 10)
	toTeredo.SetString("42540488241204005274814694018844196863", 10)

	db.f = reader

	var row []byte
	var err error
	readLen := uint32(64) // 64-byte header

	row, err = db.readRow(1, readLen)
	if err != nil {
		return fatal(db, err)
	}
	db.meta.databaseType = row[0]
	db.meta.databaseColumn = row[1]
	db.meta.databaseYear = row[2]
	db.meta.databaseMonth = row[3]
	db.meta.databaseDay = row[4]
	db.meta.ipV4DatabaseCount = db.readUint32Row(row, 5)
	db.meta.ipV4DatabaseAddr = db.readUint32Row(row, 9)
	db.meta.ipV6DatabaseCount = db.readUint32Row(row, 13)
	db.meta.ipV6DatabaseAddr = db.readUint32Row(row, 17)
	db.meta.ipV4IndexBaseAddr = db.readUint32Row(row, 21)
	db.meta.ipV6IndexBaseAddr = db.readUint32Row(row, 25)
	db.meta.productCode = row[29]
	db.meta.productType = row[30]
	db.meta.fileSize = db.readUint32Row(row, 31)

	// check if is correct BIN (should be 2 for IP2Proxy BIN file), also checking for zipped file (PK being the first 2 chars)
	if (db.meta.productCode != 2 && db.meta.databaseYear >= 21) || (db.meta.databaseType == 80 && db.meta.databaseColumn == 75) { // only BINs from Jan 2021 onwards have this byte set
		return fatal(db, errors.New(msgInvalidBin))
	}

	if db.meta.ipV4IndexBaseAddr > 0 {
		db.meta.ipV4Indexed = true
	}

	if db.meta.ipV6DatabaseCount > 0 && db.meta.ipV6IndexBaseAddr > 0 {
		db.meta.ipV6Indexed = true
	}

	db.meta.ipV4ColumnSize = uint32(db.meta.databaseColumn << 2)              // 4 bytes each column
	db.meta.ipV6ColumnSize = uint32(16 + ((db.meta.databaseColumn - 1) << 2)) // 4 bytes each column, except IPFrom column which is 16 bytes

	dbt := db.meta.databaseType

	if countryPosition[dbt] != 0 {
		db.countryPositionOffset = uint32(countryPosition[dbt]-2) << 2
		db.countryEnabled = true
	}
	if regionPosition[dbt] != 0 {
		db.regionPositionOffset = uint32(regionPosition[dbt]-2) << 2
		db.regionEnabled = true
	}
	if cityPosition[dbt] != 0 {
		db.cityPositionOffset = uint32(cityPosition[dbt]-2) << 2
		db.cityEnabled = true
	}
	if ispPosition[dbt] != 0 {
		db.ispPositionOffset = uint32(ispPosition[dbt]-2) << 2
		db.ispEnabled = true
	}
	if proxyTypePosition[dbt] != 0 {
		db.proxyTypePositionOffset = uint32(proxyTypePosition[dbt]-2) << 2
		db.proxyTypeEnabled = true
	}
	if domainPosition[dbt] != 0 {
		db.domainPositionOffset = uint32(domainPosition[dbt]-2) << 2
		db.domainEnabled = true
	}
	if usageTypePosition[dbt] != 0 {
		db.usageTypePositionOffset = uint32(usageTypePosition[dbt]-2) << 2
		db.usageTypeEnabled = true
	}
	if asnPosition[dbt] != 0 {
		db.asnPositionOffset = uint32(asnPosition[dbt]-2) << 2
		db.asnEnabled = true
	}
	if asPosition[dbt] != 0 {
		db.asPositionOffset = uint32(asPosition[dbt]-2) << 2
		db.asEnabled = true
	}
	if lastSeenPosition[dbt] != 0 {
		db.lastSeenPositionOffset = uint32(lastSeenPosition[dbt]-2) << 2
		db.lastSeenEnabled = true
	}
	if threatPosition[dbt] != 0 {
		db.threatPositionOffset = uint32(threatPosition[dbt]-2) << 2
		db.threatEnabled = true
	}
	if providerPosition[dbt] != 0 {
		db.providerPositionOffset = uint32(providerPosition[dbt]-2) << 2
		db.providerEnabled = true
	}

	db.metaOK = true

	return db, nil
}

// Open takes the path to the IP2Proxy BIN database file. It will read all the metadata required to
// be able to extract the embedded proxy data.
//
// Deprecated: No longer being updated.
func Open(dbPath string) int8 {
	db, err := OpenDB(dbPath)
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
	defaultDB.meta.databaseType = 0
	defaultDB.meta.databaseColumn = 0
	defaultDB.meta.databaseYear = 0
	defaultDB.meta.databaseMonth = 0
	defaultDB.meta.databaseDay = 0
	defaultDB.meta.ipV4DatabaseCount = 0
	defaultDB.meta.ipV4DatabaseAddr = 0
	defaultDB.meta.ipV6DatabaseCount = 0
	defaultDB.meta.ipV6DatabaseAddr = 0
	defaultDB.meta.ipV4IndexBaseAddr = 0
	defaultDB.meta.ipV6IndexBaseAddr = 0
	defaultDB.meta.ipV4ColumnSize = 0
	defaultDB.meta.ipV6ColumnSize = 0
	defaultDB.metaOK = false
	defaultDB.countryPositionOffset = 0
	defaultDB.regionPositionOffset = 0
	defaultDB.cityPositionOffset = 0
	defaultDB.ispPositionOffset = 0
	defaultDB.proxyTypePositionOffset = 0
	defaultDB.domainPositionOffset = 0
	defaultDB.usageTypePositionOffset = 0
	defaultDB.asnPositionOffset = 0
	defaultDB.asPositionOffset = 0
	defaultDB.lastSeenPositionOffset = 0
	defaultDB.countryEnabled = false
	defaultDB.regionEnabled = false
	defaultDB.cityEnabled = false
	defaultDB.ispEnabled = false
	defaultDB.proxyTypeEnabled = false
	defaultDB.domainEnabled = false
	defaultDB.usageTypeEnabled = false
	defaultDB.asnEnabled = false
	defaultDB.asEnabled = false
	defaultDB.lastSeenEnabled = false

	err := defaultDB.Close()

	if err != nil {
		return -1
	}
	return 0
}

// ModuleVersion returns the version of the component.
func ModuleVersion() string {
	return moduleVersion
}

// PackageVersion returns the database type.
//
// Deprecated: No longer being updated.
func PackageVersion() string {
	return strconv.Itoa(int(defaultDB.meta.databaseType))
}

// DatabaseVersion returns the database version.
//
// Deprecated: No longer being updated.
func DatabaseVersion() string {
	return "20" + strconv.Itoa(int(defaultDB.meta.databaseYear)) + "." + strconv.Itoa(int(defaultDB.meta.databaseMonth)) + "." + strconv.Itoa(int(defaultDB.meta.databaseDay))
}

// PackageVersion returns the database type.
func (d *DB) PackageVersion() string {
	return strconv.Itoa(int(d.meta.databaseType))
}

// DatabaseVersion returns the database version.
func (d *DB) DatabaseVersion() string {
	return "20" + strconv.Itoa(int(d.meta.databaseYear)) + "." + strconv.Itoa(int(d.meta.databaseMonth)) + "." + strconv.Itoa(int(d.meta.databaseDay))
}

// populate record with message
func loadMessage(mesg string) ip2proxyRecord {
	var x ip2proxyRecord

	x.countryShort = mesg
	x.countryLong = mesg
	x.region = mesg
	x.city = mesg
	x.isp = mesg
	x.proxyType = mesg
	x.domain = mesg
	x.usageType = mesg
	x.asn = mesg
	x.as = mesg
	x.lastSeen = mesg
	x.threat = mesg
	x.provider = mesg
	x.isProxy = -1

	return x
}

func handleError(rec ip2proxyRecord, err error) ip2proxyRecord {
	if err != nil {
		fmt.Print(err)
	}
	return rec
}

// GetAll will return all proxy fields based on the queried IP address.
//
// Deprecated: No longer being updated.
func GetAll(ipAddress string) map[string]string {
	data := handleError(defaultDB.query(ipAddress, all))

	var x = make(map[string]string)
	s := strconv.Itoa(int(data.isProxy))
	x["isProxy"] = s
	x["ProxyType"] = data.proxyType
	x["CountryShort"] = data.countryShort
	x["CountryLong"] = data.countryLong
	x["Region"] = data.region
	x["City"] = data.city
	x["ISP"] = data.isp
	x["Domain"] = data.domain
	x["UsageType"] = data.usageType
	x["ASN"] = data.asn
	x["AS"] = data.as
	x["LastSeen"] = data.lastSeen

	return x
}

// GetCountryShort will return the ISO-3166 country code based on the queried IP address.
//
// Deprecated: No longer being updated.
func GetCountryShort(ipAddress string) string {
	data := handleError(defaultDB.query(ipAddress, countryShort))
	return data.countryShort
}

// GetCountryLong will return the country name based on the queried IP address.
//
// Deprecated: No longer being updated.
func GetCountryLong(ipAddress string) string {
	data := handleError(defaultDB.query(ipAddress, countryLong))
	return data.countryLong
}

// GetRegion will return the region name based on the queried IP address.
//
// Deprecated: No longer being updated.
func GetRegion(ipAddress string) string {
	data := handleError(defaultDB.query(ipAddress, region))
	return data.region
}

// GetCity will return the city name based on the queried IP address.
//
// Deprecated: No longer being updated.
func GetCity(ipAddress string) string {
	data := handleError(defaultDB.query(ipAddress, city))
	return data.city
}

// GetIsp will return the Internet Service Provider name based on the queried IP address.
//
// Deprecated: No longer being updated.
func GetIsp(ipAddress string) string {
	data := handleError(defaultDB.query(ipAddress, isp))
	return data.isp
}

// GetProxyType will return the proxy type based on the queried IP address.
//
// Deprecated: No longer being updated.
func GetProxyType(ipAddress string) string {
	data := handleError(defaultDB.query(ipAddress, proxyType))
	return data.proxyType
}

// GetDomain will return the domain name based on the queried IP address.
//
// Deprecated: No longer being updated.
func GetDomain(ipAddress string) string {
	data := handleError(defaultDB.query(ipAddress, domain))
	return data.domain
}

// GetUsageType will return the usage type based on the queried IP address.
//
// Deprecated: No longer being updated.
func GetUsageType(ipAddress string) string {
	data := handleError(defaultDB.query(ipAddress, usageType))
	return data.usageType
}

// GetAsn will return the autonomous system number based on the queried IP address.
//
// Deprecated: No longer being updated.
func GetAsn(ipAddress string) string {
	data := handleError(defaultDB.query(ipAddress, asn))
	return data.asn
}

// GetAs will return the autonomous system name based on the queried IP address.
//
// Deprecated: No longer being updated.
func GetAs(ipAddress string) string {
	data := handleError(defaultDB.query(ipAddress, as))
	return data.as
}

// GetLastSeen will return the number of days that the proxy was last seen based on the queried IP address.
//
// Deprecated: No longer being updated.
func GetLastSeen(ipAddress string) string {
	data := handleError(defaultDB.query(ipAddress, lastSeen))
	return data.lastSeen
}

// IsProxy checks whether the queried IP address was a proxy. Returned value: -1 (errors), 0 (not a proxy), 1 (a proxy), 2 (a data center IP address or search engine robot).
//
// Deprecated: No longer being updated.
func IsProxy(ipAddress string) int8 {
	data := handleError(defaultDB.query(ipAddress, isProxy))
	return data.isProxy
}

// GetAll will return all proxy fields based on the queried IP address.
func (d *DB) GetAll(ipAddress string) (map[string]string, error) {
	data, err := d.query(ipAddress, all)

	var x = make(map[string]string)
	s := strconv.Itoa(int(data.isProxy))
	x["isProxy"] = s
	x["ProxyType"] = data.proxyType
	x["CountryShort"] = data.countryShort
	x["CountryLong"] = data.countryLong
	x["Region"] = data.region
	x["City"] = data.city
	x["ISP"] = data.isp
	x["Domain"] = data.domain
	x["UsageType"] = data.usageType
	x["ASN"] = data.asn
	x["AS"] = data.as
	x["LastSeen"] = data.lastSeen
	x["Threat"] = data.threat
	x["Provider"] = data.provider

	return x, err
}

// GetCountryShort will return the ISO-3166 country code based on the queried IP address.
func (d *DB) GetCountryShort(ipAddress string) (string, error) {
	data, err := d.query(ipAddress, countryShort)
	return data.countryShort, err
}

// GetCountryLong will return the country name based on the queried IP address.
func (d *DB) GetCountryLong(ipAddress string) (string, error) {
	data, err := d.query(ipAddress, countryLong)
	return data.countryLong, err
}

// GetRegion will return the region name based on the queried IP address.
func (d *DB) GetRegion(ipAddress string) (string, error) {
	data, err := d.query(ipAddress, region)
	return data.region, err
}

// GetCity will return the city name based on the queried IP address.
func (d *DB) GetCity(ipAddress string) (string, error) {
	data, err := d.query(ipAddress, city)
	return data.city, err
}

// GetIsp will return the Internet Service Provider name based on the queried IP address.
func (d *DB) GetIsp(ipAddress string) (string, error) {
	data, err := d.query(ipAddress, isp)
	return data.isp, err
}

// GetProxyType will return the proxy type based on the queried IP address.
func (d *DB) GetProxyType(ipAddress string) (string, error) {
	data, err := d.query(ipAddress, proxyType)
	return data.proxyType, err
}

// GetDomain will return the domain name based on the queried IP address.
func (d *DB) GetDomain(ipAddress string) (string, error) {
	data, err := d.query(ipAddress, domain)
	return data.domain, err
}

// GetUsageType will return the usage type based on the queried IP address.
func (d *DB) GetUsageType(ipAddress string) (string, error) {
	data, err := d.query(ipAddress, usageType)
	return data.usageType, err
}

// GetAsn will return the autonomous system number based on the queried IP address.
func (d *DB) GetAsn(ipAddress string) (string, error) {
	data, err := d.query(ipAddress, asn)
	return data.asn, err
}

// GetAs will return the autonomous system name based on the queried IP address.
func (d *DB) GetAs(ipAddress string) (string, error) {
	data, err := d.query(ipAddress, as)
	return data.as, err
}

// GetLastSeen will return the number of days that the proxy was last seen based on the queried IP address.
func (d *DB) GetLastSeen(ipAddress string) (string, error) {
	data, err := d.query(ipAddress, lastSeen)
	return data.lastSeen, err
}

// GetThreat will return the threat type of the proxy.
func (d *DB) GetThreat(ipAddress string) (string, error) {
	data, err := d.query(ipAddress, threat)
	return data.threat, err
}

// GetProvider will return the provider of the proxy.
func (d *DB) GetProvider(ipAddress string) (string, error) {
	data, err := d.query(ipAddress, provider)
	return data.provider, err
}

// IsProxy checks whether the queried IP address was a proxy. Returned value: -1 (errors), 0 (not a proxy), 1 (a proxy), 2 (a data center IP address or search engine robot).
func (d *DB) IsProxy(ipAddress string) (int8, error) {
	data, err := d.query(ipAddress, isProxy)
	return data.isProxy, err
}

// main query
func (d *DB) query(ipAddress string, mode uint32) (ip2proxyRecord, error) {
	x := loadMessage(msgNotSupported) // default message

	// read metadata
	if !d.metaOK {
		x = loadMessage(msgMissingFile)
		return x, nil
	}

	// check IP type and return IP number & index (if exists)
	ipType, ipNo, ipIndex := d.checkIP(ipAddress)

	if ipType == 0 {
		x = loadMessage(msgInvalidIP)
		return x, nil
	}

	var err error
	var colSize uint32
	var baseAddr uint32
	var low uint32
	var high uint32
	var mid uint32
	var rowOffset uint32
	var countryPos uint32
	var firstCol uint32 = 4 // 4 bytes for ip from
	var row []byte
	var fullRow []byte
	var readLen uint32
	ipFrom := big.NewInt(0)
	ipTo := big.NewInt(0)
	maxIP := big.NewInt(0)

	if ipType == 4 {
		baseAddr = d.meta.ipV4DatabaseAddr
		high = d.meta.ipV4DatabaseCount
		maxIP = maxIPV4Range
		colSize = d.meta.ipV4ColumnSize
	} else {
		if d.meta.ipV6DatabaseCount == 0 {
			x = loadMessage(msgIPV6Unsupported)
			return x, nil
		}
		firstCol = 16 // 16 bytes for ip from
		baseAddr = d.meta.ipV6DatabaseAddr
		high = d.meta.ipV6DatabaseCount
		maxIP = maxIPV6Range
		colSize = d.meta.ipV6ColumnSize
	}

	// reading index
	if ipIndex > 0 {
		row, err = d.readRow(ipIndex, 8) // 4 bytes each for IP From and IP To
		if err != nil {
			return x, err
		}
		low = d.readUint32Row(row, 0)
		high = d.readUint32Row(row, 4)
	}

	if ipNo.Cmp(maxIP) >= 0 {
		ipNo.Sub(ipNo, big.NewInt(1))
	}

	for low <= high {
		mid = ((low + high) >> 1)
		rowOffset = baseAddr + (mid * colSize)

		// reading IP From + whole row + next IP From
		readLen = colSize + firstCol
		fullRow, err = d.readRow(rowOffset, readLen)
		if err != nil {
			return x, err
		}

		if ipType == 4 {
			ipFrom32 := d.readUint32Row(fullRow, 0)
			ipFrom = big.NewInt(int64(ipFrom32))

			ipTo32 := d.readUint32Row(fullRow, colSize)
			ipTo = big.NewInt(int64(ipTo32))
		} else {
			ipFrom = d.readUint128Row(fullRow, 0)

			ipTo = d.readUint128Row(fullRow, colSize)
		}

		if ipNo.Cmp(ipFrom) >= 0 && ipNo.Cmp(ipTo) < 0 {
			rowLen := colSize - firstCol
			row = fullRow[firstCol:(firstCol + rowLen)] // extract the actual row data

			if d.proxyTypeEnabled {
				if mode&proxyType != 0 || mode&isProxy != 0 {
					if x.proxyType, err = d.readStr(d.readUint32Row(row, d.proxyTypePositionOffset)); err != nil {
						return x, err
					}
				}
			}

			if d.countryEnabled {
				if mode&countryShort != 0 || mode&countryLong != 0 || mode&isProxy != 0 {
					countryPos = d.readUint32Row(row, d.countryPositionOffset)
				}
				if mode&countryShort != 0 || mode&isProxy != 0 {
					if x.countryShort, err = d.readStr(countryPos); err != nil {
						return x, err
					}
				}
				if mode&countryLong != 0 {
					if x.countryLong, err = d.readStr(countryPos + 3); err != nil {
						return x, err
					}
				}
			}

			if mode&region != 0 && d.regionEnabled {
				if x.region, err = d.readStr(d.readUint32Row(row, d.regionPositionOffset)); err != nil {
					return x, err
				}
			}

			if mode&city != 0 && d.cityEnabled {
				if x.city, err = d.readStr(d.readUint32Row(row, d.cityPositionOffset)); err != nil {
					return x, err
				}
			}

			if mode&isp != 0 && d.ispEnabled {
				if x.isp, err = d.readStr(d.readUint32Row(row, d.ispPositionOffset)); err != nil {
					return x, err
				}
			}

			if mode&domain != 0 && d.domainEnabled {
				if x.domain, err = d.readStr(d.readUint32Row(row, d.domainPositionOffset)); err != nil {
					return x, err
				}
			}

			if mode&usageType != 0 && d.usageTypeEnabled {
				if x.usageType, err = d.readStr(d.readUint32Row(row, d.usageTypePositionOffset)); err != nil {
					return x, err
				}
			}

			if mode&asn != 0 && d.asnEnabled {
				if x.asn, err = d.readStr(d.readUint32Row(row, d.asnPositionOffset)); err != nil {
					return x, err
				}
			}

			if mode&as != 0 && d.asEnabled {
				if x.as, err = d.readStr(d.readUint32Row(row, d.asPositionOffset)); err != nil {
					return x, err
				}
			}

			if mode&lastSeen != 0 && d.lastSeenEnabled {
				if x.lastSeen, err = d.readStr(d.readUint32Row(row, d.lastSeenPositionOffset)); err != nil {
					return x, err
				}
			}

			if mode&threat != 0 && d.threatEnabled {
				if x.threat, err = d.readStr(d.readUint32Row(row, d.threatPositionOffset)); err != nil {
					return x, err
				}
			}

			if mode&provider != 0 && d.providerEnabled {
				if x.provider, err = d.readStr(d.readUint32Row(row, d.providerPositionOffset)); err != nil {
					return x, err
				}
			}

			if x.countryShort == "-" || x.proxyType == "-" {
				x.isProxy = 0
			} else {
				if x.proxyType == "DCH" || x.proxyType == "SES" {
					x.isProxy = 2
				} else {
					x.isProxy = 1
				}
			}

			return x, nil
		}

		if ipNo.Cmp(ipFrom) < 0 {
			high = mid - 1
		} else {
			low = mid + 1
		}
	}
	return x, nil
}

// Close is used to close file descriptor.
func (d *DB) Close() error {
	err := d.f.Close()
	return err
}
