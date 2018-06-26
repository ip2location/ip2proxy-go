package ip2proxy

import (
	"fmt"
	"os"
	"bytes"
	"encoding/binary"
	"math/big"
	"strconv"
	"net"
)

type ip2proxymeta struct {
	databasetype uint8
	databasecolumn uint8
	databaseday uint8
	databasemonth uint8
	databaseyear uint8
	ipv4databasecount uint32
	ipv4databaseaddr uint32
	ipv6databasecount uint32
	ipv6databaseaddr uint32
	ipv4indexbaseaddr uint32
	ipv6indexbaseaddr uint32
	ipv4columnsize uint32
	ipv6columnsize uint32
}

type IP2Proxyrecord struct {
	Country_short string
	Country_long string
	Region string
	City string
	Isp string
	Proxy_type string
	Is_proxy int8
}

var f *os.File
var meta ip2proxymeta

var country_position = [5]uint8{0, 2, 3, 3, 3}
var region_position = [5]uint8{0, 0, 0, 4, 4}
var city_position = [5]uint8{0, 0, 0, 5, 5}
var isp_position = [5]uint8{0, 0, 0, 0, 6}
var proxytype_position = [5]uint8{0, 0, 2, 2, 2}

const module_version string = "1.0.0"

var max_ipv4_range = big.NewInt(4294967295)
var max_ipv6_range = big.NewInt(0)

const countryshort uint32 = 0x00001
const countrylong uint32 = 0x00002
const region uint32 = 0x00004
const city uint32 = 0x00008
const isp uint32 = 0x00010
const proxytype uint32 = 0x00020
const isproxy uint32 = 0x00040

const all uint32 = countryshort | countrylong | region | city | isp | proxytype | isproxy

const msg_not_supported string = "NOT SUPPORTED";
const msg_invalid_ip string = "INVALID IP ADDRESS";
const msg_missing_file string = "MISSING FILE";
const msg_ipv6_unsupported string = "IPV6 ADDRESS MISSING IN IPV4 BIN";

var metaok bool

var country_position_offset uint32
var region_position_offset uint32
var city_position_offset uint32
var isp_position_offset uint32
var proxytype_position_offset uint32

var country_enabled bool
var region_enabled bool
var city_enabled bool
var isp_enabled bool
var proxytype_enabled bool

// get IP type and calculate IP number; calculates index too if exists
func checkip(ip string) (iptype uint32, ipnum *big.Int, ipindex uint32) {
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
			}
		}
	}
	if iptype == 4 {
		if meta.ipv4indexbaseaddr > 0 {
			ipnumtmp.Rsh(ipnum, 16)
			ipnumtmp.Lsh(ipnumtmp, 3)
			ipindex = uint32(ipnumtmp.Add(ipnumtmp, big.NewInt(int64(meta.ipv4indexbaseaddr))).Uint64())
		}
	} else if iptype == 6 {
		if meta.ipv6indexbaseaddr > 0 {
			ipnumtmp.Rsh(ipnum, 112)
			ipnumtmp.Lsh(ipnumtmp, 3)
			ipindex = uint32(ipnumtmp.Add(ipnumtmp, big.NewInt(int64(meta.ipv6indexbaseaddr))).Uint64())
		}
	}
	return 
}

// read byte
func readuint8(pos int64) uint8 {
	var retval uint8
	data := make([]byte, 1)
	_, err := f.ReadAt(data, pos - 1)
	if err != nil {
		fmt.Println("File read failed:", err)
	}
	retval = data[0]
	return retval
}

// read unsigned 32-bit integer
func readuint32(pos uint32) uint32 {
	pos2 := int64(pos)
	var retval uint32
	data := make([]byte, 4)
	_, err := f.ReadAt(data, pos2 - 1)
	if err != nil {
		fmt.Println("File read failed:", err)
	}
	buf := bytes.NewReader(data)
	err = binary.Read(buf, binary.LittleEndian, &retval)
	if err != nil {
		fmt.Println("Binary read failed:", err)
	}
	return retval
}

// read unsigned 128-bit integer
func readuint128(pos uint32) *big.Int {
	pos2 := int64(pos)
	retval := big.NewInt(0)
	data := make([]byte, 16)
	_, err := f.ReadAt(data, pos2 - 1)
	if err != nil {
		fmt.Println("File read failed:", err)
	}
	
	// little endian to big endian
	for i, j := 0, len(data)-1; i < j; i, j = i+1, j-1 {
		data[i], data[j] = data[j], data[i]
	}
	retval.SetBytes(data)
	return retval
}

// read string
func readstr(pos uint32) string {
	pos2 := int64(pos)
	var retval string
	lenbyte := make([]byte, 1)
	_, err := f.ReadAt(lenbyte, pos2)
	if err != nil {
		fmt.Println("File read failed:", err)
	}
	strlen := lenbyte[0]
	data := make([]byte, strlen)
	_, err = f.ReadAt(data, pos2 + 1)
	if err != nil {
		fmt.Println("File read failed:", err)
	}
	retval = string(data[:strlen])
	return retval
}

// read float
func readfloat(pos uint32) float32 {
	pos2 := int64(pos)
	var retval float32
	data := make([]byte, 4)
	_, err := f.ReadAt(data, pos2 - 1)
	if err != nil {
		fmt.Println("File read failed:", err)
	}
	buf := bytes.NewReader(data)
	err = binary.Read(buf, binary.LittleEndian, &retval)
	if err != nil {
		fmt.Println("Binary read failed:", err)
	}
	return retval
}

// initialize the component with the database path
func Open(dbpath string) int8 {
	Close() // reset in case user didn't call Close() before calling Open() again
	
	max_ipv6_range.SetString("340282366920938463463374607431768211455", 10)
	
	var err error
	f, err = os.Open(dbpath)
	if err != nil {
		return -1
	}
	
	meta.databasetype = readuint8(1)
	meta.databasecolumn = readuint8(2)
	meta.databaseyear = readuint8(3)
	meta.databasemonth = readuint8(4)
	meta.databaseday = readuint8(5)
	meta.ipv4databasecount = readuint32(6)
	meta.ipv4databaseaddr = readuint32(10)
	meta.ipv6databasecount = readuint32(14)
	meta.ipv6databaseaddr = readuint32(18)
	meta.ipv4indexbaseaddr = readuint32(22)
	meta.ipv6indexbaseaddr = readuint32(26)
	meta.ipv4columnsize = uint32(meta.databasecolumn << 2) // 4 bytes each column
	meta.ipv6columnsize = uint32(16 + ((meta.databasecolumn - 1) << 2)) // 4 bytes each column, except IPFrom column which is 16 bytes
	
	dbt := meta.databasetype
	
	// since both IPv4 and IPv6 use 4 bytes for the below columns, can just do it once here
	if country_position[dbt] != 0 {
		country_position_offset = uint32(country_position[dbt] - 1) << 2
		country_enabled = true
	}
	if region_position[dbt] != 0 {
		region_position_offset = uint32(region_position[dbt] - 1) << 2
		region_enabled = true
	}
	if city_position[dbt] != 0 {
		city_position_offset = uint32(city_position[dbt] - 1) << 2
		city_enabled = true
	}
	if isp_position[dbt] != 0 {
		isp_position_offset = uint32(isp_position[dbt] - 1) << 2
		isp_enabled = true
	}
	if proxytype_position[dbt] != 0 {
		proxytype_position_offset = uint32(proxytype_position[dbt] - 1) << 2
		proxytype_enabled = true
	}
	
	metaok = true
	return 0
}

// close database file handle & reset
func Close() int8 {
	meta.databasetype = 0
	meta.databasecolumn = 0
	meta.databaseyear = 0
	meta.databasemonth = 0
	meta.databaseday = 0
	meta.ipv4databasecount = 0
	meta.ipv4databaseaddr = 0
	meta.ipv6databasecount = 0
	meta.ipv6databaseaddr = 0
	meta.ipv4indexbaseaddr = 0
	meta.ipv6indexbaseaddr = 0
	meta.ipv4columnsize = 0
	meta.ipv6columnsize = 0
	metaok = false
	country_position_offset = 0
	region_position_offset = 0
	city_position_offset = 0
	isp_position_offset = 0
	proxytype_position_offset = 0
	country_enabled = false
	region_enabled = false
	city_enabled = false
	isp_enabled = false
	proxytype_enabled = false
	
	err := f.Close()
	if err != nil {
		return -1
	} else {
		return 0
	}
}

// get module version
func ModuleVersion() string {
	return module_version
}

// get package version
func PackageVersion() string {
	return strconv.Itoa(int(meta.databasetype))
}

// get database version
func DatabaseVersion() string {
	return "20" + strconv.Itoa(int(meta.databaseyear)) + "." + strconv.Itoa(int(meta.databasemonth)) + "." + strconv.Itoa(int(meta.databaseday))
}

// populate record with message
func loadmessage (mesg string) IP2Proxyrecord {
	var x IP2Proxyrecord
	
	x.Country_short = mesg
	x.Country_long = mesg
	x.Region = mesg
	x.City = mesg
	x.Isp = mesg
	x.Proxy_type = mesg
	x.Is_proxy = -1
	
	return x
}

// get all fields
func GetAll(ipaddress string) map[string]string {
	data := query(ipaddress, all)
	
	var x = make(map[string]string)
	s := strconv.Itoa(int(data.Is_proxy))
	x["isProxy"] = s
	x["ProxyType"] = data.Proxy_type
	x["CountryShort"] = data.Country_short
	x["CountryLong"] = data.Country_long
	x["Region"] = data.Region
	x["City"] = data.City
	x["ISP"] = data.Isp
	
	return x
}

// get country code
func GetCountryShort(ipaddress string) string {
	data := query(ipaddress, countryshort)
	return data.Country_short
}

// get country name
func GetCountryLong(ipaddress string) string {
	data := query(ipaddress, countrylong)
	return data.Country_long
}

// get region
func GetRegion(ipaddress string) string {
	data := query(ipaddress, region)
	return data.Region
}

// get city
func GetCity(ipaddress string) string {
	data := query(ipaddress, city)
	return data.City
}

// get isp
func GetIsp(ipaddress string) string {
	data := query(ipaddress, isp)
	return data.Isp
}

// get proxy type
func GetProxyType(ipaddress string) string {
	data := query(ipaddress, proxytype)
	return data.Proxy_type
}

// is proxy
func IsProxy(ipaddress string) int8 {
	data := query(ipaddress, isproxy)
	return data.Is_proxy
}

// main query
func query(ipaddress string, mode uint32) IP2Proxyrecord {
	x := loadmessage(msg_not_supported) // default message
	
	// read metadata
	if !metaok {
		x = loadmessage(msg_missing_file)
		return x
	}
	
	// check IP type and return IP number & index (if exists)
	iptype, ipno, ipindex := checkip(ipaddress)
	
	if iptype == 0 {
		x = loadmessage(msg_invalid_ip)
		return x
	}
	
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
		baseaddr = meta.ipv4databaseaddr
		high = meta.ipv4databasecount
		maxip = max_ipv4_range
		colsize = meta.ipv4columnsize
	} else {
		if meta.ipv6databasecount == 0 {
			x = loadmessage(msg_ipv6_unsupported)
			return x
		}
		baseaddr = meta.ipv6databaseaddr
		high = meta.ipv6databasecount
		maxip = max_ipv6_range
		colsize = meta.ipv6columnsize
	}
	
	// reading index
	if ipindex > 0 {
		low = readuint32(ipindex)
		high = readuint32(ipindex + 4)
	}
	
	if ipno.Cmp(maxip)>=0 {
		ipno = ipno.Sub(ipno, big.NewInt(1))
	}
	
	for low <= high {
		mid = ((low + high) >> 1)
		rowoffset = baseaddr + (mid * colsize)
		rowoffset2 = rowoffset + colsize
		
		if iptype == 4 {
			ipfrom = big.NewInt(int64(readuint32(rowoffset)))
			ipto = big.NewInt(int64(readuint32(rowoffset2)))
		} else {
			ipfrom = readuint128(rowoffset)
			ipto = readuint128(rowoffset2)
		}
		
		if ipno.Cmp(ipfrom)>=0 && ipno.Cmp(ipto)<0 {
			if iptype == 6 {
				rowoffset = rowoffset + 12 // coz below is assuming all columns are 4 bytes, so got 12 left to go to make 16 bytes total
			}
			
			if proxytype_enabled {
				if mode&proxytype != 0 || mode&isproxy != 0 {
					x.Proxy_type = readstr(readuint32(rowoffset + proxytype_position_offset))
				}
			}
			
			if country_enabled {
				if mode&countryshort != 0 || mode&countrylong != 0 || mode&isproxy != 0 {
					countrypos = readuint32(rowoffset + country_position_offset)
				}
				if mode&countryshort != 0 || mode&isproxy != 0 {
					x.Country_short = readstr(countrypos)
				}
				if mode&countrylong != 0 {
					x.Country_long = readstr(countrypos + 3)
				}
			}
			
			if mode&region != 0 && region_enabled {
				x.Region = readstr(readuint32(rowoffset + region_position_offset))
			}
			
			if mode&city != 0 && city_enabled {
				x.City = readstr(readuint32(rowoffset + city_position_offset))
			}
			
			if mode&isp != 0 && isp_enabled {
				x.Isp = readstr(readuint32(rowoffset + isp_position_offset))
			}
			
			if x.Country_short == "-" || x.Proxy_type == "-" {
				x.Is_proxy = 0
			} else {
				if x.Proxy_type == "DCH" {
					x.Is_proxy = 2
				} else {
					x.Is_proxy = 1
				}
			}
			
			return x
		} else {
			if ipno.Cmp(ipfrom)<0 {
				high = mid - 1
			} else {
				low = mid + 1
			}
		}
	}
	return x
}

// for debugging purposes
func Printrecord(x IP2Proxyrecord) {
	fmt.Printf("country_short: %s\n", x.Country_short)
	fmt.Printf("country_long: %s\n", x.Country_long)
	fmt.Printf("region: %s\n", x.Region)
	fmt.Printf("city: %s\n", x.City)
	fmt.Printf("isp: %s\n", x.Isp)
	fmt.Printf("proxy_type: %s\n", x.Proxy_type)
	fmt.Printf("is_proxy: %d\n", x.Is_proxy)
}
