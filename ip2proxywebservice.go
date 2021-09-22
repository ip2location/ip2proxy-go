package ip2proxy

import (
	"encoding/json"
	"errors"
	"io/ioutil"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
)

// The IP2ProxyResult struct stores all of the available
// proxy info found in the IP2Proxy Web Service.
type IP2ProxyResult struct {
	Response    string `json:"response"`
	CountryCode string `json:"countryCode"`
	CountryName string `json:"countryName"`
	RegionName  string `json:"regionName"`
	CityName    string `json:"cityName"`
	ISP         string `json:"isp"`
	Domain      string `json:"domain"`
	UsageType   string `json:"usageType"`
	ASN         string `json:"asn"`
	AS          string `json:"as"`
	LastSeen    string `json:"lastSeen"`
	ProxyType   string `json:"proxyType"`
	Threat      string `json:"threat"`
	IsProxy     string `json:"isProxy"`
	Provider    string `json:"provider"`
}

// The IP2ProxyCreditResult struct stores the
// credit balance for the IP2Proxy Web Service.
type IP2ProxyCreditResult struct {
	Response string `json:"response"`
}

// The WS struct is the main object used to query the IP2Proxy Web Service.
type WS struct {
	apiKey     string
	apiPackage string
	useSSL     bool
}

var regexAPIKey = regexp.MustCompile(`^[\dA-Z]{10}$`)
var regexAPIPackage = regexp.MustCompile(`^PX\d+$`)

const baseURL = "api.ip2proxy.com/"
const msgInvalidAPIKey = "Invalid API key."
const msgInvalidAPIPackage = "Invalid package name."

// OpenWS initializes with the web service API key, API package and whether to use SSL
func OpenWS(apikey string, apipackage string, usessl bool) (*WS, error) {
	var ws = &WS{}
	ws.apiKey = apikey
	ws.apiPackage = apipackage
	ws.useSSL = usessl

	err := ws.checkParams()

	if err != nil {
		return nil, err
	}

	return ws, nil
}

func (w *WS) checkParams() error {
	if !regexAPIKey.MatchString(w.apiKey) {
		return errors.New(msgInvalidAPIKey)
	}

	if !regexAPIPackage.MatchString(w.apiPackage) {
		return errors.New(msgInvalidAPIPackage)
	}

	return nil
}

// LookUp will return all proxy fields based on the queried IP address.
func (w *WS) LookUp(ipAddress string) (IP2ProxyResult, error) {
	var res IP2ProxyResult
	err := w.checkParams()

	if err != nil {
		return res, err
	}

	protocol := "https"

	if !w.useSSL {
		protocol = "http"
	}

	myUrl := protocol + "://" + baseURL + "?key=" + w.apiKey + "&package=" + w.apiPackage + "&ip=" + url.QueryEscape(ipAddress)

	resp, err := http.Get(myUrl)

	if err != nil {
		return res, err
	}

	defer resp.Body.Close()

	if resp.StatusCode == http.StatusOK {
		bodyBytes, err := ioutil.ReadAll(resp.Body)

		if err != nil {
			return res, err
		}

		err = json.Unmarshal(bodyBytes, &res)

		if err != nil {
			return res, err
		}

		return res, nil
	}

	return res, errors.New("Error HTTP " + strconv.Itoa(int(resp.StatusCode)))
}

// GetCredit will return the web service credit balance.
func (w *WS) GetCredit() (IP2ProxyCreditResult, error) {
	var res IP2ProxyCreditResult
	err := w.checkParams()

	if err != nil {
		return res, err
	}

	protocol := "https"

	if !w.useSSL {
		protocol = "http"
	}

	myUrl := protocol + "://" + baseURL + "?key=" + w.apiKey + "&check=true"

	resp, err := http.Get(myUrl)

	if err != nil {
		return res, err
	}

	defer resp.Body.Close()

	if resp.StatusCode == http.StatusOK {
		bodyBytes, err := ioutil.ReadAll(resp.Body)

		if err != nil {
			return res, err
		}

		err = json.Unmarshal(bodyBytes, &res)

		if err != nil {
			return res, err
		}

		return res, nil
	}

	return res, errors.New("Error HTTP " + strconv.Itoa(int(resp.StatusCode)))
}
