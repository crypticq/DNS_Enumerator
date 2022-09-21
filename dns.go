package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/PuerkitoBio/goquery"
	"github.com/enescakir/emoji"
	"github.com/fatih/color"
	"github.com/xxjwxc/gowp/workpool"
)

var all_domain []string // -> store all results for later filteration from duplicates

func read_file(file string) []string {
	f, err := os.Open(file)
	if err != nil {
		log.Fatal(err)
	}
	defer f.Close()

	var domains []string
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		domains = append(domains, scanner.Text())
	}

	if err := scanner.Err(); err != nil {
		log.Fatal(err)
	}
	return domains
}

type URLSCAN struct {
	Results []struct {
		Task struct {
			URL string `json:"url"`
		} `json:"task"`

		Page struct {
			URL string `json:"url"`
		} `json:"page"`
	} `json:"results"`
}

type json_data []struct {
	IssuerCaID     int    `json:"issuer_ca_id"`
	IssuerName     string `json:"issuer_name"`
	CommonName     string `json:"common_name"`
	NameValue      string `json:"name_value"`
	ID             int64  `json:"id"`
	EntryTimestamp string `json:"entry_timestamp"`
	NotBefore      string `json:"not_before"`
	NotAfter       string `json:"not_after"`
	SerialNumber   string `json:"serial_number"`
}

type threat_data struct {
	ResponseCode string `json:"response_code"`
	Resolutions  []struct {
		LastResolved string `json:"last_resolved"`
		IPAddress    string `json:"ip_address"`
	} `json:"resolutions"`
	Hashes     []interface{} `json:"hashes"`
	Emails     []string      `json:"emails"`
	Subdomains []string      `json:"subdomains"`
	References []string      `json:"references"`
	Votes      int           `json:"votes"`
	Permalink  string        `json:"permalink"`
}

type AlienVault struct {
	PassiveDNS []struct {
		Address       string `json:"address"`
		First         string `json:"first"`
		Last          string `json:"last"`
		Hostname      string `json:"hostname"`
		RecordType    string `json:"record_type"`
		IndicatorLink string `json:"indicator_link"`
		FlagURL       string `json:"flag_url"`
		FlagTitle     string `json:"flag_title"`
		AssetType     string `json:"asset_type"`
		Asn           string `json:"asn"`
	} `json:"passive_dns"`
	Count int `json:"count"`
}

type threatminer struct {
	StatusCode    string   `json:"status_code"`
	StatusMessage string   `json:"status_message"`
	Results       []string `json:"results"`
}

func send_request(url string) []byte {

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		log.Fatal(err)
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (X11; Linux x86_64; rv:78.0) Gecko/20100101 Firefox/78.0")
	req.Header.Set("Accept", "application/json")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return []byte("Error")
	}
	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return []byte("Error")
	}
	return body
}

func hackertarget(s string) string {
	url := fmt.Sprintf("https://api.hackertarget.com/hostsearch/?q=%s", s)
	res, err := http.Get(url)
	if err != nil {
		log.Fatal(err)
	}
	if err != nil {
		log.Fatal(err)
	}
	scanner := bufio.NewScanner(res.Body)
	for scanner.Scan() {
		record := scanner.Text()
		if record != "" {
			res := strings.Split(record, ",")[0]
			all_domain = append(all_domain, res)
		}

	}
	return "Success , hackertarget"
}

func threatcrowd(s string) string {

	url := fmt.Sprintf("https://www.threatcrowd.org/searchApi/v2/domain/report/?domain=%s", s)
	body := send_request(url)
	var data threat_data                                // -> struct for threatcrowd
	if err := json.Unmarshal(body, &data); err != nil { // Parse []byte to the go struct pointer
		fmt.Println("Can not unmarshal JSON")
		return "Error , threatcrowd"

		subdomains := data.Subdomains
		for _, subdomain := range subdomains {
			all_domain = append(all_domain, subdomain)
		}

	}
	return "Success , threatcrowd"
}

func anubis(s string) string {

	url := fmt.Sprintf("https://jldc.me/anubis/subdomains/%s", s)
	body := send_request(url)
	var hosts []string
	if err := json.Unmarshal(body, &hosts); err != nil { // Parse []byte to the go struct pointer
		fmt.Println("Can not unmarshal JSON")
		return "Error , anubis"
		for _, host := range hosts {

			all_domain = append(all_domain, host)
		}

	}
	return "Success , anubis"
}

func sonar(s string) string {

	url := fmt.Sprintf("https://sonar.omnisint.io/subdomains/%s", s)
	body := send_request(url)

	var hosts []string
	if err := json.Unmarshal(body, &hosts); err != nil { // Parse []byte to the go struct pointer
		fmt.Println("Can not unmarshal JSON")
		return "Error , sonar"
	}
	for _, host := range hosts {
		all_domain = append(all_domain, host)
	}
	return "Success , sonar"
}

func alienvault(s string) string {

	url := fmt.Sprintf("https://otx.alienvault.com/api/v1/indicators/domain/%s/passive_dns", s)
	body := send_request(url)

	var data AlienVault
	if err := json.Unmarshal(body, &data); err != nil { // Parse []byte to the go struct pointer
		fmt.Println("Can not unmarshal JSON")
		return "Error , alienvault"
	}
	for _, host := range data.PassiveDNS {
		all_domain = append(all_domain, host.Hostname)
	}
	return "Success , alienvault"
}

func rapidDNS(target string) string {

	url := fmt.Sprintf("https://rapiddns.io/subdomain/%s#result", target)
	doc, err := goquery.NewDocument(url)
	if err != nil {
		log.Fatal(err)
		return "Error , rapidDNS"
	}

	doc.Find("td").Each(func(i int, s *goquery.Selection) {
		tables := s.Text()
		clean := strings.TrimSpace(tables)

		if strings.Contains(tables, target) {
			all_domain = append(all_domain, clean)
		}
	})
	return "Success , rapidDNS"
}
func ThreatMiner(s string) string {

	url := fmt.Sprintf("https://api.threatminer.org/v2/domain.php?q=%s&rt=5", s)
	body := send_request(url)
	var data threatminer
	if err := json.Unmarshal(body, &data); err != nil { // Parse []byte to the go struct pointer
		fmt.Println("Can not unmarshal JSON")
		return "Error , ThreatMiner"
	}

	for _, subdomain := range data.Results {
		all_domain = append(all_domain, subdomain)
	}

	return "Success , ThreatMiner"
}

func UrlScan(s string) string {

	url := fmt.Sprintf("https://urlscan.io/api/v1/search/?q=domain:%s", s)
	body := send_request(url)
	var hosts URLSCAN
	if err := json.Unmarshal(body, &hosts); err != nil { // Parse []byte to the go struct pointer
		fmt.Println("Can not unmarshal JSON")
		return "Error , UrlScan"
		for i, _ := range hosts.Results {
			if strings.Contains(hosts.Results[i].Task.URL, s) {
				all_domain = append(all_domain, hosts.Results[i].Task.URL)
			}
		}

	}
	return "Success , UrlScan"
}

func removeDuplicateStr(strSlice []string) []string {
	allKeys := make(map[string]bool)
	list := []string{}
	for _, item := range strSlice {
		if _, value := allKeys[item]; !value {
			allKeys[item] = true
			list = append(list, item)
		}
	}
	return list
}

func crt(host string) string {

	url := fmt.Sprintf("https://crt.sh/?q=%%25.%s&output=json", host)
	body := send_request(url)
	var result json_data
	if err := json.Unmarshal(body, &result); err != nil { // Parse []byte to the go struct pointer

		return "Error , crt.sh"
	}

	json.Unmarshal(body, &result)

	for index := range result {
		sub := (result[index].CommonName)
		all_domain = append(all_domain, sub)
	}

	return "Success , crt.sh"
}

func passive_dns(taregt string) []string {
	hackertarget(os.Args[1])
	threatcrowd(os.Args[1])
	anubis(os.Args[1])
	sonar(os.Args[1])
	alienvault(os.Args[1])
	crt(os.Args[1])
	ThreatMiner(os.Args[1])
	UrlScan(os.Args[1])
	f := read_file(os.Args[2])
	for _, subdomain := range f {
		su := fmt.Sprintf("%s.%s", subdomain, os.Args[1])
		all_domain = append(all_domain, su)
	}
	return removeDuplicateStr(all_domain)
}
func is_alive(s string) bool {
	_, e := net.LookupIP(s)
	if e != nil {
		return false
	}
	return true
}
func run() []string {
	var dns []string
	consumer := os.Args[3]
	// convert string to int
	intVar, err := strconv.Atoi(consumer)
	if err != nil {
		log.Fatal(err)
	}
	wp := workpool.New(intVar)
	urlAll := passive_dns(os.Args[1])
	for i := 0; i < len(urlAll); i++ {
		url := urlAll[i]
		wp.Do(func() error {

			if is_alive(url) {
				fmt.Println(color.BlueString("Alive -> %s", url))
				dns = append(dns, url)
			}

			return nil
		})
	}
	wp.Wait()
	for _, domain := range dns {
		fmt.Println(color.GreenString(domain))
	}
	file, err := json.MarshalIndent(dns, "", " ")
	if err != nil {
		fmt.Println(err)
	}
	fmt.Printf(color.RedString("Found total of %d subdomains\n", len(dns)))
	fmt.Printf(color.YellowString("All result saved to %s\n", "subdomains.json"))
	_ = ioutil.WriteFile("subdomains.json", file, 0644)
	return dns
}
func banner() {
	const banner = `
	_____       __    ______                    
	/ ___/__  __/ /_  / ____/___  __  ______ ___ 
	\__ \/ / / / __ \/ __/ / __ \/ / / / __ __ \
   ___/ / /_/ / /_/ / /___/ / / / /_/ / / / / / /
  /____/\__,_/_.___/_____/_/ /_/\__,_/_/ /_/ /_/ 
												 
  `
	fmt.Println(color.RedString(banner))
	fmt.Printf(color.BlueString("Gathring subdomains for %s\n", os.Args[1]))
	fmt.Printf(color.YellowString("Coded by Eng Yazeed Alzahrani\n instagram: @commplicated\n snapchat: @jp-q \n github:crypticq\n"))
}
func main() {
	if len(os.Args) != 4 {
		fmt.Println("Usage: ./dns <domain> <wordlist> <threading int> ")
		os.Exit(1)
	}
	start := time.Now()
	banner()
	run()
	elapsed := time.Since(start)
	fmt.Printf(color.BlackString("Elapsed time: %s"+" "+"", elapsed))
}
