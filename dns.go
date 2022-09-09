package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/fatih/color"
)

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

func genrate_domainPattern(domain string) []string { // -> for brute force subdomains , it read a file and generate a list of subdomains

	var domainPattern []string
	file, err := os.Open(os.Args[2])
	if err != nil {
		fmt.Println(err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		domainPattern = append(domainPattern, scanner.Text())
	}
	return domainPattern

}

//make is_alive chanel

func is_alive(s string, ch chan bool) bool {

	_, e := net.LookupIP(s)
	if e != nil {
		ch <- false
		return false
	}
	ch <- true
	return true
}

func hackertarget(s string) []string {
	var domain []string
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
			domain = append(domain, res)
		}

	}
	return domain
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

const (
	empty = ""
	tab   = "\t"
)

func PrettyJson(data interface{}) (string, error) {
	buffer := new(bytes.Buffer)
	encoder := json.NewEncoder(buffer)
	encoder.SetIndent(empty, tab)

	err := encoder.Encode(data)
	if err != nil {
		return empty, err
	}
	return buffer.String(), nil
}

func ippp(taregt string) {
	var wg sync.WaitGroup
	var alive_domains []string
	var all_subs []string

	url := fmt.Sprintf("https://crt.sh/?q=%s&output=json", os.Args[1])
	resp, err := http.Get(url)
	if err != nil {
		log.Fatal(err)
	}
	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		log.Fatal(err)
	}

	var result json_data
	if err := json.Unmarshal(body, &result); err != nil { // Parse []byte to the go struct pointer
		fmt.Println("Can not unmarshal JSON")
	}

	json.Unmarshal(body, &result)

	for index := range result {
		sub := (result[index].CommonName)
		all_subs = append(all_subs, sub)
	}
	hackertarget_subs := hackertarget(os.Args[1])
	for _, sub := range hackertarget_subs {
		all_subs = append(all_subs, sub)
	}
	domainPattern := genrate_domainPattern(os.Args[1])

	for _, subdomain := range domainPattern {
		if strings.Contains(subdomain, "www") {
			continue
		}

		subdomains := fmt.Sprintf("%s.%s", subdomain, os.Args[1])
		all_subs = append(all_subs, subdomains)
	}

	dom := removeDuplicateStr(all_subs)
	// use is_alive with WaitGroup
	for _, sub := range dom {
		wg.Add(1)
		go func(sub string) {
			defer wg.Done()
			ch := make(chan bool)
			go is_alive(sub, ch)
			if <-ch {
				alive_domains = append(alive_domains, sub)
			}
		}(sub)
	}
	wg.Wait()

	fmt.Printf(color.RedString("Found total of %d subdomains\n", len(alive_domains)))
	for _, domain := range alive_domains {
		fmt.Println(color.GreenString(domain))
	}

	file, err := json.MarshalIndent(alive_domains, "", " ")
	if err != nil {
		fmt.Println(err)
	}
	_ = ioutil.WriteFile("subdomains.json", file, 0644)
	fmt.Printf(color.YellowString("All result saved to %s\n", "subdomains.json"))

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
	fmt.Printf(color.BlueString("colelct subdomains from crt.sh and brute force subdomains for %s\n", os.Args[1]))
	fmt.Printf(color.YellowString("Coded by Eng Yazeed Alzahrani\n instagram: @commplicated\n snapchat: @jp-q \n github:crypticq\n"))

}
func main() {
	if len(os.Args) != 3 {
		fmt.Println("Usage: ./subdomain <domain> <wordlist>")
		os.Exit(0)
	}
	start := time.Now()
	banner()
	ippp(os.Args[1])
	elapsed := time.Since(start)
	fmt.Printf(color.YellowString("Time taken: %s", elapsed))

}
