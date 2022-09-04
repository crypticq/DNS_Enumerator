package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"strings"
	"sync"

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

func is_alive(s string) bool {
	url := fmt.Sprintf("https://%s", s)
	r, e := http.Head(url)
	return e == nil && r.StatusCode == 200
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
	var subs []string
	json.Unmarshal(body, &result)

	for index := range result {
		sub := (result[index].CommonName)
		subs = append(subs, sub)
	}
	fmt.Printf(color.RedString("Found total of %d subdomains\n", len(subs)))
	fmt.Println(color.GreenString("Filtering out the dead ones"))
	dom := removeDuplicateStr(subs)
	for _, domain := range dom {
		wg.Add(1)
		go func(domain string) {
			defer wg.Done()
			if is_alive(domain) && strings.Contains(domain, os.Args[1]) {
				alive_domains = append(alive_domains, domain)
			}
		}(domain)
	}

	wg.Wait()
	fmt.Printf(color.RedString("alive subdomains:%d\n", len(alive_domains)))
	for index, domain := range alive_domains {
		fmt.Printf(color.GreenString("%d: %s\n", index, domain))

	}

}

func main() {
	ippp(os.Args[1])

}
