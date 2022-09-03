//parse json web request

package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"bytes"
	"strings"

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



func ippp(taregt string){
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
	//fmt.Println(strings.TrimSpace(string(body)))

	var result json_data
	if err := json.Unmarshal(body, &result); err != nil {  // Parse []byte to the go struct pointer
        fmt.Println("Can not unmarshal JSON")
}
	var subs []string
	json.Unmarshal(body, &result)
	//fmt.Println(result[0].CommonName)

	for index := range result {
		sub := (result[index].CommonName)
		subs = append(subs , sub)
	}
	final_res := removeDuplicateStr(subs)
	
	for all := range final_res {
		if strings.Contains(final_res[all], "*"){
			continue
		}
		fmt.Println("Found subdomain -> : " , final_res[all])
	}

}

func main() {
	ippp(os.Args[1])

}


