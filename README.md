# DNS_Enumerator


```bash
git clone https://github.com/crypticq/DNS_Enumerator
cd DNS_Enumerator
go build dns.go 
```


```bash
Usage: ./dns <domain> <wordlist>
```
#run it in docker

```bash
docker build -t dns.
docker run dns ./dns <target> subdomains-top1million-5000.txt 
```
