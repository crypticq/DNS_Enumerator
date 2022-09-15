# DNS_Enumerator


```bash
git clone https://github.com/crypticq/DNS_Enumerator
cd DNS_Enumerator
go build dns.go 
```


```bash
Usage: ./dns <domain> <wordlist> <threading num>
```

# example
```bash
./dns hackerone.com subdomains-top1million-5000.txt 40
```

# run it in docker

```bash
docker build -t dns . 
docker run dns hackerone.com subdomains-top1million-5000.txt 40
```

![img](https://i.imgur.com/EAfFfuN.png)
