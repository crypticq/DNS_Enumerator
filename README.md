# DNS_Enumerator


```
git clone https://github.com/crypticq/DNS_Enumerator
cd DNS_Enumerator
go build dns.go 
```


```
Usage: ./dns <domain> <wordlist> <threading num>
```

# example
```
./dns hackerone.com subdomains-top1million-5000.txt 40
```

# run it in docker

```
docker build -t dns . 
docker run dns hackerone.com subdomains-top1million-5000.txt 40
```

![img](https://i.imgur.com/RpmnSJb.png)
