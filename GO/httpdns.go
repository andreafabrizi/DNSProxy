//use dnspod's httpdns service to query dns


package main

import (
	"bytes"
	"fmt"
	"github.com/miekg/dns"
	"io/ioutil"
	"log"
	"net/http"
)

var server_url string = "http://119.29.29.29/d?dn=%s"

func get_a(domain string) []string {
	url := fmt.Sprintf(server_url, domain)

	r, err := http.Get(url)

	if err != nil {
		fmt.Println(err)
		return []string{}
	}

	defer r.Body.Close()

	buf, err := ioutil.ReadAll(r.Body)
	if err != nil {
		fmt.Println(err)
		return []string{}
	}

	ip := []string{}

	ips := bytes.Split(buf, []byte(";"))

	for _, ii := range ips {
		ip = append(ip, string(ii))
	}

	return ip
}

func handleRoot(w dns.ResponseWriter, r *dns.Msg) {
	// Only A supported
	if r.Question[0].Qtype != dns.TypeA {
		dns.HandleFailed(w, r)
		return
	}

	domain := r.Question[0].Name

	ip := get_a(domain)

	if len(ip) == 0 {
		dns.HandleFailed(w, r)
		return
	}

	msg := new(dns.Msg)
	msg.SetReply(r)

	for _, ii := range ip {
		s := fmt.Sprintf("%s 3600 IN A %s",
			dns.Fqdn(domain), ii)
		rr, _ := dns.NewRR(s)
		msg.Answer = append(msg.Answer, rr)
	}

	w.WriteMsg(msg)
}

func main() {
	dns.HandleFunc(".", handleRoot)
	err := dns.ListenAndServe("0.0.0.0:53", "udp", nil)
	if err != nil {
		log.Fatal(err)
	}
}
