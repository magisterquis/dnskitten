// dnskitten wraps streams in DNS
package main

/*
 * dnskitten.go
 * Streams over DNS, minimally
 * By J. Stuart McMurray
 * Created 20180123
 * Last Modified 20180125
 */

import (
	"encoding/base64"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"strings"
	"sync"

	lru "github.com/hashicorp/golang-lru"
	"github.com/miekg/dns"
)

const (
	// MAXSTRINGLEN is the maximum number of bytes returned in a character
	// string, as in TXT records.
	MAXSTRINGLEN = 128

	// BUFLEN is the maximum number of bytes to buffer from stdin and byte
	// slices to buffer to stdout.
	BUFLEN = 4096

	// CACHESIZE is the size of the dedupe cache
	CACHESIZE = 10240
)

var (
	// IN holds bytes from stdin
	IN = make(chan byte, BUFLEN)

	// OUT holds byte slices destined to stdout
	OUT = make(chan []byte, BUFLEN)

	// CACHE is used to prevent duplicate requests getting output
	CACHE *lru.Cache

	// INLOCK prevents two requests from reading stdin simultaneously
	INLOCK = &sync.Mutex{}
)

func main() {
	var (
		domain = flag.String(
			"d",
			"",
			"DNS `domain`",
		)
		addr = flag.String(
			"l",
			"127.0.0.1:5353",
			"Listen `address`",
		)
	)
	flag.Usage = func() {
		fmt.Fprintf(
			os.Stderr,
			`Usage: %v [options]

Listens on the given address for queries either for input or to give output.

Input (i.e. stdin -> DNS response) queries may be for A, AAAA, TXT, or URI
records, and may be for any subdomain of the domain given with -d.  Each query
should use a unique subdomain.

Output (i.e. DNS query -> stdout) queries should be for a subdomain of the
domain name given with -d such that the first label has hex-encoded data to
print to stdout, i.e. <hex>.<whatever>.o.domain.tld.  Each query should use
a unique subdomain.

Options:
`,
			os.Args[0],
		)
		flag.PrintDefaults()
	}
	flag.Parse()

	/* Make sure we have a domain */
	if "" == *domain {
		fmt.Fprintf(os.Stderr, "A domain is required (-domain).\n")
		os.Exit(1)
	}

	/* Set up cache */
	var err error
	CACHE, err = lru.New(CACHESIZE)
	if nil != err { /* Should only happen on a negative CACHESIZE */
		panic(err)
	}

	/* Read stdin and out */
	go proxyStdin()
	go proxyStdout()

	/* Register handler */
	*domain = dns.Fqdn(*domain)
	dns.HandleFunc(*domain, handleInput)
	dns.HandleFunc("o."+*domain, handleOutput)
	dns.HandleFunc(".", dns.HandleFailed)

	/* Serve DNS */
	log.Fatalf(
		"[ERROR] Server error: %v",
		dns.ListenAndServe(*addr, "udp", nil),
	)
}

/* handleInput responds to DNS requests for input */
func handleInput(w dns.ResponseWriter, r *dns.Msg) {

	/* Response message */
	m := &dns.Msg{}
	m.SetReply(r)

	/* Make an answer for each question */
	var f func() (dns.RR, error) /* Function to return data from stdin */
	INLOCK.Lock()
	for _, q := range r.Question {
		/* Ignore case */
		q.Name = strings.ToLower(q.Name)

		/* Prevent duplicate queries from getting more stdio than they
		should  */
		if a, ok := CACHE.Get(q.Name); ok {
			ans, ok := a.(dns.RR)
			if !ok {
				log.Panicf(
					"invalid type %T for cached answer "+
						"to %v",
					a,
					q.Name,
				)
			}
			/* Don't answer if it's the wrong type.  Prevents AAAA
			requests for previously-seen A requests from getting
			an A response. */
			if q.Qtype == ans.Header().Rrtype {
				m.Answer = append(m.Answer, ans)
			}
			continue
		}

		/* Choose the function which gives the appropriate RR type */
		switch q.Qtype {
		case dns.TypeA:
			f = inA
		case dns.TypeAAAA:
			f = inAAAA
		case dns.TypeTXT:
			f = inTXT
		case dns.TypeURI:
			f = inURI
		default: /* Unhandled query type */
			log.Printf(
				"[%v-%v] Unknown Type %s in query for %q",
				w.RemoteAddr(),
				r.Id,
				qtString(q),
				q.Name,
			)
			continue
		}
		/* Get data for STDIN in the appropriate format */
		a, err := f()
		if nil != err {
			if io.EOF == err {
				log.Fatalf("[ERROR] EOF on input")
			}
			log.Printf(
				"[ERROR] Cannot make %v record: %v",
				qtString(q),
				err,
			)
			continue
		}
		/* Set RR header */
		a.Header().Name = q.Name
		a.Header().Class = q.Qclass
		a.Header().Rrtype = q.Qtype
		a.Header().Ttl = 0
		/* Add it to the list of answers to send back */
		m.Answer = append(m.Answer, a)
		/* Cache it for deduplication */
		CACHE.Add(q.Name, a)

	}
	INLOCK.Unlock()

	/* Send response back */
	if err := w.WriteMsg(m); nil != err {
		log.Printf(
			"[%v-%v] Unable to write input response: %v",
			w.RemoteAddr(),
			r.Id,
			err,
		)
	}
}

/* handleOutput sends the hex-encoded bytes in the leftmost label to stdout */
func handleOutput(w dns.ResponseWriter, r *dns.Msg) {
	/* Response message */
	m := &dns.Msg{}
	m.SetReply(r)

	for _, q := range r.Question {
		/* Ignore case */
		q.Name = strings.ToLower(q.Name)
		/* Make sure we've not seen this before */
		if seen, _ := CACHE.ContainsOrAdd(q.Name, true); seen {
			continue
		}
		/* Split label into payload and the rest */
		parts := strings.SplitN(q.Name, ".", 2)
		if 0 == len(parts) {
			panic("empty name")
		}
		/* Make sure it wasn't a bare output request */
		if "o" == parts[0] {
			continue
		}
		/* Extract payload */
		b, err := hex.DecodeString(parts[0])
		if nil != err {
			log.Printf(
				"[%v-%v] Invalid output %q: %v",
				w.RemoteAddr(),
				r.Id,
				parts[0],
				err,
			)
		}
		/* Send for output */
		OUT <- b
	}

	/* Send response back */
	if err := w.WriteMsg(m); nil != err {
		log.Printf(
			"[%v-%v] Unable to write output response: %v",
			w.RemoteAddr(),
			r.Id,
			err,
		)
	}
}

/* inA returns a A RR with up to three bytes of stdin, base64-encoded. */
func inA() (dns.RR, error) {
	ip, err := stdinToIP(4)
	return &dns.A{A: ip}, err
}

/* inAAAA returns an A RR with up to 12 bytes of stdin, base64-encoded */
func inAAAA() (dns.RR, error) {
	ip, err := stdinToIP(6)
	return &dns.AAAA{AAAA: ip}, err
}

/* stdinToIP returns a net.IP made from base64-encoding stdin.  The IP version
(4 or 6) is given in v. */
func stdinToIP(v int) (net.IP, error) {
	/* Work out how many bytes to read */
	var (
		n uint /* Number of payload bytes */
		b []byte
	)

	/* Work out how big we need our buffers to be */
	switch v {
	case 4:
		n = 3
		b = make([]byte, 4)
	case 6:
		n = 12
		b = make([]byte, 16)
	default:
		log.Panicf("bad IP version %v", v)
	}

	/* Read from stdin */
	in := inBytes(n)
	if nil == in {
		return nil, io.EOF
	}

	/* Convert to base-64, filling empty bytes with ='s */
	base64.StdEncoding.Encode(b, in)
	for i, v := range b {
		if 0 == v {
			b[i] = '='
		}
	}

	return net.IP(b), nil
}

/* inTXT returns a TXT RR with a single string of up to MAXSTRINGLEN bytes */
func inTXT() (dns.RR, error) {
	s, err := readString()
	rr := &dns.TXT{}
	if nil != s {
		rr.Txt = append(rr.Txt, *s)
	}
	return rr, err
}

/* inURI returns a URI RR with a target of up to MAXSTRINLEN bytes, and a
priority and weight of 0 */
func inURI() (dns.RR, error) {
	s, err := readString()
	rr := &dns.URI{
		Priority: 0,
		Weight:   0,
	}
	if nil != s {
		rr.Target = *s
	}
	return rr, err
}

/* readString returns a pointer to a string of up to MAXSTRINGLEN bytes, or nil
if no string was read. */
func readString() (*string, error) {
	/* Read from stdin */
	b := inBytes(MAXSTRINGLEN)
	if nil == b {
		return nil, io.EOF
	}
	s := string(b)
	return &s, nil
}

/* qtString returns the type of r as a string */
func qtString(q dns.Question) string {
	t, ok := dns.TypeToString[q.Qtype]
	if !ok {
		t = fmt.Sprintf("Type%v", q.Qtype)
	}
	return t
}

/* proxyStdin reads bytes from stdin and buffers them onto IN */
func proxyStdin() {
	/* Read buffer */
	var (
		b   = make([]byte, BUFLEN)
		n   int
		err error
		v   byte
	)
	defer close(IN)

	/* Read bytes, put on input */
	for {
		n, err = os.Stdin.Read(b)
		for _, v = range b[:n] {
			IN <- v
		}
		if nil != err {
			if io.EOF != err {
				log.Printf("[ERROR] Stdin: %v", err)
			}
			return
		}
	}
}

/* proxyStdout reads byte slices from OUT and proxies them to stdout */
func proxyStdout() {
	var (
		b   []byte
		err error
	)
	for b = range OUT {
		if _, err = os.Stdout.Write(b); nil != err {
			log.Fatalf("[ERROR] Stdout: %v", err)
		}
	}
}

/* inBytes returns at most N bytes from stdin.  If stdin is closed and there
are no bytes left, nil is returned. */
func inBytes(n uint) []byte {
	var (
		b  = make([]byte, int(n))
		ok bool
	)
	/* Try to fill the buffer */
	for i := range b {
		select {
		case b[i], ok = <-IN:
			/* Stop if the channel's closed */
			if !ok {
				/* If we didn't read anything, let the caller
				know */
				if 0 == i {
					return nil
				}
				/* Return what we got */
				b = b[:i]
				break
			}
		default: /* Nothing to read, channel's open */
			b = b[:i]
			break
		}
	}

	return b
}
