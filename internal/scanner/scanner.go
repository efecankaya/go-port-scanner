package scanner

import (
	"bytes"
	"fmt"
	"io"
	"net"
	"strconv"
	"sync"
	"time"

	"github.com/efecankaya/go-port-scanner/data"
	"github.com/efecankaya/go-port-scanner/internal/modules/banner"
	"github.com/valyala/fasthttp"
)

func ScanPort(targets []string, timeout time.Duration, wg *sync.WaitGroup) {
	defer wg.Done()
	client := &fasthttp.Client{}
	clientHeader := "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36"
	for _, target := range targets {
		host, portStr, err := net.SplitHostPort(target)
		if err != nil {
			//fmt.Printf("Invalid target format: %s\n", target)
			continue
		}
		port, err := strconv.Atoi(portStr)
		if err != nil {
			//fmt.Printf("Invalid port format: %s\n", portStr)
			continue
		}
		conn, err := net.DialTimeout("tcp4", target, timeout)
		if err != nil {
			//Might handle this error better
			continue
		}
		fmt.Printf("Discovered open port %d/tcp (%s) on %s\n", port, data.PortToService[port], host)

		if port == 80 || port == 443 {
			// HTTP(S) request
			req := fasthttp.AcquireRequest()
			req.SetRequestURI("http://" + target)
			req.Header.Set("User-Agent", clientHeader)
			resp := fasthttp.AcquireResponse()

			if err := client.DoTimeout(req, resp, timeout); err != nil {
				//Handle error better
				continue
			}
			if resp.StatusCode() != fasthttp.StatusOK {
				//Handle different status codes -- Redirect etc.
				continue
			}

			_, err := io.ReadAll(bytes.NewReader(resp.Body()))
			if err != nil {
				//Handle error better
				continue
			}
			//fmt.Printf("Response from %s: %s\n", target, responsePacket)
			fasthttp.ReleaseResponse(resp)
			fasthttp.ReleaseRequest(req)
		} else {
			// Grabbing banner
			banner.GrabBanner(conn, timeout)
		}
		conn.Close()
	}
}
