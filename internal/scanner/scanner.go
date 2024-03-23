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
		host, portStr, _ := net.SplitHostPort(target)
		port, _ := strconv.Atoi(portStr)

		conn, err := fasthttp.DialDualStackTimeout(target, timeout)
		if err != nil {
			//Might handle this error better
			continue
		}
		fmt.Printf("Discovered open port %d/tcp (%s) on %s\n", port, data.PortToService[port], host)

		if port == 80 || port == 443 {
			// HTTP(S) request
			req_target := fasthttp.AcquireRequest()
			req_target.SetRequestURI("http://" + target)
			req_target.SetTimeout(timeout)
			req_target.Header.Set("User-Agent", clientHeader)
			resp_target := fasthttp.AcquireResponse()

			if err := client.DoTimeout(req_target, resp_target, timeout); err != nil {
				//Handle error better
				continue
			}
			if resp_target.StatusCode() != fasthttp.StatusOK {
				//Handle different status codes -- Redirect etc.
				if 300 <= resp_target.StatusCode() && resp_target.StatusCode() < 400 {
					//Handle redirect
					redirect_limit := 5
					err := client.DoRedirects(req_target, resp_target, redirect_limit)
					if err == fasthttp.ErrTooManyRedirects {
						fmt.Printf("Redirect for %s exceded the limit!\n", target)
						continue
					} else if err != nil {
						//Handle other errors
						continue
					}
				} else if 400 <= resp_target.StatusCode() && resp_target.StatusCode() < 500 {
					//Handle client errors
					fmt.Printf("Client error %d recieved \n", resp_target.StatusCode())
					continue
				} else if 500 <= resp_target.StatusCode() && resp_target.StatusCode() < 600 {
					fmt.Printf("Server error %d recieved \n", resp_target.StatusCode())
					continue
				}
			}
			headers := make(map[string]string)
			resp_target.Header.VisitAll(func(key, value []byte) { //Gather headers from response
				headers[string(key)] = string(value)
			})
			fmt.Printf("Headers from %s: %v\n", target, headers)

			responsePacket, err := io.ReadAll(bytes.NewReader(resp_target.Body()))
			if err != nil {
				//Handle error better
				continue
			}
			fmt.Printf("Response from %s: %s\n", target, responsePacket) //Response to be saved
			fasthttp.ReleaseResponse(resp_target)
			fasthttp.ReleaseRequest(req_target)
		} else {
			// Grabbing banner
			banner.GrabBanner(conn, timeout)
		}
		conn.Close()
	}
}
