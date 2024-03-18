package scanner

import (
	"bytes"
	"fmt"
	"io"
	"strings"
	"sync"
	"time"

	"github.com/valyala/fasthttp"
)

func ScanPort(targets []string, timeout time.Duration, wg *sync.WaitGroup) {
	defer wg.Done()
	client := &fasthttp.Client{}
	client_header := "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36"
	for i := 0; i < len(targets); i++ {
		conn, err := fasthttp.DialDualStackTimeout(targets[i], timeout)
		if err != nil {
			//Might handle this error better
			continue
		}
		fmt.Printf("Discovered open port %s/tcp on %s\n", targets[i][strings.LastIndex(targets[i], ":")+1:], targets[i][:strings.LastIndex(targets[i], ":")])
		//Commuting with target happens here

		req_target := fasthttp.AcquireRequest()

		req_target.SetRequestURI("http://" + targets[i])
		req_target.Header.Set("User-Agent", client_header)
		resp_target := fasthttp.AcquireResponse()

		if err := client.DoTimeout(req_target, resp_target, 6*timeout); err != nil {
			//Handle error better
			continue
		}
		if resp_target.StatusCode() != fasthttp.StatusOK {
			//Handle different status codes -- Redirect etc.
			continue
		}

		response_packet, err := io.ReadAll(bytes.NewReader(resp_target.Body()))
		if err != nil {
			//Handle error better
			continue
		}
		fmt.Printf("Response from %s: %s\n", targets[i], response_packet)
		fasthttp.ReleaseResponse(resp_target)
		fasthttp.ReleaseRequest(req_target)
		conn.Close()
	}
}
