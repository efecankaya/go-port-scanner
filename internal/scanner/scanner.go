package scanner

import (
	"bytes"
	"fmt"
	"io"
	"net"
	"strconv"
	"sync"
	"time"

	"github.com/efecankaya/go-port-scanner/internal/modules/banner"
	techfinder "github.com/efecankaya/go-port-scanner/internal/modules/tech_finder"
	"github.com/fatih/color"
	"github.com/valyala/fasthttp"
)

type TargetResult struct {
	HostIP             string //IP address of the target
	Port               int    //Port number of the target
	Banner             string //Banner of the target
	http_valid         bool   //If contains valid http response
	http_headers       string //HTTP headers
	http_response_body string //HTTP response body
	OperatingSystem    string //Operating system of the target
	Error              string //Discarded targets
}

func ScanPort(comm_up_result_channel chan bool, comm_result_channel chan []TargetResult, targets []string, timeout time.Duration, wg *sync.WaitGroup) {
	error_print := color.New(color.FgRed, color.Bold)
	client := &fasthttp.Client{}
	clientHeader := "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36"
	ret_targets_results := make([]TargetResult, 0)
	for _, target := range targets {
		target_identify := TargetResult{}
		host, portStr, _ := net.SplitHostPort(target)
		port, _ := strconv.Atoi(portStr)
		conn, err := fasthttp.DialDualStackTimeout(target, timeout)
		if err != nil {
			//Might handle this error better
			target_identify.Error = err.Error()
			continue
		}
		target_identify.HostIP = host
		target_identify.Port = port

		if port == 80 || port == 443 {
			// HTTP(S) request
			req_target := fasthttp.AcquireRequest()
			req_target.SetRequestURI("http://" + target)
			req_target.SetTimeout(timeout)
			req_target.Header.Set("User-Agent", clientHeader)
			resp_target := fasthttp.AcquireResponse()

			if err := client.DoTimeout(req_target, resp_target, timeout); err != nil {
				//Handle error better
				target_identify.Error = err.Error()
				conn.Close()
				continue
			}
			if resp_target.StatusCode() != fasthttp.StatusOK {
				//Handle different status codes -- Redirect etc.
				if 300 <= resp_target.StatusCode() && resp_target.StatusCode() < 400 {
					//Handle redirect
					redirect_limit := 5
					err := client.DoRedirects(req_target, resp_target, redirect_limit)
					if err != nil {
						target_identify.Error = err.Error()
						conn.Close()
						continue
					}
				} else if 400 <= resp_target.StatusCode() && resp_target.StatusCode() < 500 {
					//Handle client errors
					fmt.Printf("Client error %d recieved \n", resp_target.StatusCode())
					conn.Close()
					continue
				} else if 500 <= resp_target.StatusCode() && resp_target.StatusCode() < 600 {
					fmt.Printf("Server error %d recieved \n", resp_target.StatusCode())
					conn.Close()
					continue
				}
			}

			headers := make(map[string]string)
			resp_target.Header.VisitAll(func(key, value []byte) { //Gather headers from response
				headers[string(key)] = string(value)
			})
			headersString := fmt.Sprintf("%v", headers)

			responsePacket, err := io.ReadAll(bytes.NewReader(resp_target.Body()))
			if err != nil {
				//Handle error better
				target_identify.Error = err.Error()
				conn.Close()
				continue
			}

			fasthttp.ReleaseResponse(resp_target)
			fasthttp.ReleaseRequest(req_target)
			target_identify.http_valid = true
			target_identify.http_headers = headersString
			target_identify.http_response_body = string(responsePacket)

		} else {
			// Grabbing banner
			target_identify.Banner, err = banner.GrabBanner(conn, timeout)
			if err != nil {
				//Handle error better
				conn.Close()
				continue
			}
			target_identify.http_valid = false
		}
		ret_targets_results = append(ret_targets_results, target_identify)
		conn.Close()
	}
	//Analyze for http/https results for provided signatures
	for _, target := range ret_targets_results {
		if target.http_valid { //Struct contains http/https body
			http_tag_analyze := techfinder.HttpAnalyze(target.http_response_body, target.http_headers)
			for _, tag := range http_tag_analyze {
				error_print.Println(tag)
			}
		}
	}
	if len(ret_targets_results) > 0 { //If valuable results are found
		fmt.Println("Results found")
		comm_up_result_channel <- true
		wg.Done()
		comm_result_channel <- ret_targets_results
	} else {
		comm_up_result_channel <- false
		wg.Done()
	}
}
