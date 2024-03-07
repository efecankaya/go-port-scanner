package main

import (
	"bufio"
	"bytes"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/valyala/fasthttp"
)

// Find IP range provided by the user
func CIDRRange(cidr string) ([]string, error) {
	iterate_IP := func(ip net.IP) {
		for j := len(ip) - 1; j >= 0; j-- {
			ip[j]++
			if ip[j] > 0 {
				break
			}
		}
	}
	//Parse IP address
	ip, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil, err
	}

	var ips []string
	for ip := ip.Mask(ipnet.Mask); ipnet.Contains(ip); iterate_IP(ip) {
		ips = append(ips, ip.String())
	}
	return ips, nil
}

// Distribute the entirety of ports in to threads
func port_range_distribute(IP_Count int, port_array []int, thread_count int) []int {
	port_amount := IP_Count * len(port_array)
	thread_load := port_amount / thread_count
	thread_mod := port_amount % thread_count

	//Create port load per thread slice
	var port_range_dist []int
	if thread_load == 0 {
		port_range_dist = make([]int, thread_mod)
		for i := 0; i < len(port_range_dist); i++ {
			port_range_dist[i] = 1
		}
	} else {
		port_range_dist = make([]int, thread_count)
		for i := 0; i < thread_count; i++ {
			if thread_mod > 0 {
				port_range_dist[i] = thread_load + 1
				thread_mod -= 1
			} else {
				port_range_dist[i] = thread_load
			}
		}
	}
	return port_range_dist
}

// Scan ports for the given by the user
func scanPort(targets []string, timeout time.Duration, wg *sync.WaitGroup) {
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

func main() {

	fmt.Println("TCP port scanner implementation...")
	var (
		usr_inputIP      string
		usr_domain_input string
		usr_domain_file  string
		usr_port_scan    string
		thread_count     int
		usr_timeout      int
		wg               sync.WaitGroup
	)

	validateFlags := func(flag1 string, flag2 string, flag3 string) error {
		if flag1 != "" && flag2 != "" && flag3 != "" { //Mutual Exclusion
			return fmt.Errorf("mutually Exclusive flags are used")
		}
		if flag1 == "" && flag2 == "" && flag3 == "" { //No Input
			return fmt.Errorf("no input is given")
		}
		return nil
	}

	flag.StringVar(&usr_domain_input, "d", "", "Domain Name")
	flag.StringVar(&usr_inputIP, "ip", "", "CIDR IP range")
	flag.StringVar(&usr_domain_file, "df", "", "Domains to be scanned from file")
	flag.IntVar(&thread_count, "t", 10, "Thread Count")
	flag.StringVar(&usr_port_scan, "p", "1-1024", "Port Scan Range")
	flag.IntVar(&usr_timeout, "time", 1, "Seconds of Timeout")
	flag.Parse()

	if err := validateFlags(usr_domain_input, usr_inputIP, usr_domain_file); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		flag.Usage()
		return
	}

	if thread_count < 0 || thread_count > 300 { //Limit threads
		fmt.Println("Thread count violation!")
		return
	}
	if usr_timeout < 0 {
		fmt.Println("Invalid timeout set!")
		return
	}
	//Parse ports to scan
	var port_input []int

	portSpecs := strings.Split(usr_port_scan, ",")
	for _, spec := range portSpecs {
		if strings.Contains(spec, "-") {
			rangePorts := strings.Split(spec, "-")
			if len(rangePorts) != 2 {
				fmt.Printf("Error: Invalid format! ==> %s", spec)
				return
			}
			start_port, err1 := strconv.Atoi(rangePorts[0])
			end_port, err2 := strconv.Atoi(rangePorts[1])

			if err1 != nil || err2 != nil {
				fmt.Printf("Error: Invalid port type! ==> %s", spec)
				return
			}
			if start_port <= 0 || end_port > 65535 || start_port > end_port {
				fmt.Printf("Error: Invalid Range! ==> %s", spec)
				return
			}

			for i := start_port; i <= end_port; i++ {
				if !slices.Contains(port_input, i) {
					port_input = append(port_input, i)
				}
			}
		} else {
			port, err := strconv.Atoi(spec)
			if err != nil {
				fmt.Println("Error: Invalid type!")
				return
			}
			if port <= 0 || port > 65535 {
				fmt.Printf("Error: Port out of range! ==> %s", spec)
				return
			}
			if !slices.Contains(port_input, port) {
				port_input = append(port_input, port)
			}
		}
	}

	//Execute Scan
	var (
		IP_addresses []string //Target IP addresses
		err_parse    error
	)

	if usr_inputIP != "" { //Perform CIDR IP scan
		IP_addresses, err_parse = CIDRRange(usr_inputIP)
		if err_parse != nil {
			fmt.Println(err_parse)
			return
		}
	} else if usr_domain_input != "" { //Perform Domain Name scan
		IP_addresses, err_parse = net.LookupHost(usr_domain_input)
		if err_parse != nil {
			fmt.Println("No such domain found!")
			return
		}
	} else if usr_domain_file != "" { //Perform Domain Name scan from file
		file, err_parse := os.Open(usr_domain_file)
		if err_parse != nil {
			fmt.Println("Error opening file:", err_parse)
			return
		}
		defer file.Close()

		scanner := bufio.NewScanner(file)
		for scanner.Scan() {
			domain := scanner.Text()
			if ip_address, err := net.LookupHost(domain); err == nil {
				for i := 0; i < len(ip_address); i++ {
					IP_addresses = append(IP_addresses, ip_address[i])
				}
			} else {
				fmt.Printf("No such domain found! ==> %s\n", domain)
				continue
			}
		}
		if err := scanner.Err(); err != nil {
			fmt.Println("Error reading file:", err)
			return
		}
	}
	//Create targets
	var targets []string
	for i := 0; i < len(IP_addresses); i++ {
		for j := 0; j < len(port_input); j++ {
			target := fmt.Sprintf("%s:%d", IP_addresses[i], port_input[j])
			targets = append(targets, target)
		}
	}
	var port_range_dist []int = port_range_distribute(len(IP_addresses), port_input, thread_count)
	port_index := 0
	for i := 0; i < len(port_range_dist); i++ {
		wg.Add(1)
		go scanPort(targets[port_index:port_index+port_range_dist[i]], time.Duration(usr_timeout)*time.Second, &wg)
		port_index += port_range_dist[i]
	}
	wg.Wait()
}
