package main

import (
	"flag"
	"fmt"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"
)

func scanPort(ip string, port_start int, port_end int, timeout time.Duration, wg *sync.WaitGroup) {
	defer wg.Done()
	for scan_port := port_start; scan_port < port_end; scan_port++ {
		target := fmt.Sprintf("%s:%d", ip, scan_port)
		conn, err := net.DialTimeout("tcp", target, timeout)
		if err != nil {
			continue
		}
		fmt.Printf("Port %d is open\n", scan_port)
		defer conn.Close()
	}
}

func main() {

	fmt.Println("TCP port scanner implementation...")
	var (
		usr_domain_input string
		port_limit       string
		thread_count     int
		wg               sync.WaitGroup
	)
	flag.StringVar(&usr_domain_input, "d", "", "Domain Name")
	flag.IntVar(&thread_count, "tc", 10, "Thread Count")
	flag.StringVar(&port_limit, "p", "1-1024", "Port Scan Range")
	flag.Parse()

	//Resolve the domain name to IPv4 address
	IPaddress, err := net.LookupHost(usr_domain_input)
	if err != nil || usr_domain_input == "" { //Cannot resolve domain name
		fmt.Println("Invalid domain name!")
		return
	}
	fmt.Printf("The IP address of host is %s\n", IPaddress[0])

	if thread_count < 0 || thread_count > 100 { //Limit threads
		fmt.Println("Thread count violation!")
		return
	}
	//Split port range
	port_span := strings.Split(port_limit, "-")
	if len(port_span) != 2 {
		fmt.Println("Error: Input string must be in the format 'integer-integer'")
		flag.Usage() // Print usage message
		return
	}

	start_port, err_startp := strconv.Atoi(port_span[0])
	end_port, err_endp := strconv.Atoi(port_span[1])

	if err_startp != nil || err_endp != nil {
		fmt.Println("Error: Limit not integer defined!")
		return
	}
	if start_port > end_port {
		fmt.Println("Error: Start port cannot be greater than ending port!")
		return
	}

	//Give threads the port scan loads && Assign threads their port load
	thread_load := (end_port - start_port) / thread_count
	thread_mod := (end_port - start_port) % thread_count
	timeout := time.Second

	for i := 0; i < thread_count; i++ {
		wg.Add(1)
		if start_port+thread_load < end_port {
			go scanPort(IPaddress[0], start_port, start_port+thread_load, timeout, &wg)
			start_port += thread_load
		} else {
			go scanPort(IPaddress[0], start_port, start_port+thread_mod, timeout, &wg)
		}
	}
	wg.Wait()
}
