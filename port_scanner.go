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

func port_range_distribute(end_port int, start_port int, thread_count int) []int {
	port_amount := (end_port - start_port) + 1
	thread_load := port_amount / thread_count
	thread_mod := port_amount % thread_count

	//Create port load per thread slice
	if thread_load == 0 {
		port_range_dist := make([]int, thread_mod)
		for i := 0; i < len(port_range_dist); i++ {
			port_range_dist[i] = 1
		}
		return port_range_dist
	} else {
		port_range_dist := make([]int, thread_count)
		for i := 0; i < thread_count; i++ {
			if thread_mod > 0 {
				port_range_dist[i] = thread_load + 1
				thread_mod -= 1
			} else {
				port_range_dist[i] = thread_load
			}
		}
		return port_range_dist
	}
}
func scanPort(ip string, port_start int, scan_amount int, timeout time.Duration, wg *sync.WaitGroup) {
	defer wg.Done()
	for scan_port := port_start; scan_port < port_start+scan_amount; scan_port++ {
		target := fmt.Sprintf("%s:%d", ip, scan_port)
		conn, err := net.DialTimeout("tcp", target, timeout) //Exception Handling --> Port maybe not availiable
		if err != nil {
			continue
		}
		fmt.Printf("Port %d is open\n", scan_port)
		conn.Close()
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
		flag.Usage()
		return
	}
	fmt.Printf("The IP address of host is %s\n", IPaddress[0])

	if thread_count < 0 || thread_count > 300 { //Limit threads
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

	if start_port < 1 || end_port < 1 || start_port > end_port {
		fmt.Println("Error: Invalid Port Range!")
		return
	}

	//Give threads the port scan loads && Assign threads their port load
	port_range_dist := port_range_distribute(end_port, start_port, thread_count)
	timeout := time.Second

	for i := 0; i < len(port_range_dist); i++ {
		wg.Add(1)
		go scanPort(IPaddress[0], start_port, port_range_dist[i], timeout, &wg)
		start_port += port_range_dist[i]
	}

	wg.Wait()
}
