package main

import (
	"bufio"
	"flag"
	"fmt"
	"net"
	"os"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/efecankaya/go-port-scanner/internal/scanner"
	"github.com/efecankaya/go-port-scanner/internal/utils"
	"github.com/fatih/color"
)

func main() {
	welcome_print := color.New(color.FgCyan, color.Bold)
	welcome_print.Print("  ______   ______    ____    _____                          ______\n /_  __/  / ____/   / __ \\  / ___/  _____  ____ _   ____   / ____/  ____ \n  / /    / /       / /_/ /  \\__ \\  / ___/ / __ `/  / __ \\ / / __   / __ \\\n / /    / /___    / ____/  ___/ / / /__  / /_/ /  / / / // /_/ /  / /_/ /\n/_/     \\____/   /_/      /____/  \\___/  \\__,_/  /_/ /_/ \\____/   \\____/\n")
	var (
		usr_inputIP      string
		usr_domain_input string
		usr_domain_file  string
		usr_port_scan    string
		thread_count     int
		usr_timeout      int
		wg               sync.WaitGroup
	)

	flag.StringVar(&usr_domain_input, "d", "", "Domain Name")
	flag.StringVar(&usr_inputIP, "ip", "", "CIDR IP range")
	flag.StringVar(&usr_domain_file, "df", "", "Domains to be scanned from file")
	flag.IntVar(&thread_count, "t", 10, "Thread Count")
	flag.StringVar(&usr_port_scan, "p", "1-1024", "Port Scan Range")
	flag.IntVar(&usr_timeout, "time", 1, "Seconds of Timeout")
	flag.Parse()

	if err := utils.ValidateFlags(usr_domain_input, usr_inputIP, usr_domain_file); err != nil {
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
		IP_addresses, err_parse = utils.CIDRRange(usr_inputIP)
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
	var port_range_dist []int = utils.PortRangeDistribute(len(IP_addresses), port_input, thread_count)
	port_index := 0
	for i := 0; i < len(port_range_dist); i++ {
		wg.Add(1)
		go scanner.ScanPort(targets[port_index:port_index+port_range_dist[i]], time.Duration(usr_timeout)*time.Second, &wg)
		port_index += port_range_dist[i]
	}
	wg.Wait()
}
