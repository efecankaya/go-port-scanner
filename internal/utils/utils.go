package utils

import (
	"fmt"
	"net"
)

func ValidateFlags(flag1 string, flag2 string, flag3 string) error {
	if flag1 != "" && flag2 != "" && flag3 != "" { //Mutual Exclusion
		return fmt.Errorf("mutually Exclusive flags are used")
	}
	if flag1 == "" && flag2 == "" && flag3 == "" { //No Input
		return fmt.Errorf("no input is given")
	}
	return nil
}

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

func PortRangeDistribute(IP_Count int, port_array []int, thread_count int) []int {
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
