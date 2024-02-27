package main

import (
	"fmt"
	"net"
	"sync"
	"time"
)

func scanPort(host string, port int, wg *sync.WaitGroup, limiter chan struct{}) {
	defer wg.Done()
	target := fmt.Sprintf("%s:%d", host, port)
	conn, err := net.DialTimeout("tcp", target, 1*time.Second)
	if err != nil {
		return
	}
	defer conn.Close()
	fmt.Printf("Port %d is open\n", port)
}

func main() {
	host := "scanme.nmap.org"
	var wg sync.WaitGroup
	limiter := make(chan struct{}, 100) // Limit concurrency to 100 goroutines
	for port := 1; port <= 65535; port++ {
		wg.Add(1)
		limiter <- struct{}{} // Add token to limiter channel
		go func(p int) {
			defer func() { <-limiter }() // Remove token from limiter channel
			scanPort(host, p, &wg, limiter)
		}(port)
	}
	wg.Wait()
}
