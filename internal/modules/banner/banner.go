package banner

import (
	"bufio"
	"fmt"
	"net"
	"strings"
	"time"
)

func GrabBanner(conn net.Conn, timeout time.Duration) {
	reader := bufio.NewReader(conn)
	conn.SetReadDeadline(time.Now().Add(timeout))
	response, err := reader.ReadString('\n')
	if err != nil {
		//fmt.Printf("Error reading banner: %s\n", err)
	} else {
		fmt.Printf(" - %s\n", strings.TrimSpace(response))
	}
}
