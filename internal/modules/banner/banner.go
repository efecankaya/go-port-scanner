package banner

import (
	"bufio"
	"net"
	"strings"
	"time"
)

func GrabBanner(conn net.Conn, timeout time.Duration) (string, error) {
	reader := bufio.NewReader(conn)
	conn.SetReadDeadline(time.Now().Add(timeout))
	response, err := reader.ReadString('\n')
	if err != nil {
		return "", err
	} else {
		return strings.TrimSpace(response), nil
	}
}
