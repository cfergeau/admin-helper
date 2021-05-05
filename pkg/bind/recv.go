// +build !windows

package bind

import (
	"fmt"
	"net"
	"os"
	"syscall"
)

type Result struct {
	Error            string `json:"error,omitempty"`
	UnixDomainSocket string `json:"socket,omitempty"`
}

// Receive a file descriptor (*net.TCPListener here) from an unix domain socket
// https://github.com/moby/vpnkit/blob/master/go/pkg/vpnkit/forward/vmnet_darwin.go#L16
// https://github.com/ftrvxmtrx/fd/blob/master/fd.go
func Recv(via *net.UnixConn, localIP string) (net.Listener, error) {
	viaf, err := via.File()
	if err != nil {
		return nil, err
	}
	socket := int(viaf.Fd())
	defer viaf.Close()

	buf := make([]byte, syscall.CmsgSpace(4))
	_, _, _, _, err = syscall.Recvmsg(socket, nil, buf, 0)
	if err != nil {
		return nil, err
	}

	var msgs []syscall.SocketControlMessage
	msgs, err = syscall.ParseSocketControlMessage(buf)
	if err != nil {
		return nil, err
	}
	if len(msgs) != 1 {
		return nil, fmt.Errorf("unexpected number of messages (got %d)", len(msgs))
	}
	fds, err := syscall.ParseUnixRights(&msgs[0])
	if err != nil {
		return nil, err
	}
	if len(fds) != 1 {
		return nil, fmt.Errorf("unexpected number of fd (got %d)", len(fds))
	}

	fd := os.NewFile(uintptr(fds[0]), "")
	if fd == nil {
		return nil, fmt.Errorf("could not open fd")
	}

	return net.FileListener(fd)
}
