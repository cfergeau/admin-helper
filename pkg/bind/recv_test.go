// +build !windows

package bind

import (
	"fmt"
	"io/ioutil"
	"net"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestRoundTrip(t *testing.T) {
	dir, err := ioutil.TempDir("", "test-bind")
	assert.NoError(t, err)
	defer os.RemoveAll(dir)

	sentLn, err := net.Listen("tcp", "127.0.0.1:1234")
	assert.NoError(t, err)
	defer sentLn.Close()

	uds := filepath.Join(dir, "server.sock")
	viaLn, err := net.Listen("unix", uds)
	assert.NoError(t, err)
	defer viaLn.Close()
	go func() {
		viaconn, err := viaLn.Accept()
		assert.NoError(t, err)
		assert.NoError(t, Send(viaconn.(*net.UnixConn), sentLn.(*net.TCPListener)))
	}()

	clientConn, err := net.Dial("unix", uds)
	assert.NoError(t, err)

	receivedLn, err := Recv(clientConn.(*net.UnixConn), "127.0.0.1")
	assert.NoError(t, err)
	go func() {
		dataConn, err := receivedLn.Accept()
		assert.NoError(t, err)
		defer dataConn.Close()
		fmt.Println("Connection accepted")
		var data []byte
		bytesRead, err := dataConn.Read(data)
		fmt.Println("Data read")
		assert.NoError(t, err)
		assert.Equal(t, 8, bytesRead)
		assert.Equal(t, string(data), "sentdata")
	}()
	clientConn, err = net.Dial("tcp", "127.0.0.1:1234")
	assert.NoError(t, err)
	fmt.Println("Client connected")
	bytesSent, err := clientConn.Write([]byte("sentdata"))
	fmt.Println("Data written")
	assert.NoError(t, err)
	assert.Equal(t, bytesSent, 8)
	assert.NoError(t, receivedLn.Close())
}
