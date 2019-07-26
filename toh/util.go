package toh

import (
	"bufio"
	"encoding/base32"
	"fmt"
	"math/rand"
	"net"
	"os"
	"path/filepath"
	"sync/atomic"
	"time"
	"unsafe"
)

var (
	debug = false
)

type timeoutError struct{}

func (e *timeoutError) Error() string {
	return "operation timed out"
}

func (e *timeoutError) Timeout() bool {
	return true
}

func (e *timeoutError) Temporary() bool {
	return false
}

type BufConn struct {
	net.Conn
	*bufio.Reader
}

func NewBufConn(conn net.Conn) *BufConn {
	return &BufConn{Conn: conn, Reader: bufio.NewReader(conn)}
}

func (c *BufConn) Write(p []byte) (int, error) {
	return c.Conn.Write(p)
}

func (c *BufConn) Read(p []byte) (int, error) {
	return c.Reader.Read(p)
}

var countermark uint32

func newConnectionIdx() uint64 {
	// 25bit timestamp (1 yr) | 16bit counter | 23bit random values
	now := uint32(time.Now().Unix())
	c := atomic.AddUint32(&countermark, 1)
	return uint64(now)<<39 | uint64(c&0xffff)<<23 | uint64(rand.Uint32()&0x7fffff)
}

func formatConnIdx(idx uint64) string {
	return base32.HexEncoding.EncodeToString((*(*[8]byte)(unsafe.Pointer(&idx)))[1:6])
}

func frameTmpPath(connIdx uint64, idx uint32) string {
	return filepath.Join(os.TempDir(), fmt.Sprintf("%x-%d.toh", connIdx, idx))
}
