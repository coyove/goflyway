package toh

import (
	"crypto/cipher"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/coyove/common/waitobject"
	"github.com/coyove/goflyway/v"
)

var (
	errClosedConn = fmt.Errorf("use of closed connection")
	dummyTouch    = func(interface{}) interface{} { return 1 }
)

// Define the max pending bytes stored in memory, any further bytes will be written to disk
var MaxReadBufferSize = 1024 * 1024 * 1

type readConn struct {
	sync.Mutex
	idx          uint64             // readConn index, should be the same as the one in ClientConn/SerevrConn
	buf          []byte             // read buffer
	frames       chan frame         // incoming frames
	futureframes map[uint32]frame   // future frames, which have arrived early
	futureSize   int                // total size of future frames
	ready        *waitobject.Object // it being touched means that data in "buf" are ready
	err          error              // stored error, if presented, all operations afterwards should return it
	blk          cipher.Block       // cipher block, aes-128
	closed       bool               // is readConn closed already
	tag          byte               // tag, 'c' for readConn in ClientConn, 's' for readConn in ServerConn
	counter      uint32             // counter, must be synced with the writer on the other side
}

func newReadConn(idx uint64, blk cipher.Block, tag byte) *readConn {
	r := &readConn{
		frames:       make(chan frame, 1024),
		futureframes: map[uint32]frame{},
		idx:          idx,
		tag:          tag,
		blk:          blk,
		ready:        waitobject.New(),
	}
	go r.readLoopRearrange()
	return r
}

func (c *readConn) feedframes(r io.ReadCloser) (datalen int, err error) {
	count := 0
	for {
		f, ok := parseframe(r, c.blk)
		if !ok {
			err = fmt.Errorf("invalid frames")
			c.feedError(err)
			return 0, err
		}
		if f.idx == 0 {
			break
		}
		if c.closed {
			return 0, errClosedConn
		}
		if c.err != nil {
			return 0, c.err
		}

		// v.Vprint("feed: ", f.data)

		if !c.feedframe(f) {
			return 0, errClosedConn
		}
		count += len(f.data)
	}
	return count, nil
}

func (c *readConn) feedframe(f frame) (ok bool) {
	defer func() {
		if r := recover(); r != nil {
			// Dirty way to avoid closed channel panic
			if strings.Contains(fmt.Sprintf("%v", r), "send on close") {
				ok = false
			} else {
				panic(r)
			}
		}
	}()
	c.frames <- f
	return true
}

func (c *readConn) feedError(err error) {
	c.err = err
	c.ready.Touch(dummyTouch)
	c.close()
}

func (c *readConn) close() {
	c.Lock()
	defer c.Unlock()
	if c.closed {
		return
	}
	c.closed = true
	close(c.frames)
	c.ready.SetWaitDeadline(time.Now())
}

func (c *readConn) readLoopRearrange() {
LOOP:
	select {
	//		case <-time.After(time.Second * 10):
	//			v.Vprint("timeout")
	case f, ok := <-c.frames:
		if !ok {
			return
		}

		c.Lock()
		if f.connIdx != c.idx {
			c.Unlock()
			c.feedError(fmt.Errorf("fatal: unmatched stream index"))
			return
		}

		if f.idx <= c.counter {
			c.Unlock()
			//c.feedError(fmt.Errorf("unmatched counter, maybe server GCed the connection"))
			return
		}

		c.futureframes[f.idx] = f
		c.futureSize += len(f.data)
		for {
			idx := c.counter + 1
			if f, ok := c.futureframes[idx]; ok {
				if f.future {
					buf, err := ioutil.ReadFile(frameTmpPath(c.idx, f.idx))
					if err != nil {
						c.Unlock()
						c.feedError(fmt.Errorf("fatal: missing certain frame from disk"))
						return
					}
					os.Remove(frameTmpPath(c.idx, f.idx))
					f.data = buf
					v.Vprint(c, " back load frame: ", f)
				}

				c.buf = append(c.buf, f.data...)
				c.counter = f.idx
				delete(c.futureframes, f.idx)
				c.futureSize -= len(f.data)
				continue
			}

			if c.futureSize > MaxReadBufferSize {
				if ioutil.WriteFile(frameTmpPath(c.idx, f.idx), f.data, 0755) != nil {
					c.Unlock()
					c.feedError(fmt.Errorf("fatal: missing certain frame"))
					return
				}

				v.Vprint(c, " tmp save frame: ", f)
				c.futureframes[f.idx] = frame{future: true, idx: f.idx}
			}
			break
		}
		if c.counter == 0xffffffff {
			panic("surprise!")
		}
		c.Unlock()
		c.ready.Touch(dummyTouch)
	}
	goto LOOP
}

func (c *readConn) Read(p []byte) (n int, err error) {
READ:
	if c.closed {
		return 0, errClosedConn
	}

	if c.err != nil {
		return 0, c.err
	}

	if c.ready.IsTimedout() {
		return 0, &timeoutError{}
	}

	c.Lock()
	if len(c.buf) > 0 {
		n = copy(p, c.buf)
		c.buf = c.buf[n:]
		c.Unlock()
		return
	}
	c.Unlock()

	_, ontime := c.ready.Wait()

	if c.closed {
		return 0, errClosedConn
	}

	if !ontime {
		return 0, &timeoutError{}
	}

	goto READ
}

func (c *readConn) String() string {
	return fmt.Sprintf("<%s,ctr:%d>", string(c.tag), c.counter)
}
