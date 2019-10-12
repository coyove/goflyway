package toh

import (
	"bytes"
	"encoding/binary"
	"math/rand"
	"sync/atomic"
	"time"

	"github.com/coyove/common/sched"
	"github.com/coyove/goflyway/v"
)

func init() {
	rand.Seed(time.Now().UnixNano())
}

func (d *Dialer) startOrch() {
	sched.Verbose = false

	var (
		directs   int    // number of requests with valid payload
		pings     int    // number of requests with no payload (ping)
		positives uint64 // number of positive pings (server said it had valid data for this ClientConn to read)
		loopcount int    // number of orch loops
	)

	go func() {
		for {
			conns := make(map[uint64]*ClientConn)
			loopcount++

		READ:
			for {
				select {
				case c := <-d.orch:
					conns[c.idx] = c
				case <-time.After((time.Millisecond) * 50):
					break READ
				}
			}

			if loopcount%20 == 0 || positives > 0 {
				v.VVprint("orch pings: ", pings, "(+", positives, "), directs: ", directs)
				directs, pings, positives = 0, 0, 0
			}

			if len(conns) == 0 {
				time.Sleep(200 * time.Millisecond)
				continue
			}

			var p bytes.Buffer
			var lastconn *ClientConn

			for k, conn := range conns {
				if len(conn.write.buf) > 0 || conn.write.survey.lastIsPositive {
					// For connections with actual data waiting to be sent, send them directly
					go conn.sendWriteBuf()
					delete(conns, k)
					directs++
					continue
				}

				binary.Write(&p, binary.BigEndian, conn.idx)
				lastconn = conn
			}

			if len(conns) <= 3 {
				for _, conn := range conns {
					directs++
					go conn.sendWriteBuf()
				}
				lastconn = nil
			}

			if lastconn == nil {
				// vprint("batch ping: 0, direct: ", count)
				continue
			}

			pingframe := frame{options: optPing, data: p.Bytes()}
			pings += p.Len() / 8

			go func(pingframe frame, lastconn *ClientConn, conns map[uint64]*ClientConn) {
				resp, err := lastconn.send(pingframe)
				if err != nil {
					v.Eprint("send error: ", err)
					return
				}
				defer resp.Body.Close()

				f, ok := parseframe(resp.Body, lastconn.read.blk)
				if !ok || f.options != optPing {
					return
				}

				for i := 0; i < len(f.data); i += 10 {
					connState := binary.BigEndian.Uint16(f.data[i:])
					connIdx := binary.BigEndian.Uint64(f.data[i+2:])

					if c := conns[connIdx]; c != nil && !c.read.closed && c.read.err == nil {
						switch connState {
						case PING_CLOSED:
							v.VVprint(c, " server side has closed")
							c.read.feedError(errClosedConn)
							c.Close()
						case PING_OK_VOID:
							c.write.survey.lastIsPositive = false
						case PING_OK:
							atomic.AddUint64(&positives, 1)
							c.write.survey.lastIsPositive = true
							go c.sendWriteBuf()
						}
					}
				}

				resp.Body.Close()
			}(pingframe, lastconn, conns)
		}
	}()
}

func (d *Dialer) orchSendWriteBuf(c *ClientConn) {
	select {
	case d.orch <- c:
	default:
		go c.sendWriteBuf()
	}
}
