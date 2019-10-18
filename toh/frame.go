package toh

import (
	"bytes"
	"crypto/cipher"
	"encoding/binary"
	"fmt"
	"hash/crc32"
	"io"
	"time"

	"github.com/coyove/common/sched"
	"github.com/coyove/goflyway/v"
)

const (
	optSyncConnIdx = 1 << iota
	optHello
	optPing
	optClosed
)

type frame struct {
	connIdx uint64
	idx     uint32
	options byte
	future  bool
	data    []byte
	next    *frame
}

// connection id 8b | data idx 4b | data length 4b | hash 3b | option 1b
func (f *frame) marshal(blk cipher.Block) []byte {
	buf := [20]byte{}
	binary.BigEndian.PutUint32(buf[:4], f.idx)
	binary.BigEndian.PutUint64(buf[4:], f.connIdx)

	gcm, _ := cipher.NewGCM(blk)
	x := gcm.Seal(f.data[:0], buf[:12], f.data, nil)
	binary.LittleEndian.PutUint32(buf[12:], uint32(len(x)))
	buf[16] = f.options

	h := crc32.Checksum(buf[:17], crc32.IEEETable)
	buf[17], buf[18], buf[19] = byte(h), byte(h>>8), byte(h>>16)

	blk.Encrypt(buf[:], buf[:])
	blk.Encrypt(buf[4:], buf[4:])

	p := new(bytes.Buffer)
	p.Write(buf[:])
	p.Write(x)

	if f.next != nil {
		p.Write(f.next.marshal(blk))
	}

	return p.Bytes()
}

func parseframe(r io.ReadCloser, blk cipher.Block) (f frame, ok bool) {
	k := sched.Schedule(func() {
		v.VVprint("[ParseFrame] waiting too long")
		go r.Close()
	}, time.Minute)
	defer k.Cancel()

	header := [20]byte{}
	if n, err := io.ReadAtLeast(r, header[:], len(header)); err != nil || n != len(header) {
		if err == io.EOF {
			ok = true
		} else {
			v.Eprint(err)
		}
		return
	}

	blk.Decrypt(header[4:], header[4:])
	blk.Decrypt(header[:], header[:])

	h := crc32.Checksum(header[:17], crc32.IEEETable)
	if header[17] != byte(h) || header[18] != byte(h>>8) || header[19] != byte(h>>16) {
		v.Vprint(header)
		return
	}

	datalen := int(binary.LittleEndian.Uint32(header[12:]))
	data := make([]byte, datalen)
	if n, err := io.ReadAtLeast(r, data, datalen); err != nil || n != datalen {
		v.Eprint(err)
		return
	}

	gcm, err := cipher.NewGCM(blk)
	data, err = gcm.Open(nil, header[:12], data, nil)
	if err != nil {
		v.Eprint(err)
		return
	}

	f.idx = binary.BigEndian.Uint32(header[:4])
	f.connIdx = binary.BigEndian.Uint64(header[4:])
	f.data = data
	f.options = header[16]
	return f, true
}

func (f frame) String() string {
	return fmt.Sprintf("<F:%d,conn:%s,opt:%d,len:%d>", f.idx, formatConnIdx(f.connIdx), f.options, len(f.data))
}
