package trafficmon

import (
	"math"
	"sync"
	"sync/atomic"
	"time"
	"unsafe"
)

type trafficData struct {
	logarithm bool
	startTime int64
	lastTime  int64
	lastData  int64
	ticks     int64
	interval  int // seconds
	tmp       float64
	min, max  float64
	data      []float64
}

func (d *trafficData) Init(ln, intval int) {
	d.data = make([]float64, ln)
	d.interval = intval
	d.startTime = time.Now().UnixNano()
	d.lastTime = d.startTime
	d.ticks = 1
}

func (d *trafficData) Log(n float64) float64 {
	return math.Log2(n + 1)
}

func round(x float64) int64 {
	if int64(x+0.5) == int64(x) {
		return int64(x)
	}
	return int64(x) + 1
}

func (d *trafficData) Append(data int64) {
	now := time.Now().UnixNano()
	intv := int64(d.interval) * 1e9

AGAIN:
	if now <= d.startTime+d.ticks*intv {
		d.tmp += float64(data - d.lastData)
		d.lastData = data
		d.lastTime = now
	} else {
		ds := float64(data-d.lastData) / (float64(now-d.lastTime) / 1e9) // average data per second
		rem := ds * float64(d.startTime+d.ticks*intv-d.lastTime) / 1e9   // remaining data to next tick
		// fmt.Println(d.lastData, ds, rem)
		d.tmp += rem
		d.lastData += round(rem)
		d.tmp /= float64(d.interval)

		copy(d.data[1:], d.data)
		d.data[0] = d.tmp
		d.tmp = 0

		d.lastTime = d.startTime + d.ticks*intv
		d.ticks++
		goto AGAIN
	}
}

func (d *trafficData) Range() (min float64, avg float64, max float64) {
	min, max = 1e100, 0.0

	for i := len(d.data) - 1; i >= 0; i-- {
		f := d.data[i]
		avg += f

		if f > max {
			max = f
		} else if f < min {
			min = f
		}
	}

	d.min, d.max = min, max
	avg /= float64(len(d.data))
	return
}

func (d *trafficData) Get(index int) float64 {
	f := d.data[index]
	if d.logarithm {
		return d.Log(f)
	}
	return f
}

type Survey struct {
	totalSent   int64
	totalRecved int64
	latency     float64
	latencyMin  int64
	latencyMax  int64
	sent        trafficData
	recved      trafficData
	sync.Mutex
}

func (s *Survey) Init(length, intval int) {
	s.sent.Init(length/intval, intval)
	s.recved.Init(length/intval, intval)
	s.latencyMin = -1
}

func (s *Survey) Send(size int64) *Survey {
	atomic.AddInt64(&s.totalSent, size)
	return s
}

func (s *Survey) Recv(size int64) *Survey {
	atomic.AddInt64(&s.totalRecved, size)
	return s
}

func (s *Survey) Latency(nsec int64) {
	const N = 2
	for {
		o := s.latency
		n := o - o/N + float64(nsec)/N

		oi, ni := *(*uint64)(unsafe.Pointer(&o)), *(*uint64)(unsafe.Pointer(&n))
		if atomic.CompareAndSwapUint64((*uint64)(unsafe.Pointer(&s.latency)), oi, ni) {
			break
		}
	}

	if nsec > s.latencyMax {
		s.latencyMax = nsec
	}

	if nsec < s.latencyMin || s.latencyMin == -1 {
		s.latencyMin = nsec
	}
}

func (s *Survey) Update() {
	s.Lock()
	s.sent.Append(s.totalSent)
	s.recved.Append(s.totalRecved)
	s.Unlock()
}

func (s *Survey) Data() (int64, int64) {
	return s.totalRecved, s.totalSent
}
