package proxy

import (
	"bytes"
	"fmt"
	"math"
	"sync"
	"time"
)

/*
 * A variation of token bucket for traffic throttling
 * Note goflyway is intended for single user mainly, so throttling is really not that necessary for now
 * TODO: bugs all around
 */

type TokenBucket struct {
	Speed int64 // bytes per second

	capacity    int64 // bytes
	maxCapacity int64
	lastConsume int64

	mu sync.Mutex
}

func NewTokenBucket(speed, max int64) *TokenBucket {
	return &TokenBucket{
		Speed:       speed,
		lastConsume: time.Now().UnixNano(),
		maxCapacity: max,
	}
}

func (tb *TokenBucket) Consume(n int64) {
	tb.mu.Lock()
	defer tb.mu.Unlock()

	now := time.Now().UnixNano()

	if tb.Speed == 0 {
		tb.lastConsume = now
		return
	}

	ms := (now - tb.lastConsume) / 1e6
	tb.capacity += ms * tb.Speed / 1000

	if tb.capacity > tb.maxCapacity {
		tb.capacity = tb.maxCapacity
	}

	if n <= tb.capacity {
		tb.lastConsume = now
		tb.capacity -= n
		return
	}

	sec := float64(n-tb.capacity) / float64(tb.Speed)
	time.Sleep(time.Duration(sec*1000) * time.Millisecond)

	tb.capacity = 0
	tb.lastConsume = time.Now().UnixNano()
}

type trafficData struct {
	data []float64
}

func (d *trafficData) Append(f float64) {
	copy(d.data[1:], d.data)
	d.data[0] = f
}

func (d *trafficData) Range() (min float64, max float64) {
	min, max = 1e100, 0.0

	for i := len(d.data) - 1; i >= 0; i-- {
		if f := d.data[i]; f > max {
			max = f
		} else if f < min {
			min = f
		}
	}

	return
}

func (iot *io_t) SVG(id string, w, h int) *bytes.Buffer {
	ret := &bytes.Buffer{}
	ret.WriteString(fmt.Sprintf("<svg id=\"%s\" viewBox=\"0 0 %d %d\">", id, w, h))

	wTick := float64(w) / float64(len(iot.TrSent.data)-1)
	smin, smax := iot.TrSent.Range()
	rmin, rmax := iot.TrRecved.Range()
	min, max := math.Min(smin, rmin), math.Max(smax, rmax)
	delta := max - min

	tick := 60 / trafficSurveyinterval
	minutes, m := len(iot.TrSent.data)/tick, -1
	for i := 0; i < len(iot.TrSent.data); i += tick {
		x := float64(i) * wTick
		m++
		if m%2 == 1 {
			ret.WriteString(fmt.Sprintf("<rect x=\"%f\" y=\"0\" width=\"%f\" height=\"%d\" fill=\"#f7f8f9\"/>",
				x-wTick, wTick*float64(tick), h))
		}
		if m%5 == 0 {
			ret.WriteString(fmt.Sprintf("<text x=\"%f\" y=\"%d\" font-size=\".3em\">-%d</text>", x+1, h-2, minutes-m))
		}
	}

	ret.WriteString(fmt.Sprintf("<polyline stroke-width=\"1px\" stroke=\"#d1d2d3\" fill=\"none\" points=\"0,0 %d,%d %d,%d %d,%d 0,0\"/>",
		w, 0, w, h, 0, h))

	if delta > 0 {
		hScale := float64(h) / delta

		out := func(data []float64, color string) {
			ret.WriteString(fmt.Sprintf("<polyline fill-opacity=\"0.5\" stroke=\"%s\" fill=\"%s\" stroke-width=\"0.5px\" points=\"",
				color, color))

			x := 0.0
			for i := len(data) - 1; i >= 0; i-- {
				f := int((data[i] - min) * hScale)
				ret.WriteString(fmt.Sprintf("%f,%d ", x, h-f))
				x += wTick
			}
			ret.WriteString(fmt.Sprintf(" %d,%d %d,%d %d,%d -10,%d -10,%d\"/>", w, h, w+10, h, w+10, h+10, h+10, h))
		}

		out(iot.TrSent.data, "#F44336")
		out(iot.TrRecved.data, "#00796B")
	}

	ret.WriteString("<text font-size=\"0.4em\">")

	ret.WriteString(fmt.Sprintf("<tspan fill=\"#F44336\" x=\".4em\" dy=\"1.2em\">&uarr; %.2fKiB/s (%.2fKiB/s, %.2fMiB)</tspan>",
		iot.TrSent.data[0]/1024, smax/1024, float64(iot.sent)/1024/1024))

	ret.WriteString(fmt.Sprintf("<tspan fill=\"#00796B\" x=\".4em\" dy=\"1.2em\">&darr; %.2fKiB/s (%.2fKiB/s, %.2fMiB)</tspan>",
		iot.TrRecved.data[0]/1024, rmax/1024, float64(iot.recved)/1024/1024))

	ret.WriteString("</text></svg>")
	return ret
}
