package proxy

import (
	"bytes"
	"fmt"
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

	if delta := smax - smin; delta > 0 {
		hScale := float64(h-1) / delta
		ret.WriteString("<polyline fill-opacity=\"0.5\" stroke=\"#F44336\" fill=\"#F44336\" stroke-width=\"0.5px\" points=\"")

		x := 0.0
		for i := len(iot.TrSent.data) - 1; i >= 0; i-- {
			f := int((iot.TrSent.data[i] - smin) * hScale)
			ret.WriteString(fmt.Sprintf("%f,%d %f,%d ", x-wTick/2, f-1, x+wTick/2, f-1))
			x += wTick
		}

		ret.WriteString(fmt.Sprintf(" %d,%d %d,%d %d,%d -10,-10 -10,0\"/>", w, 0, w+10, 0, w+10, -10))
	}

	if delta := rmax - rmin; delta > 0 {
		hScale := float64(h-1) / delta
		ret.WriteString("<polyline fill-opacity=\"0.5\" stroke=\"#00796B\" fill=\"#00796B\" stroke-width=\"0.5px\" points=\"")

		x := 0.0
		for i := len(iot.TrRecved.data) - 1; i >= 0; i-- {
			f := int((iot.TrRecved.data[i] - rmin) * hScale)
			ret.WriteString(fmt.Sprintf("%f,%d %f,%d ", x-wTick/2, h-f+1, x+wTick/2, h-f+1))
			x += wTick
		}

		ret.WriteString(fmt.Sprintf(" %d,%d %d,%d %d,%d -10,%d -10,%d\"/>", w, h, w+10, h, w+10, h+10, h+10, h))
	}

	ret.WriteString("<defs><linearGradient id=\"" + id + "-i\" x1=\"0\" x2=\"1\" y1=\"0\" y2=\"0\"><stop offset=\"0%\" stop-color=\"white\" stop-opacity=\"0.75\"/><stop offset=\"100%\" stop-color=\"white\" stop-opacity=\"0\"/></linearGradient></defs>")

	ret.WriteString("<rect width=\"50%\" height=\"100%\" fill=\"url(#" + id + "-i)\"/>")

	ret.WriteString("<text font-size=\"0.4em\" style='text-shadow: 0 0 1px #ccc'>")

	ret.WriteString(fmt.Sprintf("<tspan fill=\"#F44336\" x=\".4em\" dy=\"1.2em\">&uarr; %.2fKiB/s (%.2fKiB/s, %.2fMiB)</tspan>",
		iot.TrSent.data[0]/1024, smax/1024, float64(iot.sent)/1024/1024))

	ret.WriteString(fmt.Sprintf("<tspan fill=\"#00796B\" x=\".4em\" dy=\"1.2em\">&darr; %.2fKiB/s (%.2fKiB/s, %.2fMiB)</tspan>",
		iot.TrRecved.data[0]/1024, rmax/1024, float64(iot.recved)/1024/1024))

	ret.WriteString("</text>")

	ret.WriteString(fmt.Sprintf("<polyline stroke-width=\"1px\" stroke=\"#d1d2d3\" fill=\"none\" points=\"0,0 %d,%d %d,%d %d,%d 0,0\"/>",
		w, 0, w, h, 0, h))

	ret.WriteString("</svg>")
	return ret
}
