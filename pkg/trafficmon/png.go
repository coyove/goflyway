package trafficmon

import (
	"bytes"
	"fmt"
	"image"
	"image/color"
	"image/draw"
	"image/png"
	"math"
	"strings"
	"time"

	"golang.org/x/image/font"
	"golang.org/x/image/font/basicfont"
	"golang.org/x/image/math/fixed"
)

const (
	margin     = 10 // pixels
	lineHeight = 16
)

func drawHVLine(canvas draw.Image, x0, y0 int, dir byte, length int, dotted bool, startColor, endColor color.Color) {
	if length <= 1 {
		return
	}

	sr, sg, sb, _ := startColor.RGBA()
	er, eg, eb, _ := endColor.RGBA()
	dr, dg, db := int(er)-int(sr), int(eg)-int(sg), int(eb)-int(sb)
	clr, k := color.RGBA{}, 0
	clr.A = 255

	ic := func(in uint32) uint8 { return uint8(in / 256) }
	ici := func(in int) uint8 { return uint8(in / 256) }

	calcColor := func() {
		if k == length-1 {
			clr.R, clr.G, clr.B = ic(er), ic(eg), ic(eb)
		} else {
			k := k / 4 * 4
			clr.R, clr.G, clr.B = ici(int(sr)+dr*k/(length-1)), ici(int(sg)+dg*k/(length-1)), ici(int(sb)+db*k/(length-1))
		}
		k++
	}

	switch dir {
	case 's':
		for y := y0; y < y0+length; y++ {
			calcColor()
			if !dotted || y%2 == 0 {
				canvas.Set(x0, y, clr)
			}
		}
	case 'n':
		for y := y0; y > y0-length; y-- {
			calcColor()
			if !dotted || y%2 == 0 {
				canvas.Set(x0, y, clr)
			}
		}
	case 'e':
		for x := x0; x < x0+length; x++ {
			calcColor()
			if !dotted || x%2 == 0 {
				canvas.Set(x, y0, clr)
			}
		}
	case 'w':
		for x := x0; x > x0-length; x-- {
			calcColor()
			if !dotted || x%2 == 0 {
				canvas.Set(x, y0, clr)
			}
		}
	}
}

func formatFloat(f float64) string {
	return fmt.Sprintf("%.2f", f)
}

var colorGray = color.RGBA{0xcc, 0xcc, 0xcc, 255}

func (s *Survey) PNG(h int, wScale int, xTickMinute int, extra string) *bytes.Buffer {
	smin, savg, smax := s.sent.Range()
	rmin, ravg, rmax := s.recved.Range()

	leftmargin := len(formatFloat(smax/1024)) * 9
	if m := len(formatFloat(rmax/1024)) * 9; m > leftmargin {
		leftmargin = m
	}

	face := basicfont.Face7x13
	pix := face.Mask.(*image.Alpha).Pix
	fixDot := func(i int) { pix[i+2], pix[i+10], pix[i+15] = 255, 0, 0 }
	fixDot(78*14 + 6*9)
	fixDot(78*26 + 6*4)
	fixDot(78*26 + 6*9)

	ln := len(s.sent.data) * wScale
	width := leftmargin + 1 + ln + 1 + margin
	height := margin + 1 + h + 1 + h + 1 + margin + 4*lineHeight + margin
	if extra != "" {
		height += lineHeight * len(strings.Split(extra, "\n"))
	}

	canvas := image.NewRGBA(image.Rect(0, 0, width, height))
	draw.Draw(canvas, canvas.Bounds(), image.White, image.Point{0, 0}, draw.Over)

	d := &font.Drawer{Dst: canvas, Src: image.Black, Face: face}

	drawYLabel := func(text string, y int) {
		d.Dot = fixed.P(leftmargin-2-d.MeasureString(text).Round(), y+face.Height/2)
		d.DrawString(text)
	}

	drawXLabel := func(text string, x int, align byte) {
		w := d.MeasureString(text).Round()
		switch align {
		case 'r':
			d.Dot = fixed.P(x-w, margin+1+h+1+h+1+2+face.Height)
		case 'l':
			d.Dot = fixed.P(x, margin+1+h+1+h+1+2+face.Height)
		default:
			d.Dot = fixed.P(x-w/2, margin+1+h+1+h+1+2+face.Height)
		}
		d.DrawString(text)
	}

	minutes := len(s.sent.data) / (60 / s.sent.interval)
	tick := ln / minutes

	now := time.Now()
	u := now.Unix()
	now = time.Unix(u-int64(now.Second())+round(float64(now.Second())/float64(s.sent.interval))*int64(s.sent.interval), 0)
	formatTime := func(minute int) string { return time.Unix(now.Unix()-int64(minute)*60, 0).Format("15:04") }

	// roundedTime := time.Unix(now.Unix()-int64(now.Second()), 0)
	fm := int(float64(tick*now.Second()) / 60)
	for i := 0; i < minutes; i += xTickMinute {
		drawHVLine(canvas, leftmargin+1+ln-fm-i*tick, margin+1, 's', h+1+h, false, colorGray, colorGray)
	}

	for i := 4; i < minutes-2; i += xTickMinute * 2 {
		drawXLabel(formatTime(i), leftmargin+1+ln-fm-i*tick, 's')
	}

	drawXLabel(formatTime(minutes), leftmargin+1, 'l')
	drawXLabel(formatTime(0), leftmargin+1+ln+1, 'r')

	_draw := func(avg, max float64, data []float64, reverse bool, clr, clr2 color.Color) {
		k := float64(h) / float64(max)

		y := margin + 1 + h + 1 - int(avg*k)
		if reverse {
			y = margin + 1 + h + 1 + int(avg*k)
		}

		drawHVLine(canvas, leftmargin+1, y, 'e', ln, true, clr, clr)

		yAxi := h * 2 / 3 / face.Height
		delta := max / 1024 / float64(yAxi)

		if delta > 1 {
			delta = math.Ceil(delta) * 1024
			for s := delta; s < max; s += delta {
				y := 0
				if reverse {
					y = margin + 1 + h + 1 + int(s*k)
					if margin+1+h+1+h+1-y < face.Height/2 {
						break
					}
				} else {
					y = margin + 1 + h + 1 - int(s*k)
					if y-margin < face.Height/2 {
						break
					}
				}

				drawHVLine(canvas, leftmargin+1, y, 'e', ln, false, colorGray, colorGray)
				drawYLabel(formatFloat(s/1024), y)
			}
		}

		for i := 0; i < len(data); i++ {
			sh := int(data[i] * k)

			for s := 0; s < wScale; s++ {
				dir := byte('n')
				if reverse {
					dir = 's'
				}
				drawHVLine(canvas, leftmargin+1+ln-i*2-s, margin+h+1+1, dir, sh, false, clr2, clr)
			}
		}
	}

	_draw(savg, smax, s.sent.data, false, color.RGBA{0xff, 0x52, 0x52, 255}, color.RGBA{0xbb, 0x32, 0x32, 255})
	_draw(ravg, rmax, s.recved.data, true, color.RGBA{0x00, 0x96, 0x88, 255}, color.RGBA{0x00, 0x59, 0x4b, 255})
	drawYLabel(formatFloat(smax/1024), margin+6)
	drawYLabel("0.00", margin+1+h)
	drawYLabel(formatFloat(rmax/1024), margin+h+1+h-6)

	text := fmt.Sprintf("Out: %sMB / %sKB/s Max: %sKB/s Avg: %sKB/s Min: %sKB/s\n"+
		" In: %sMB / %sKB/s Max: %sKB/s Avg: %sKB/s Min: %sKB/s\n"+
		" Lt: Max: %dms Avg: %.0fms Min: %dms",
		format(float64(s.totalSent)/1024/1024), format(s.sent.data[0]/1024),
		format(float64(smax)/1024), format(float64(savg)/1024), format(float64(smin)/1024),
		format(float64(s.totalRecved)/1024/1024), format(s.recved.data[0]/1024),
		format(float64(rmax)/1024), format(float64(ravg)/1024), format(float64(rmin)/1024),
		s.latencyMax/1e6, s.latency/1e6, s.latencyMin/1e6)

	if extra != "" {
		text += "\n" + extra
	}

	drawHVLine(canvas, 0, margin+1+h+1+h+1+lineHeight+4, 'e', width, true, colorGray, colorGray)

	for i, line := range strings.Split(text, "\n") {
		d.Dot = fixed.P(margin, margin+1+h+1+h+1+lineHeight+4+lineHeight*(1+i))
		d.DrawString(line)
	}

	_ = fmt.Println
	drawHVLine(canvas, leftmargin, margin, 'e', ln+2, false, color.Black, color.Black)
	drawHVLine(canvas, leftmargin, margin+h+h+2, 'e', ln+2, false, color.Black, color.Black)
	drawHVLine(canvas, leftmargin, margin+h+2, 'e', ln+2, false, color.Black, color.Black)
	drawHVLine(canvas, leftmargin, margin, 's', h+h+3, false, color.Black, color.Black)
	drawHVLine(canvas, leftmargin+ln+2, margin, 's', h+h+3, false, color.Black, color.Black)

	b := &bytes.Buffer{}
	png.Encode(b, canvas)
	return b
}
