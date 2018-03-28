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
	margin     = 15 // pixels
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

var (
	colorGray      = color.RGBA{0xcc, 0xcc, 0xcc, 255}
	colorGray2     = color.RGBA{0xdd, 0xdd, 0xdd, 255}
	colorLightGray = color.RGBA{0xee, 0xee, 0xee, 255}
	colorBorder    = color.RGBA{0x76, 0x76, 0x76, 255}
	colorBorder2   = color.RGBA{0xcf, 0xcf, 0xcf, 255}
	colorBorder3   = color.RGBA{0x9e, 0x9e, 0x9e, 255}
)

func (s *Survey) PNG(h int, wScale int, xTickMinute int, extra string) *bytes.Buffer {
	smin, savg, smax := s.sent.Range()
	rmin, ravg, rmax := s.recved.Range()

	leftmargin := len(formatFloat(smax/1024)) * 9
	if m := len(formatFloat(rmax/1024)) * 9; m > leftmargin {
		leftmargin = m
	}
	leftmargin += margin / 2

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
	draw.Draw(canvas, canvas.Bounds(), image.NewUniform(color.RGBA{0xf3, 0xf3, 0xf3, 0xff}), image.Point{0, 0}, draw.Over)
	draw.Draw(canvas, image.Rect(leftmargin, margin, leftmargin+1+ln, margin+h*2+3), image.White, image.Point{0, 0}, draw.Over)

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
	for i := 0; i < minutes; i++ {
		clr := colorLightGray
		if i%xTickMinute == 0 {
			clr = colorGray
		}
		drawHVLine(canvas, leftmargin+1+ln-fm-i*tick, margin+1, 's', h+1+h, false, clr, clr)
	}

	for i := xTickMinute * 2; i < minutes-xTickMinute; i += xTickMinute * 2 {
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
			for s, i := delta/2, 0; s < max; s, i = s+delta/2, i+1 {
				y := 0
				if reverse {
					y = margin + 1 + h + 1 + int(s*k)
				} else {
					y = margin + 1 + h + 1 - int(s*k)
				}

				if i%2 == 1 {
					drawHVLine(canvas, leftmargin+1, y, 'e', ln, false, colorGray2, colorGray2)
					if reverse {
						if margin+1+h+1+h+1-y < face.Height*3/2 {
							break
						}
					} else {
						if y-margin < face.Height*3/2 {
							break
						}
					}
					drawYLabel(formatFloat(s/1024), y)
				} else {
					drawHVLine(canvas, leftmargin+1, y, 'e', ln, true, colorLightGray, colorLightGray)
				}
			}
		}

		for i := 0; i < len(data); i++ {
			sh := int(data[i] * k)

			for s := 0; s < wScale; s++ {
				dir := byte('n')
				if reverse {
					dir = 's'
				}
				drawHVLine(canvas, leftmargin+1+ln-i*wScale-s, margin+h+1+1, dir, sh, false, clr2, clr)
			}
		}
	}

	sColor := color.RGBA{0xff, 0x52, 0x52, 255}
	rColor := color.RGBA{0x00, 0x96, 0x88, 255}
	_draw(savg, smax, s.sent.data, false, sColor, color.RGBA{0xbb, 0x32, 0x32, 255})
	_draw(ravg, rmax, s.recved.data, true, rColor, color.RGBA{0x00, 0x59, 0x4b, 255})
	drawYLabel(formatFloat(smax/1024), margin+3)
	drawYLabel("0.00", margin+1+h)
	drawYLabel(formatFloat(rmax/1024), margin+h+1+h-3)

	text := fmt.Sprintf("out: %sMB / %sKB/s  max: %sKB/s  avg: %sKB/s  min: %sKB/s\n"+
		"in:  %sMB / %sKB/s  max: %sKB/s  avg: %sKB/s  min: %sKB/s\n"+
		"ack: %dms %.0fms %dms",
		format(float64(s.totalSent)/1024/1024), format(s.sent.data[0]/1024),
		format(float64(smax)/1024), format(float64(savg)/1024), format(float64(smin)/1024),
		format(float64(s.totalRecved)/1024/1024), format(s.recved.data[0]/1024),
		format(float64(rmax)/1024), format(float64(ravg)/1024), format(float64(rmin)/1024),
		s.latencyMax/1e6, s.latency/1e6, s.latencyMin/1e6)

	if extra != "" {
		text += "\n" + extra
	}

	y := margin + 1 + h + 1 + h + 1 + lineHeight + 4
	drawHVLine(canvas, 0, y, 'e', width, true, colorGray, colorGray)
	y += 4

	drawLegend := func(x0, y0 int, img image.Image) {
		const legendSize = 10
		draw.Draw(canvas, image.Rect(x0, y+y0, x0+legendSize, y+y0+legendSize), image.Black, image.Point{0, 0}, draw.Over)
		draw.Draw(canvas, image.Rect(x0+1, y+y0+1, x0+legendSize-1, y+y0+legendSize-1), img, image.Point{0, 0}, draw.Over)
	}

	drawLegend(12, 6, image.NewUniform(sColor))
	drawLegend(12, 6+lineHeight, image.NewUniform(rColor))

	for i, line := range strings.Split(text, "\n") {
		d.Dot = fixed.P(margin*2, y+lineHeight*(1+i))
		d.DrawString(line)
	}

	_ = fmt.Println
	drawHVLine(canvas, leftmargin, margin, 'e', ln+2, false, colorBorder, colorBorder)
	drawHVLine(canvas, leftmargin, margin+h+h+2, 'e', ln+2, false, colorBorder, colorBorder)
	drawHVLine(canvas, leftmargin, margin+h+2, 'e', ln+2, false, colorBorder, colorBorder)
	drawHVLine(canvas, leftmargin, margin, 's', h+h+3, false, colorBorder, colorBorder)
	drawHVLine(canvas, leftmargin+ln+2, margin, 's', h+h+3, false, colorBorder, colorBorder)
	drawHVLine(canvas, 0, 0, 'e', width, false, colorBorder2, colorBorder2)
	drawHVLine(canvas, 0, 1, 'e', width, false, colorBorder2, colorBorder2)
	drawHVLine(canvas, 0, 0, 's', height, false, colorBorder2, colorBorder2)
	drawHVLine(canvas, 1, 0, 's', height, false, colorBorder2, colorBorder2)
	drawHVLine(canvas, 0, height-1, 'e', width, false, colorBorder3, colorBorder3)
	drawHVLine(canvas, 1, height-2, 'e', width, false, colorBorder3, colorBorder3)
	drawHVLine(canvas, width-1, 0, 's', height, false, colorBorder3, colorBorder3)
	drawHVLine(canvas, width-2, 1, 's', height, false, colorBorder3, colorBorder3)

	b := &bytes.Buffer{}
	png.Encode(b, canvas)
	return b
}
