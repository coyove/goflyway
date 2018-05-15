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

	"github.com/coyove/common/dejavu"
)

const (
	margin = 18 // pixels
)

func drawHVLine(canvas draw.Image, x0, y0 int, dir byte, length int, dotted bool, startColor, endColor color.Color) {
	if length < 1 {
		return
	}

	set := func(x, y int, clr color.Color) {
		rgba := canvas.At(x, y).(color.RGBA)
		n := clr.(color.RGBA)
		r, g, b := int(n.R)*int(n.A)/255, int(n.G)*int(n.A)/255, int(n.B)*int(n.A)/255
		r0, g0, b0 := int(rgba.R)*int(255-n.A)/255, int(rgba.G)*int(255-n.A)/255, int(rgba.B)*int(255-n.A)/255
		c := func(a, b int) uint8 {
			if a+b > 255 {
				return 255
			}
			return uint8(a + b)
		}

		rgba.R, rgba.G, rgba.B = c(r, r0), c(g, g0), c(b, b0)
		canvas.Set(x, y, rgba)
	}

	if length == 1 {
		set(x0, y0, startColor)
		return
	}

	sr, sg, sb, _ := startColor.RGBA()
	er, eg, eb, _ := endColor.RGBA()
	dr, dg, db := int(er)-int(sr), int(eg)-int(sg), int(eb)-int(sb)
	clr, k := startColor.(color.RGBA), 0

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
				set(x0, y, clr)
			}
		}
	case 'n':
		for y := y0; y > y0-length; y-- {
			calcColor()
			if !dotted || y%2 == 0 {
				set(x0, y, clr)
			}
		}
	case 'e':
		for x := x0; x < x0+length; x++ {
			calcColor()
			if !dotted || x%2 == 0 {
				set(x, y0, clr)
			}
		}
	case 'w':
		for x := x0; x > x0-length; x-- {
			calcColor()
			if !dotted || x%2 == 0 {
				set(x, y0, clr)
			}
		}
	}
}

func formatFloat(f float64) string {
	return fmt.Sprintf("%.2f", f)
}

var (
	colorBlack     = color.RGBA{0x00, 0x00, 0x00, 0xff}
	colorGray      = color.RGBA{0xcc, 0xcc, 0xcc, 0xff}
	colorGray2     = color.RGBA{0xdd, 0xdd, 0xdd, 0xff}
	colorLightGray = color.RGBA{0x00, 0x00, 0x00, 0x11}
	colorBorder    = color.RGBA{0x76, 0x76, 0x76, 0xff}
	colorBorder2   = color.RGBA{0xcf, 0xcf, 0xcf, 0xff}
	colorBorder3   = color.RGBA{0x9e, 0x9e, 0x9e, 0xff}
	colorGrid      = color.RGBA{207, 0, 0, 64}
)

// PNG xScale should be an even number
func (s *Survey) PNG(h0 int, xScale int, xTickMinute int, xTickSubMinute int, extra string) *bytes.Buffer {
	_, savg, smax := s.sent.Range()
	_, ravg, rmax := s.recved.Range()

	leftmargin := len(formatFloat(smax/1024)) * 9
	if m := len(formatFloat(rmax/1024)) * 9; m > leftmargin {
		leftmargin = m
	}
	leftmargin += margin / 2

	ln := len(s.sent.data) * xScale
	width := leftmargin + 1 + ln + 1 + margin
	lineHeight := dejavu.FullHeight + 2
	height := margin + 1 + h0 + 1 + 1 + margin + 5*lineHeight + margin
	if extra != "" {
		height += lineHeight * len(strings.Split(extra, "\n"))
	}

	canvas := image.NewRGBA(image.Rect(0, 0, width, height))
	draw.Draw(canvas, canvas.Bounds(), image.NewUniform(color.RGBA{0xf3, 0xf3, 0xf3, 0xff}), image.Point{0, 0}, draw.Over)
	draw.Draw(canvas, image.Rect(leftmargin, margin+1+1, leftmargin+1+ln, margin+1+h0+1+1), image.White, image.Point{0, 0}, draw.Over)

	drawYLabel := func(text string, y int) {
		dejavu.DrawText(canvas, text, leftmargin-5-len(text)*dejavu.Width, y+dejavu.Height/2, image.Black)
	}

	drawXLabel := func(text string, x int, align byte) {
		w := len(text) * dejavu.Width
		base := margin + 1 + h0 + 1 + 1 + 2

		var y int
		switch align {
		case 'r':
			x, y = x-w, base+dejavu.Height
		case 'l':
			x, y = x, base+dejavu.Height
		default:
			x, y = x-w/2, base+dejavu.Height
		}

		dejavu.DrawText(canvas, text, x, y, image.Black)
	}

	minutes := len(s.sent.data) * s.sent.interval / 60
	tick := ln / minutes

	now := time.Now()
	u := now.Unix()
	now = time.Unix(u-int64(now.Second())+round(float64(now.Second())/float64(s.sent.interval))*int64(s.sent.interval), 0)
	formatTime := func(minute int) string { return time.Unix(now.Unix()-int64(minute)*60, 0).Format("15:04") }
	fm := int(float64(tick*now.Second()) / 60)

	for i := xTickMinute * xScale; i < minutes-xTickMinute; i += xTickMinute * xScale {
		x := leftmargin + 1 + ln - fm - i*tick
		t := formatTime(i)
		if x < leftmargin+1+len(t)*dejavu.Width*3/2 {
			// very close to the first label, so ignore it
			continue
		}
		drawXLabel(t, x, 's')
	}

	drawXLabel(formatTime(minutes), leftmargin+1, 'l')
	drawXLabel(formatTime(0), leftmargin+1+ln+1, 'r')

	h1, h2 := h0/2, h0/2
	if smax != 0 {
		h1 = int(float64(h0) * smax / (smax + rmax))
		h2 = h0 - h1
	}

	_draw := func(avg, max float64, h int, data []float64, reverse bool, drawSubGrid bool, clr, clr2 color.Color) {
		k := float64(h) / float64(max)

		if !drawSubGrid {
			for i := 0; i < len(data); i++ {
				sh := int(data[i] * k)

				for s := 0; s < xScale; s++ {
					if reverse {
						drawHVLine(canvas, leftmargin+ln-i*xScale-s, margin+h1+1+1, 's', sh, false, clr2, clr)
					} else {
						drawHVLine(canvas, leftmargin+ln-i*xScale-s, margin+h1+1, 'n', sh, false, clr2, clr)
					}
				}
			}
		}

		yAxi := h * 2 / 3 / dejavu.Height
		delta := max / 1024 / float64(yAxi)

		if delta > 1 {
			delta = math.Ceil(delta) * 1024
			for s, i := delta/2, 0; s < max; s, i = s+delta/2, i+1 {
				y := 0
				if reverse {
					y = margin + 1 + h1 + 1 + int(s*k)
				} else {
					y = margin + 1 + h1 + 1 - int(s*k)
				}

				if i%2 == 1 {
					if drawSubGrid {
						continue
					}

					// Draw horizontal primary grid line
					drawHVLine(canvas, leftmargin+1, y, 'e', ln+3, true, colorGrid, colorGrid)
					drawHVLine(canvas, leftmargin+1, y, 'w', 4, false, colorGrid, colorGrid)
					if reverse {
						if margin+1+h0+1+1-y < dejavu.Height*3/2 {
							break
						}
					} else {
						if y-margin < dejavu.Height*3/2 {
							break
						}
					}
					drawYLabel(formatFloat(s/1024), y)
				} else if drawSubGrid {
					// Draw horizontal sub grid line
					drawHVLine(canvas, leftmargin+1, y, 'e', ln+3, true, colorLightGray, colorLightGray)
					drawHVLine(canvas, leftmargin+1, y, 'w', 3, false, colorLightGray, colorLightGray)
				}
			}
		}

		if drawSubGrid {
			return
		}

		y := margin + 1 + h1 + 1 - int(avg*k)
		if reverse {
			y = margin + 1 + h1 + 1 + int(avg*k)
		}

		drawHVLine(canvas, leftmargin+1, y, 'e', ln, true, clr, clr)
		drawHVLine(canvas, leftmargin+1, y, 'w', 3, false, clr, clr)
	}

	_drawVGrid := func(sub bool) {
		xt := xTickMinute * xScale
		xst := xTickSubMinute * xScale

		for i := 0; i < minutes; i++ {
			x, h2 := leftmargin+1+ln-fm-i*tick, 1+h0+1+1
			if i%xt != 0 && i%xst == 0 && sub {
				drawHVLine(canvas, x, margin-1, 's', h2+2, true, colorLightGray, colorLightGray)
				drawHVLine(canvas, x, margin+h2, 's', 1, false, colorLightGray, colorLightGray)
			}

			if i%xt == 0 && !sub {
				drawHVLine(canvas, x, margin-1, 's', h2+2, true, colorGrid, colorGrid)
				drawHVLine(canvas, x, margin+h2, 's', 2, false, colorGrid, colorGrid)
			}
		}
	}

	rColor, rColor2 := color.RGBA{0x19, 0xa9, 0xda, 255}, color.RGBA{0x0e, 0x6f, 0x90, 255}
	sColor, sColor2 := color.RGBA{0x00, 0x96, 0x88, 255}, color.RGBA{0x00, 0x59, 0x4b, 255}

	_draw(savg, smax, h1, s.sent.data, false, false, sColor, sColor2)
	_draw(ravg, rmax, h2, s.recved.data, true, false, rColor, rColor2)
	_drawVGrid(true)
	_draw(savg, smax, h1, s.sent.data, false, true, sColor, sColor2)
	_draw(ravg, rmax, h2, s.recved.data, true, true, rColor, rColor2)
	_drawVGrid(false)

	drawYLabel(formatFloat(smax/1024), margin+3)
	drawYLabel("0.00", margin+1+h1)
	drawYLabel(formatFloat(rmax/1024), margin+h0-2)

	text := fmt.Sprintf("out    last:%s kb/s  max:%s kb/s  avg:%s kb/s\n"+
		"in     last:%s kb/s  max:%s kb/s  avg:%s kb/s\n"+
		"total  in:  %s GB    out:%s GB\n"+
		"ping   max: %s ms    avg:%s ms    min:%s ms",
		format(s.sent.data[0]/128), format(float64(smax)/128), format(float64(savg)/128),
		format(s.recved.data[0]/128), format(float64(rmax)/128), format(float64(ravg)/128),
		format(float64(s.totalRecved)/1073741824), format(float64(s.totalSent)/1073741824),
		format(float64(s.latencyMax)/1e6), format(s.latency/1e6), format(float64(s.latencyMin)/1e6))

	if extra != "" {
		text += "\n" + extra
	}

	y := margin + 1 + h0 + 1 + 1 + lineHeight + 4
	drawHVLine(canvas, 0, y, 'e', width, true, colorGray, colorGray)
	y += 2

	drawLegend := func(x0, y0 int, img image.Image) {
		const legendSize = 10
		draw.Draw(canvas, image.Rect(x0, y+y0, x0+legendSize, y+y0+legendSize), image.Black, image.Point{0, 0}, draw.Over)
		draw.Draw(canvas, image.Rect(x0+1, y+y0+1, x0+legendSize-1, y+y0+legendSize-1), img, image.Point{0, 0}, draw.Over)
	}

	drawLegend(margin, 6, image.NewUniform(sColor))
	drawLegend(margin, 6+lineHeight, image.NewUniform(rColor))

	for i, line := range strings.Split(text, "\n") {
		dejavu.DrawText(canvas, line, margin*2, y+lineHeight*(1+i), image.Black)
	}

	// Zero Axis
	drawHVLine(canvas, leftmargin, margin+h1+2, 'e', ln+2, false, colorBlack, colorBlack)

	// X Axis
	drawHVLine(canvas, leftmargin-2, margin+h0+2, 'e', ln+7, false, colorBorder, colorBorder)
	drawHVLine(canvas, leftmargin+ln+5, margin+h0, 's', 5, false, colorBorder, colorBorder)
	drawHVLine(canvas, leftmargin+ln+6, margin+h0+1, 's', 3, false, colorBorder, colorBorder)
	drawHVLine(canvas, leftmargin+ln+7, margin+h0+2, 's', 1, false, colorBorder, colorBorder)

	// Y Axis
	drawHVLine(canvas, leftmargin, margin-3, 's', h0+8, false, colorBorder, colorBorder)
	drawHVLine(canvas, leftmargin-2, margin-3, 'e', 5, false, colorBorder, colorBorder)
	drawHVLine(canvas, leftmargin-1, margin-4, 'e', 3, false, colorBorder, colorBorder)
	drawHVLine(canvas, leftmargin, margin-5, 'e', 1, false, colorBorder, colorBorder)

	// Border
	drawHVLine(canvas, 0, 0, 'e', width, false, colorBorder2, colorBorder2)
	drawHVLine(canvas, 0, 1, 'e', width, false, colorBorder2, colorBorder2)
	drawHVLine(canvas, 0, 0, 's', height, false, colorBorder2, colorBorder2)
	drawHVLine(canvas, 1, 0, 's', height, false, colorBorder2, colorBorder2)
	drawHVLine(canvas, 0, height-1, 'e', width, false, colorBorder3, colorBorder3)
	drawHVLine(canvas, 1, height-2, 'e', width, false, colorBorder3, colorBorder3)
	drawHVLine(canvas, width-1, 0, 's', height, false, colorBorder3, colorBorder3)
	drawHVLine(canvas, width-2, 1, 's', height, false, colorBorder3, colorBorder3)

	date := now.Format(time.RFC1123)
	dejavu.DrawText(canvas, date, width-4-len(date)*dejavu.Width, height-6, image.Black)

	b := &bytes.Buffer{}
	png.Encode(b, canvas)
	return b
}
