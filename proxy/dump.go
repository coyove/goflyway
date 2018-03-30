package proxy

import (
	"fmt"
	"io"
	"math"
	"os"
	"strconv"
	"strings"
	"time"
)

func timeStampMilli() string {
	return time.Now().Format(time.StampMilli)
}

type dumpReadWriteWrapper struct {
	reader  io.Reader
	writer  io.Writer
	counter int64
	file    *os.File
}

func (w *dumpReadWriteWrapper) Write(buf []byte) (int, error) {
	n, err := w.writer.Write(buf)
	var b buffer
	b.WriteString(fmt.Sprintf("# %s >>>>>> response payload %d <<<<<<\n", timeStampMilli(), w.counter))
	writeBuffer(&b, buf[:n], 16)
	w.file.Write(b.Bytes())
	return n, err
}

func (w *dumpReadWriteWrapper) Read(buf []byte) (int, error) {
	n, err := w.reader.Read(buf)
	var b buffer
	b.WriteString(fmt.Sprintf("# %s >>>>>> request payload %d <<<<<<\n", timeStampMilli(), w.counter))
	writeBuffer(&b, buf[:n], 16)
	w.file.Write(b.Bytes())
	return n, err
}

func (w *dumpReadWriteWrapper) Close() error {
	return nil
}

func writeBuffer(b *buffer, buf []byte, columns int) {
	const spaces = "                                                                "
	getSpaces := func(len int) string {
		if len < 64 {
			return spaces[:len]
		}
		return strings.Repeat(" ", len)
	}

	writeASCII := func(i int) {
		x := buf[i]
		if x >= 0x20 && x < 0x7f {
			b.WriteByte(x)
		} else {
			b.WriteByte('.')
		}
	}

	if len(buf) == 0 {
		b.WriteString("<empty buffer>\n\n")
		return
	}

	rows := int(math.Ceil(float64(len(buf)) / float64(columns)))
	ln := len(strconv.FormatInt(int64((rows-1)*columns), 16))
	formatRow := func(r int) string {
		x := strconv.FormatInt(int64(r), 16)
		x = "0000000000000000"[:ln-len(x)] + x
		return x
	}

	//        | .0 .1 .... .x .y |
	// 000000 | 00 00 .... 00 00 | abcdefg
	// 0000xx | 00               | a

	b.WriteString(getSpaces(ln+1) + "|")
	for i := 0; i < columns; i++ {
		x := strconv.FormatInt(int64(i), 16)
		b.WriteString(" ."[:3-len(x)] + x)
	}
	b.WriteString(" |\n")

	for r := 0; r < rows; r++ {
		b.WriteString(formatRow(r * columns))
		b.WriteString(" |")

		if r != rows-1 {
			for c := 0; c < columns; c++ {
				b.WriteString(fmt.Sprintf(" %02x", buf[r*columns+c]))
			}
		} else {
			m := 0
			for i := r * columns; i < len(buf); i++ {
				b.WriteString(fmt.Sprintf(" %02x", buf[i]))
				m++
			}

			b.WriteString(getSpaces((columns - m) * 3))
		}

		b.WriteString(" | ")

		if r != rows-1 {
			for c := 0; c < columns; c++ {
				writeASCII(r*columns + c)
			}
		} else {
			for i := r * columns; i < len(buf); i++ {
				writeASCII(i)
			}
		}

		b.WriteString("\n")
	}

	b.WriteString("\n")
}
