package toh

import (
	"io"
	"net/http"
	"time"
)

type CommonOptions struct {
	MaxWriteBuffer int
	Timeout        time.Duration
}

func (d *CommonOptions) check() {
	if d.Timeout == 0 {
		d.Timeout = time.Second * 15
	}
	if d.MaxWriteBuffer == 0 {
		d.MaxWriteBuffer = 1024 * 1024
	}
}

type Option func(d *Dialer, ln *Listener)

var (
	WithTransport = func(tr http.RoundTripper) Option {
		return Option(func(d *Dialer, ln *Listener) {
			if d != nil {
				d.Transport = tr
			}
		})
	}
	WithInactiveTimeout = func(t time.Duration) Option {
		return Option(func(d *Dialer, ln *Listener) {
			if d != nil {
				d.Timeout = t
			}
			if ln != nil {
				ln.Timeout = t
			}
		})
	}
	WithWebSocket = func(ws bool) Option {
		return Option(func(d *Dialer, ln *Listener) {
			if d != nil {
				d.WebSocket = ws
			}
		})
	}
	WithMaxWriteBuffer = func(size int) Option {
		return Option(func(d *Dialer, ln *Listener) {
			if d != nil {
				d.MaxWriteBuffer = size
			}
			if ln != nil {
				ln.MaxWriteBuffer = size
			}
		})
	}
	WithHeader = func(hdr string) Option {
		return Option(func(d *Dialer, ln *Listener) {
			if d != nil {
				d.URLHeader = hdr
			}
		})
	}
	WithPathPattern = func(pattern string) Option {
		return Option(func(d *Dialer, ln *Listener) {
			if d != nil {
				d.PathPattern = pattern
			}
		})
	}
	WithBadRequest = func(callback http.HandlerFunc) Option {
		return Option(func(d *Dialer, ln *Listener) {
			if ln != nil {
				ln.OnBadRequest = callback
			}
		})
	}
	WithBadRequestRoundTripper = func(rt http.RoundTripper) Option {
		return Option(func(d *Dialer, ln *Listener) {
			if ln != nil {
				ln.OnBadRequest = func(w http.ResponseWriter, r *http.Request) {
					resp, err := rt.RoundTrip(r)
					if err != nil {
						w.WriteHeader(http.StatusServiceUnavailable)
						w.Write([]byte(err.Error()))
						return
					}

					defer resp.Body.Close()
					w.WriteHeader(resp.StatusCode)

					for k := range w.Header() {
						w.Header().Del(k)
					}

					for k, v := range resp.Header {
						hdr := w.Header()
						for _, v := range v {
							hdr.Add(k, v)
						}
					}
					io.Copy(w, resp.Body)
				}
			}
		})
	}
)
