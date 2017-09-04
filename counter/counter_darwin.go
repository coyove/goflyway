package counter

import (
	"time"
)

func Get() int64 {
	return time.Now().UnixNano()
}
