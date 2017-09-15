package counter

import (
	"time"
)

func GetCounter() int64 {
	return time.Now().UnixNano()
}
