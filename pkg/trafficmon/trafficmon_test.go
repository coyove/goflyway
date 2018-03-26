package trafficmon

import (
	"testing"
	"time"
)

func TestSurvey(t *testing.T) {
	tr := &Survey{}
	tr.Init(60, 1)

	time.Sleep(100 * time.Millisecond) // 0.1s
	tr.Send(10).Update()

	time.Sleep(600 * time.Millisecond) // 0.7s
	tr.Send(10).Update()

	time.Sleep(1500 * time.Millisecond) // 2.2s
	tr.Send(10).Update()

	time.Sleep(20000 * time.Millisecond) // 22.2s
	tr.Send(10).Update()

	time.Sleep(1500 * time.Millisecond) // 23.7s
	tr.Send(10).Update()

	compare := []int64{5, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 1, 7, 22}
	for i := 0; i < 23; i++ {
		if round(tr.sent.data[i]) != compare[i] {
			t.Error(tr.sent.data)
			break
		}
	}

}
