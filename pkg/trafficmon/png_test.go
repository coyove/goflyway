package trafficmon

import (
	"io/ioutil"
	"testing"
	"time"
)

func TestSurvey_PNG(t *testing.T) {
	tr := &Survey{}
	tr.Init(1200, 1)
	tr.Send(10)
	tr.Recv(10)
	time.Sleep(time.Second)
	tr.Send(10)
	tr.Recv(10)
	tr.Update()
	ioutil.WriteFile("test.png", tr.PNG(30, 2, 1, "").Bytes(), 0777)
}
