package main

import (
	"reflect"
	"testing"
)

func newEventMap() map[int]map[string]string {
	mappy := map[int]map[string]string{
		1234: make(map[string]string),
		//1235: map[string]string{"hi": "bye"},
	}
	return mappy
}

/*Test that event has info added*/
func Test_makeJsonString(t *testing.T) {
	m := newEventMap()
	makeJsonString(m, 1300, "audit(1446832550.594:1234): blah=blah")

	if !reflect.DeepEqual(m[1234], map[string]string{
		"blah":         "blah",
		"auditd_seq":   "1234",
		"netlink_type": "1300",
	}) {
		t.Error()
	}
}

/*Test that event disappears properly when EOE (1320) is received*/
func Test_makeJsonString_EOE(t *testing.T) {
	m := newEventMap()
	makeJsonString(m, 1320, "audit(1446832550.594:1234): blah=blah")

	if _, ok := m[1234]; ok {
		t.Error()
	}
}
