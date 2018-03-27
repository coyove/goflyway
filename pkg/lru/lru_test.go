package lru

import (
	"strconv"
	"testing"
)

func TestCache_Add(t *testing.T) {
	c := NewCache(10)

	for i := 0; i < 10; i++ {
		c.Add("key"+strconv.Itoa(i), "value"+strconv.Itoa(i))
	}

	for i := 0; i < 10; i++ {
		v, _ := c.Get("key" + strconv.Itoa(i))
		if v.(string) != "value"+strconv.Itoa(i) {
			t.Error("Add failed")
		}
	}

	c.Add("key10", "value10")
	if _, ok := c.Get("key0"); ok {
		t.Error("key0 should be removed")
	}

	c.AddWeight("bigkey", "", 10)
	for i := 0; i <= 10; i++ {
		_, ok := c.Get("key" + strconv.Itoa(i))
		if ok {
			t.Errorf("key%d should be removed", i)
		}
	}

	if c.Weight() != 10 {
		t.Error("cache now should weight 10")
	}

	c.Add("key11", "")
	if _, ok := c.Get("bigkey"); ok {
		t.Error("bigkey should be removed")
	}

	if c.Len() != 1 {
		t.Error("cache now should contain only one element")
	}

	if c.AddWeight("reallybigkey", "", 100) != ErrWeightTooBig {
		t.Error("how can you add a key this big?")
	}

	if c.Len() != 1 || c.Weight() != 1 {
		t.Error("cache now should contain only one element")
	}

	// add 6 keys
	for i := 0; i < 6; i++ {
		c.Add("key"+strconv.Itoa(i), "value"+strconv.Itoa(i))
	}

	// key5, key4, key3, key2, key1, key0, key11
	c.AddWeight("keyFive", "", 5)
	// keyFive, key5, key4, key3, key2, key1

	if _, ok := c.Get("key4"); !ok {
		t.Error("key4 should exist")
	}

	if _, ok := c.Get("key11"); ok {
		t.Error("key11 should not exist")
	}

	c.AddWeight("keyFive", "", 6)

	if _, ok := c.Get("key1"); ok {
		t.Error("key1 should not exist")
	}

	c.AddWeight("keyFive", "", 5)
	c.AddWeight("keyX", "", 1)
	// keyX, keyFive, key5, key4, key3, key2
	if _, ok := c.Get("key2"); !ok {
		t.Error("key2 should exist")
	}

	c.AddWeight("keyFive", "", 10)
	if c.Len() != 1 || c.Weight() != 10 {
		t.Error("cache now should contain only one element", c.Len(), c.Weight())
	}

	if _, ok := c.Get("keyX"); ok {
		t.Error("keyX should not exist")
	}
}
