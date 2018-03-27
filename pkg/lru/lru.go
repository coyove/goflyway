package lru

import (
	"container/list"
	"fmt"
	"sync"
)

type Cache struct {
	// OnEvicted is called when an entry is going to be purged from the cache.
	OnEvicted func(key Key, value interface{})

	maxWeight int64
	curWeight int64

	ll    *list.List
	cache map[interface{}]*list.Element

	sync.Mutex
}

// A Key may be any value that is comparable. See http://golang.org/ref/spec#Comparison_operators
type Key interface{}

type entry struct {
	key    Key
	value  interface{}
	hits   int64
	weight int64
}

var ErrWeightTooBig = fmt.Errorf("weight can't be held by the cache")

// NewCache creates a new Cache.
func NewCache(maxWeight int64) *Cache {
	return &Cache{
		maxWeight: maxWeight,
		ll:        list.New(),
		cache:     make(map[interface{}]*list.Element),
	}
}

// Clear clears the cache
func (c *Cache) Clear() {
	c.Lock()
	c.ll = list.New()
	c.cache = make(map[interface{}]*list.Element)
	c.Unlock()
}

// Info iterates the cache
func (c *Cache) Info(callback func(Key, interface{}, int64, int64)) {
	c.Lock()

	for f := c.ll.Front(); f != nil; f = f.Next() {
		e := f.Value.(*entry)
		callback(e.key, e.value, e.hits, e.weight)
	}

	c.Unlock()
}

// Add adds a value to the cache with weight = 1.
func (c *Cache) Add(key Key, value interface{}) error {
	return c.AddWeight(key, value, 1)
}

// AddWeight adds a value to the cache with weight.
func (c *Cache) AddWeight(key Key, value interface{}, weight int64) error {
	if weight > c.maxWeight || weight < 1 {
		return ErrWeightTooBig
	}

	c.Lock()
	defer c.Unlock()

	controlWeight := func() {
		if c.maxWeight == 0 {
			return
		}

		for c.curWeight > c.maxWeight {
			if ele := c.ll.Back(); ele != nil {
				c.removeElement(ele, true)
			} else {
				panic("shouldn't happen")
			}
		}
		// Since weight <= c.maxWeight, we will always reach here without problems
	}

	if ee, ok := c.cache[key]; ok {
		e := ee.Value.(*entry)
		c.ll.MoveToFront(ee)
		diff := weight - e.weight
		e.weight = weight
		e.value = value
		e.hits++

		c.curWeight += diff
		controlWeight()
		return nil
	}

	c.curWeight += weight
	ele := c.ll.PushFront(&entry{key, value, 1, weight})
	c.cache[key] = ele
	controlWeight()

	if c.curWeight < 0 {
		panic("too many entries, really?")
	}

	return nil
}

// Get gets a key
func (c *Cache) Get(key Key) (value interface{}, ok bool) {
	c.Lock()
	defer c.Unlock()

	if ele, hit := c.cache[key]; hit {
		e := ele.Value.(*entry)
		e.hits++
		c.ll.MoveToFront(ele)
		return e.value, true
	}

	return
}

// GetEx returns the extra info of the given key
func (c *Cache) GetEx(key Key) (hits int64, weight int64, ok bool) {
	c.Lock()
	defer c.Unlock()

	if ele, hit := c.cache[key]; hit {
		return ele.Value.(*entry).hits, ele.Value.(*entry).weight, true
	}

	return
}

// Remove removes the given key from the cache.
func (c *Cache) Remove(key Key) {
	c.Lock()
	c.remove(key, true)
	c.Unlock()
}

// RemoveSlient removes the given key without triggering OnEvicted
func (c *Cache) RemoveSlient(key Key) {
	c.Lock()
	c.remove(key, false)
	c.Unlock()
}

// Len returns the number of items in the cache.
func (c *Cache) Len() (len int) {
	c.Lock()
	len = c.ll.Len()
	c.Unlock()
	return
}

// MaxWeight returns max weight
func (c *Cache) MaxWeight() int64 {
	return c.maxWeight
}

// Weight returns current weight
func (c *Cache) Weight() int64 {
	return c.curWeight
}

func (c *Cache) remove(key Key, doCallback bool) {
	if ele, hit := c.cache[key]; hit {
		c.removeElement(ele, doCallback)
	}
}

func (c *Cache) removeElement(e *list.Element, doCallback bool) {
	kv := e.Value.(*entry)

	if c.OnEvicted != nil && doCallback {
		c.OnEvicted(kv.key, kv.value)
	}

	c.ll.Remove(e)
	c.curWeight -= e.Value.(*entry).weight
	delete(c.cache, kv.key)
}
