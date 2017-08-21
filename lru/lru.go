package lru

import (
	"container/list"
	"sync"
	"time"
)

type Cache struct {
	// MaxEntries is the maximum number of cache entries before
	// an item is evicted. Zero means no limit.
	MaxEntries int

	// Seconds
	PurgeInterval int

	// OnEvicted optionally specificies a callback function to be
	// executed when an entry is purged from the cache.
	OnEvicted func(key Key, value interface{})

	ll    *list.List
	cache map[interface{}]*list.Element

	sync.RWMutex
}

// A Key may be any value that is comparable. See http://golang.org/ref/spec#Comparison_operators
type Key interface{}

type entry struct {
	key   Key
	value interface{}
	born  int64
	ttl   int64
	hits  int64
}

// New creates a new Cache.
// If maxEntries is zero, the cache has no limit and it's assumed
// that eviction is done by the caller.
func NewCache(maxEntries int) *Cache {
	return &Cache{
		MaxEntries:    maxEntries,
		PurgeInterval: 60,
		ll:            list.New(),
		cache:         make(map[interface{}]*list.Element),
	}
}

func (c *Cache) Clear() {
	c.Lock()
	c.ll = list.New()
	c.cache = make(map[interface{}]*list.Element)
	c.Unlock()
}

func (c *Cache) GetLowLevelCache() map[interface{}]*list.Element {
	c.RLock()
	defer c.RUnlock()

	return c.cache
}

func (c *Cache) Info(v *list.Element) (interface{}, int, int) {
	c.RLock()
	defer c.RUnlock()

	elem := v.Value.(*entry)
	return elem.value, int((elem.born + elem.ttl) - time.Now().Unix()), int(elem.hits)
}

func (c *Cache) Start() {
	go func() {
		for {
			c.Lock()
			cur := time.Now().Unix()
			count := 0
			if c.cache != nil {
				for _, v := range c.cache {
					e := v.Value.(*entry)
					if e.ttl > 0 && cur > e.born+e.ttl {
						c.removeElement(v)
						count++
					}
				}
				// c.removeElement(ele)
			}
			c.Unlock()
			// glog.Infoln(count, "items expired then purged")
			time.Sleep(time.Duration(c.PurgeInterval) * time.Second)
		}
	}()
}

// Add adds a value to the cache.
func (c *Cache) Add(key Key, value interface{}, ttl int) {
	c.Lock()
	defer c.Unlock()

	if c.cache == nil {
		c.cache = make(map[interface{}]*list.Element)
		c.ll = list.New()
	}

	if ee, ok := c.cache[key]; ok {
		c.ll.MoveToFront(ee)
		e := ee.Value.(*entry)

		e.value = value
		e.born = time.Now().Unix()
		e.ttl = int64(ttl)
		e.hits++
		return
	}

	ele := c.ll.PushFront(&entry{key, value, time.Now().Unix(), int64(ttl), 0})
	c.cache[key] = ele
	if c.MaxEntries != 0 && c.ll.Len() > c.MaxEntries {
		c.removeOldest()
	}
}

// Get looks up a key's value from the cache.
func (c *Cache) Get(key Key) (value interface{}, ok bool) {
	c.RLock()
	defer c.RUnlock()

	if c.cache == nil {
		return
	}

	if ele, hit := c.cache[key]; hit {
		e := ele.Value.(*entry)

		if e.ttl > 0 && time.Now().Unix() > e.born+e.ttl {
			// Value is expired, waits for being purged or client may set a new value for it
			return
		}

		e.hits++
		c.ll.MoveToFront(ele)
		return e.value, true
	}

	return
}

// Remove removes the provided key from the cache.
func (c *Cache) Remove(key Key) {
	c.Lock()
	defer c.Unlock()

	if c.cache == nil {
		return
	}
	if ele, hit := c.cache[key]; hit {
		c.removeElement(ele)
	}
}

// Len returns the number of items in the cache.
func (c *Cache) Len() int {
	c.Lock()
	defer c.Unlock()

	if c.cache == nil {
		return 0
	}
	return c.ll.Len()
}

// RemoveOldest removes the oldest item from the cache.
func (c *Cache) removeOldest() {
	if c.cache == nil {
		return
	}
	ele := c.ll.Back()
	if ele != nil {
		c.removeElement(ele)
	}
}

func (c *Cache) removeElement(e *list.Element) {
	c.ll.Remove(e)
	kv := e.Value.(*entry)
	delete(c.cache, kv.key)
	if c.OnEvicted != nil {
		c.OnEvicted(kv.key, kv.value)
	}
}
