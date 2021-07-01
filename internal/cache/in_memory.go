package cache

import (
	"fmt"
	"github.com/patrickmn/go-cache"
	"time"
)

const cleanupInterval = 10 * time.Minute

func NewInMemoryCache(defaultExpiration time.Duration) *MemoryCache {
	return &MemoryCache{
		expiration: defaultExpiration,
		cache:      cache.New(defaultExpiration, cleanupInterval),
	}
}

type MemoryCache struct {
	expiration time.Duration
	cache      *cache.Cache
}

func (i *MemoryCache) GetRedirectURI(state string) (string, error) {
	raw, found := i.cache.Get(state)
	if !found {
		return "", ErrNotFound
	}
	uri, ok := raw.(string)
	if !ok {
		return "", fmt.Errorf("item is not a string")
	}
	return uri, nil
}

func (i *MemoryCache) SetRedirectURI(state, redirectURI string) error {
	i.cache.Set(state, redirectURI, i.expiration)
	return nil
}
