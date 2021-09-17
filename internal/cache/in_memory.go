package cache

import (
	"fmt"
	"time"

	"github.com/patrickmn/go-cache"
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

func (i *MemoryCache) GetRedirectURI(state string) (AuthorizationState, error) {
	raw, found := i.cache.Get(state)
	if !found {
		return AuthorizationState{}, ErrNotFound
	}
	uri, ok := raw.(AuthorizationState)
	if !ok {
		return AuthorizationState{}, fmt.Errorf("item is not a string")
	}
	return uri, nil
}

func (i *MemoryCache) SetRedirectURI(state string, authZState AuthorizationState) error {
	i.cache.Set(state, authZState, i.expiration)
	return nil
}

func (i *MemoryCache) DeleteState(state string) error {
	i.cache.Delete(state)
	return nil
}
