package cache

import (
	"fmt"
)

var ErrNotFound error = fmt.Errorf("item not found in cache")

const (
	InMemoryDriver string = "inmemory"
	RedisDriver    string = "redis"
)

type AuthorizationState struct {
	RedirectURI                    string
	AuthorizationVerificationToken string
}
