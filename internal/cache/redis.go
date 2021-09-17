package cache

import (
	"context"
	"encoding/json"
	"time"

	"github.com/go-redis/redis/v8"
	"github.com/pkg/errors"
)

type RedisConfig struct {
	Address  string
	Password string
	DB       int
}

func NewRedisCache(redisCfg RedisConfig, defaultExpiration time.Duration) (*RedisCache, error) {
	redisClient := redis.NewClient(&redis.Options{
		Addr:     redisCfg.Address,
		Password: redisCfg.Password,
		DB:       redisCfg.DB,
	})

	return &RedisCache{
		redisClient: redisClient,
		expiration:  defaultExpiration,
	}, nil
}

type RedisCache struct {
	expiration  time.Duration
	redisClient *redis.Client
}

func (r *RedisCache) GetRedirectURI(state string) (AuthorizationState, error) {
	data, err := r.redisClient.Get(context.Background(), state).Result()
	if err == redis.Nil {
		return AuthorizationState{}, ErrNotFound
	}
	if err != nil {
		return AuthorizationState{}, errors.Wrap(err, "failed to get redirect URI from Redis")
	}

	var authZState AuthorizationState
	err = json.Unmarshal([]byte(data), &authZState)
	if err != nil {
		return AuthorizationState{}, errors.Wrap(err, "failed to unmarshall authorization state")
	}

	return authZState, nil
}

func (r *RedisCache) SetRedirectURI(state string, authZState AuthorizationState) error {
	data, err := json.Marshal(authZState)
	if err != nil {
		return errors.Wrap(err, "failed to marshal authorization state")
	}

	err = r.redisClient.Set(context.Background(), state, data, r.expiration).Err()
	if err != nil {
		return errors.Wrap(err, "error while inserting state to redirect URI mapping to Redis")
	}

	return nil
}

func (r *RedisCache) DeleteState(state string) error {
	err := r.redisClient.Del(context.Background(), state).Err()
	if err == redis.Nil {
		return nil
	}
	if err != nil {
		return errors.Wrap(err, "error while deleting state mapping from Redis")
	}
	return nil
}
