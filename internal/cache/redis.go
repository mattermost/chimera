package cache

import (
	"context"
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

func (r *RedisCache) GetRedirectURI(state string) (string, error) {
	data, err := r.redisClient.Get(context.Background(), state).Result()
	if err == redis.Nil {
		return "", ErrNotFound
	}
	if err != nil {
		return "", errors.Wrap(err, "failed to get redirect URI from Redis")
	}
	return data, nil
}

func (r *RedisCache) SetRedirectURI(state, redirectURI string) error {
	err := r.redisClient.Set(context.Background(), state, redirectURI, r.expiration).Err()
	if err != nil {
		return errors.Wrap(err, "error while inserting state to redirect URI mapping to Redis")
	}

	return nil
}
