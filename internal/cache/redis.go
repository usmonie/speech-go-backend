package cache

import (
	"context"
	"fmt"
	//	"os"
	"time"

	"github.com/go-redis/redis/v8"
)

type RedisCache struct {
	Client *redis.Client
}

func NewRedisCache() (*RedisCache, error) {
	client := redis.NewClient(&redis.Options{
		//		Addr: os.Getenv("REDIS_ADDR"),
	})

	ctx := context.Background()
	_, err := client.Ping(ctx).Result()
	if err != nil {
		return nil, fmt.Errorf("failed to connect to Redis: %w", err)
	}

	return &RedisCache{Client: client}, nil
}

func (c *RedisCache) Set(ctx context.Context, key string, value interface{}, ttl time.Duration) error {
	return c.Client.Set(ctx, key, value, ttl).Err()
}

func (c *RedisCache) Get(ctx context.Context, key string) (string, error) {
	return c.Client.Get(ctx, key).Result()
}
