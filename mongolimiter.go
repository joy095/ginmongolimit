package ginmongolimiter

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

// RateLimitEntry represents a rate limit record in MongoDB
type RateLimitEntry struct {
	ID        string    `bson:"_id"`
	Count     int64     `bson:"count"`
	ResetTime time.Time `bson:"reset_time"`
	CreatedAt time.Time `bson:"created_at"`
	UpdatedAt time.Time `bson:"updated_at"`
}

// InMemoryStore represents an in-memory cache entry
type InMemoryStore struct {
	Count     int64
	ResetTime time.Time
}

// Config holds the configuration for the rate limiter
type Config struct {
	// MongoDB collection to store rate limit data
	Collection *mongo.Collection
	// Maximum requests allowed per window
	Limit int64
	// Time window duration
	Window time.Duration
	// Key generator function to create unique keys for clients
	KeyGenerator KeyGeneratorFunc
	// Handler for when rate limit is exceeded
	LimitExceededHandler gin.HandlerFunc
	// Skip function to bypass rate limiting for certain requests
	Skip SkipFunc
	// Headers to include in response
	Headers HeadersConfig
	// Cleanup interval for expired entries
	CleanupInterval time.Duration
	// Enable in-memory cache
	EnableInMemoryCache bool
	// Enable debug logging
	Debug bool
}

// HeadersConfig defines which headers to include in responses
type HeadersConfig struct {
	Total      bool // X-RateLimit-Limit
	Remaining  bool // X-RateLimit-Remaining
	Reset      bool // X-RateLimit-Reset
	RetryAfter bool // Retry-After (when limit exceeded)
}

// KeyGeneratorFunc generates a unique key for rate limiting
type KeyGeneratorFunc func(c *gin.Context) string

// SkipFunc determines if rate limiting should be skipped
type SkipFunc func(c *gin.Context) bool

// RateLimiter represents the rate limiter instance
type RateLimiter struct {
	config         Config
	collection     *mongo.Collection
	stopChan       chan struct{}
	rateLimitCache sync.Map // In-memory cache for rate limit entries
	keyMutexes     sync.Map // Mutexes for each key to prevent race conditions
}

// DefaultConfig returns a default configuration
func DefaultConfig(collection *mongo.Collection) Config {
	return Config{
		Collection: collection,
		Limit:      100,
		Window:     time.Hour,
		KeyGenerator: func(c *gin.Context) string {
			return c.ClientIP()
		},
		LimitExceededHandler: DefaultLimitExceededHandler,
		Skip:                 nil,
		Headers: HeadersConfig{
			Total:      true,
			Remaining:  true,
			Reset:      true,
			RetryAfter: true,
		},
		CleanupInterval:     5 * time.Minute,
		EnableInMemoryCache: true,
		Debug:               false,
	}
}

// DefaultKeyGenerator generates keys based on client IP
func DefaultKeyGenerator(c *gin.Context) string {
	return fmt.Sprintf("rate_limit:%s", c.ClientIP())
}

// DefaultLimitExceededHandler returns a 429 status when rate limit is exceeded
func DefaultLimitExceededHandler(c *gin.Context) {
	c.JSON(http.StatusTooManyRequests, gin.H{
		"error":   "Rate limit exceeded",
		"message": "Too many requests, please try again later",
	})
	c.Abort()
}

// New creates a new rate limiter instance
func New(config Config) (*RateLimiter, error) {
	if config.Collection == nil {
		return nil, fmt.Errorf("MongoDB collection is required")
	}

	if config.Limit <= 0 && config.Window > 0 {
		return nil, fmt.Errorf("limit must be greater than 0")
	}

	if config.Window <= 0 && config.Limit > 0 {
		return nil, fmt.Errorf("window duration must be greater than 0")
	}

	if config.KeyGenerator == nil {
		config.KeyGenerator = DefaultKeyGenerator
	}

	if config.LimitExceededHandler == nil {
		config.LimitExceededHandler = DefaultLimitExceededHandler
	}

	if config.CleanupInterval <= 0 {
		config.CleanupInterval = 5 * time.Minute
	}

	rl := &RateLimiter{
		config:     config,
		collection: config.Collection,
		stopChan:   make(chan struct{}),
	}

	// Create indexes for better performance
	if err := rl.createIndexes(); err != nil {
		return nil, fmt.Errorf("failed to create indexes: %w", err)
	}

	// Start cleanup routine
	go rl.cleanupRoutine()

	return rl, nil
}

// createIndexes creates necessary MongoDB indexes
func (rl *RateLimiter) createIndexes() error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Index on reset_time for efficient cleanup with TTL
	resetTimeIndex := mongo.IndexModel{
		Keys:    bson.D{{Key: "reset_time", Value: 1}},
		Options: options.Index().SetExpireAfterSeconds(0),
	}

	// Index on _id for efficient lookups
	idIndex := mongo.IndexModel{
		Keys: bson.D{{Key: "_id", Value: 1}},
	}

	_, err := rl.collection.Indexes().CreateMany(ctx, []mongo.IndexModel{
		resetTimeIndex,
		idIndex,
	})

	return err
}

// Middleware returns the Gin middleware function
func (rl *RateLimiter) Middleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		// Check if we should skip rate limiting
		if rl.config.Skip != nil && rl.config.Skip(c) {
			c.Next()
			return
		}

		key := rl.config.KeyGenerator(c)

		allowed, remaining, resetTime, err := rl.checkRateLimit(key, rl.config.Limit, rl.config.Window)
		if err != nil {
			if rl.config.Debug {
				log.Printf("Rate limiter error: %v", err)
			}
			// On error, allow the request to proceed
			c.Next()
			return
		}

		// Set headers
		rl.setHeaders(c, rl.config.Limit, remaining, resetTime)

		if !allowed {
			rl.config.LimitExceededHandler(c)
			return
		}

		c.Next()
	}
}

// CombinedRateLimiter creates a middleware that enforces multiple rate limits.
// key: The base key for rate limiting (e.g., "update-email").
// rates: A list of rate limit strings, e.g., "5-1m", "30-60m".
func (rl *RateLimiter) CombinedRateLimiter(key string, rates ...string) (gin.HandlerFunc, error) {
	type rateLimitRule struct {
		limit   int64
		window  time.Duration
		rateStr string
	}

	var rules []rateLimitRule
	for _, rate := range rates {
		parts := strings.Split(rate, "-")
		if len(parts) != 2 {
			return nil, fmt.Errorf("invalid rate format: %s", rate)
		}

		limit, err := strconv.ParseInt(parts[0], 10, 64)
		if err != nil {
			return nil, fmt.Errorf("invalid limit in rate: %s", rate)
		}

		window, err := time.ParseDuration(parts[1])
		if err != nil {
			return nil, fmt.Errorf("invalid duration in rate: %s", rate)
		}
		rules = append(rules, rateLimitRule{limit: limit, window: window, rateStr: rate})
	}

	return func(c *gin.Context) {
		if rl.config.Skip != nil && rl.config.Skip(c) {
			c.Next()
			return
		}

		baseKey := rl.config.KeyGenerator(c)

		var overallRemaining int64 = -1
		var nextResetTime time.Time
		var mostRestrictiveLimit int64 = -1

		for _, rule := range rules {
			// Each rule gets a unique key to be stored independently
			ruleKey := fmt.Sprintf("%s:%s:%s", baseKey, key, rule.rateStr)
			allowed, remaining, resetTime, err := rl.checkRateLimit(ruleKey, rule.limit, rule.window)

			if err != nil {
				if rl.config.Debug {
					log.Printf("Rate limiter error for rule %s: %v", rule.rateStr, err)
				}
				c.Next()
				return
			}
			if !allowed {
				// If any rule is not allowed, set headers for that specific rule and abort.
				rl.setHeaders(c, rule.limit, 0, resetTime)
				rl.config.LimitExceededHandler(c)
				return
			}
			// Track the most restrictive rule (the one with the fewest requests remaining).
			if overallRemaining == -1 || remaining < overallRemaining {
				overallRemaining = remaining
				mostRestrictiveLimit = rule.limit
			}
			// Track the furthest reset time of all rules.
			if nextResetTime.IsZero() || resetTime.After(nextResetTime) {
				nextResetTime = resetTime
			}
		}

		// If the request is allowed, set the headers based on the most restrictive rule.
		if mostRestrictiveLimit != -1 {
			rl.setHeaders(c, mostRestrictiveLimit, overallRemaining, nextResetTime)
		}

		c.Next()
	}, nil
}

// checkRateLimit checks if the request should be allowed
func (rl *RateLimiter) checkRateLimit(key string, limit int64, window time.Duration) (allowed bool, remaining int64, resetTime time.Time, err error) {
	now := time.Now()

	// Use in-memory cache if enabled
	if rl.config.EnableInMemoryCache {
		value, _ := rl.keyMutexes.LoadOrStore(key, &sync.Mutex{})
		mutex := value.(*sync.Mutex)
		mutex.Lock()
		defer mutex.Unlock()

		if entry, ok := rl.rateLimitCache.Load(key); ok {
			cachedEntry := entry.(InMemoryStore)
			if now.Before(cachedEntry.ResetTime) {
				if cachedEntry.Count < limit {
					cachedEntry.Count++
					rl.rateLimitCache.Store(key, cachedEntry)
					// Asynchronously update MongoDB
					go rl.updateMongoEntry(key, cachedEntry.Count, cachedEntry.ResetTime)
					return true, limit - cachedEntry.Count, cachedEntry.ResetTime, nil
				}
				return false, 0, cachedEntry.ResetTime, nil
			}
		}
	}

	// Fallback to MongoDB if cache is disabled or entry is not in cache/expired
	return rl.checkRateLimitMongo(key, limit, window)
}

func (rl *RateLimiter) checkRateLimitMongo(key string, limit int64, window time.Duration) (bool, int64, time.Time, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	now := time.Now()
	filter := bson.M{"_id": key}
	var entry RateLimitEntry

	err := rl.collection.FindOne(ctx, filter).Decode(&entry)
	if err == mongo.ErrNoDocuments {
		// First request, create new entry
		newEntry := RateLimitEntry{
			ID:        key,
			Count:     1,
			ResetTime: now.Add(window),
			CreatedAt: now,
			UpdatedAt: now,
		}
		_, err := rl.collection.InsertOne(ctx, newEntry)
		if err != nil {
			return false, 0, time.Time{}, err
		}
		if rl.config.EnableInMemoryCache {
			rl.rateLimitCache.Store(key, InMemoryStore{Count: 1, ResetTime: newEntry.ResetTime})
		}
		return true, limit - 1, newEntry.ResetTime, nil
	} else if err != nil {
		return false, 0, time.Time{}, err
	}

	if now.After(entry.ResetTime) {
		// Window expired, reset
		newResetTime := now.Add(window)
		update := bson.M{
			"$set": bson.M{
				"count":      1,
				"reset_time": newResetTime,
				"updated_at": now,
			},
		}
		_, err := rl.collection.UpdateOne(ctx, filter, update)
		if err != nil {
			return false, 0, time.Time{}, err
		}
		if rl.config.EnableInMemoryCache {
			rl.rateLimitCache.Store(key, InMemoryStore{Count: 1, ResetTime: newResetTime})
		}
		return true, limit - 1, newResetTime, nil
	}

	// Window not expired, check limit
	if entry.Count >= limit {
		if rl.config.EnableInMemoryCache {
			rl.rateLimitCache.Store(key, InMemoryStore{Count: entry.Count, ResetTime: entry.ResetTime})
		}
		return false, 0, entry.ResetTime, nil
	}

	// Increment count
	update := bson.M{
		"$inc": bson.M{"count": 1},
		"$set": bson.M{"updated_at": now},
	}
	opts := options.FindOneAndUpdate().SetReturnDocument(options.After)
	var updatedEntry RateLimitEntry
	err = rl.collection.FindOneAndUpdate(ctx, filter, update, opts).Decode(&updatedEntry)
	if err != nil {
		return false, 0, time.Time{}, err
	}
	if rl.config.EnableInMemoryCache {
		rl.rateLimitCache.Store(key, InMemoryStore{Count: updatedEntry.Count, ResetTime: entry.ResetTime})
	}

	remaining := limit - updatedEntry.Count
	if remaining < 0 {
		remaining = 0
	}
	return updatedEntry.Count <= limit, remaining, entry.ResetTime, nil
}

func (rl *RateLimiter) updateMongoEntry(key string, count int64, resetTime time.Time) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	filter := bson.M{"_id": key}
	update := bson.M{
		"$set": bson.M{
			"count":      count,
			"reset_time": resetTime,
			"updated_at": time.Now(),
		},
	}
	opts := options.Update().SetUpsert(true)

	_, err := rl.collection.UpdateOne(ctx, filter, update, opts)
	if err != nil && rl.config.Debug {
		log.Printf("Failed to update MongoDB entry for key %s: %v", key, err)
	}
}

// setHeaders sets rate limiting headers
func (rl *RateLimiter) setHeaders(c *gin.Context, limit, remaining int64, resetTime time.Time) {
	if rl.config.Headers.Total {
		c.Header("X-RateLimit-Limit", strconv.FormatInt(limit, 10))
	}
	if rl.config.Headers.Remaining {
		c.Header("X-RateLimit-Remaining", strconv.FormatInt(remaining, 10))
	}
	if rl.config.Headers.Reset {
		c.Header("X-RateLimit-Reset", strconv.FormatInt(resetTime.Unix(), 10))
	}
	if rl.config.Headers.RetryAfter && remaining <= 0 {
		retryAfter := int64(time.Until(resetTime).Seconds())
		if retryAfter < 0 {
			retryAfter = 0
		}
		c.Header("Retry-After", strconv.FormatInt(retryAfter, 10))
	}
}

// cleanupRoutine removes expired entries
func (rl *RateLimiter) cleanupRoutine() {
	ticker := time.NewTicker(rl.config.CleanupInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			// The TTL index on reset_time handles MongoDB cleanup automatically.
			// This routine now also cleans the in-memory cache.
			if rl.config.EnableInMemoryCache {
				now := time.Now()
				rl.rateLimitCache.Range(func(key, value interface{}) bool {
					if entry, ok := value.(InMemoryStore); ok {
						if now.After(entry.ResetTime) {
							rl.rateLimitCache.Delete(key)
							rl.keyMutexes.Delete(key)
						}
					}
					return true
				})
			}
			if rl.config.Debug {
				log.Println("Cleanup routine running.")
			}
		case <-rl.stopChan:
			return
		}
	}
}

// Stop gracefully stops the rate limiter
func (rl *RateLimiter) Stop() {
	close(rl.stopChan)
}

// Reset removes rate limit data for a specific key
func (rl *RateLimiter) Reset(key string) error {
	if rl.config.EnableInMemoryCache {
		rl.rateLimitCache.Delete(key)
		rl.keyMutexes.Delete(key)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	filter := bson.M{"_id": bson.M{"$regex": fmt.Sprintf("^%s", key)}}
	_, err := rl.collection.DeleteMany(ctx, filter)
	return err
}

// GetStats returns current rate limit stats for a key
func (rl *RateLimiter) GetStats(key string) (*RateLimitEntry, error) {
	if rl.config.EnableInMemoryCache {
		if entry, ok := rl.rateLimitCache.Load(key); ok {
			cachedEntry := entry.(InMemoryStore)
			return &RateLimitEntry{
				ID:        key,
				Count:     cachedEntry.Count,
				ResetTime: cachedEntry.ResetTime,
			}, nil
		}
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	var entry RateLimitEntry
	err := rl.collection.FindOne(ctx, bson.M{"_id": key}).Decode(&entry)
	if err == mongo.ErrNoDocuments {
		return nil, nil
	}
	return &entry, err
}

// KeyGenerators provides common key generation strategies
type KeyGenerators struct{}

// ByIP generates keys based on client IP address
func (KeyGenerators) ByIP(c *gin.Context) string {
	return fmt.Sprintf("rate_limit:ip:%s", c.ClientIP())
}

// ByUserID generates keys based on user ID (requires user_id in context)
func (KeyGenerators) ByUserID(c *gin.Context) string {
	userID, exists := c.Get("user_id")
	if !exists {
		return fmt.Sprintf("rate_limit:ip:%s", c.ClientIP())
	}
	return fmt.Sprintf("rate_limit:user:%v", userID)
}

// ByIPAndEndpoint generates keys based on IP and endpoint
func (KeyGenerators) ByIPAndEndpoint(c *gin.Context) string {
	return fmt.Sprintf("rate_limit:ip_endpoint:%s:%s", c.ClientIP(), c.Request.URL.Path)
}

// ByHeader generates keys based on a specific header value
func (KeyGenerators) ByHeader(headerName string) KeyGeneratorFunc {
	return func(c *gin.Context) string {
		headerValue := c.GetHeader(headerName)
		if headerValue == "" {
			return fmt.Sprintf("rate_limit:ip:%s", c.ClientIP())
		}
		return fmt.Sprintf("rate_limit:header:%s:%s", headerName, headerValue)
	}
}
