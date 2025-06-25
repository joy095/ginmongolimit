// example/main.go - Example usage of the rate limiter package
package main

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	ginmongolimiter "github.com/joy095/ginmongolimit" // Adjust import path as needed

	"github.com/gin-gonic/gin"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"go.mongodb.org/mongo-driver/mongo/readpref"
)

// Global registry to keep track of all dynamically created rate limiters
var limiterRegistry []*ginmongolimiter.RateLimiter

// initMongoDB initializes and returns a MongoDB client and collection.
func initMongoDB() (*mongo.Client, *mongo.Collection, error) {
	// godotenv.Load() is moved to main() for centralized environment loading

	mongoURI := os.Getenv("MONGO_URI")
	if mongoURI == "" {
		fmt.Println("MONGO_URI environment variable not set. Using default value.")

	}

	clientOptions := options.Client().ApplyURI(mongoURI)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	client, err := mongo.Connect(ctx, clientOptions)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to connect to MongoDB: %w", err)
	}

	if err = client.Ping(ctx, readpref.Primary()); err != nil {
		return nil, nil, fmt.Errorf("failed to ping MongoDB: %w", err)
	}

	log.Println("Successfully connected to MongoDB!")

	collection := client.Database("myapp").Collection("rate_limits_dynamic")

	return client, collection, nil
}

// createSingleRuleMiddleware creates and registers a new RateLimiter for a single rule.
// This function acts as the equivalent of `middleware.NewRateLimiter("limit-window", "operation-key")`
func createSingleRuleMiddleware(rlCollection *mongo.Collection, rate string, operationKey string) (gin.HandlerFunc, error) {
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

	config := ginmongolimiter.Config{
		Collection: rlCollection,
		Limit:      limit,
		Window:     window,
		KeyGenerator: func(c *gin.Context) string {
			return fmt.Sprintf("rate_limit:%s:%s", operationKey, c.ClientIP())
		},
		LimitExceededHandler: customLimitExceededHandler,
		Headers: ginmongolimiter.HeadersConfig{
			Total: true, Remaining: true, Reset: true, RetryAfter: true,
		},
		Debug: true,
	}

	limiter, err := ginmongolimiter.New(config)
	if err != nil {
		return nil, fmt.Errorf("failed to create single rule limiter for %s: %w", operationKey, err)
	}
	limiterRegistry = append(limiterRegistry, limiter) // Add to global registry for stopping

	return limiter.Middleware(), nil
}

// RegisterAppRoutes sets up all application routes with appropriate rate limiting.
func RegisterAppRoutes(router *gin.Engine, combinedRateLimiter *ginmongolimiter.RateLimiter, rlCollection *mongo.Collection) {

	// --- Public Routes ---
	// Public route with a single rate limiter
	publicSingleMiddleware, err := createSingleRuleMiddleware(rlCollection, "10-1m", "public-single-test")
	if err != nil {
		log.Fatalf("Failed to create public single limiter: %v", err)
	}
	router.GET("/public/single-test", publicSingleMiddleware, func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"message": "Public single-rule test passed!"})
	})
	log.Println("Route /public/single-test: 10 requests per minute.")

	// Public route with combined rate limits
	publicCombinedMiddleware, err := combinedRateLimiter.CombinedRateLimiter("public-combined-test", "5-30s", "15-5m")
	if err != nil {
		log.Fatalf("Failed to create public combined limiter: %v", err)
	}
	router.GET("/public/combined-test", publicCombinedMiddleware, func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"message": "Public combined-rule test passed!"})
	})
	log.Println("Route /public/combined-test: 5 requests per 30s AND 15 requests per 5m.")

	// --- Private/Protected Routes ---
	protected := router.Group("/private")
	protected.Use(authMiddleware()) // Apply authentication middleware first
	{
		// Private route with a single rate limiter
		privateSingleMiddleware, err := createSingleRuleMiddleware(rlCollection, "5-10s", "private-single-data")
		if err != nil {
			log.Fatalf("Failed to create private single limiter: %v", err)
		}
		protected.GET("/single-data", privateSingleMiddleware, func(c *gin.Context) {
			c.JSON(http.StatusOK, gin.H{"message": "Private single-rule data accessed!"})
		})
		log.Println("Route /private/single-data: 5 requests per 10s (requires auth).")

		// Private route with combined rate limits
		privateCombinedMiddleware, err := combinedRateLimiter.CombinedRateLimiter("private-combined-action", "3-1m", "10-1h")
		if err != nil {
			log.Fatalf("Failed to create private combined limiter: %v", err)
		}
		protected.POST("/combined-action", privateCombinedMiddleware, func(c *gin.Context) {
			c.JSON(http.StatusOK, gin.H{"message": "Private combined-rule action performed!"})
		})
		log.Println("Route /private/combined-action: 3 requests per 1m AND 10 requests per 1h (requires auth).")
	}

	// --- Admin Routes for Management (Optional, for testing/resetting limits) ---
	admin := router.Group("/admin")
	admin.POST("/reset-rate-limit/:key", func(c *gin.Context) {
		key := c.Param("key")
		for _, limiter := range limiterRegistry {
			if err := limiter.Reset(key); err != nil {
				log.Printf("Warning: Failed to reset limiter for key %s: %v", key, err)
			}
		}
		c.JSON(http.StatusOK, gin.H{"message": fmt.Sprintf("Attempted to reset rate limit for key prefix '%s'", key)})
	})

	admin.GET("/rate-limit-stats/:key", func(c *gin.Context) {
		key := c.Param("key")
		var foundStats *ginmongolimiter.RateLimitEntry
		var err error

		// Check all registered limiters for stats on the exact key
		for _, limiter := range limiterRegistry {
			stats, currentErr := limiter.GetStats(key)
			if currentErr != nil {
				log.Printf("Error getting stats from a limiter: %v", currentErr)
				err = currentErr // Keep track of the first error
			}
			if stats != nil {
				foundStats = stats
				break // Found stats, no need to check other limiters for this exact key
			}
		}

		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
		if foundStats == nil {
			c.JSON(http.StatusNotFound, gin.H{"message": "No rate limit data found for exact key"})
			return
		}
		c.JSON(http.StatusOK, foundStats)
	})
}

func main() {
	// godotenv.Load() // Load environment variables from .env file

	mongoClient, dynamicCollection, err := initMongoDB()
	if err != nil {
		log.Fatalf("Error initializing MongoDB: %v", err)
	}
	defer func() {
		// Stop all registered limiters' background routines
		for _, limiter := range limiterRegistry {
			limiter.Stop()
		}
		// Disconnect MongoDB client
		if err = mongoClient.Disconnect(context.Background()); err != nil {
			log.Printf("Error disconnecting from MongoDB: %v", err)
		} else {
			log.Println("Disconnected from MongoDB.")
		}
	}()

	r := gin.Default()

	// Initialize a single combined rate limiter instance to be reused by combined routes
	combinedRLConfig := ginmongolimiter.DefaultConfig(dynamicCollection)
	combinedRLConfig.KeyGenerator = ginmongolimiter.KeyGenerators{}.ByIP
	combinedRLConfig.Debug = true

	combinedRateLimiter, err := ginmongolimiter.New(combinedRLConfig)
	if err != nil {
		log.Fatalf("Failed to create combined rate limiter instance: %v", err)
	}
	limiterRegistry = append(limiterRegistry, combinedRateLimiter) // Add to registry

	// Register all application routes
	RegisterAppRoutes(r, combinedRateLimiter, dynamicCollection)

	log.Println("Server starting on :8080")
	r.Run(":8080")
}

// Placeholder auth middleware for demonstration purposes.
func authMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		// Simulate successful authentication and set user_id and user_role in context
		c.Set("user_id", "demoUser123")
		c.Set("user_role", "user")
		// In a real app, you might check a header like "Authorization"
		authHeader := c.GetHeader("Authorization")
		if authHeader == "" || !strings.HasPrefix(authHeader, "Bearer ") {
			c.JSON(http.StatusUnauthorized, gin.H{"message": "Authorization required"})
			c.Abort()
			return
		}
		// Simulate successful auth. For a true "admin" test, you'd parse JWT/session.
		if strings.Contains(authHeader, "admin") { // Simple check for demo purposes
			c.Set("user_role", "admin")
		}
		c.Next()
	}
}

// customLimitExceededHandler provides a custom response when rate limit is exceeded.
func customLimitExceededHandler(c *gin.Context) {
	retryAfter := c.GetHeader("Retry-After")
	c.JSON(http.StatusTooManyRequests, gin.H{
		"error":       "RATE_LIMIT_EXCEEDED",
		"message":     "You have sent too many requests. Please try again later.",
		"retry_after": retryAfter,
		"details":     "Custom handler active.",
	})
	c.Abort()
}
