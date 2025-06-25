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

	ginmongolimiter "github.com/joy095/mongolimiter/config"

	"github.com/joho/godotenv"

	"github.com/gin-gonic/gin"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"go.mongodb.org/mongo-driver/mongo/readpref"
)

// Global registry to keep track of all dynamically created rate limiters
var limiterRegistry []*ginmongolimiter.RateLimiter

// initMongoDB initializes and returns a MongoDB client and collection.
func initMongoDB() (*mongo.Client, *mongo.Collection, error) {
	godotenv.Load()

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

// RegisterUserRoutes sets up all user-related routes with appropriate rate limiting.
func RegisterUserRoutes(router *gin.Engine, combinedRateLimiter *ginmongolimiter.RateLimiter, rlCollection *mongo.Collection) {

	// Public routes
	registerMiddleware, err := combinedRateLimiter.CombinedRateLimiter("register", "10-2m", "30-60m")
	if err != nil {
		log.Fatalf("Failed to create combined rate limiter for register: %v", err)
	}
	router.POST("/register", registerMiddleware, userController.Register)

	loginMiddleware, err := combinedRateLimiter.CombinedRateLimiter("login", "10-2m", "30-30m")
	if err != nil {
		log.Fatalf("Failed to create combined rate limiter for login: %v", err)
	}
	router.POST("/login", loginMiddleware, userController.Login)

	refreshTokenMiddleware, err := createSingleRuleMiddleware(rlCollection, "10-60m", "refresh-token")
	if err != nil {
		log.Fatalf("Failed to create refresh-token limiter: %v", err)
	}
	router.POST("/refresh-token", refreshTokenMiddleware, userController.RefreshToken)

	usernameAvailabilityMiddleware, err := createSingleRuleMiddleware(rlCollection, "60-2m", "username-availability")
	if err != nil {
		log.Fatalf("Failed to create username-availability limiter: %v", err)
	}
	router.POST("/username-availability", usernameAvailabilityMiddleware, userController.UsernameAvailability)

	forgotPasswordMiddleware, err := createSingleRuleMiddleware(rlCollection, "10-5m", "forgot-password")
	if err != nil {
		log.Fatalf("Failed to create forgot-password limiter: %v", err)
	}
	router.POST("/forgot-password", forgotPasswordMiddleware, userController.ForgotPassword)

	forgotPasswordOTPMiddleware, err := combinedRateLimiter.CombinedRateLimiter("forgot-password-otp", "5-1m", "20-10m")
	if err != nil {
		log.Fatalf("Failed to create combined rate limiter for forgot-password-otp: %v", err)
	}
	router.POST("/forgot-password-otp", forgotPasswordOTPMiddleware, mail.VerifyForgotPasswordOTP)

	changePasswordMiddleware, err := combinedRateLimiter.CombinedRateLimiter("change-password", "5-1m", "20-10m")
	if err != nil {
		log.Fatalf("Failed to create combined rate limiter for change-password: %v", err)
	}
	router.POST("/change-password", changePasswordMiddleware, userController.ChangePassword)

	resendOTPMiddleware, err := combinedRateLimiter.CombinedRateLimiter("resend-otp", "5-1m", "20-10m")
	if err != nil {
		log.Fatalf("Failed to create combined rate limiter for resend-otp: %v", err)
	}
	router.POST("/resend-otp", resendOTPMiddleware, mail.ResendOTP)

	verifyEmailMiddleware, err := combinedRateLimiter.CombinedRateLimiter("verify-email", "5-1m", "20-10m")
	if err != nil {
		log.Fatalf("Failed to create combined rate limiter for verify-email: %v", err)
	}
	router.POST("/verify-email", verifyEmailMiddleware, mail.VerifyEmail)

	// Protected routes
	protected := router.Group("/")
	protected.Use(authMiddleware())
	{
		logoutMiddleware, err := combinedRateLimiter.CombinedRateLimiter("logout", "5-1m", "20-10m")
		if err != nil {
			log.Fatalf("Failed to create combined rate limiter for logout: %v", err)
		}
		protected.POST("/logout", logoutMiddleware, userController.Logout)

		getProfileMiddleware, err := createSingleRuleMiddleware(rlCollection, "30-1m", "profile")
		if err != nil {
			log.Fatalf("Failed to create get-profile limiter: %v", err)
		}
		protected.GET("/profile", getProfileMiddleware, userController.GetMyProfile)

		updateProfileMiddleware, err := combinedRateLimiter.CombinedRateLimiter("update-profile", "5-1m", "10-5m")
		if err != nil {
			log.Fatalf("Failed to create combined rate limiter for update-profile: %v", err)
		}
		protected.PATCH("/update-profile", updateProfileMiddleware, userController.UpdateProfile)

		updateEmailMiddleware, err := combinedRateLimiter.CombinedRateLimiter("update-email", "5-1m", "30-60m")
		if err != nil {
			log.Fatalf("Failed to create combined rate limiter for update-email: %v", err)
		}
		protected.POST("/update-email", updateEmailMiddleware, userController.UpdateEmailWithPassword)

		verifyEmailUpdateOTPMiddleware, err := combinedRateLimiter.CombinedRateLimiter("verify-email-update-otp", "5-1m", "30-60m")
		if err != nil {
			log.Fatalf("Failed to create combined rate limiter for verify-email-update-otp: %v", err)
		}
		protected.POST("/verify-email-update-otp", verifyEmailUpdateOTPMiddleware, userController.VerifyEmailChangeOTP)
	}

	// Public routes for viewing basic user info
	public := router.Group("/public")
	{
		// Added the requested middleware for public-user route
		getPublicProfileMiddleware, err := createSingleRuleMiddleware(rlCollection, "30-1m", "public-user")
		if err != nil {
			log.Fatalf("Failed to create public-user limiter: %v", err)
		}
		public.GET("/user/:username", getPublicProfileMiddleware, userController.GetPublicUserProfile)
	}
}

func main() {
	mongoClient, dynamicCollection, err := initMongoDB()
	if err != nil {
		log.Fatalf("Error initializing MongoDB: %v", err)
	}
	defer func() {
		for _, limiter := range limiterRegistry {
			limiter.Stop()
		}
		if err = mongoClient.Disconnect(context.Background()); err != nil {
			log.Printf("Error disconnecting from MongoDB: %v", err)
		} else {
			log.Println("Disconnected from MongoDB.")
		}
	}()

	r := gin.Default()

	combinedRLConfig := ginmongolimiter.DefaultConfig(dynamicCollection)
	combinedRLConfig.KeyGenerator = ginmongolimiter.KeyGenerators{}.ByIP
	combinedRLConfig.Debug = true

	combinedRateLimiter, err := ginmongolimiter.New(combinedRLConfig)
	if err != nil {
		log.Fatalf("Failed to create combined rate limiter instance: %v", err)
	}
	limiterRegistry = append(limiterRegistry, combinedRateLimiter)

	RegisterUserRoutes(r, combinedRateLimiter, dynamicCollection)

	log.Println("Server starting on :8080")
	r.Run(":8080")
}

// Placeholder Controllers and Mail functions (replace with your actual implementations)
type UserController struct{}

func NewUserController() *UserController { return &UserController{} }
func (uc *UserController) Register(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"message": "User registered"})
}
func (uc *UserController) Login(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"message": "User logged in"})
}
func (uc *UserController) RefreshToken(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"message": "Token refreshed"})
}
func (uc *UserController) UsernameAvailability(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"message": "Username available"})
}
func (uc *UserController) ForgotPassword(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"message": "Forgot password request"})
}
func (uc *UserController) ChangePassword(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"message": "Password changed"})
}
func (uc *UserController) Logout(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"message": "User logged out"})
}
func (uc *UserController) GetMyProfile(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"profile": "My profile data"})
}
func (uc *UserController) UpdateProfile(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"message": "Profile updated"})
}
func (uc *UserController) UpdateEmailWithPassword(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"message": "Email update requested"})
}
func (uc *UserController) VerifyEmailChangeOTP(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"message": "Email update OTP verified"})
}
func (uc *UserController) GetPublicUserProfile(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"public_profile": "Public user data"})
}

type MailController struct{}

var mail = &MailController{}

func (mc *MailController) VerifyForgotPasswordOTP(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"message": "Forgot password OTP verified"})
}
func (mc *MailController) ResendOTP(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"message": "OTP re-sent"})
}
func (mc *MailController) VerifyEmail(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"message": "Email verification successful"})
}

var userController = NewUserController() // Initialize once

// authMiddleware for demonstration purposes.
func authMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Set("user_id", "demoUser123")
		c.Set("user_role", "user")
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
