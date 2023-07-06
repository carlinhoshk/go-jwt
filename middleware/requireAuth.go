package middleware

import (
	"fmt"
	"net/http"
	"os"
	"time"

	"github.com/carlinhoshk/go-jwt/initializers"
	"github.com/carlinhoshk/go-jwt/models"
	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v4"
	//"github.com/google/uuid"
)

func RequireAuth(c *gin.Context) {
	
	tokenString, err := c.Cookie("Authorization")

	if err!= nil {
		c.AbortWithStatus(http.StatusUnauthorized)
	}

	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {

 		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
	
		return []byte(os.Getenv("SECRET")), nil
	})

	if err != nil {
		c.AbortWithStatus(http.StatusUnauthorized)
	}
	if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
		if float64(time.Now().Unix()) > claims["exp"].(float64) {
			c.AbortWithStatus(http.StatusUnauthorized)
			return
		}
	
		userID, ok := claims["sub"].(string)
		if !ok {
			c.AbortWithStatus(http.StatusUnauthorized)
			return
		}
	
		var user models.User
		result := initializers.DB.First(&user, "id = ?", userID)
		if result.Error != nil {
			c.AbortWithStatus(http.StatusUnauthorized)
			return
		}
	
		c.Set("user", user)
		c.Next()
		
	} else {
		c.AbortWithStatus(http.StatusUnauthorized)
		return
	}
	
	
}