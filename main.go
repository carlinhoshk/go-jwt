package main

import (
	"github.com/gin-gonic/gin"

	"github.com/carlinhoshk/go-jwt/controllers"
	"github.com/carlinhoshk/go-jwt/initializers"
	"github.com/carlinhoshk/go-jwt/middleware"
)
func init(){
	initializers.LoadEnvVariables()
	initializers.ConnectToDb() 
	initializers.SyncDatabase()
}

func main(){
	r := gin.Default()

	r.POST("/signup", controllers.Signup)
	r.POST("/login", controllers.Login)
	r.GET("/validate", middleware.RequireAuth, controllers.Validate)
	r.POST("/uploadfile", middleware.RequireAuth, controllers.UploadFile)
	r.GET("/users/:id", controllers.GetIde)
	r.GET("/videos/:login", controllers.GetVideosByUser)
	
	r.Run()

}