package initializers

import (

	"github.com/carlinhoshk/go-jwt/models"
)
func SyncDatabase(){
	DB.AutoMigrate(&models.Usar{})
}