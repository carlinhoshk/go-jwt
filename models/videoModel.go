package models

import (
	"time"

	
	"github.com/google/uuid"
	"gorm.io/gorm"
	
)

type Video struct {
	ID         	uuid.UUID `gorm:"type:uuid;default:uuid_generate_v4()"`
	Name 	   	string
	UploadDate  time.Time `gorm:"type:datetime"`
	UserId    	uuid.UUID
	BlobName  	string
	BlobUrl   	string
}

func (video *Video) BeforeCreate(tx *gorm.DB) (err error) {
	video.ID = uuid.New()
	return nil
}
