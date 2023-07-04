package models

import "gorm.io/gorm"


type Usar struct {
	gorm.Model
	Email    string `gorm:"unique"`
	Password string
}