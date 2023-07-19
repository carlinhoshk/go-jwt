package services

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"

	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/Azure/azure-sdk-for-go/sdk/storage/azblob"
	"github.com/carlinhoshk/go-jwt/initializers"
	"github.com/carlinhoshk/go-jwt/models"
	"github.com/google/uuid"
	"gorm.io/gorm"
)

// GetUserID retrieves the ID of a user based on their login.// GetUserID retrieves the ID of a user based on their login.
func GetUserID(login string) (uuid.UUID, error) {
    var user models.User
    err := initializers.DB.Where("login = ?", login).First(&user).Error
    if errors.Is(err, gorm.ErrRecordNotFound) {
        return uuid.Nil, fmt.Errorf("user not found")
    } else if err != nil {
        return uuid.Nil, fmt.Errorf("failed to retrieve user: %w", err)
    }
    return user.ID, nil
}

func GetVideoByID(id uuid.UUID) (*models.Video, *bytes.Buffer, error) {
    var video models.Video
    err := initializers.DB.First(&video, id).Error
    if err != nil {
        return nil, nil, err
    }

    buffer := &bytes.Buffer{}
    
    if err != nil {
        return nil, nil, err
    }

    return &video, buffer, nil
}


func GetVideosByUserLogin(login string) ([]models.Video, error) {
	var user models.User
	err := initializers.DB.Where("login = ?", login).First(&user).Error
	if err != nil {
		return nil, err
	}

	var videos []models.Video
	err = initializers.DB.Where("user_id = ?", user.ID).Find(&videos).Error
	if err != nil {
		return nil, err
	}

	return videos, nil
}

// Function to download a video
func DownloadVideo(blobName string) error {
    url := os.Getenv("AZURE_BLOB_URL")
    containerName := os.Getenv("CONTAINER_NAME")

    credential, err := azidentity.NewDefaultAzureCredential(nil)
    if err != nil {
        return err
    }

    client, err := azblob.NewClient(url, credential, nil)
    if err != nil {
        return err
    }

    file, err := os.Create("/tmp/" + blobName)
    if err != nil {
        return err
    }
    defer file.Close()

    _, err = client.DownloadFile(context.TODO(), containerName, blobName, file, nil)
    if err != nil {
        return err
    }

    return nil
}



func GetBlobUrlByName(name string) (string, error) {
	
    video := models.Video{}
    err := initializers.DB.Where("name = ?", name).First(&video).Error
    if err != nil {
        return "", err
    }

    return video.BlobName, nil
}


func GetBlobNameByName(videoName string) (string, error) {
	var video models.Video
	err := initializers.DB.Where("name = ?", videoName).First(&video).Error
	if err != nil {
		return "", err
	}

	return video.BlobName, nil
}