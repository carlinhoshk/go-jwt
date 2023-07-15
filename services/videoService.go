package services

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"

	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/Azure/azure-sdk-for-go/sdk/storage/azblob"
	"github.com/carlinhoshk/go-jwt/models"
	"github.com/carlinhoshk/go-jwt/initializers"
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

/*
type customError struct {
    msg string
}

func (e *customError) Error() string {
    return e.msg
}

func GetVideosByUserLogin(login string) ([]map[string]interface{}, error) {
    var user models.User
    if err := DB.Where("login = ?", login).First(&user).Error; err != nil {
        return nil, err
    }

    var videos []models.Video
    if errFunc := DB.Model(&user).Select("name, videos.upload_date").Association("Videos").Find(&videos).Error; errFunc != nil {
        err := &customError{msg: errFunc()}
        if errors.Is(err, gorm.ErrRecordNotFound) {
            return nil, fmt.Errorf("no videos found for user with login: %s", login)
        } else {
            return nil, fmt.Errorf("error fetching videos: %w", err)
        }
    }

    videoData := make([]map[string]interface{}, len(videos))
    for i, video := range videos {
        videoData[i] = map[string]interface{}{
            "name":        video.Name,
            "upload_date": video.UploadDate,
        }
    }

    return videoData, nil
}
*/



// Função para fazer o download do vídeo
func DownloadVideo(video models.Video, buffer *bytes.Buffer) error {

	url := os.Getenv("AZURE_BLOB_URL")
	contername := os.Getenv("CONTAINER_NAME")
	var BlobName = video.BlobName

	credential, err := azidentity.NewDefaultAzureCredential(nil)
	if err!= nil {
		panic(err)
	}

	client, err := azblob.NewClient(url, credential, nil)
	if err!= nil {
		panic(err)
	}

	file, err := os.Create("/tmp/" + video.ID.String() + ".mp4")
	if err!= nil {
        panic(err)
    }
	defer file.Close()
	
	//resp, err := http.Get(video.BlobUrl)
	_, err = client.DownloadFile(context.TODO(), contername, BlobName, file, nil)
	if err != nil {
		return err
	}
	return nil
}