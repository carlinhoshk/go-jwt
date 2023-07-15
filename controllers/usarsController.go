package controllers

import (
	"context"
	"io"
	"net/http"
	"os"
	"time"
	"strings"
	

	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/Azure/azure-sdk-for-go/sdk/storage/azblob"
	"github.com/carlinhoshk/go-jwt/initializers"
	"github.com/carlinhoshk/go-jwt/models"
	"github.com/carlinhoshk/go-jwt/services"
	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v4"
	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
	//"github.com/patrickmn/go-cache"

)
//var c = cache.New(5*time.Minute, 10*time.Minute)

func Signup(c *gin.Context) {
	var body struct {
		Login    string
		Password string
		Role     models.UserRole
	}

	if c.Bind(&body) != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Failed to read body",
		})

		return
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(body.Password), 10)

	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Failed to hash password " + err.Error(),
		})

		return
	}

	user := models.User{Login: body.Login, Password: string(hash), Role: body.Role }
	result := initializers.DB.Create(&user)

	if result.Error != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Failed to create user " + result.Error.Error(),
		})

		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message": "User created successfully",
	})
}
func Login(c *gin.Context) {
	var body struct {
		Login    string
		Password string
	}

	if c.Bind(&body) != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Failed to read body",
		})
		return

	}
	var user models.User

	initializers.DB.First(&user, "login = ?", body.Login)

	if user.ID == uuid.Nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Invalid login or password",
		})
		return
	}

	err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(body.Password))

	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Invalid login or password",
		})
		return
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"sub": user.ID,
		"exp": time.Now().Add(time.Hour * 24 * 30).Unix(),
	})

	// Sign and get the complete encoded token as a string using the secret
	tokenString, err := token.SignedString([]byte(os.Getenv("SECRET")))

	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Failed to create token",
		})
		return
	}

	c.SetSameSite(http.SameSiteLaxMode)
	c.SetCookie("Authorization", tokenString, 3600*24*30, "", "", false, true)
	c.JSON(http.StatusOK, gin.H{
		"token": tokenString,
	})
}

func Validate(c *gin.Context) {

	user, _ := c.Get("user")
	
	

	c.JSON(http.StatusOK, gin.H{
		"message": user,
		// "message": user.(models.User).Login,
	})
}


func UploadFile(c *gin.Context) {

	url := os.Getenv("AZURE_BLOB_URL")
	ctx := context.Background()

	credential, err := azidentity.NewDefaultAzureCredential(nil)
	if err!= nil {
        panic(err)
    }
	

	client, err := azblob.NewClient(url, credential, nil)
	if err!= nil {
        panic(err)
    }

	
	file, err := c.FormFile("file")
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Abrir o arquivo para leitura
	src, err := file.Open()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	defer src.Close()

	user, _ := c.Get("user")
	username := user.(models.User).Login

	// Obtém a data atual
	currentTime := time.Now()
	date := currentTime.Format("20060102")

	blobName := username + "-" + date + "-" + strings.ReplaceAll(file.Filename, " ", "")

	// Nome do container
	containerName := "container-tv-carlos"

	// Lê o arquivo em binário
	src, err = file.Open()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	defer src.Close()

	// Converte o arquivo para um buffer de bytes
	fileData, err := io.ReadAll(src)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	// Upload do arquivo para o Azure Blob Storage
	_, err = client.UploadBuffer(ctx, containerName, blobName, fileData, &azblob.UploadBufferOptions{})
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	blobURL := "https://blobtvcarlos.blob.core.windows.net/" + containerName + "/" + strings.ReplaceAll(blobName, " ", "")
	
	video := models.Video{
		Name:       strings.ReplaceAll(file.Filename, " ", ""),
		UploadDate: currentTime,
		UserId:     user.(models.User).ID,
		BlobName:   strings.ReplaceAll(blobName, " ", ""),
		BlobUrl:    blobURL,
	}
	// Salvar o vídeo no banco de dados
	err = saveVideoToDB(video)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	// Retornar a resposta de sucesso
	c.JSON(http.StatusOK, gin.H{"message": "Upload do vídeo concluído com sucesso!" + blobURL})
}
func saveVideoToDB(video models.Video) error {
    // Execute a operação de criação do vídeo no banco de dados
    result := initializers.DB.Create(&video)
    if result.Error != nil {
        return result.Error
    }

    // A operação foi concluída com sucesso
    return nil
}

// função de controller para usar o método criado no videoService GetUserID e mostre no final o id
func GetIde(c *gin.Context) {
	// Obtenha o login do parâmetro da solicitação ou de qualquer outra fonte
	login := c.Param("login")

	// Chame a função GetUserID para obter o ID do usuário
	userID, err := services.GetUserID(login)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	// Faça qualquer lógica adicional com o ID do usuário
	// ...

	// Retorne a resposta com o ID do usuário
	c.JSON(http.StatusOK, gin.H{"userID": userID})
}


/*
func DownloadFile(c *gin.Context) {
	// Download blob file from azure and service cache 	
}
 */

/*
func DownloadBlob(c *gin.Context) {
	lid := c.Param("id")

	userID, err := uuid.Parse(lid)
    if err != nil {
        c.String(http.StatusBadRequest, "Invalid user ID")
        return
    }
	videoData, err := services.GetVideoByUserID(userID)
	if err != nil {
		c.String(http.StatusInternalServerError, "Erro ao buscar vídeos")
		return
	}

	c.JSON(http.StatusOK, videoData)
}
 */