package controllers

import (
	//"bytes"
	"context"
	"strconv"

	"io"
	"net/http"
	"os"

	"strings"
	"time"

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

	Name := c.PostForm("name")
	
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
		Name:       Name,
		UploadDate: currentTime,
		UserId:     user.(models.User).ID,
		BlobName:   blobName,                       // strings.ReplaceAll(blobName, " ", "")
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
	login := c.Param("id")

	// Chame a função GetUserID para obter o ID do usuário
	userID, err := services.GetUserID(login)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"userID": userID})
}

func GetVideosByUser(c *gin.Context) {
	login := c.Param("login")

	videos, err := services.GetVideosByUserLogin(login)
	if err != nil {
		c.String(http.StatusInternalServerError, "Erro ao buscar vídeos")
		return
	}

	c.JSON(http.StatusOK, videos)
}

/*
func GetVideoFromBlob(c *gin.Context) {
    name := c.Param("name")

    blobName, err := services.GetBlobUrlByName(name)
    if err != nil {
        c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
        return
    }

    // Cria um buffer para armazenar o arquivo baixado
    buffer := &bytes.Buffer{}
    err = services.DownloadVideo(blobName, buffer)
    if err != nil {
        c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
        return
    }

    // Define o cabeçalho de resposta para o tipo de mídia correto (no exemplo, é um vídeo mp4)
    c.Header("Content-Type", "video/mp4")

    // Define o cabeçalho de resposta para indicar que o conteúdo está sendo transmitido
    c.Header("Content-Disposition", "attachment; filename=video.mp4")

    // Define o status HTTP para 200 OK
    c.Status(http.StatusOK)

    // Envia o conteúdo do buffer para o cliente
    c.Writer.Write(buffer.Bytes())
    c.Writer.Flush()
}
*/

func ServeVideo(c *gin.Context) {
	videoName := c.Param("name")

	blobName, err := services.GetBlobNameByName(videoName)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	err = services.DownloadVideo(blobName)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	filePath := "/tmp/" + blobName

	file, err := os.Open(filePath)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Erro ao abrir o arquivo"})
		return
	}
	defer file.Close()

	stat, err := file.Stat()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Erro ao obter informações do arquivo"})
		return
	}

	c.Header("Content-Disposition", "attachment; filename="+blobName)
	c.Header("Content-Type", "video/mp4")
	c.Header("Content-Length", strconv.FormatInt(stat.Size(), 10))

	_, err = io.Copy(c.Writer, file)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Erro ao enviar o conteúdo do arquivo"})
		return
	}
}
