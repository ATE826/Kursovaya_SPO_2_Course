package handlers

import (
	"backend/models"
	"backend/utils"
	"net/http"
	"os"

	"github.com/gin-gonic/gin"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"
)

type RegisterInput struct { // Структура для валидации данных при регистрации
	FirstName string `json:"first_name" binding:"required"`
	LastName  string `json:"last_name" binding:"required"`
	UserName  string `json:"username" binding:"required"`
	Email     string `json:"email" binding:"required"`
	Password  string `json:"password" binding:"required"`
	City      string `json:"city" binding:"required"`
}

type LoginInput struct { // Структура для валидации данных при входе
	UserName string `json:"username" binding:"required"`
	Password string `json:"password" binding:"required"`
}

type Server struct { // Структура для хранения экземпляра сервера и экземпляра базы данных
	db *gorm.DB
}

func NewServer(db *gorm.DB) *Server { // Функция для создания экземпляра сервера
	return &Server{db: db}
}

func (s *Server) Register(c *gin.Context) { // Функция для регистрации пользователя
	var input RegisterInput

	if err := c.ShouldBind(&input); err != nil { // Проверка валидности данных
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()}) // Отправка ошибки, если данные не валидны
	}

	adminLogin := os.Getenv("ADMIN_LOGIN")       // Получение логина администратора из переменной окружения
	adminPassword := os.Getenv("ADMIN_PASSWORD") // Получение пароля администратора из переменной окружения

	var role string
	if input.Email == adminLogin && input.Password == adminPassword { // Проверка на совпадение логина и пароля с администратором
		role = "admin" // Если совпадает, то роль администратора
	} else {
		role = "user" // Иначе роль пользователя
	}

	user := models.User{ // Создание экземпляра пользователя
		FirstName: input.FirstName,
		LastName:  input.LastName,
		UserName:  input.UserName,
		Email:     input.Email,
		Password:  input.Password,
		City:      input.City,
		Role:      role,
	}

	user.HashPassword() // Хеширование пароля

	if err := s.db.Create(&user).Error; err != nil { // Проверка на ошибку при создании пользователя
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
	}

	c.JSON(http.StatusCreated, gin.H{"message": "User created"}) // Отправка сообщения об успешной регистрации
}

func (s *Server) LoginCheck(email, password string) (string, error) {
	var err error

	user := models.User{}

	if err = s.db.Model(models.User{}).Where("email = ?", email).Take(&user).Error; err != nil {
		return "", err
	}

	err = user.VerifyPassword(password)

	if err != nil && err == bcrypt.ErrMismatchedHashAndPassword {
		return "", err
	}

	token, err := utils.GenerateToken(user)

	if err != nil {
		return "", err
	}

	return token, nil
}

func (s *Server) Login(c *gin.Context) {
	var input LoginInput

	// Валидация входных данных
	if err := c.ShouldBind(&input); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Поиск пользователя по UerName
	var user models.User
	if err := s.db.Where("username = ?", input.UserName).First(&user).Error; err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid username or password"})
		return
	}

	// Проверка пароля
	if err := user.VerifyPassword(input.Password); err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid email or password"})
		return
	}

	// Генерация токена
	token, err := utils.GenerateToken(user)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to generate token"})
		return
	}

	// Успешный ответ
	c.JSON(http.StatusOK, gin.H{"token": token})
}
