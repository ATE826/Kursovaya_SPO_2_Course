// backend/auth/auth.go
package auth

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"

	"backend/db"
	"backend/models"
	"backend/utils" // Для хеширования паролей

	"github.com/golang-jwt/jwt/v5" // v5 - последняя версия библиотеки
	// Для хеширования паролей
)

// Секретный ключ для подписи JWT
var jwtSecret []byte

// SetJWTSecret устанавливает секретный ключ JWT
func SetJWTSecret(secret string) {
	jwtSecret = []byte(secret)
}

// JwtClaims определяет поля, которые мы будем хранить в JWT
type JwtClaims struct {
	UserID   int    `json:"user_id"`
	Username string `json:"username"`
	Role     string `json:"role"`
	jwt.RegisteredClaims
}

// GenerateJWT генерирует новый JWT токен для пользователя
func GenerateJWT(user *models.User) (string, error) {
	// Устанавливаем время истечения токена (например, 24 часа)
	expirationTime := time.Now().Add(24 * time.Hour)

	claims := &JwtClaims{
		UserID:   user.ID,
		Username: user.Username,
		Role:     user.Role,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(expirationTime),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			Issuer:    "music-store-backend",
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString(jwtSecret)
	if err != nil {
		return "", fmt.Errorf("failed to sign token: %w", err)
	}

	return tokenString, nil
}

// JwtAuthentication является middleware для проверки JWT токена
func JwtAuthentication(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Извлекаем токен из заголовка Authorization
		authHeader := r.Header.Get("Authorization")
		if authHeader == "" {
			w.WriteHeader(http.StatusUnauthorized)
			json.NewEncoder(w).Encode(map[string]string{"error": "Missing authorization header"})
			return
		}

		// Ожидаем формат "Bearer <token>"
		bearerToken := strings.Split(authHeader, " ")
		if len(bearerToken) != 2 || strings.ToLower(bearerToken[0]) != "bearer" {
			w.WriteHeader(http.StatusUnauthorized)
			json.NewEncoder(w).Encode(map[string]string{"error": "Invalid authorization header format"})
			return
		}

		tokenString := bearerToken[1]

		// Парсим и валидируем токен
		claims := &JwtClaims{}
		token, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
			// Проверяем алгоритм подписи
			if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
			}
			return jwtSecret, nil
		})

		if err != nil {
			// Ошибки парсинга или валидации (например, истекший токен)
			log.Printf("JWT parse error: %v", err)
			w.WriteHeader(http.StatusUnauthorized)
			json.NewEncoder(w).Encode(map[string]string{"error": "Invalid or expired token"})
			return
		}

		if !token.Valid {
			w.WriteHeader(http.StatusUnauthorized)
			json.NewEncoder(w).Encode(map[string]string{"error": "Invalid token"})
			return
		}

		// Токен валиден. Сохраняем информацию о пользователе в контексте запроса.
		// Это позволит обработчикам иметь доступ к ID пользователя и его роли.
		ctx := context.WithValue(r.Context(), "user", claims)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// GetUserFromContext извлекает информацию о пользователе из контекста запроса
func GetUserFromContext(ctx context.Context) (*JwtClaims, bool) {
	userClaims, ok := ctx.Value("user").(*JwtClaims)
	return userClaims, ok
}

// AdminRequired является middleware для проверки роли пользователя
func AdminRequired(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		userClaims, ok := GetUserFromContext(r.Context())
		if !ok || userClaims == nil {
			// Этого не должно произойти, если JwtAuthentication сработал
			w.WriteHeader(http.StatusInternalServerError)
			json.NewEncoder(w).Encode(map[string]string{"error": "Could not get user from context"})
			return
		}

		if userClaims.Role != "admin" {
			w.WriteHeader(http.StatusForbidden) // 403 Forbidden
			json.NewEncoder(w).Encode(map[string]string{"error": "Admin access required"})
			return
		}

		// Пользователь является админом, продолжаем выполнение запроса
		next.ServeHTTP(w, r)
	})
}

// RegisterAdminUser пытается зарегистрировать пользователя-админа, если он еще не существует
func RegisterAdminUser(username, password string) error {
	db := db.GetDB()
	if db == nil {
		return fmt.Errorf("database not initialized")
	}

	// Проверяем, существует ли уже пользователь с таким именем
	var existingID int
	err := db.QueryRow("SELECT id FROM users WHERE username = ?", username).Scan(&existingID)

	switch {
	case err == sql.ErrNoRows:
		// Пользователь не найден, регистрируем его как админа
		hashedPassword, err := utils.HashPassword(password) // Используем утилиту для хеширования
		if err != nil {
			return fmt.Errorf("failed to hash admin password: %w", err)
		}

		_, err = db.Exec("INSERT INTO users (first_name, last_name, username, email, password_hash, city, role) VALUES (?, ?, ?, ?, ?, ?, ?)",
			"Admin", "User", username, fmt.Sprintf("%s@example.com", username), hashedPassword, "Unknown", "admin")
		if err != nil {
			return fmt.Errorf("failed to insert admin user: %w", err)
		}
		log.Printf("Admin user '%s' registered successfully.", username)
		return nil
	case err != nil:
		// Произошла другая ошибка при запросе к БД
		return fmt.Errorf("error checking for existing admin user: %w", err)
	default:
		// Пользователь с таким именем уже существует
		// Проверим, является ли он админом
		var existingRole string
		err := db.QueryRow("SELECT role FROM users WHERE username = ?", username).Scan(&existingRole)
		if err != nil {
			return fmt.Errorf("error checking role for existing user: %w", err)
		}
		if existingRole == "admin" {
			// Пользователь уже существует и является админом, ничего не делаем
			return nil // Все хорошо
		} else {
			// Пользователь существует, но не админ. Логируем предупреждение.
			log.Printf("Warning: User '%s' already exists but is not an admin. Cannot register admin user with this username.", username)
			return nil // Считаем это не ошибкой, а просто невозможностью зарегистрировать админа
		}
	}
}
