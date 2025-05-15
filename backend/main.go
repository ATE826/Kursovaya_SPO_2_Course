// backend/main.go
package main

import (
	"log"
	"net/http"
	"os"

	"backend/auth"
	"backend/db" // Убедись, что путь правильный относительно твоего go.mod
	"backend/handlers"

	"github.com/gorilla/mux"   // Роутер
	"github.com/joho/godotenv" // Для загрузки .env
)

func main() {
	// Загружаем переменные из .env файла
	err := godotenv.Load()
	if err != nil {
		log.Println("No .env file found, assuming environment variables are set.")
		// Не останавливаемся, если .env не найден, возможно, переменные установлены в окружении
	}

	// Получаем путь к БД из .env или окружения
	databaseURL := os.Getenv("DATABASE_URL")
	if databaseURL == "" {
		log.Fatal("DATABASE_URL not set in .env or environment")
	}

	// Инициализируем базу данных
	db.InitDB(databaseURL)
	defer db.GetDB().Close() // Закрываем соединение при завершении программы

	// Получаем JWT Secret из .env или окружения
	jwtSecret := os.Getenv("JWT_SECRET")
	if jwtSecret == "" {
		log.Fatal("JWT_SECRET not set in .env or environment")
	}
	auth.SetJWTSecret(jwtSecret) // Устанавливаем секрет в пакете auth

	// Получаем Admin User/Pass из .env или окружения (для первой регистрации)
	adminUsername := os.Getenv("ADMIN_USERNAME")
	adminPassword := os.Getenv("ADMIN_PASSWORD")
	if adminUsername == "" || adminPassword == "" {
		log.Println("ADMIN_USERNAME or ADMIN_PASSWORD not set. Cannot register admin automatically.")
	} else {
		// Попробуем зарегистрировать админа при первом запуске (безопасно повторно вызывать)
		err := auth.RegisterAdminUser(adminUsername, adminPassword)
		if err != nil {
			log.Printf("Error registering admin user: %v", err)
		} else {
			log.Println("Admin user checked/registered successfully (if not already exists)")
		}
	}

	// Настраиваем роутер
	r := mux.NewRouter()

	// Публичные роуты
	r.HandleFunc("/api/register", handlers.RegisterHandler).Methods("POST")
	r.HandleFunc("/api/login", handlers.LoginHandler).Methods("POST")
	r.HandleFunc("/api/records", handlers.GetRecordsHandler).Methods("GET") // Получение всех пластинок

	// Защищенные роуты (требуют аутентификации)
	s := r.PathPrefix("/api").Subrouter()
	s.Use(auth.JwtAuthentication) // Применяем middleware для проверки JWT
	s.HandleFunc("/profile", handlers.GetProfileHandler).Methods("GET")
	s.HandleFunc("/profile", handlers.UpdateProfileHandler).Methods("PUT")
	s.HandleFunc("/cart", handlers.GetCartHandler).Methods("GET")
	s.HandleFunc("/cart", handlers.AddToCartHandler).Methods("POST")
	s.HandleFunc("/cart/{recordId}", handlers.UpdateCartHandler).Methods("PUT")        // Изменение количества
	s.HandleFunc("/cart/{recordId}", handlers.RemoveFromCartHandler).Methods("DELETE") // Удаление из корзины

	// Админские роуты (требуют аутентификации и роли 'admin')
	a := r.PathPrefix("/api/admin").Subrouter()
	a.Use(auth.JwtAuthentication) // Сначала проверяем JWT
	a.Use(auth.AdminRequired)     // Затем проверяем роль
	a.HandleFunc("/records", handlers.AddRecordHandler).Methods("POST")
	a.HandleFunc("/records/{id}", handlers.UpdateRecordHandler).Methods("PUT")
	a.HandleFunc("/records/{id}", handlers.DeleteRecordHandler).Methods("DELETE")
	a.HandleFunc("/musicians", handlers.AddMusicianHandler).Methods("POST")
	a.HandleFunc("/ensembles", handlers.AddEnsembleHandler).Methods("POST")
	a.HandleFunc("/ensembles", handlers.GetEnsemblesHandler).Methods("GET") // Нужен для фронтенда (выбор ансамбля для музыканта)
	a.HandleFunc("/tracks", handlers.GetAllTracksHandler).Methods("GET")    // Нужен для фронтенда (выбор треков для пластинки)

	// Роуты для отчетов (скорее всего, админские)
	a.HandleFunc("/reports/ensemble-tracks/{ensembleId}", handlers.GetEnsembleTrackCountHandler).Methods("GET")
	a.HandleFunc("/reports/ensemble-records/{ensembleId}", handlers.GetRecordsByEnsembleHandler).Methods("GET")
	a.HandleFunc("/reports/bestsellers", handlers.GetBestSellersHandler).Methods("GET")

	// Запускаем HTTP сервер
	port := os.Getenv("BACKEND_PORT")
	if port == "" {
		port = "8080" // Порт по умолчанию
	}
	log.Printf("Server listening on :%s", port)
	log.Fatal(http.ListenAndServe(":"+port, r))
}
