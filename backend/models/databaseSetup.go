package models

import (
	"fmt"
	"log"
	"os"

	"github.com/joho/godotenv"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

func Setup() (*gorm.DB, error) { // Функция для инициализации подключения к БД
	err := godotenv.Load() // Загрузка переменных окружения из файла .env
	if err != nil {
		log.Println("Error loading .env file")
	}

	// Формирование DSN для подключения к БД (PostgreSQL)
	dsn := fmt.Sprintf(
		"host=%s user=%s password=%s dbname=%s port=%s sslmode=disable TimeZone=Europe/Moscow",
		os.Getenv("DB_HOST"),     // Добавлен параметр хоста
		os.Getenv("DB_USER"),     // Добавлен параметр пользователя
		os.Getenv("DB_PASSWORD"), // Добавлен параметр пароля
		os.Getenv("DB_NAME"),     // Добавлен параметр имени БД
		os.Getenv("DB_PORT"),     // Добавлен параметр порта
	)

	db, err := gorm.Open(postgres.Open(dsn), &gorm.Config{}) // Подключение к БД
	if err != nil {
		log.Fatal("Can't connect to database")
	}

	if err := db.AutoMigrate(&User{}); err != nil {
		log.Println("Can't migrate database: ", err)
	}

	log.Println("Database connected")
	return db, nil // Возвращаем объект подключения к БД
}
