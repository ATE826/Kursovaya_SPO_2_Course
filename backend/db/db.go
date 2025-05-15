// backend/db/db.go
package db

import (
	"database/sql"
	"log"
)

var DB *sql.DB

// InitDB инициализирует базу данных и создает таблицы, если они не существуют
func InitDB(databaseURL string) {
	var err error
	DB, err = sql.Open("sqlite3", databaseURL)
	if err != nil {
		log.Fatalf("Failed to open database: %v", err)
	}

	// Проверяем соединение
	err = DB.Ping()
	if err != nil {
		log.Fatalf("Failed to connect to database: %v", err)
	}

	log.Println("Database connected successfully")

	// Создаем таблицы
	createTables()
}

// createTables создает необходимые таблицы в базе данных
func createTables() {
	// ВНИМАНИЕ: Используем ON DELETE CASCADE для автоматического удаления связанных записей.
	// Это заменяет необходимость явных триггеров для каскадного удаления в данном случае.
	// SQLite поддерживает эту возможность.

	queries := []string{
		`CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            first_name TEXT NOT NULL,
            last_name TEXT NOT NULL,
            username TEXT UNIQUE NOT NULL,
            email TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            city TEXT,
            role TEXT NOT NULL CHECK (role IN ('user', 'admin'))
        );`,
		`CREATE TABLE IF NOT EXISTS ensembles (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT UNIQUE NOT NULL,
            type TEXT
        );`,
		`CREATE TABLE IF NOT EXISTS musicians (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            first_name TEXT NOT NULL,
            last_name TEXT NOT NULL,
            role TEXT, -- Например: барабанщик, гитарист, композитор, дирижер
            ensemble_id INTEGER,
            FOREIGN KEY (ensemble_id) REFERENCES ensembles(id) ON DELETE SET NULL -- Если ансамбль удален, музыкант остается, но без привязки
        );`,
		`CREATE TABLE IF NOT EXISTS tracks (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            duration INTEGER NOT NULL, -- Длительность в секундах (или другой единице, главное int)
            musician_id INTEGER NULL,  -- ID музыканта, если это личный трек
            ensemble_id INTEGER NULL,   -- ID ансамбля, если это ансамблевый трек
            -- Проверка, что трек принадлежит либо музыканту, либо ансамблю, но не обоим
            CHECK ((musician_id IS NULL AND ensemble_id IS NOT NULL) OR (musician_id IS NOT NULL AND ensemble_id IS NULL)),
            FOREIGN KEY (musician_id) REFERENCES musicians(id) ON DELETE CASCADE, -- Если музыкант удален, его треки удаляются
            FOREIGN KEY (ensemble_id) REFERENCES ensembles(id) ON DELETE CASCADE  -- Если ансамбль удален, его треки удаляются
        );`,
		`CREATE TABLE IF NOT EXISTS records (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            title TEXT NOT NULL,
            label TEXT,             -- EMI в задании
            wholesale_address TEXT,
            wholesale_price REAL DEFAULT 0, -- Добавлено по описанию задачи
            retail_price REAL DEFAULT 0,    -- Добавлено по описанию задачи
            release_date TEXT,              -- Добавлено по описанию задачи (можно хранить как текст YYYY-MM-DD)
            sold_last_year INTEGER DEFAULT 0, -- Добавлено по описанию задачи
            sold_current_year INTEGER DEFAULT 0, -- Добавлено по описанию задачи
            stock INTEGER DEFAULT 0         -- Добавлено по описанию задачи
        );`,
		`CREATE TABLE IF NOT EXISTS record_tracks (
            record_id INTEGER,
            track_id INTEGER,
            PRIMARY KEY (record_id, track_id), -- Составной первичный ключ
            FOREIGN KEY (record_id) REFERENCES records(id) ON DELETE CASCADE, -- Если пластинка удалена, ссылки на треки удаляются
            FOREIGN KEY (track_id) REFERENCES tracks(id) ON DELETE CASCADE   -- Если трек удален, ссылки на пластинки удаляются
        );`,
		`CREATE TABLE IF NOT EXISTS cart_items (
            user_id INTEGER NOT NULL,
            record_id INTEGER NOT NULL,
            quantity INTEGER NOT NULL DEFAULT 1,
            PRIMARY KEY (user_id, record_id), -- У пользователя может быть только одна запись для каждого типа пластинки
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,    -- Если пользователь удален, его корзина очищается
            FOREIGN KEY (record_id) REFERENCES records(id) ON DELETE CASCADE -- Если пластинка удалена, она удаляется из корзин
        );`,
	}

	for _, query := range queries {
		_, err := DB.Exec(query)
		if err != nil {
			log.Fatalf("Failed to create table: %v Query: %s", err, query)
		}
	}
	log.Println("Database tables checked/created successfully")
}

// GetDB возвращает экземпляр подключения к базе данных
func GetDB() *sql.DB {
	return DB
}
