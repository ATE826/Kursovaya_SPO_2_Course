// backend/models/models.go
package models

// User представляет пользователя в системе.
type User struct {
	ID           int    `json:"id"`
	FirstName    string `json:"firstName"`
	LastName     string `json:"lastName"`
	Username     string `json:"username"`
	Email        string `json:"email"`
	PasswordHash string `json:"-"` // Игнорируем при сериализации в JSON
	City         string `json:"city"`
	Role         string `json:"role"` // 'user' или 'admin'
}

// LoginRequest используется для парсинга запросов на вход.
type LoginRequest struct {
	Username string `json:"username" binding:"required"`
	Password string `json:"password" binding:"required"`
}

// RegisterRequest используется для парсинга запросов на регистрацию.
type RegisterRequest struct {
	FirstName string `json:"firstName" binding:"required"`
	LastName  string `json:"lastName" binding:"required"`
	Username  string `json:"username" binding:"required"`
	Email     string `json:"email" binding:"required"`
	Password  string `json:"password" binding:"required"`
	City      string `json:"city"`
	// Роль определяется бэкендом на основе username и password
}

// Ensemble представляет музыкальный коллектив.
type Ensemble struct {
	ID   int    `json:"id"`
	Name string `json:"name"`
	Type string `json:"type"` // Например: квинтет, оркестр
}

// Musician представляет музыканта.
type Musician struct {
	ID           int    `json:"id"`
	FirstName    string `json:"firstName"`
	LastName     string `json:"lastName"`
	Role         string `json:"role"`                   // Например: барабанщик, гитарист
	EnsembleID   *int   `json:"ensembleId"`             // Используем указатель *int для nullable поля
	EnsembleName string `json:"ensembleName,omitempty"` // Для удобства отображения на фронте, опционально
}

// Track представляет музыкальную композицию (личную или ансамблевую).
type Track struct {
	ID           int    `json:"id"`
	Name         string `json:"name"`
	Duration     int    `json:"duration"`               // Длительность в секундах
	MusicianID   *int   `json:"musicianId"`             // ID музыканта, если личный трек
	EnsembleID   *int   `json:"ensembleId"`             // ID ансамбля, если ансамблевый трек
	MusicianName string `json:"musicianName,omitempty"` // Для удобства отображения
	EnsembleName string `json:"ensembleName,omitempty"` // Для удобства отображения
}

// Record представляет пластинку (виниловую или компакт-диск).
type Record struct {
	ID               int     `json:"id"`
	Title            string  `json:"title"`
	Label            string  `json:"label"` // EMI
	WholesaleAddress string  `json:"wholesaleAddress"`
	WholesalePrice   float64 `json:"wholesalePrice"`
	RetailPrice      float64 `json:"retailPrice"`
	ReleaseDate      string  `json:"releaseDate"` // Дата выпуска (строка YYYY-MM-DD)
	SoldLastYear     int     `json:"soldLastYear"`
	SoldCurrentYear  int     `json:"soldCurrentYear"`
	Stock            int     `json:"stock"`
	Tracks           []Track `json:"tracks"` // Список треков на этой пластинке
}

// CartItem представляет одну позицию в корзине пользователя.
type CartItem struct {
	UserID   int     `json:"userId"`
	RecordID int     `json:"recordId"`
	Quantity int     `json:"quantity"`
	Record   *Record `json:"record,omitempty"` // Информация о пластинке (опционально для отображения)
}

// AddTracksRequest используется для парсинга запросов на добавление треков к музыканту, ансамблю или пластинке
// (вспомогательная структура для форм добавления/редактирования)
type AddTrackRequest struct {
	Name     string `json:"name"`
	Duration int    `json:"duration"`
}

// AddMusicianRequest используется для парсинга запроса на добавление музыканта
type AddMusicianRequest struct {
	FirstName  string            `json:"firstName" binding:"required"`
	LastName   string            `json:"lastName" binding:"required"`
	Role       string            `json:"role"`
	EnsembleID *int              `json:"ensembleId"` // Используем указатель для nullable
	Tracks     []AddTrackRequest `json:"tracks"`     // Личные треки музыканта
}

// AddEnsembleRequest используется для парсинга запроса на добавление ансамбля
type AddEnsembleRequest struct {
	Name   string            `json:"name" binding:"required"`
	Type   string            `json:"type"`
	Tracks []AddTrackRequest `json:"tracks"` // Ансамблевые треки
}

// AddRecordRequest используется для парсинга запроса на добавление пластинки
type AddRecordRequest struct {
	Title            string  `json:"title" binding:"required"`
	Label            string  `json:"label"`
	WholesaleAddress string  `json:"wholesaleAddress"`
	WholesalePrice   float64 `json:"wholesalePrice"`
	RetailPrice      float64 `json:"retailPrice"`
	ReleaseDate      string  `json:"releaseDate"`
	Stock            int     `json:"stock"`
	TrackIDs         []int   `json:"trackIds"` // Список ID треков, которые будут на пластинке
}
