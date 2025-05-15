// backend/handlers/handlers.go
package handlers

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings" // Для strings.Repeat

	"backend/auth"
	"backend/db"
	"backend/models"
	"backend/utils"

	"github.com/gorilla/mux"
)

// Вспомогательная функция для отправки JSON ответов с ошибкой
func respondWithError(w http.ResponseWriter, code int, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(map[string]string{"error": message})
}

// Вспомогательная функция для отправки JSON ответов с данными
func respondWithJSON(w http.ResponseWriter, code int, payload interface{}) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(payload) // WriteHeader вызывается Encode, если не был вызван ранее
	// w.WriteHeader(code) // Если нужен явный вызов статуса, его лучше вызвать ПЕРЕД Encode
}

// --- Обработчики аутентификации и профиля ---

// RegisterHandler обрабатывает запросы на регистрацию новых пользователей
func RegisterHandler(w http.ResponseWriter, r *http.Request) {
	var req models.RegisterRequest
	decoder := json.NewDecoder(r.Body)
	if err := decoder.Decode(&req); err != nil {
		respondWithError(w, http.StatusBadRequest, "Invalid request payload")
		return
	}
	defer r.Body.Close()

	if req.Username == "" || req.Password == "" || req.Email == "" || req.FirstName == "" || req.LastName == "" {
		respondWithError(w, http.StatusBadRequest, "Username, password, email, first name, and last name are required")
		return
	}

	role := "user"
	adminUsername := os.Getenv("ADMIN_USERNAME")
	adminPassword := os.Getenv("ADMIN_PASSWORD")

	if req.Username == adminUsername && req.Password == adminPassword {
		role = "admin"
	}

	hashedPassword, err := utils.HashPassword(req.Password)
	if err != nil {
		log.Printf("Failed to hash password: %v", err)
		respondWithError(w, http.StatusInternalServerError, "Failed to hash password")
		return
	}

	db := db.GetDB()

	var exists bool
	err = db.QueryRow("SELECT EXISTS(SELECT 1 FROM users WHERE username = ? OR email = ?)", req.Username, req.Email).Scan(&exists)
	if err != nil {
		log.Printf("Database error checking user existence: %v", err)
		respondWithError(w, http.StatusInternalServerError, "Database error checking user existence")
		return
	}
	if exists {
		respondWithError(w, http.StatusConflict, "Username or email already exists")
		return
	}

	_, err = db.Exec("INSERT INTO users (first_name, last_name, username, email, password_hash, city, role) VALUES (?, ?, ?, ?, ?, ?, ?)",
		req.FirstName, req.LastName, req.Username, req.Email, hashedPassword, req.City, role)
	if err != nil {
		log.Printf("Failed to create user: %v", err)
		respondWithError(w, http.StatusInternalServerError, "Failed to create user")
		return
	}

	respondWithJSON(w, http.StatusCreated, map[string]string{"message": "User registered successfully"})
}

// LoginHandler обрабатывает запросы на авторизацию пользователей
func LoginHandler(w http.ResponseWriter, r *http.Request) {
	var req models.LoginRequest
	decoder := json.NewDecoder(r.Body)
	if err := decoder.Decode(&req); err != nil {
		respondWithError(w, http.StatusBadRequest, "Invalid request payload")
		return
	}
	defer r.Body.Close()

	if req.Username == "" || req.Password == "" {
		respondWithError(w, http.StatusBadRequest, "Username and password are required")
		return
	}

	db := db.GetDB()
	user := &models.User{}
	err := db.QueryRow("SELECT id, username, password_hash, role, first_name, last_name, email, city FROM users WHERE username = ?", req.Username).
		Scan(&user.ID, &user.Username, &user.PasswordHash, &user.Role, &user.FirstName, &user.LastName, &user.Email, &user.City)

	if err == sql.ErrNoRows {
		respondWithError(w, http.StatusUnauthorized, "Invalid username or password")
		return
	}
	if err != nil {
		log.Printf("Error fetching user for login: %v", err)
		respondWithError(w, http.StatusInternalServerError, "Database error during login")
		return
	}

	if !utils.CheckPasswordHash(req.Password, user.PasswordHash) {
		respondWithError(w, http.StatusUnauthorized, "Invalid username or password")
		return
	}

	token, err := auth.GenerateJWT(user)
	if err != nil {
		log.Printf("Error generating JWT: %v", err)
		respondWithError(w, http.StatusInternalServerError, "Failed to generate token")
		return
	}

	respondWithJSON(w, http.StatusOK, map[string]string{"token": token})
}

// GetProfileHandler возвращает информацию о текущем аутентифицированном пользователе
func GetProfileHandler(w http.ResponseWriter, r *http.Request) {
	userClaims, ok := auth.GetUserFromContext(r.Context())
	if !ok || userClaims == nil {
		respondWithError(w, http.StatusInternalServerError, "Could not get user info from context")
		return
	}

	db := db.GetDB()
	user := &models.User{}
	err := db.QueryRow("SELECT id, first_name, last_name, username, email, city, role FROM users WHERE id = ?", userClaims.UserID).
		Scan(&user.ID, &user.FirstName, &user.LastName, &user.Username, &user.Email, &user.City, &user.Role)

	if err == sql.ErrNoRows {
		log.Printf("User ID from token %d not found in database!", userClaims.UserID)
		respondWithError(w, http.StatusNotFound, "User not found")
		return
	}
	if err != nil {
		log.Printf("Error fetching user profile: %v", err)
		respondWithError(w, http.StatusInternalServerError, "Database error fetching profile")
		return
	}

	respondWithJSON(w, http.StatusOK, user)
}

// UpdateProfileHandler обновляет информацию о профиле текущего аутентифицированного пользователя
func UpdateProfileHandler(w http.ResponseWriter, r *http.Request) {
	userClaims, ok := auth.GetUserFromContext(r.Context())
	if !ok || userClaims == nil {
		respondWithError(w, http.StatusInternalServerError, "Could not get user info from context")
		return
	}
	userID := userClaims.UserID

	var updatedUser models.User
	decoder := json.NewDecoder(r.Body)
	if err := decoder.Decode(&updatedUser); err != nil {
		respondWithError(w, http.StatusBadRequest, "Invalid request payload")
		return
	}
	defer r.Body.Close()

	db := db.GetDB()

	result, err := db.Exec("UPDATE users SET first_name = ?, last_name = ?, city = ? WHERE id = ?",
		updatedUser.FirstName, updatedUser.LastName, updatedUser.City, userID)
	if err != nil {
		log.Printf("Error updating user profile: %v", err)
		respondWithError(w, http.StatusInternalServerError, "Failed to update profile")
		return
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		log.Printf("Error getting rows affected after update: %v", err)
	}

	if rowsAffected == 0 {
		// respondWithJSON(w, http.StatusOK, map[string]string{"message": "Profile updated (or no changes made)"}) // Может быть полезно для отладки
		respondWithJSON(w, http.StatusOK, map[string]string{"message": "Profile updated successfully"}) // Считаем, что запрос без ошибок - успех
	} else {
		respondWithJSON(w, http.StatusOK, map[string]string{"message": "Profile updated successfully"})
	}
}

// --- Обработчики пластинок (публичный доступ) ---

// GetRecordsHandler обрабатывает запросы на получение списка всех пластинок
func GetRecordsHandler(w http.ResponseWriter, r *http.Request) {
	db := db.GetDB()

	// 1. Получаем все пластинки
	rows, err := db.Query("SELECT id, title, label, wholesale_address, wholesale_price, retail_price, release_date, sold_last_year, sold_current_year, stock FROM records")
	if err != nil {
		log.Printf("Error querying records: %v", err)
		respondWithError(w, http.StatusInternalServerError, "Database error fetching records")
		return
	}
	defer rows.Close()

	records := []models.Record{}
	recordIDs := []int{}

	for rows.Next() {
		var rec models.Record
		err := rows.Scan(
			&rec.ID,
			&rec.Title,
			&rec.Label,
			&rec.WholesaleAddress,
			&rec.WholesalePrice,
			&rec.RetailPrice,
			&rec.ReleaseDate,
			&rec.SoldLastYear,
			&rec.SoldCurrentYear,
			&rec.Stock,
		)
		if err != nil {
			log.Printf("Error scanning record row: %v", err)
			continue
		}
		records = append(records, rec)
		recordIDs = append(recordIDs, rec.ID)
	}
	if err = rows.Err(); err != nil {
		log.Printf("Error after iterating records rows: %v", err)
		respondWithError(w, http.StatusInternalServerError, "Database error processing records")
		return
	}

	if len(records) == 0 {
		respondWithJSON(w, http.StatusOK, records)
		return
	}

	// 2. Получаем все связи record_tracks для полученных пластинок
	query := "SELECT record_id, track_id FROM record_tracks WHERE record_id IN (?" + strings.Repeat(",?", len(recordIDs)-1) + ")"
	args := make([]interface{}, len(recordIDs))
	for i, id := range recordIDs {
		args[i] = id
	}

	trackLinkRows, err := db.Query(query, args...)
	if err != nil {
		log.Printf("Error querying record_tracks: %v", err)
		respondWithError(w, http.StatusInternalServerError, "Database error fetching record tracks links")
		return
	}
	defer trackLinkRows.Close()

	recordTrackLinks := make(map[int][]int) // map: recordID -> []trackID
	trackIDs := []int{}
	trackIDSet := make(map[int]bool)

	for trackLinkRows.Next() {
		var recordID, trackID int
		if err := trackLinkRows.Scan(&recordID, &trackID); err != nil {
			log.Printf("Error scanning record_tracks row: %v", err)
			continue
		}
		recordTrackLinks[recordID] = append(recordTrackLinks[recordID], trackID)
		if _, exists := trackIDSet[trackID]; !exists {
			trackIDs = append(trackIDs, trackID)
			trackIDSet[trackID] = true
		}
	}
	if err = trackLinkRows.Err(); err != nil {
		log.Printf("Error after iterating record_tracks rows: %v", err)
		respondWithError(w, http.StatusInternalServerError, "Database error processing record tracks links")
		return
	}

	if len(trackIDs) == 0 {
		for i := range records {
			records[i].Tracks = []models.Track{}
		}
		respondWithJSON(w, http.StatusOK, records)
		return
	}

	// 3. Получаем все треки, связанные с пластинками
	query = `
        SELECT
            t.id, t.name, t.duration, t.musician_id, t.ensemble_id,
            m.first_name, m.last_name, e.name
        FROM tracks t
        LEFT JOIN musicians m ON t.musician_id = m.id
        LEFT JOIN ensembles e ON t.ensemble_id = e.id
        WHERE t.id IN (?" + strings.Repeat(",?", len(trackIDs)-1) + ")`

	args = make([]interface{}, len(trackIDs))
	for i, id := range trackIDs {
		args[i] = id
	}

	trackRows, err := db.Query(query, args...)
	if err != nil {
		log.Printf("Error querying tracks: %v", err)
		respondWithError(w, http.StatusInternalServerError, "Database error fetching tracks")
		return
	}
	defer trackRows.Close()

	tracksMap := make(map[int]models.Track)
	for trackRows.Next() {
		var t models.Track
		var musicianFirstName, musicianLastName, ensembleName sql.NullString
		var musicianID, ensembleID sql.NullInt64

		err := trackRows.Scan(
			&t.ID,
			&t.Name,
			&t.Duration,
			&musicianID,
			&ensembleID,
			&musicianFirstName,
			&musicianLastName,
			&ensembleName,
		)
		if err != nil {
			log.Printf("Error scanning track row: %v", err)
			continue
		}

		if musicianID.Valid {
			id := int(musicianID.Int64)
			t.MusicianID = &id
			if musicianFirstName.Valid || musicianLastName.Valid {
				t.MusicianName = strings.TrimSpace(musicianFirstName.String + " " + musicianLastName.String)
			} else {
				t.MusicianName = "Unknown Musician" // Fallback
			}
		}
		if ensembleID.Valid {
			id := int(ensembleID.Int64)
			t.EnsembleID = &id
			if ensembleName.Valid {
				t.EnsembleName = ensembleName.String
			} else {
				t.EnsembleName = "Unknown Ensemble" // Fallback
			}
		}

		tracksMap[t.ID] = t
	}
	if err = trackRows.Err(); err != nil {
		log.Printf("Error after iterating tracks rows: %v", err)
		respondWithError(w, http.StatusInternalServerError, "Database error processing tracks")
		return
	}

	// 4. Собираем пластинки с их треками
	for i := range records {
		records[i].Tracks = []models.Track{}
		linkedTrackIDs, ok := recordTrackLinks[records[i].ID]
		if !ok {
			continue
		}
		for _, trackID := range linkedTrackIDs {
			if track, exists := tracksMap[trackID]; exists {
				records[i].Tracks = append(records[i].Tracks, track)
			} else {
				log.Printf("Warning: Linked track ID %d for record %d not found in fetched tracks map", trackID, records[i].ID)
			}
		}
	}

	// 5. Возвращаем результат
	respondWithJSON(w, http.StatusOK, records)
}

// --- Обработчики корзины (требуют аутентификации) ---

// AddToCartHandler добавляет пластинку в корзину пользователя или увеличивает ее количество
func AddToCartHandler(w http.ResponseWriter, r *http.Request) {
	userClaims, ok := auth.GetUserFromContext(r.Context())
	if !ok || userClaims == nil {
		respondWithError(w, http.StatusInternalServerError, "Could not get user info from context")
		return
	}
	userID := userClaims.UserID

	var req struct {
		RecordID int `json:"recordId"`
		Quantity int `json:"quantity"`
	}
	decoder := json.NewDecoder(r.Body)
	if err := decoder.Decode(&req); err != nil {
		respondWithError(w, http.StatusBadRequest, "Invalid request payload")
		return
	}
	defer r.Body.Close()

	if req.RecordID <= 0 || req.Quantity <= 0 {
		respondWithError(w, http.StatusBadRequest, "Valid record ID and quantity (>= 1) are required")
		return
	}

	db := db.GetDB()

	// Проверяем, существует ли пластинка (опционально: проверка запаса)
	var recordExists bool
	err := db.QueryRow("SELECT EXISTS(SELECT 1 FROM records WHERE id = ?)", req.RecordID).Scan(&recordExists)
	if err != nil {
		log.Printf("Database error checking record existence: %v", err)
		respondWithError(w, http.StatusInternalServerError, "Database error")
		return
	}
	if !recordExists {
		respondWithError(w, http.StatusNotFound, "Record not found")
		return
	}

	query := `INSERT INTO cart_items (user_id, record_id, quantity)
              VALUES (?, ?, ?)
              ON CONFLICT (user_id, record_id) DO UPDATE SET quantity = quantity + excluded.quantity`

	_, err = db.Exec(query, userID, req.RecordID, req.Quantity)
	if err != nil {
		log.Printf("Database error adding/updating cart item: %v", err)
		respondWithError(w, http.StatusInternalServerError, "Failed to add item to cart")
		return
	}

	respondWithJSON(w, http.StatusOK, map[string]string{"message": "Item added to cart"})
}

// GetCartHandler возвращает содержимое корзины текущего пользователя
func GetCartHandler(w http.ResponseWriter, r *http.Request) {
	userClaims, ok := auth.GetUserFromContext(r.Context())
	if !ok || userClaims == nil {
		respondWithError(w, http.StatusInternalServerError, "Could not get user info from context")
		return
	}
	userID := userClaims.UserID

	db := db.GetDB()

	// 1. Получаем все позиции корзины для пользователя
	cartItemRows, err := db.Query("SELECT user_id, record_id, quantity FROM cart_items WHERE user_id = ?", userID)
	if err != nil {
		log.Printf("Database error fetching cart items: %v", err)
		respondWithError(w, http.StatusInternalServerError, "Database error fetching cart")
		return
	}
	defer cartItemRows.Close()

	cartItems := []models.CartItem{}
	recordIDs := []int{}
	recordIDSet := make(map[int]bool)

	for cartItemRows.Next() {
		var item models.CartItem
		if err := cartItemRows.Scan(&item.UserID, &item.RecordID, &item.Quantity); err != nil {
			log.Printf("Error scanning cart item row: %v", err)
			continue
		}
		cartItems = append(cartItems, item)
		if _, exists := recordIDSet[item.RecordID]; !exists {
			recordIDs = append(recordIDs, item.RecordID)
			recordIDSet[item.RecordID] = true
		}
	}
	if err = cartItemRows.Err(); err != nil {
		log.Printf("Error after iterating cart item rows: %v", err)
		respondWithError(w, http.StatusInternalServerError, "Database error processing cart items")
		return
	}

	if len(cartItems) == 0 {
		respondWithJSON(w, http.StatusOK, cartItems)
		return
	}

	// 2. Получаем детали пластинок, которые находятся в корзине
	query := "SELECT id, title, label, wholesale_address, wholesale_price, retail_price, release_date, sold_last_year, sold_current_year, stock FROM records WHERE id IN (?" + strings.Repeat(",?", len(recordIDs)-1) + ")"
	args := make([]interface{}, len(recordIDs))
	for i, id := range recordIDs {
		args[i] = id
	}

	recordRows, err := db.Query(query, args...)
	if err != nil {
		log.Printf("Error querying records for cart: %v", err)
		respondWithError(w, http.StatusInternalServerError, "Database error fetching records for cart")
		return
	}
	defer recordRows.Close()

	recordsMap := make(map[int]models.Record)
	fetchedRecordIDs := []int{}
	fetchedRecordIDSet := make(map[int]bool)

	for recordRows.Next() {
		var rec models.Record
		err := recordRows.Scan(
			&rec.ID, &rec.Title, &rec.Label, &rec.WholesaleAddress, &rec.WholesalePrice,
			&rec.RetailPrice, &rec.ReleaseDate, &rec.SoldLastYear, &rec.SoldCurrentYear, &rec.Stock,
		)
		if err != nil {
			log.Printf("Error scanning record row for cart: %v", err)
			continue
		}
		recordsMap[rec.ID] = rec
		if _, exists := fetchedRecordIDSet[rec.ID]; !exists {
			fetchedRecordIDs = append(fetchedRecordIDs, rec.ID)
			fetchedRecordIDSet[rec.ID] = true
		}
	}
	if err = recordRows.Err(); err != nil {
		log.Printf("Error after iterating record rows for cart: %v", err)
		respondWithError(w, http.StatusInternalServerError, "Database error processing records for cart")
		return
	}

	if len(fetchedRecordIDs) == 0 {
		respondWithJSON(w, http.StatusOK, cartItems)
		return
	}

	// 3. Получаем связи record_tracks для пластинок в корзине
	query = "SELECT record_id, track_id FROM record_tracks WHERE record_id IN (?" + strings.Repeat(",?", len(fetchedRecordIDs)-1) + ")"
	args = make([]interface{}, len(fetchedRecordIDs))
	for i, id := range fetchedRecordIDs {
		args[i] = id
	}

	cartRecordTrackLinkRows, err := db.Query(query, args...)
	if err != nil {
		log.Printf("Error querying record_tracks for cart: %v", err)
		respondWithError(w, http.StatusInternalServerError, "Database error fetching record tracks links for cart")
		return
	}
	defer cartRecordTrackLinkRows.Close()

	cartRecordTrackLinks := make(map[int][]int) // map: recordID -> []trackID
	cartTrackIDs := []int{}
	cartTrackIDSet := make(map[int]bool)

	for cartRecordTrackLinkRows.Next() {
		var recordID, trackID int
		if err := cartRecordTrackLinkRows.Scan(&recordID, &trackID); err != nil {
			log.Printf("Error scanning record_tracks row for cart: %v", err)
			continue
		}
		cartRecordTrackLinks[recordID] = append(cartRecordTrackLinks[recordID], trackID)
		if _, exists := cartTrackIDSet[trackID]; !exists {
			cartTrackIDs = append(cartTrackIDs, trackID)
			cartTrackIDSet[trackID] = true
		}
	}
	if err = cartRecordTrackLinkRows.Err(); err != nil {
		log.Printf("Error after iterating record_tracks rows for cart: %v", err)
		respondWithError(w, http.StatusInternalServerError, "Database error processing record tracks links for cart")
		return
	}

	// 4. Получаем треки, связанные с пластинками в корзине
	cartTracksMap := make(map[int]models.Track)
	if len(cartTrackIDs) > 0 {
		query = `
            SELECT
                t.id, t.name, t.duration, t.musician_id, t.ensemble_id,
                m.first_name, m.last_name, e.name
            FROM tracks t
            LEFT JOIN musicians m ON t.musician_id = m.id
            LEFT JOIN ensembles e ON t.ensemble_id = e.id
            WHERE t.id IN (?" + strings.Repeat(",?", len(cartTrackIDs)-1) + ")`

		args = make([]interface{}, len(cartTrackIDs))
		for i, id := range cartTrackIDs {
			args[i] = id
		}

		cartTrackRows, err := db.Query(query, args...)
		if err != nil {
			log.Printf("Error querying tracks for cart: %v", err)
			respondWithError(w, http.StatusInternalServerError, "Database error fetching tracks for cart")
			return
		}
		defer cartTrackRows.Close()

		for cartTrackRows.Next() {
			var t models.Track
			var musicianFirstName, musicianLastName, ensembleName sql.NullString
			var musicianID, ensembleID sql.NullInt64

			err := cartTrackRows.Scan(
				&t.ID, &t.Name, &t.Duration, &musicianID, &ensembleID,
				&musicianFirstName, &musicianLastName, &ensembleName,
			)
			if err != nil {
				log.Printf("Error scanning track row for cart: %v", err)
				continue
			}

			if musicianID.Valid {
				id := int(musicianID.Int64)
				t.MusicianID = &id
				if musicianFirstName.Valid || musicianLastName.Valid {
					t.MusicianName = strings.TrimSpace(musicianFirstName.String + " " + musicianLastName.String)
				} else {
					t.MusicianName = "Unknown Musician"
				}
			}
			if ensembleID.Valid {
				id := int(ensembleID.Int64)
				t.EnsembleID = &id
				if ensembleName.Valid {
					t.EnsembleName = ensembleName.String
				} else {
					t.EnsembleName = "Unknown Ensemble"
				}
			}
			cartTracksMap[t.ID] = t
		}
		if err = cartTrackRows.Err(); err != nil {
			log.Printf("Error after iterating tracks rows for cart: %v", err)
			respondWithError(w, http.StatusInternalServerError, "Database error processing tracks for cart")
			return
		}
	}

	// 5. Собираем позиции корзины, добавляя к ним детали пластинок и их треки
	for i := range cartItems {
		record, exists := recordsMap[cartItems[i].RecordID]
		if !exists {
			cartItems[i].Record = nil
			log.Printf("Warning: Record ID %d for cart item not found in fetched records map", cartItems[i].RecordID)
			continue
		}
		cartItems[i].Record = &record // Присваиваем указатель на копию структуры

		cartItems[i].Record.Tracks = []models.Track{}
		linkedTrackIDs, ok := cartRecordTrackLinks[cartItems[i].Record.ID]
		if !ok {
			continue
		}
		for _, trackID := range linkedTrackIDs {
			if track, exists := cartTracksMap[trackID]; exists {
				cartItems[i].Record.Tracks = append(cartItems[i].Record.Tracks, track)
			} else {
				log.Printf("Warning: Linked track ID %d for record %d not found in fetched cart tracks map", trackID, cartItems[i].Record.ID)
			}
		}
	}

	respondWithJSON(w, http.StatusOK, cartItems)
}

// UpdateCartHandler обновляет количество пластинки в корзине пользователя
func UpdateCartHandler(w http.ResponseWriter, r *http.Request) {
	userClaims, ok := auth.GetUserFromContext(r.Context())
	if !ok || userClaims == nil {
		respondWithError(w, http.StatusInternalServerError, "Could not get user info from context")
		return
	}
	userID := userClaims.UserID

	vars := mux.Vars(r)
	recordIDStr := vars["recordId"]
	recordID, err := strconv.Atoi(recordIDStr)
	if err != nil || recordID <= 0 {
		respondWithError(w, http.StatusBadRequest, "Invalid record ID in URL")
		return
	}

	var req struct {
		Quantity int `json:"quantity"`
	}
	decoder := json.NewDecoder(r.Body)
	if err := decoder.Decode(&req); err != nil {
		respondWithError(w, http.StatusBadRequest, "Invalid request payload")
		return
	}
	defer r.Body.Close()

	if req.Quantity < 0 {
		respondWithError(w, http.StatusBadRequest, "Quantity cannot be negative")
		return
	}

	db := db.GetDB()

	if req.Quantity == 0 {
		result, err := db.Exec("DELETE FROM cart_items WHERE user_id = ? AND record_id = ?", userID, recordID)
		if err != nil {
			log.Printf("Database error deleting cart item: %v", err)
			respondWithError(w, http.StatusInternalServerError, "Failed to remove item from cart")
			return
		}
		rowsAffected, _ := result.RowsAffected()
		if rowsAffected == 0 {
			respondWithError(w, http.StatusNotFound, "Item not found in cart")
			return
		}
		respondWithJSON(w, http.StatusOK, map[string]string{"message": "Item removed from cart"})

	} else {
		// Проверяем, существует ли пластинка и достаточно ли запаса (опционально)
		var stock int
		err := db.QueryRow("SELECT stock FROM records WHERE id = ?", recordID).Scan(&stock)
		if err == sql.ErrNoRows {
			respondWithError(w, http.StatusNotFound, "Record not found")
			return
		}
		if err != nil {
			log.Printf("Database error checking record stock for update: %v", err)
			respondWithError(w, http.StatusInternalServerError, "Database error")
			return
		}
		// TODO: Опционально добавить проверку, что req.Quantity не превышает доступный запас.
		// При UPDATE корзины это сложнее, т.к. нужно учитывать текущее количество + req.Quantity
		// Для простоты пока пропустим проверку запаса при обновлении количества.

		result, err := db.Exec("UPDATE cart_items SET quantity = ? WHERE user_id = ? AND record_id = ?", req.Quantity, userID, recordID)
		if err != nil {
			log.Printf("Database error updating cart item: %v", err)
			respondWithError(w, http.StatusInternalServerError, "Failed to update item quantity in cart")
			return
		}
		rowsAffected, _ := result.RowsAffected()
		if rowsAffected == 0 {
			respondWithError(w, http.StatusNotFound, "Item not found in cart")
			return
		}
		respondWithJSON(w, http.StatusOK, map[string]string{"message": "Cart item quantity updated"})
	}
}

// RemoveFromCartHandler удаляет пластинку из корзины пользователя
func RemoveFromCartHandler(w http.ResponseWriter, r *http.Request) {
	userClaims, ok := auth.GetUserFromContext(r.Context())
	if !ok || userClaims == nil {
		respondWithError(w, http.StatusInternalServerError, "Could not get user info from context")
		return
	}
	userID := userClaims.UserID

	vars := mux.Vars(r)
	recordIDStr := vars["recordId"]
	recordID, err := strconv.Atoi(recordIDStr)
	if err != nil || recordID <= 0 {
		respondWithError(w, http.StatusBadRequest, "Invalid record ID in URL")
		return
	}

	db := db.GetDB()

	result, err := db.Exec("DELETE FROM cart_items WHERE user_id = ? AND record_id = ?", userID, recordID)
	if err != nil {
		log.Printf("Database error deleting cart item: %v", err)
		respondWithError(w, http.StatusInternalServerError, "Failed to remove item from cart")
		return
	}

	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		respondWithError(w, http.StatusNotFound, "Item not found in cart")
		return
	}

	respondWithJSON(w, http.StatusOK, map[string]string{"message": "Item removed from cart"})
}

// --- Обработчики админов (требуют аутентификации и роли admin) ---

// AddMusicianHandler добавляет нового музыканта и его личные треки
func AddMusicianHandler(w http.ResponseWriter, r *http.Request) {
	var req models.AddMusicianRequest
	decoder := json.NewDecoder(r.Body)
	if err := decoder.Decode(&req); err != nil {
		respondWithError(w, http.StatusBadRequest, "Invalid request payload")
		return
	}
	defer r.Body.Close()

	if req.FirstName == "" || req.LastName == "" {
		respondWithError(w, http.StatusBadRequest, "First name and last name are required for a musician")
		return
	}

	db := db.GetDB()
	tx, err := db.Begin() // Начинаем транзакцию
	if err != nil {
		log.Printf("Failed to start transaction: %v", err)
		respondWithError(w, http.StatusInternalServerError, "Database error starting transaction")
		return
	}
	// Если что-то пойдет не так, откатываем транзакцию
	defer func() {
		if r := recover(); r != nil {
			tx.Rollback()
			panic(r) // Ре-паника после отката
		} else if err != nil {
			tx.Rollback() // Откат при возврате с ошибкой
		}
		// В случае успеха Commit будет вызван явно
	}()

	// 1. Вставляем музыканта
	result, err := tx.Exec("INSERT INTO musicians (first_name, last_name, role, ensemble_id) VALUES (?, ?, ?, ?)",
		req.FirstName, req.LastName, req.Role, req.EnsembleID) // req.EnsembleID может быть nil
	if err != nil {
		log.Printf("Database error inserting musician: %v", err)
		err = fmt.Errorf("failed to insert musician: %w", err) // Оборачиваем ошибку для defer
		respondWithError(w, http.StatusInternalServerError, "Failed to add musician")
		return
	}
	musicianID, err := result.LastInsertId()
	if err != nil {
		log.Printf("Failed to get last insert ID for musician: %v", err)
		err = fmt.Errorf("failed to get musician ID: %w", err)
		respondWithError(w, http.StatusInternalServerError, "Failed to add musician")
		return
	}

	// 2. Вставляем личные треки музыканта
	for _, trackReq := range req.Tracks {
		if trackReq.Name == "" || trackReq.Duration <= 0 {
			log.Printf("Skipping track with invalid data for musician %d: Name='%s', Duration=%d", musicianID, trackReq.Name, trackReq.Duration)
			continue // Пропускаем треки с неполными данными
		}
		_, err = tx.Exec("INSERT INTO tracks (name, duration, musician_id, ensemble_id) VALUES (?, ?, ?, NULL)",
			trackReq.Name, trackReq.Duration, musicianID) // Связываем с музыкантом, ensemble_id = NULL
		if err != nil {
			log.Printf("Database error inserting track for musician %d: %v", musicianID, err)
			err = fmt.Errorf("failed to insert track for musician: %w", err)
			respondWithError(w, http.StatusInternalServerError, "Failed to add musician's tracks")
			return
		}
	}

	// 3. Подтверждаем транзакцию
	err = tx.Commit()
	if err != nil {
		log.Printf("Failed to commit transaction for musician: %v", err)
		respondWithError(w, http.StatusInternalServerError, "Database error committing transaction")
		return
	}

	respondWithJSON(w, http.StatusCreated, map[string]interface{}{"message": "Musician added successfully", "id": musicianID})
}

// AddEnsembleHandler добавляет новый ансамбль и его треки
func AddEnsembleHandler(w http.ResponseWriter, r *http.Request) {
	var req models.AddEnsembleRequest
	decoder := json.NewDecoder(r.Body)
	if err := decoder.Decode(&req); err != nil {
		respondWithError(w, http.StatusBadRequest, "Invalid request payload")
		return
	}
	defer r.Body.Close()

	if req.Name == "" {
		respondWithError(w, http.StatusBadRequest, "Name is required for an ensemble")
		return
	}

	db := db.GetDB()
	tx, err := db.Begin() // Начинаем транзакцию
	if err != nil {
		log.Printf("Failed to start transaction: %v", err)
		respondWithError(w, http.StatusInternalServerError, "Database error starting transaction")
		return
	}
	defer func() {
		if r := recover(); r != nil {
			tx.Rollback()
			panic(r)
		} else if err != nil {
			tx.Rollback()
		}
	}()

	// 1. Вставляем ансамбль
	result, err := tx.Exec("INSERT INTO ensembles (name, type) VALUES (?, ?)",
		req.Name, req.Type)
	if err != nil {
		// Проверяем на ошибку уникальности имени
		if strings.Contains(err.Error(), "UNIQUE constraint failed") {
			err = nil // Сбрасываем для defer
			respondWithError(w, http.StatusConflict, "Ensemble name already exists")
			return
		}
		log.Printf("Database error inserting ensemble: %v", err)
		err = fmt.Errorf("failed to insert ensemble: %w", err)
		respondWithError(w, http.StatusInternalServerError, "Failed to add ensemble")
		return
	}
	ensembleID, err := result.LastInsertId()
	if err != nil {
		log.Printf("Failed to get last insert ID for ensemble: %v", err)
		err = fmt.Errorf("failed to get ensemble ID: %w", err)
		respondWithError(w, http.StatusInternalServerError, "Failed to add ensemble")
		return
	}

	// 2. Вставляем треки ансамбля
	for _, trackReq := range req.Tracks {
		if trackReq.Name == "" || trackReq.Duration <= 0 {
			log.Printf("Skipping track with invalid data for ensemble %d: Name='%s', Duration=%d", ensembleID, trackReq.Name, trackReq.Duration)
			continue // Пропускаем треки с неполными данными
		}
		_, err = tx.Exec("INSERT INTO tracks (name, duration, musician_id, ensemble_id) VALUES (?, ?, NULL, ?)",
			trackReq.Name, trackReq.Duration, ensembleID) // Связываем с ансамблем, musician_id = NULL
		if err != nil {
			log.Printf("Database error inserting track for ensemble %d: %v", ensembleID, err)
			err = fmt.Errorf("failed to insert track for ensemble: %w", err)
			respondWithError(w, http.StatusInternalServerError, "Failed to add ensemble's tracks")
			return
		}
	}

	// 3. Подтверждаем транзакцию
	err = tx.Commit()
	if err != nil {
		log.Printf("Failed to commit transaction for ensemble: %v", err)
		respondWithError(w, http.StatusInternalServerError, "Database error committing transaction")
		return
	}

	respondWithJSON(w, http.StatusCreated, map[string]interface{}{"message": "Ensemble added successfully", "id": ensembleID})
}

// GetEnsemblesHandler возвращает список всех ансамблей
func GetEnsemblesHandler(w http.ResponseWriter, r *http.Request) {
	db := db.GetDB()

	rows, err := db.Query("SELECT id, name, type FROM ensembles")
	if err != nil {
		log.Printf("Database error fetching ensembles: %v", err)
		respondWithError(w, http.StatusInternalServerError, "Database error fetching ensembles")
		return
	}
	defer rows.Close()

	ensembles := []models.Ensemble{}
	for rows.Next() {
		var e models.Ensemble
		if err := rows.Scan(&e.ID, &e.Name, &e.Type); err != nil {
			log.Printf("Error scanning ensemble row: %v", err)
			continue
		}
		ensembles = append(ensembles, e)
	}
	if err = rows.Err(); err != nil {
		log.Printf("Error after iterating ensemble rows: %v", err)
		respondWithError(w, http.StatusInternalServerError, "Database error processing ensembles")
		return
	}

	respondWithJSON(w, http.StatusOK, ensembles)
}

// GetAllTracksHandler возвращает список всех треков с информацией о музыканте/ансамбле
func GetAllTracksHandler(w http.ResponseWriter, r *http.Request) {
	db := db.GetDB()

	// Выбираем все треки, джойним с музыкантами и ансамблями для получения имен
	query := `
        SELECT
            t.id, t.name, t.duration, t.musician_id, t.ensemble_id,
            m.first_name, m.last_name, e.name
        FROM tracks t
        LEFT JOIN musicians m ON t.musician_id = m.id
        LEFT JOIN ensembles e ON t.ensemble_id = e.id`

	rows, err := db.Query(query)
	if err != nil {
		log.Printf("Database error fetching tracks: %v", err)
		respondWithError(w, http.StatusInternalServerError, "Database error fetching tracks")
		return
	}
	defer rows.Close()

	tracks := []models.Track{}
	for rows.Next() {
		var t models.Track
		var musicianFirstName, musicianLastName, ensembleName sql.NullString
		var musicianID, ensembleID sql.NullInt64

		err := rows.Scan(
			&t.ID, &t.Name, &t.Duration, &musicianID, &ensembleID,
			&musicianFirstName, &musicianLastName, &ensembleName,
		)
		if err != nil {
			log.Printf("Error scanning track row: %v", err)
			continue
		}

		if musicianID.Valid {
			id := int(musicianID.Int64)
			t.MusicianID = &id
			if musicianFirstName.Valid || musicianLastName.Valid {
				t.MusicianName = strings.TrimSpace(musicianFirstName.String + " " + musicianLastName.String)
			} else {
				t.MusicianName = "Unknown Musician"
			}
		}
		if ensembleID.Valid {
			id := int(ensembleID.Int64)
			t.EnsembleID = &id
			if ensembleName.Valid {
				t.EnsembleName = ensembleName.String
			} else {
				t.EnsembleName = "Unknown Ensemble"
			}
		}
		tracks = append(tracks, t)
	}
	if err = rows.Err(); err != nil {
		log.Printf("Error after iterating track rows: %v", err)
		respondWithError(w, http.StatusInternalServerError, "Database error processing tracks")
		return
	}

	respondWithJSON(w, http.StatusOK, tracks)
}

// AddRecordHandler добавляет новую пластинку и связывает ее с треками
func AddRecordHandler(w http.ResponseWriter, r *http.Request) {
	var req models.AddRecordRequest
	decoder := json.NewDecoder(r.Body)
	if err := decoder.Decode(&req); err != nil {
		respondWithError(w, http.StatusBadRequest, "Invalid request payload")
		return
	}
	defer r.Body.Close()

	if req.Title == "" {
		respondWithError(w, http.StatusBadRequest, "Title is required for a record")
		return
	}
	if req.Stock < 0 {
		respondWithError(w, http.StatusBadRequest, "Stock cannot be negative")
		return
	}

	db := db.GetDB()
	tx, err := db.Begin() // Начинаем транзакцию
	if err != nil {
		log.Printf("Failed to start transaction: %v", err)
		respondWithError(w, http.StatusInternalServerError, "Database error starting transaction")
		return
	}
	defer func() {
		if r := recover(); r != nil {
			tx.Rollback()
			panic(r)
		} else if err != nil {
			tx.Rollback()
		}
	}()

	// 1. Вставляем пластинку
	result, err := tx.Exec("INSERT INTO records (title, label, wholesale_address, wholesale_price, retail_price, release_date, stock, sold_last_year, sold_current_year) VALUES (?, ?, ?, ?, ?, ?, ?, 0, 0)",
		req.Title, req.Label, req.WholesaleAddress, req.WholesalePrice, req.RetailPrice, req.ReleaseDate, req.Stock)
	if err != nil {
		log.Printf("Database error inserting record: %v", err)
		err = fmt.Errorf("failed to insert record: %w", err)
		respondWithError(w, http.StatusInternalServerError, "Failed to add record")
		return
	}
	recordID, err := result.LastInsertId()
	if err != nil {
		log.Printf("Failed to get last insert ID for record: %v", err)
		err = fmt.Errorf("failed to get record ID: %w", err)
		respondWithError(w, http.StatusInternalServerError, "Failed to add record")
		return
	}

	// 2. Связываем пластинку с треками в record_tracks
	if len(req.TrackIDs) > 0 {
		// Опционально: проверить, существуют ли все TrackIDs
		// Для простоты пока пропускаем эту проверку

		stmt, err := tx.Prepare("INSERT INTO record_tracks (record_id, track_id) VALUES (?, ?)")
		if err != nil {
			log.Printf("Failed to prepare statement for record_tracks: %v", err)
			err = fmt.Errorf("failed to prepare record track statement: %w", err)
			respondWithError(w, http.StatusInternalServerError, "Failed to add record tracks")
			return
		}
		defer stmt.Close() // Закрываем подготовленный запрос после использования

		for _, trackID := range req.TrackIDs {
			// Проверяем, что трек с таким ID существует (опционально)
			var trackExists bool
			checkErr := db.QueryRow("SELECT EXISTS(SELECT 1 FROM tracks WHERE id = ?)", trackID).Scan(&trackExists)
			if checkErr != nil || !trackExists {
				log.Printf("Warning: Track ID %d not found for record %d. Skipping link.", trackID, recordID)
				continue // Пропускаем трек, если он не существует
			}

			_, err = stmt.Exec(recordID, trackID)
			if err != nil {
				// Проверяем, не дубликат ли это (если вдруг в запросе есть одинаковые trackID)
				if strings.Contains(err.Error(), "UNIQUE constraint failed") {
					log.Printf("Warning: Duplicate track ID %d provided for record %d. Skipping.", trackID, recordID)
					continue // Игнорируем дубликаты
				}
				log.Printf("Database error inserting record_track link for record %d, track %d: %v", recordID, trackID, err)
				err = fmt.Errorf("failed to insert record track link: %w", err)
				respondWithError(w, http.StatusInternalServerError, "Failed to link record tracks")
				return
			}
		}
	}

	// 3. Подтверждаем транзакцию
	err = tx.Commit()
	if err != nil {
		log.Printf("Failed to commit transaction for record: %v", err)
		respondWithError(w, http.StatusInternalServerError, "Database error committing transaction")
		return
	}

	respondWithJSON(w, http.StatusCreated, map[string]interface{}{"message": "Record added successfully", "id": recordID})
}

// UpdateRecordHandler обновляет данные пластинки (без изменения связей с треками)
func UpdateRecordHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	recordIDStr := vars["id"]
	recordID, err := strconv.Atoi(recordIDStr)
	if err != nil || recordID <= 0 {
		respondWithError(w, http.StatusBadRequest, "Invalid record ID in URL")
		return
	}

	var req models.AddRecordRequest // Переиспользуем структуру запроса для добавления, т.к. поля похожи
	decoder := json.NewDecoder(r.Body)
	if err := decoder.Decode(&req); err != nil {
		respondWithError(w, http.StatusBadRequest, "Invalid request payload")
		return
	}
	defer r.Body.Close()

	if req.Title == "" {
		respondWithError(w, http.StatusBadRequest, "Title cannot be empty")
		return
	}
	if req.Stock < 0 {
		respondWithError(w, http.StatusBadRequest, "Stock cannot be negative")
		return
	}

	db := db.GetDB()

	// Обновляем поля пластинки. Связи с треками через этот эндпоинт не меняются.
	result, err := db.Exec(`UPDATE records SET
        title = ?, label = ?, wholesale_address = ?, wholesale_price = ?,
        retail_price = ?, release_date = ?, stock = ?
        WHERE id = ?`,
		req.Title, req.Label, req.WholesaleAddress, req.WholesalePrice,
		req.RetailPrice, req.ReleaseDate, req.Stock, recordID)

	if err != nil {
		log.Printf("Database error updating record %d: %v", recordID, err)
		respondWithError(w, http.StatusInternalServerError, "Failed to update record")
		return
	}

	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		// Пластинка с таким ID не найдена
		respondWithError(w, http.StatusNotFound, "Record not found")
		return
	}

	respondWithJSON(w, http.StatusOK, map[string]string{"message": "Record updated successfully"})
}

// DeleteRecordHandler удаляет пластинку (каскадное удаление в record_tracks и cart_items благодаря ON DELETE CASCADE)
func DeleteRecordHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	recordIDStr := vars["id"]
	recordID, err := strconv.Atoi(recordIDStr)
	if err != nil || recordID <= 0 {
		respondWithError(w, http.StatusBadRequest, "Invalid record ID in URL")
		return
	}

	db := db.GetDB()

	// Удаляем пластинку. Связанные записи в record_tracks и cart_items удалятся автоматически.
	result, err := db.Exec("DELETE FROM records WHERE id = ?", recordID)
	if err != nil {
		log.Printf("Database error deleting record %d: %v", recordID, err)
		respondWithError(w, http.StatusInternalServerError, "Failed to delete record")
		return
	}

	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		// Пластинка с таким ID не найдена
		respondWithError(w, http.StatusNotFound, "Record not found")
		return
	}

	respondWithJSON(w, http.StatusOK, map[string]string{"message": "Record deleted successfully"})
}

// --- Обработчики отчетов (требуют роли admin) ---

// GetEnsembleTrackCountHandler возвращает количество треков для заданного ансамбля
func GetEnsembleTrackCountHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	ensembleIDStr := vars["ensembleId"]
	ensembleID, err := strconv.Atoi(ensembleIDStr)
	if err != nil || ensembleID <= 0 {
		respondWithError(w, http.StatusBadRequest, "Invalid ensemble ID in URL")
		return
	}

	db := db.GetDB()

	// Проверяем, существует ли ансамбль
	var ensembleExists bool
	err = db.QueryRow("SELECT EXISTS(SELECT 1 FROM ensembles WHERE id = ?)", ensembleID).Scan(&ensembleExists)
	if err != nil {
		log.Printf("Database error checking ensemble existence for track count: %v", err)
		respondWithError(w, http.StatusInternalServerError, "Database error")
		return
	}
	if !ensembleExists {
		respondWithError(w, http.StatusNotFound, "Ensemble not found")
		return
	}

	// Считаем количество треков, связанных с этим ансамблем
	var trackCount int
	err = db.QueryRow("SELECT COUNT(*) FROM tracks WHERE ensemble_id = ?", ensembleID).Scan(&trackCount)
	if err != nil {
		log.Printf("Database error counting tracks for ensemble %d: %v", ensembleID, err)
		respondWithError(w, http.StatusInternalServerError, "Database error fetching track count")
		return
	}

	respondWithJSON(w, http.StatusOK, map[string]interface{}{"ensembleId": ensembleID, "trackCount": trackCount})
}

// GetRecordsByEnsembleHandler возвращает список пластинок, содержащих треки заданного ансамбля
func GetRecordsByEnsembleHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	ensembleIDStr := vars["ensembleId"]
	ensembleID, err := strconv.Atoi(ensembleIDStr)
	if err != nil || ensembleID <= 0 {
		respondWithError(w, http.StatusBadRequest, "Invalid ensemble ID in URL")
		return
	}

	db := db.GetDB()

	// Проверяем, существует ли ансамбль
	var ensembleExists bool
	err = db.QueryRow("SELECT EXISTS(SELECT 1 FROM ensembles WHERE id = ?)", ensembleID).Scan(&ensembleExists)
	if err != nil {
		log.Printf("Database error checking ensemble existence for records: %v", err)
		respondWithError(w, http.StatusInternalServerError, "Database error")
		return
	}
	if !ensembleExists {
		respondWithError(w, http.StatusNotFound, "Ensemble not found")
		return
	}

	// 1. Находим все треки, принадлежащие этому ансамблю
	trackIDsForEnsemble := []int{}
	rows, err := db.Query("SELECT id FROM tracks WHERE ensemble_id = ?", ensembleID)
	if err != nil {
		log.Printf("Database error fetching track IDs for ensemble %d: %v", ensembleID, err)
		respondWithError(w, http.StatusInternalServerError, "Database error fetching ensemble tracks")
		return
	}
	defer rows.Close()

	for rows.Next() {
		var trackID int
		if err := rows.Scan(&trackID); err != nil {
			log.Printf("Error scanning track ID for ensemble: %v", err)
			continue
		}
		trackIDsForEnsemble = append(trackIDsForEnsemble, trackID)
	}
	if err = rows.Err(); err != nil {
		log.Printf("Error after iterating track ID rows for ensemble: %v", err)
		respondWithError(w, http.StatusInternalServerError, "Database error processing ensemble track IDs")
		return
	}

	if len(trackIDsForEnsemble) == 0 {
		// У ансамбля нет треков, значит, нет и пластинок с его треками
		respondWithJSON(w, http.StatusOK, []models.Record{})
		return
	}

	// 2. Находим все уникальные record_id из record_tracks, которые ссылаются на треки этого ансамбля
	recordIDsWithEnsembleTracks := []int{}
	recordIDSet := make(map[int]bool)

	query := "SELECT DISTINCT record_id FROM record_tracks WHERE track_id IN (?" + strings.Repeat(",?", len(trackIDsForEnsemble)-1) + ")"
	args := make([]interface{}, len(trackIDsForEnsemble))
	for i, id := range trackIDsForEnsemble {
		args[i] = id
	}

	recordIDRows, err := db.Query(query, args...)
	if err != nil {
		log.Printf("Database error fetching record IDs from record_tracks: %v", err)
		respondWithError(w, http.StatusInternalServerError, "Database error fetching record IDs")
		return
	}
	defer recordIDRows.Close()

	for recordIDRows.Next() {
		var recordID int
		if err := recordIDRows.Scan(&recordID); err != nil {
			log.Printf("Error scanning record ID from record_tracks: %v", err)
			continue
		}
		if _, exists := recordIDSet[recordID]; !exists {
			recordIDsWithEnsembleTracks = append(recordIDsWithEnsembleTracks, recordID)
			recordIDSet[recordID] = true
		}
	}
	if err = recordIDRows.Err(); err != nil {
		log.Printf("Error after iterating record ID rows from record_tracks: %v", err)
		respondWithError(w, http.StatusInternalServerError, "Database error processing record IDs")
		return
	}

	if len(recordIDsWithEnsembleTracks) == 0 {
		// Нет пластинок, содержащих треки этого ансамбля
		respondWithJSON(w, http.StatusOK, []models.Record{})
		return
	}

	// 3. Получаем полные детали этих пластинок (и их треков, как в GetRecordsHandler)
	// Переиспользуем логику из GetRecordsHandler, но для конкретного списка ID
	// Это потребует некоторого рефакторинга, чтобы вынести общую часть в функцию.
	// Для простоты пока напишем inline или скопируем логику. Скопируем логику выборки пластинок по ID.

	query = "SELECT id, title, label, wholesale_address, wholesale_price, retail_price, release_date, sold_last_year, sold_current_year, stock FROM records WHERE id IN (?" + strings.Repeat(",?", len(recordIDsWithEnsembleTracks)-1) + ")"
	args = make([]interface{}, len(recordIDsWithEnsembleTracks))
	for i, id := range recordIDsWithEnsembleTracks {
		args[i] = id
	}

	recordRows, err := db.Query(query, args...)
	if err != nil {
		log.Printf("Error querying records for ensemble report: %v", err)
		respondWithError(w, http.StatusInternalServerError, "Database error fetching records for report")
		return
	}
	defer recordRows.Close()

	records := []models.Record{}
	// recordIDs (собираем снова, т.к. recordIDsWithEnsembleTracks может быть неполным, если какие-то пластинки не нашлись)
	actualFetchedRecordIDs := []int{}

	for recordRows.Next() {
		var rec models.Record
		err := recordRows.Scan(
			&rec.ID, &rec.Title, &rec.Label, &rec.WholesaleAddress, &rec.WholesalePrice,
			&rec.RetailPrice, &rec.ReleaseDate, &rec.SoldLastYear, &rec.SoldCurrentYear, &rec.Stock,
		)
		if err != nil {
			log.Printf("Error scanning record row for ensemble report: %v", err)
			continue
		}
		records = append(records, rec)
		actualFetchedRecordIDs = append(actualFetchedRecordIDs, rec.ID)
	}
	if err = recordRows.Err(); err != nil {
		log.Printf("Error after iterating record rows for ensemble report: %v", err)
		respondWithError(w, http.StatusInternalServerError, "Database error processing records for report")
		return
	}

	if len(records) == 0 {
		respondWithJSON(w, http.StatusOK, records) // Пластинки не найдены (хотя ID были)
		return
	}

	// 4. Получаем связи record_tracks и треки для этих пластинок (та же логика, что в GetRecordsHandler)
	// Эта часть повторяет логику из GetRecordsHandler для получения треков для заданного списка RecordIDs.
	// В реальном проекте это стоило бы вынести в отдельную функцию.

	query = "SELECT record_id, track_id FROM record_tracks WHERE record_id IN (?" + strings.Repeat(",?", len(actualFetchedRecordIDs)-1) + ")"
	args = make([]interface{}, len(actualFetchedRecordIDs))
	for i, id := range actualFetchedRecordIDs {
		args[i] = id
	}

	reportTrackLinkRows, err := db.Query(query, args...)
	if err != nil {
		log.Printf("Error querying record_tracks for ensemble report tracks: %v", err)
		respondWithError(w, http.StatusInternalServerError, "Database error fetching record tracks links for report")
		return
	}
	defer reportTrackLinkRows.Close()

	reportRecordTrackLinks := make(map[int][]int)
	reportTrackIDs := []int{}
	reportTrackIDSet := make(map[int]bool)

	for reportTrackLinkRows.Next() {
		var recordID, trackID int
		if err := reportTrackLinkRows.Scan(&recordID, &trackID); err != nil {
			log.Printf("Error scanning record_tracks row for report tracks: %v", err)
			continue
		}
		reportRecordTrackLinks[recordID] = append(reportRecordTrackLinks[recordID], trackID)
		if _, exists := reportTrackIDSet[trackID]; !exists {
			reportTrackIDs = append(reportTrackIDs, trackID)
			reportTrackIDSet[trackID] = true
		}
	}
	if err = reportTrackLinkRows.Err(); err != nil {
		log.Printf("Error after iterating record_tracks rows for report tracks: %v", err)
		respondWithError(w, http.StatusInternalServerError, "Database error processing record tracks links for report")
		return
	}

	reportTracksMap := make(map[int]models.Track)
	if len(reportTrackIDs) > 0 {
		query = `
            SELECT
                t.id, t.name, t.duration, t.musician_id, t.ensemble_id,
                m.first_name, m.last_name, e.name
            FROM tracks t
            LEFT JOIN musicians m ON t.musician_id = m.id
            LEFT JOIN ensembles e ON t.ensemble_id = e.id
            WHERE t.id IN (?" + strings.Repeat(",?", len(reportTrackIDs)-1) + ")`

		args = make([]interface{}, len(reportTrackIDs))
		for i, id := range reportTrackIDs {
			args[i] = id
		}

		reportTrackRows, err := db.Query(query, args...)
		if err != nil {
			log.Printf("Error querying tracks for ensemble report: %v", err)
			respondWithError(w, http.StatusInternalServerError, "Database error fetching tracks for report")
			return
		}
		defer reportTrackRows.Close()

		for reportTrackRows.Next() {
			var t models.Track
			var musicianFirstName, musicianLastName, ensembleName sql.NullString
			var musicianID, ensembleID sql.NullInt64

			err := reportTrackRows.Scan(
				&t.ID, &t.Name, &t.Duration, &musicianID, &ensembleID,
				&musicianFirstName, &musicianLastName, &ensembleName,
			)
			if err != nil {
				log.Printf("Error scanning track row for report: %v", err)
				continue
			}

			if musicianID.Valid {
				id := int(musicianID.Int64)
				t.MusicianID = &id
				if musicianFirstName.Valid || musicianLastName.Valid {
					t.MusicianName = strings.TrimSpace(musicianFirstName.String + " " + musicianLastName.String)
				} else {
					t.MusicianName = "Unknown Musician"
				}
			}
			if ensembleID.Valid {
				id := int(ensembleID.Int64)
				t.EnsembleID = &id
				if ensembleName.Valid {
					t.EnsembleName = ensembleName.String
				} else {
					t.EnsembleName = "Unknown Ensemble"
				}
			}
			reportTracksMap[t.ID] = t
		}
		if err = reportTrackRows.Err(); err != nil {
			log.Printf("Error after iterating tracks rows for report: %v", err)
			respondWithError(w, http.StatusInternalServerError, "Database error processing tracks for report")
			return
		}
	}

	// 5. Собираем пластинки с их треками
	for i := range records {
		records[i].Tracks = []models.Track{}
		linkedTrackIDs, ok := reportRecordTrackLinks[records[i].ID]
		if !ok {
			continue
		}
		for _, trackID := range linkedTrackIDs {
			if track, exists := reportTracksMap[trackID]; exists {
				records[i].Tracks = append(records[i].Tracks, track)
			} else {
				log.Printf("Warning: Linked track ID %d for record %d not found in fetched report tracks map", trackID, records[i].ID)
			}
		}
	}

	respondWithJSON(w, http.StatusOK, records)
}

// GetBestSellersHandler возвращает список самых продаваемых пластинок текущего года
func GetBestSellersHandler(w http.ResponseWriter, r *http.Request) {
	db := db.GetDB()

	// 1. Получаем пластинки, отсортированные по sold_current_year по убыванию
	rows, err := db.Query("SELECT id, title, label, wholesale_address, wholesale_price, retail_price, release_date, sold_last_year, sold_current_year, stock FROM records ORDER BY sold_current_year DESC")
	if err != nil {
		log.Printf("Database error fetching bestsellers: %v", err)
		respondWithError(w, http.StatusInternalServerError, "Database error fetching bestsellers")
		return
	}
	defer rows.Close()

	records := []models.Record{}
	recordIDs := []int{}

	for rows.Next() {
		var rec models.Record
		err := rows.Scan(
			&rec.ID, &rec.Title, &rec.Label, &rec.WholesaleAddress, &rec.WholesalePrice,
			&rec.RetailPrice, &rec.ReleaseDate, &rec.SoldLastYear, &rec.SoldCurrentYear, &rec.Stock,
		)
		if err != nil {
			log.Printf("Error scanning bestseller record row: %v", err)
			continue
		}
		records = append(records, rec)
		recordIDs = append(recordIDs, rec.ID)
	}
	if err = rows.Err(); err != nil {
		log.Printf("Error after iterating bestseller record rows: %v", err)
		respondWithError(w, http.StatusInternalServerError, "Database error processing bestsellers")
		return
	}

	if len(records) == 0 {
		respondWithJSON(w, http.StatusOK, records)
		return
	}

	// 2. Получаем связи record_tracks и треки для этих пластинок (та же логика, что в GetRecordsHandler)
	// Эта часть повторяет логику из GetRecordsHandler для получения треков для заданного списка RecordIDs.
	// В реальном проекте это стоило бы вынести в отдельную функцию.

	query := "SELECT record_id, track_id FROM record_tracks WHERE record_id IN (?" + strings.Repeat(",?", len(recordIDs)-1) + ")"
	args := make([]interface{}, len(recordIDs))
	for i, id := range recordIDs {
		args[i] = id
	}

	bestsellerTrackLinkRows, err := db.Query(query, args...)
	if err != nil {
		log.Printf("Error querying record_tracks for bestsellers: %v", err)
		respondWithError(w, http.StatusInternalServerError, "Database error fetching record tracks links for bestsellers")
		return
	}
	defer bestsellerTrackLinkRows.Close()

	bestsellerRecordTrackLinks := make(map[int][]int)
	bestsellerTrackIDs := []int{}
	bestsellerTrackIDSet := make(map[int]bool)

	for bestsellerTrackLinkRows.Next() {
		var recordID, trackID int
		if err := bestsellerTrackLinkRows.Scan(&recordID, &trackID); err != nil {
			log.Printf("Error scanning record_tracks row for bestsellers: %v", err)
			continue
		}
		bestsellerRecordTrackLinks[recordID] = append(bestsellerRecordTrackLinks[recordID], trackID)
		if _, exists := bestsellerTrackIDSet[trackID]; !exists {
			bestsellerTrackIDs = append(bestsellerTrackIDs, trackID)
			bestsellerTrackIDSet[trackID] = true
		}
	}
	if err = bestsellerTrackLinkRows.Err(); err != nil {
		log.Printf("Error after iterating record_tracks rows for bestsellers: %v", err)
		respondWithError(w, http.StatusInternalServerError, "Database error processing record tracks links for bestsellers")
		return
	}

	bestsellerTracksMap := make(map[int]models.Track)
	if len(bestsellerTrackIDs) > 0 {
		query = `
            SELECT
                t.id, t.name, t.duration, t.musician_id, t.ensemble_id,
                m.first_name, m.last_name, e.name
            FROM tracks t
            LEFT JOIN musicians m ON t.musician_id = m.id
            LEFT JOIN ensembles e ON t.ensemble_id = e.id
            WHERE t.id IN (?" + strings.Repeat(",?", len(bestsellerTrackIDs)-1) + ")`

		args = make([]interface{}, len(bestsellerTrackIDs))
		for i, id := range bestsellerTrackIDs {
			args[i] = id
		}

		bestsellerTrackRows, err := db.Query(query, args...)
		if err != nil {
			log.Printf("Error querying tracks for bestsellers: %v", err)
			respondWithError(w, http.StatusInternalServerError, "Database error fetching tracks for bestsellers")
			return
		}
		defer bestsellerTrackRows.Close()

		for bestsellerTrackRows.Next() {
			var t models.Track
			var musicianFirstName, musicianLastName, ensembleName sql.NullString
			var musicianID, ensembleID sql.NullInt64

			err := bestsellerTrackRows.Scan(
				&t.ID, &t.Name, &t.Duration, &musicianID, &ensembleID,
				&musicianFirstName, &musicianLastName, &ensembleName,
			)
			if err != nil {
				log.Printf("Error scanning track row for bestsellers: %v", err)
				continue
			}

			if musicianID.Valid {
				id := int(musicianID.Int64)
				t.MusicianID = &id
				if musicianFirstName.Valid || musicianLastName.Valid {
					t.MusicianName = strings.TrimSpace(musicianFirstName.String + " " + musicianLastName.String)
				} else {
					t.MusicianName = "Unknown Musician"
				}
			}
			if ensembleID.Valid {
				id := int(ensembleID.Int64)
				t.EnsembleID = &id
				if ensembleName.Valid {
					t.EnsembleName = ensembleName.String
				} else {
					t.EnsembleName = "Unknown Ensemble"
				}
			}
			bestsellerTracksMap[t.ID] = t
		}
		if err = bestsellerTrackRows.Err(); err != nil {
			log.Printf("Error after iterating tracks rows for bestsellers: %v", err)
			respondWithError(w, http.StatusInternalServerError, "Database error processing tracks for bestsellers")
			return
		}
	}

	// 3. Собираем пластинки с их треками
	for i := range records {
		records[i].Tracks = []models.Track{}
		linkedTrackIDs, ok := bestsellerRecordTrackLinks[records[i].ID]
		if !ok {
			continue
		}
		for _, trackID := range linkedTrackIDs {
			if track, exists := bestsellerTracksMap[trackID]; exists {
				records[i].Tracks = append(records[i].Tracks, track)
			} else {
				log.Printf("Warning: Linked track ID %d for record %d not found in fetched bestsellers tracks map", trackID, records[i].ID)
			}
		}
	}

	respondWithJSON(w, http.StatusOK, records)
}
