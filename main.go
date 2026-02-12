package main

import (
	"encoding/json"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"time"
	
	"github.com/gorilla/mux"
)

// Структура для хранения данных сканирования
type ScanData struct {
	ID          string    `json:"id"`
	URL         string    `json:"url"`
	Timestamp   time.Time `json:"timestamp"`
	Status      string    `json:"status"`
	Detection   string    `json:"detection"`
	UserAgent   string    `json:"user_agent"`
	IPAddress   string    `json:"ip_address"`
}

// Структура для ответа API
type ScanResponse struct {
	Success bool   `json:"success"`
	Message string `json:"message"`
	ScanID  string `json:"scan_id"`
	Data    ScanData `json:"data,omitempty"`
}

// Структура для передачи данных в шаблоны
type PageData struct {
	Title       string
	CurrentYear int
	ActiveTab   string
}

var scans []ScanData // Хранилище в памяти

func main() {
	// Загружаем сохраненные данные при старте
	loadScansFromFile()
	
	r := mux.NewRouter()
	
	// Статические файлы
	fs := http.FileServer(http.Dir("./static"))
	r.PathPrefix("/static/").Handler(http.StripPrefix("/static/", fs))
	
	// Маршруты
	r.HandleFunc("/", homeHandler)
	r.HandleFunc("/url-scanner", urlScannerHandler)
	r.HandleFunc("/coming-soon", comingSoonHandler)
	r.HandleFunc("/api/scan", scanHandler).Methods("POST")
	r.HandleFunc("/api/scans", getAllScansHandler).Methods("GET")
	r.HandleFunc("/admin/scans", adminScansHandler).Methods("GET") // Страница с данными
	
	srv := &http.Server{
		Handler:      r,
		Addr:         ":8080",
		WriteTimeout: 15 * time.Second,
		ReadTimeout:  15 * time.Second,
	}
	
	log.Println("🚀 Сервер запущен на http://localhost:8080")
	log.Println("📁 Главная страница: http://localhost:8080")
	log.Println("🔗 URL сканер: http://localhost:8080/url-scanner")
	log.Println("⏳ Coming Soon: http://localhost:8080/coming-soon")
	log.Println("📊 Просмотр данных: http://localhost:8080/admin/scans")
	
	log.Fatal(srv.ListenAndServe())
}

// Загрузка данных из файла
func loadScansFromFile() {
	file, err := os.OpenFile("scans.json", os.O_RDONLY|os.O_CREATE, 0644)
	if err != nil {
		log.Printf("Ошибка открытия файла: %v", err)
		return
	}
	defer file.Close()
	
	decoder := json.NewDecoder(file)
	err = decoder.Decode(&scans)
	if err != nil && err.Error() != "EOF" {
		log.Printf("Ошибка декодирования JSON: %v", err)
	}
}

// Сохранение данных в файл
func saveScansToFile() {
	file, err := os.Create("scans.json")
	if err != nil {
		log.Printf("Ошибка создания файла: %v", err)
		return
	}
	defer file.Close()
	
	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "  ")
	err = encoder.Encode(scans)
	if err != nil {
		log.Printf("Ошибка кодирования JSON: %v", err)
	}
}

func homeHandler(w http.ResponseWriter, r *http.Request) {
	http.Redirect(w, r, "/url-scanner", http.StatusFound)
}

func urlScannerHandler(w http.ResponseWriter, r *http.Request) {
	data := PageData{
		Title:       "VirusTotal - URL Scanner",
		CurrentYear: time.Now().Year(),
		ActiveTab:   "url-scanner",
	}
	
	renderTemplate(w, "index.html", data)
}

func comingSoonHandler(w http.ResponseWriter, r *http.Request) {
	data := PageData{
		Title:       "Coming Soon - VirusTotal",
		CurrentYear: time.Now().Year(),
		ActiveTab:   "coming-soon",
	}
	
	renderTemplate(w, "coming-soon.html", data)
}

// Обработчик страницы с данными
func adminScansHandler(w http.ResponseWriter, r *http.Request) {
	data := struct {
		Title       string
		CurrentYear int
		Scans       []ScanData
	}{
		Title:       "Scan History - VirusTotal",
		CurrentYear: time.Now().Year(),
		Scans:       scans,
	}
	
	renderTemplate(w, "admin.html", data)
}

// API обработчик для получения всех сканов
func getAllScansHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Access-Control-Allow-Origin", "*")
	
	response := map[string]interface{}{
		"success": true,
		"count":   len(scans),
		"scans":   scans,
	}
	
	json.NewEncoder(w).Encode(response)
}

// API обработчик для сканирования URL
func scanHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Access-Control-Allow-Origin", "*")
	
	// Парсим JSON из запроса
	var requestData struct {
		URL string `json:"url"`
	}
	
	err := json.NewDecoder(r.Body).Decode(&requestData)
	if err != nil {
		http.Error(w, `{"success": false, "message": "Invalid request"}`, http.StatusBadRequest)
		return
	}
	
	// Генерируем ID скана
	scanID := fmt.Sprintf("scan_%d", time.Now().UnixNano())
	
	// Случайные результаты для демонстрации
	results := []struct {
		Status    string
		Detection string
	}{
		{"Clean", "0/72"},
		{"Suspicious", "12/72"},
		{"Malicious", "58/72"},
		{"Clean", "1/72"},
	}
	
	randomResult := results[time.Now().UnixNano()%int64(len(results))]
	
	// Создаем запись скана
	scan := ScanData{
		ID:          scanID,
		URL:         requestData.URL,
		Timestamp:   time.Now(),
		Status:      randomResult.Status,
		Detection:   randomResult.Detection,
		UserAgent:   r.UserAgent(),
		IPAddress:   r.RemoteAddr,
	}
	
	// Добавляем в хранилище
	scans = append(scans, scan)
	
	// Сохраняем в файл
	saveScansToFile()
	
	// Отправляем ответ
	response := ScanResponse{
		Success: true,
		Message: "Scan completed successfully",
		ScanID:  scanID,
		Data:    scan,
	}
	
	json.NewEncoder(w).Encode(response)
}

func renderTemplate(w http.ResponseWriter, tmplName string, data interface{}) {
	tmplPath := filepath.Join("templates", tmplName)
	
	tmpl, err := template.ParseFiles(tmplPath)
	if err != nil {
		log.Printf("Ошибка парсинга шаблона %s: %v", tmplName, err)
		http.Error(w, "Внутренняя ошибка сервера", http.StatusInternalServerError)
		return
	}
	
	err = tmpl.Execute(w, data)
	if err != nil {
		log.Printf("Ошибка выполнения шаблона %s: %v", tmplName, err)
		http.Error(w, "Внутренняя ошибка сервера", http.StatusInternalServerError)
	}
}