package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"html/template"
	"io"
	"log"
	"net/http"

	//"os"
	"path/filepath"
	"time"

	"github.com/gorilla/mux"
)

// Структура для ответа от Python сервиса
type PythonScanResponse struct {
	Success bool   `json:"success"`
	ScanID  string `json:"scan_id"`
	Data    struct {
		ID          string   `json:"id"`
		URL         string   `json:"url"`
		Timestamp   string   `json:"timestamp"`
		Status      string   `json:"status"`
		Detection   string   `json:"detection"`
		LocalScore  int      `json:"local_score"`
		LocalFlags  []string `json:"local_flags"`
		VTMalicious int      `json:"vt_malicious"`
		VTTotal     int      `json:"vt_total"`
		VTError     *string  `json:"vt_error"`
	} `json:"data"`
}

// Структура для передачи данных в шаблоны
type PageData struct {
	Title       string
	CurrentYear int
	ActiveTab   string
	PythonURL   string
}

var pythonServiceURL = "http://localhost:5000"

func main() {
	// Проверяем доступность Python сервиса
	go checkPythonService()

	r := mux.NewRouter()

	// Статические файлы
	fs := http.FileServer(http.Dir("./static"))
	r.PathPrefix("/static/").Handler(http.StripPrefix("/static/", fs))

	// Маршруты
	r.HandleFunc("/", homeHandler)
	r.HandleFunc("/url-scanner", urlScannerHandler)
	r.HandleFunc("/coming-soon", comingSoonHandler)
	r.HandleFunc("/admin", adminHandler)

	// API маршруты (прокси к Python)
	r.HandleFunc("/api/scan", scanHandler).Methods("POST")
	r.HandleFunc("/api/scans", getScansHandler).Methods("GET")
	r.HandleFunc("/api/scan/{id}", getScanHandler).Methods("GET")
	r.HandleFunc("/api/health", healthHandler).Methods("GET")

	srv := &http.Server{
		Handler:      r,
		Addr:         ":8080",
		WriteTimeout: 30 * time.Second,
		ReadTimeout:  30 * time.Second,
	}

	log.Println("🚀 Go сервер запущен на http://localhost:8080")
	log.Println("🐍 Python сервер ожидается на http://localhost:5000")
	log.Println("📊 Admin панель: http://localhost:8080/admin")

	log.Fatal(srv.ListenAndServe())
}

func checkPythonService() {
	time.Sleep(2 * time.Second)
	resp, err := http.Get(pythonServiceURL + "/health")
	if err != nil {
		log.Printf("⚠️ Python сервис недоступен: %v", err)
		log.Printf("   Запустите: python scanner.py")
	} else {
		defer resp.Body.Close()
		log.Printf("✅ Python сервис подключен")
	}
}

func homeHandler(w http.ResponseWriter, r *http.Request) {
	http.Redirect(w, r, "/url-scanner", http.StatusFound)
}

func urlScannerHandler(w http.ResponseWriter, r *http.Request) {
	data := PageData{
		Title:       "VirusChecker - URL Scanner",
		CurrentYear: time.Now().Year(),
		ActiveTab:   "url-scanner",
		PythonURL:   pythonServiceURL,
	}

	renderTemplate(w, "index.html", data)
}

func comingSoonHandler(w http.ResponseWriter, r *http.Request) {
	data := PageData{
		Title:       "Coming Soon - VirusChecker",
		CurrentYear: time.Now().Year(),
		ActiveTab:   "coming-soon",
	}

	renderTemplate(w, "coming-soon.html", data)
}

func adminHandler(w http.ResponseWriter, r *http.Request) {
	data := struct {
		Title       string
		CurrentYear int
		PythonURL   string
	}{
		Title:       "Admin Panel - VirusChecker History",
		CurrentYear: time.Now().Year(),
		PythonURL:   pythonServiceURL,
	}

	renderTemplate(w, "admin.html", data)
}

// Прокси к Python API
func scanHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Access-Control-Allow-Origin", "*")

	// Читаем тело запроса
	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, `{"success": false, "error": "Cannot read request"}`, http.StatusBadRequest)
		return
	}

	// Отправляем запрос к Python сервису
	resp, err := http.Post(pythonServiceURL+"/scan", "application/json", bytes.NewBuffer(body))
	if err != nil {
		// Если Python сервис недоступен, используем упрощенный локальный анализ
		log.Printf("Python service unavailable, using fallback: %v", err)
		handleFallbackScan(w, body)
		return
	}
	defer resp.Body.Close()

	// Копируем ответ от Python сервиса
	w.WriteHeader(resp.StatusCode)
	io.Copy(w, resp.Body)
}

// Запасной вариант, если Python недоступен
func handleFallbackScan(w http.ResponseWriter, body []byte) {
	var req struct {
		URL string `json:"url"`
	}

	if err := json.Unmarshal(body, &req); err != nil {
		http.Error(w, `{"success": false, "error": "Invalid JSON"}`, http.StatusBadRequest)
		return
	}

	// Простой локальный анализ на Go
	scanID := fmt.Sprintf("scan_fallback_%d", time.Now().UnixNano())

	response := map[string]interface{}{
		"success": true,
		"scan_id": scanID,
		"data": map[string]interface{}{
			"id":          scanID,
			"url":         req.URL,
			"timestamp":   time.Now().Format(time.RFC3339),
			"status":      "Ожидает проверки",
			"detection":   "0/0 (fallback)",
			"local_score": 0,
			"local_flags": []string{"Python сервис недоступен, использован запасной анализ"},
			"vt_error":    "Python scanner offline",
		},
	}

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(response)
}

func getScansHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	resp, err := http.Get(pythonServiceURL + "/scans")
	if err != nil {
		http.Error(w, `{"success": false, "error": "Python service unavailable"}`, http.StatusServiceUnavailable)
		return
	}
	defer resp.Body.Close()

	w.WriteHeader(resp.StatusCode)
	io.Copy(w, resp.Body)
}

func getScanHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	vars := mux.Vars(r)
	scanID := vars["id"]

	resp, err := http.Get(pythonServiceURL + "/scan/" + scanID)
	if err != nil {
		http.Error(w, `{"success": false, "error": "Python service unavailable"}`, http.StatusServiceUnavailable)
		return
	}
	defer resp.Body.Close()

	w.WriteHeader(resp.StatusCode)
	io.Copy(w, resp.Body)
}

func healthHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	// Проверяем Python сервис
	pythonStatus := "unavailable"
	pythonResp, err := http.Get(pythonServiceURL + "/health")
	if err == nil {
		defer pythonResp.Body.Close()
		pythonStatus = "connected"
	}

	status := map[string]interface{}{
		"status": "ok",
		"go": map[string]interface{}{
			"version": "1.21",
			"uptime":  time.Now().Unix(),
		},
		"python": map[string]interface{}{
			"status": pythonStatus,
			"url":    pythonServiceURL,
		},
	}

	json.NewEncoder(w).Encode(status)
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
