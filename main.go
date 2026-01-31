package main

import (
	"html/template"
	"log"
	"net/http"
	"path/filepath"
	"time"
	
	"github.com/gorilla/mux"
)

// Структура для передачи данных в шаблоны
type PageData struct {
	Title       string
	CurrentYear int
	ActiveTab   string
}

func main() {
	// Создаем маршрутизатор
	r := mux.NewRouter()
	
	// Статические файлы
	fs := http.FileServer(http.Dir("./static"))
	r.PathPrefix("/static/").Handler(http.StripPrefix("/static/", fs))
	
	// Маршруты
	r.HandleFunc("/", homeHandler)
	r.HandleFunc("/url-scanner", urlScannerHandler)
	r.HandleFunc("/coming-soon", comingSoonHandler)
	r.HandleFunc("/api/scan", scanHandler).Methods("POST")
	
	// Настройка сервера
	srv := &http.Server{
		Handler:      r,
		Addr:         ":8080",
		WriteTimeout: 15 * time.Second,
		ReadTimeout:  15 * time.Second,
	}
	
	log.Println("Сервер запущен на http://localhost:8080")
	log.Println("Главная страница: http://localhost:8080")
	log.Println("URL сканер: http://localhost:8080/url-scanner")
	log.Println("Coming Soon: http://localhost:8080/coming-soon")
	
	log.Fatal(srv.ListenAndServe())
}

// Обработчик главной страницы (редирект на URL сканер)
func homeHandler(w http.ResponseWriter, r *http.Request) {
	http.Redirect(w, r, "/url-scanner", http.StatusFound)
}

// Обработчик страницы URL сканера
func urlScannerHandler(w http.ResponseWriter, r *http.Request) {
	data := PageData{
		Title:       "VirusChecker - URL Scanner",
		CurrentYear: time.Now().Year(),
		ActiveTab:   "url-scanner",
	}
	
	renderTemplate(w, "test1.html", data)
}

// Обработчик страницы "Coming Soon"
func comingSoonHandler(w http.ResponseWriter, r *http.Request) {
	data := PageData{
		Title:       "Coming Soon - VirusChecker",
		CurrentYear: time.Now().Year(),
		ActiveTab:   "coming-soon",
	}
	
	renderTemplate(w, "test0.html", data)
}

// API обработчик для сканирования URL (заглушка)
func scanHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	
	// Симуляция обработки сканирования
	response := `{
		"status": "success",
		"message": "Scan initiated",
		"scan_id": "scan_${Date.now()}",
		"estimated_time": "30 seconds"
	}`
	
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(response))
}

// Функция для рендеринга шаблонов
func renderTemplate(w http.ResponseWriter, tmplName string, data PageData) {
	// Путь к шаблону
	tmplPath := filepath.Join("templates", tmplName)
	
	// Парсинг шаблона
	tmpl, err := template.ParseFiles(tmplPath)
	if err != nil {
		log.Printf("Ошибка парсинга шаблона %s: %v", tmplName, err)
		http.Error(w, "Внутренняя ошибка сервера", http.StatusInternalServerError)
		return
	}
	
	// Выполнение шаблона
	err = tmpl.Execute(w, data)
	if err != nil {
		log.Printf("Ошибка выполнения шаблона %s: %v", tmplName, err)
		http.Error(w, "Внутренняя ошибка сервера", http.StatusInternalServerError)
	}
}