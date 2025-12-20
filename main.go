package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"

	"github.com/gorilla/mux"
)

type GetResponse struct {
	Message string `json:"message"`
}

type PostRequest struct {
	Name string `json:"name"`
	Age  int    `json:"age"`
}

type PostResponse struct {
	Info string      `json:"message"`
	Data PostRequest `json:"data"`
}

func postHandler(w http.ResponseWriter, r *http.Request) {
	var req PostRequest
	err := json.NewDecoder(r.Body).Decode(&req)
	if err != nil {
		log.Fatalln("Ошибка", err)
	}

	createdReq := req
	fmt.Println("Успешно создали переменную", createdReq)

	resp := PostResponse{
		Info: "Переменная создалась",
		Data: createdReq,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)

}

func getHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(GetResponse{Message: "Hello"})
}

func main() {
	r := mux.NewRouter()
	r.HandleFunc("/get", getHandler).Methods("GET")
	r.HandleFunc("/post", postHandler).Methods("POST")

	fmt.Println("Server is running...")
	http.ListenAndServe(":8080", r)
}
