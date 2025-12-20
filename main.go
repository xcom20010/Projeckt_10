package main

import (
	"encoding/json"
	"net/http"

	"fmt"

	"github.com/gorilla/mux"
)

type GetResponse struct {
	Message string `json:message`
}

func getHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(GetResponse{Message: "Hello"})
}

func main() {
	r := mux.NewRouter()
	r.HandleFunc("/", getHandler).Methods("GET")
	fmt.Println("Starting...")
	http.ListenAndServe(":8080", r)
}
