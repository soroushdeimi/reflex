package main

import (
	"fmt"
	"net/http"
)

func handler(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintln(w, "Server is running on port 80")
}

func main() {
	http.HandleFunc("/", handler)

	fmt.Println("Starting server on port 80...")
	err := http.ListenAndServe(":80", nil)
	if err != nil {
		panic(err)
	}
}