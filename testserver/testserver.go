package main_ignored

import (
	"fmt"
	"net/http"
)

func main() {
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		fmt.Println("Got request:", r.Method, r.URL.Path)
		fmt.Fprintln(w, "Fallback server works!")
	})

	fmt.Println("Listening on http://localhost:8080/")
	err := http.ListenAndServe(":8080", nil)
	fmt.Println("Server exited with error:", err)
}
