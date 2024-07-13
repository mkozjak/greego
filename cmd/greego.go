// inspired by https://github.com/tomikaa87/gree-remote
package main

import (
	"net/http"

	"github.com/mkozjak/greego/internal/config"
	"github.com/mkozjak/greego/internal/handlers"
	"github.com/mkozjak/greego/internal/manager"
)

func main() {
	c := config.New()
	m := manager.New(c)
	h := handlers.New(m)

	http.HandleFunc("/api/v1/power", func(res http.ResponseWriter, req *http.Request) {
		switch req.Method {
		case "POST":
			h.SetPower(res, req)
		default:
			http.Error(res, "", http.StatusMethodNotAllowed)
		}
	})

	http.ListenAndServe(":4242", nil)
}
