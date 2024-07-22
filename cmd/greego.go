// inspired by https://github.com/tomikaa87/gree-remote
package main

import (
	"net/http"
	"strconv"

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

	http.HandleFunc("/api/v1/temperature", func(res http.ResponseWriter, req *http.Request) {
		switch req.Method {
		case "GET":
			h.Temperature(res, req)
		// case "POST":
		// 	h.SetTemperature(res, req)
		default:
			http.Error(res, "", http.StatusMethodNotAllowed)
		}
	})

	http.ListenAndServe(":"+strconv.Itoa(c.App.Port), nil)
}
