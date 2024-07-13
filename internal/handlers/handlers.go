package handlers

import (
	"encoding/json"
	"log"
	"net/http"

	"github.com/mkozjak/greego/internal/manager"
)

type handlers struct {
	mgr manager.Requester
}

func New(m manager.Requester) *handlers {
	return &handlers{
		mgr: m,
	}
}

func (h *handlers) SetPower(res http.ResponseWriter, req *http.Request) {
	var body map[string]string
	err := json.NewDecoder(req.Body).Decode(&body)
	if err != nil {
		http.Error(res, err.Error(), http.StatusBadRequest)
		return
	}

	p := []string{}

	if body["set"] == "on" {
		log.Println("need to enable")
	} else {
		log.Println("need to disable")
	}

	switch body["set"] {
	case "on":
		p = append(p, "Pow=1")
	case "off":
		p = append(p, "Pow=0")
	default:
		http.Error(res, "Invalid argument for Pow", http.StatusBadRequest)
		return
	}

	if err = h.mgr.SetParam(p); err != nil {
		http.Error(res, err.Error(), http.StatusInternalServerError)
		return
	}

	res.WriteHeader(http.StatusOK)
}
