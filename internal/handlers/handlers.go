package handlers

import (
	"encoding/json"
	"net/http"
	"strconv"

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
	var body map[string]bool
	err := json.NewDecoder(req.Body).Decode(&body)
	if err != nil {
		http.Error(res, err.Error(), http.StatusBadRequest)
		return
	}

	p := []string{"Pow=" + strconv.FormatBool(body["enable"])}

	if err = h.mgr.Request(p); err != nil {
		http.Error(res, err.Error(), http.StatusInternalServerError)
		return
	}

	res.WriteHeader(http.StatusOK)
}
