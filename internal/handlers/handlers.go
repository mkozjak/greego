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

// SetPower will prepare a request for AC to set power state based
// on the data received through `req`. It will set temperature to 27
// and its mode to Cooling.
func (h *handlers) SetPower(res http.ResponseWriter, req *http.Request) {
	var body map[string]string
	err := json.NewDecoder(req.Body).Decode(&body)
	if err != nil {
		http.Error(res, err.Error(), http.StatusBadRequest)
		return
	}

	p := []string{}

	switch body["set"] {
	case "on":
		p = append(p, "Pow=1", "Mod=1", "TemUn=0", "SetTem=27")
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

func (h *handlers) Temperature(res http.ResponseWriter, req *http.Request) {
	d, err := h.mgr.GetParam([]string{"SetTem"})
	if err != nil {
		http.Error(res, err.Error(), http.StatusInternalServerError)
		return
	}

	t := strconv.FormatFloat(d[0].(float64), 'f', 0, 64)
	res.Write([]byte(t))
}
