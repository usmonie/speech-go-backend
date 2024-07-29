package email

import (
	"encoding/json"
	"github.com/gorilla/mux"
	"net/http"
)

type JSONHandler struct {
	useCase UseCase
}

func NewJSONHandler(authUseCase UseCase) *JSONHandler {
	return &JSONHandler{
		useCase: authUseCase,
	}
}

func (h *JSONHandler) VerifyEmail(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Email string `json:"email"`
		Code  string `json:"code"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	err := h.useCase.VerifyEmail(r.Context(), req.Email, req.Code)
	if err != nil {
		http.Error(w, err.Error(), http.StatusUnauthorized)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w)
}

// SetupJSONEmailRoutes Helper function to set up routes
func SetupJSONEmailRoutes(r *mux.Router, h *JSONHandler) {
	r.HandleFunc("/email/verify", h.VerifyEmail).Methods("POST")
}
