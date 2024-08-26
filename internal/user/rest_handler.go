package user

import (
	"encoding/json"
	"net/http"

	"github.com/google/uuid"
	"github.com/gorilla/mux"
)

type JSONHandler struct {
	userUseCase *AccountUseCase
}

func NewJSONHandler(userUseCase *AccountUseCase) *JSONHandler {
	return &JSONHandler{
		userUseCase: userUseCase,
	}
}

func (h *JSONHandler) CreateUser(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Username              string   `json:"username"`
		Email                 string   `json:"email"`
		Bio                   string   `json:"bio"`
		PasswordHmac          []byte   `json:"password_hmac"`
		Salt                  []byte   `json:"salt"`
		PublicIdentityKey     []byte   `json:"public_identity_key"`
		PublicSignedPreKey    []byte   `json:"public_signed_pre_key"`
		SignedPreKeySignature []byte   `json:"signed_pre_key_signature"`
		PublicKyberKey        []byte   `json:"public_kyber_key"`
		PublicOneTimePreKeys  [][]byte `json:"public_one_time_pre_keys"`
		EncryptedPrivateKeys  []byte   `json:"encrypted_private_keys"`
	}

	println("CreateUser Request")
	print(r.Body)
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)

		println(err.Error())
		return
	}

	accessToken, refreshToken, user, err := h.userUseCase.CreateUser(
		r.Context(),
		req.Username,
		req.Email,
		req.Bio,
		nil,
		req.PasswordHmac,
		req.Salt,
		req.PublicIdentityKey,
		req.PublicSignedPreKey,
		req.SignedPreKeySignature,
		req.PublicKyberKey,
		req.PublicOneTimePreKeys,
		req.EncryptedPrivateKeys,
	)

	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	println("UserUseCase Exist")

	response := struct {
		User         *User  `json:"user"`
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
	}{
		User:         user,
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

func (h *JSONHandler) GetUserById(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	userID, err := uuid.Parse(vars["id"])
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	user, err := h.userUseCase.GetUserByID(r.Context(), &userID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(user)
}

func (h *JSONHandler) GetUsersByUsername(w http.ResponseWriter, r *http.Request) {
	username := r.URL.Query().Get("username")
	if username == "" {
		http.Error(w, "Username is required", http.StatusBadRequest)
		return
	}

	users, err := h.userUseCase.GetUsersByUsername(r.Context(), username)
	if err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(users)
}

func (h *JSONHandler) UpdateUser(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	userID, err := uuid.Parse(vars["id"])
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	var req struct {
		Username string `json:"username"`
		Email    string `json:"email"`
		Bio      string `json:"bio"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	user, err := h.userUseCase.GetUserByID(r.Context(), &userID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}

	user.Bio = req.Bio
	user.Username = req.Username
	user.Email = req.Email

	err = h.userUseCase.UpdateUser(r.Context(), user)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(user)
}

func (h *JSONHandler) DeleteUser(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	userID, err := uuid.Parse(vars["id"])
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	err = h.userUseCase.DeleteUser(r.Context(), &userID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// SetupJSONRoutes Helper function to set up routes
func SetupJSONRoutes(r *mux.Router, h *JSONHandler) {
	r.HandleFunc("/users", h.CreateUser).Methods("POST")
	r.HandleFunc("/users/{id}", h.GetUserById).Methods("GET")
	r.HandleFunc("/users/{username}", h.GetUsersByUsername).Methods("GET")
	r.HandleFunc("/users/{id}", h.UpdateUser).Methods("PUT")
	r.HandleFunc("/users/{id}", h.DeleteUser).Methods("DELETE")
}
