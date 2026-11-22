package api

import (
	"errors"
	"net/http"
	"strconv"
)

// abuseID reads the panel user id from the path.
func abuseID(w http.ResponseWriter, r *http.Request) (int64, bool) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil || id <= 0 {
		writeError(w, http.StatusBadRequest, errors.New("want a Remnawave user id"))
		return 0, false
	}
	return id, true
}

func (s *Server) abuseList(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, s.app.Abuse(r.Context()))
}

func (s *Server) abuseUser(w http.ResponseWriter, r *http.Request) {
	id, ok := abuseID(w, r)
	if !ok {
		return
	}
	v, err := s.app.AbuseUser(r.Context(), id)
	if err != nil {
		s.fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, v)
}

func (s *Server) abuseEnable(w http.ResponseWriter, r *http.Request) {
	id, ok := abuseID(w, r)
	if !ok {
		return
	}
	if err := s.app.AbuseEnable(r.Context(), id); err != nil {
		writeError(w, http.StatusBadGateway, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) abuseAllow(w http.ResponseWriter, r *http.Request) {
	id, ok := abuseID(w, r)
	if !ok {
		return
	}
	if err := s.app.AbuseAllow(r.Context(), id); err != nil {
		s.fail(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
