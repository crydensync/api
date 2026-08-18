package httpapi

import (
	"database/sql"
	"net/http"
)

type HealthHandler struct {
	DB *sql.DB
}

func (h *HealthHandler) Health(w http.ResponseWriter, r *http.Request) {
	if err := h.DB.PingContext(r.Context()); err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusServiceUnavailable)
		w.Write([]byte(`{"error":{"code":"db_unreachable","message":"database is unreachable"}}`))
		return
	}
	writeData(w, http.StatusOK, map[string]string{"status": "ok"})
}
