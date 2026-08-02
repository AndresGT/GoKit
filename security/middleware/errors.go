package middleware

import (
	"encoding/json"
	"errors"
	"net/http"
)

// =============================================================================
// Errores del Paquete
// =============================================================================

var (
	// ErrMissingAuthHeader se retorna cuando la petición no incluye el
	// header Authorization.
	ErrMissingAuthHeader = errors.New("falta el header Authorization")

	// ErrInvalidAuthHeader se retorna cuando el header Authorization no
	// tiene el formato esperado "Bearer <token>".
	ErrInvalidAuthHeader = errors.New("el header Authorization debe tener el formato 'Bearer <token>'")
)

// =============================================================================
// Respuesta de Error Estándar
// =============================================================================

// errorResponse es el formato JSON usado por los middlewares de este paquete
// para reportar errores al cliente.
type errorResponse struct {
	Error string `json:"error"`
}

// writeError escribe una respuesta JSON de error con el status indicado.
//
// Deliberadamente solo recibe un mensaje "público": los middlewares de este
// paquete nunca devuelven al cliente el error interno (detalles del fallo de
// validación de un JWT, por ejemplo), para no filtrar información que pueda
// ayudar a un atacante. Si necesitas depurar, registra el error real con tu
// propio logger antes de llamar a writeError.
func writeError(w http.ResponseWriter, status int, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(errorResponse{Error: message})
}
