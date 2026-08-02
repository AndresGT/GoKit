// Package middleware provee middlewares HTTP reutilizables para el ecosistema
// GoKit: autenticación JWT, autorización por rol, verificación de sesión
// activa, limitación de tasa (rate limiting), CORS y logging de peticiones.
//
// Todos los middlewares siguen la firma estándar de Go (Middleware =
// func(http.Handler) http.Handler), por lo que son compatibles con net/http
// y con routers populares como chi, gorilla/mux o Gin (vía adaptador).
//
// Ejemplo combinando varios middlewares con Chain:
//
//	handler := middleware.Chain(mux,
//	    middleware.RequestLogger(log),
//	    middleware.CORS(corsConfig),
//	    middleware.RateLimit(limiter, nil),
//	)
//	http.ListenAndServe(":8080", handler)
//
// Para proteger una ruta específica con autenticación y roles:
//
//	authed := middleware.RequireAuth(jwtManager)
//	admin := middleware.RequireRole("admin")
//	mux.Handle("/admin", authed(admin(adminHandler)))
package middleware
