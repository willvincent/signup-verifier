package main

import (
	"flag"
	"net/http"
)

var Debug bool

func init() {
	flag.BoolVar(&Debug, "debug", false, "Enable debug logging")
}

func (app *App) getIP(r *http.Request) string {
	xff := r.Header.Get("X-Forwarded-For")
	if xff != "" {
		return xff
	}
	return r.RemoteAddr
}