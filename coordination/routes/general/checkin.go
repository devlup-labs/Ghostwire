package general

import "net/http"

func CheckinHandler(w http.ResponseWriter, r *http.Request) {
	// Disabling caching so that testing is easier
	// Replace with your own function
	w.Header().Set("Cache-Control", "no-store, no-cache, must-revalidate, max-age=0")
	w.Header().Set("Pragma", "no-cache")
	w.Header().Set("Expires", "0")
	http.Error(w, "Not Implemented", http.StatusNotImplemented)
}
