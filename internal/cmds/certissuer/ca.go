package certissuer

import (
	"net/http"

	"github.com/lunal-dev/c8s/internal/issuer"
)

func handlePublicCA(bm *issuer.BundleManager) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if bm == nil {
			http.Error(w, "service unavailable", http.StatusServiceUnavailable)
			return
		}
		w.Header().Set("Content-Type", "application/x-pem-file")
		w.Write(bm.BundlePEM())
	}
}
