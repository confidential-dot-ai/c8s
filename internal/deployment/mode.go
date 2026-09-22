package deployment

import "fmt"

// BakedAttestationAndNRIPlugin identifies the services supplied by the measured node image.
func BakedAttestationAndNRIPlugin(mode string) (bool, error) {
	switch mode {
	case "bare-metal":
		return true, nil
	case "gke", "aks":
		return false, nil
	default:
		return false, fmt.Errorf("--cvm-mode must be one of bare-metal, gke, aks, got %q", mode)
	}
}
