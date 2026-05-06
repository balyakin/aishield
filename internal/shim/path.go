package shim

import (
	"os"
	"path/filepath"
)

const (
	EnvShimDir        = "AISHIELD_SHIM_DIR"
	EnvOriginalPath   = "AISHIELD_ORIGINAL_PATH"
	EnvOriginalShell  = "AISHIELD_ORIGINAL_SHELL"
	EnvConfig         = "AISHIELD_CONFIG"
	EnvPreset         = "AISHIELD_PRESET"
	EnvLogFile        = "AISHIELD_LOG_FILE"
	EnvDryRun         = "AISHIELD_DRY_RUN"
	EnvConfirmTimeout = "AISHIELD_CONFIRM_TIMEOUT"
	EnvSessionID      = "AISHIELD_SESSION_ID"
)

type Layer struct {
	Dir string
}

func CreateLayer(binaryPath string, executables []string, shellWrapper bool) (*Layer, error) {
	dir, err := os.MkdirTemp("", "aishield-shim-*")
	if err != nil {
		return nil, err
	}

	for _, executable := range executables {
		if err := createSymlink(binaryPath, filepath.Join(dir, executable)); err != nil {
			_ = os.RemoveAll(dir)
			return nil, err
		}
	}

	if shellWrapper {
		if err := createSymlink(binaryPath, filepath.Join(dir, "aishield-shell")); err != nil {
			_ = os.RemoveAll(dir)
			return nil, err
		}
	}

	return &Layer{
		Dir: dir,
	}, nil
}

func (layer *Layer) Close() error {
	if layer == nil || layer.Dir == "" {
		return nil
	}
	return os.RemoveAll(layer.Dir)
}

func createSymlink(target string, link string) error {
	if err := os.Remove(link); err != nil && !os.IsNotExist(err) {
		return err
	}
	return os.Symlink(target, link)
}
