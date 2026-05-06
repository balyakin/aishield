package presets

import (
	"embed"
	"fmt"
)

//go:embed *.yaml
var files embed.FS

func Read(name string) ([]byte, error) {
	data, err := files.ReadFile(name + ".yaml")
	if err != nil {
		return nil, fmt.Errorf("preset %q not found: %w", name, err)
	}
	return data, nil
}
