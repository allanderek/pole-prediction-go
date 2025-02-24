package file

import (
	"encoding/json"
	"os"
)

func ReadAndMarshallFile(fileName string, target interface{}) error {
	raw, err := os.ReadFile(fileName)
	if err != nil {
		return err
	}

	if err := json.Unmarshal(raw, target); err != nil {
		return err
	}

	return nil
}
