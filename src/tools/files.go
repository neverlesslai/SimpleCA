package tools

import (
	"os"
)

func IsFileExist(filepath string) bool {
	_, err := os.Stat(filepath)
	if err != nil {
		if os.IsNotExist(err) {
			return false
		}
	}
	return true
}
