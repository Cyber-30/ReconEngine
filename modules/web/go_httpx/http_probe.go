package main

import (
	"encoding/json"
	"os"
	"time"
)

func main() {
	target := os.Args[1]

	result := map[string]interface{}{
		"module":    "web.http_probe",
		"target":    target,
		"timestamp": time.Now().UTC(),
		"data":      []string{},
	}

	json.NewEncoder(os.Stdout).Encode(result)
}
