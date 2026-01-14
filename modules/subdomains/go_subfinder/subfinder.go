package main

import (
	"fmt"
	"os"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Println("Usage: go_subfinder <domain>")
		return
	}

	domain := os.Args[1]
	fmt.Println("[+] Subdomain scan started for:", domain)

	// placeholder logic
	fmt.Println("www." + domain)
	fmt.Println("api." + domain)
	fmt.Println("dev." + domain)
}
