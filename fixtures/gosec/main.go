// WatsonSec fixture — intentionally vulnerable Go for gosec adapter testing.
// DO NOT use in production.
package main

import (
	"crypto/md5"  // G401: use of weak cryptographic primitive
	"fmt"
	"net/http"
	"os/exec"
)

// G204: Subprocess launched with variable
func runCommand(userInput string) {
	cmd := exec.Command("sh", "-c", userInput) //nolint:gosec
	cmd.Run()
}

// G401: use of MD5 (weak hash)
func hashValue(data []byte) []byte {
	h := md5.New() //nolint:gosec
	h.Write(data)
	return h.Sum(nil)
}

// G107: URL provided to HTTP request as taint input
func fetchURL(url string) (*http.Response, error) {
	return http.Get(url) //nolint:gosec
}

// G501: import of crypto/md5 (weak hash — detected at import level too)
func main() {
	fmt.Println(hashValue([]byte("hello")))
	runCommand("echo hello")
	fetchURL("http://example.com")
}
