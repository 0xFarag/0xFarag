// Serializes an inert in-memory input via the upstream writer. No HTTP is performed.
package main

import (
	"log"
	"os"

	"github.com/ffuf/ffuf/v2/pkg/ffuf"
	"github.com/ffuf/ffuf/v2/pkg/output"
)

func main() {
	if len(os.Args) != 2 {
		log.Fatal("supply one new output path")
	}
	config := ffuf.Config{Method: "POST", Data: "CONTEXT_CANARY", CommandLine: "offline context fixture"}
	writer := output.NewStdoutput(&config)
	writer.SetCurrentResults([]ffuf.Result{{StatusCode: 200, Url: "http://192.0.2.10/health", Host: "192.0.2.10"}})
	if err := writer.SaveFile(os.Args[1], "json"); err != nil {
		log.Fatal(err)
	}
}
