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
	writer := output.NewStdoutput(&ffuf.Config{Method: "GET", CommandLine: "offline serializer fixture"})
	writer.SetCurrentResults([]ffuf.Result{
		{Position: 1, StatusCode: 200, ContentLength: 2, Url: "http://192.0.2.10/health", Host: "192.0.2.10"},
		{Position: 2, StatusCode: 404, ContentLength: 0, Url: "http://192.0.2.11/health", Host: "192.0.2.11"},
	})
	if err := writer.SaveFile(os.Args[1], "json"); err != nil {
		log.Fatal(err)
	}
}
