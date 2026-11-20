package main

import (
	"encoding/json"
	"log"
	"os"

	"github.com/projectdiscovery/nuclei/v3/pkg/output"
	"github.com/projectdiscovery/nuclei/v3/pkg/types"
)

func main() {
	if len(os.Args) != 2 {
		log.Fatal("supply one new output path")
	}
	writer, err := output.NewStandardWriter(&types.Options{JSONL: true, Output: os.Args[1], OmitRawRequests: true, NoColor: true})
	if err != nil {
		log.Fatal(err)
	}
	defer writer.Close()
	writer.DisableStdout = true
	for _, status := range []bool{true, false} {
		var event output.ResultEvent
		if err := json.Unmarshal([]byte(`{"template-id":"health-label","info":{"name":"Health label","severity":"info"},"type":"http","host":"192.0.2.10","url":"http://192.0.2.10","matched-at":"http://192.0.2.10/health","matcher-name":"health-text"}`), &event); err != nil {
			log.Fatal(err)
		}
		event.MatcherStatus = status
		if err := writer.Write(&event); err != nil {
			log.Fatal(err)
		}
	}
}
