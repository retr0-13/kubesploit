package agent

import (
	"fmt"
	"os"
	"strings"
	"time"
)

type Recorder struct {
	FileName string
}

func NewRecorder(filename string) Recorder {
	r := Recorder{
		FileName: filename,
	}

	return r
}

func (r *Recorder) recordCommand(command string, args []string){
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("%s [*] Payload:\n", time.Now().UTC().Format(time.RFC3339)))
	sb.WriteString(command + "\n")
	for _, arg := range(args) {
		sb.WriteString(arg + "\n")
	}
	sb.WriteString("\n")
	recordToFile(sb.String())
}

func (r *Recorder) recordOutput(output string){
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("%s [*] Output:\n", time.Now().UTC().Format(time.RFC3339)))
	sb.WriteString(output + "\n")
	recordToFile(sb.String())
}


func recordToFile(output string){
	filename := "/tmp/agent_record"

	f, err := os.OpenFile(filename, os.O_APPEND|os.O_WRONLY|os.O_CREATE, 0644)
	if err != nil {
		panic(err)
	}

	defer f.Close()
	if _, err = f.WriteString(output); err != nil {
		message("warn", fmt.Sprintf("Failed to write to file: %s, error: %s", filename, output))
	}
}
