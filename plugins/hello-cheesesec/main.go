package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"os"
	"runtime"
	"strings"
)

const (
	version       = "0.1.0"
	protocol      = "cheesewaf-crp-sidecar-process.v1"
	maxFrameBytes = 64 << 10
)

var errRequest = errors.New("invalid sidecar request")

type identity struct {
	PluginID         string `json:"plugin_id"`
	Namespace        string `json:"namespace"`
	Version          string `json:"version"`
	ManifestIdentity string `json:"manifest_identity"`
	ArtifactIdentity string `json:"artifact_identity"`
}

type request struct {
	SchemaVersion string   `json:"schema_version"`
	Sequence      uint64   `json:"sequence"`
	Operation     string   `json:"operation"`
	Mode          string   `json:"mode"`
	Identity      identity `json:"identity"`
}

type acknowledgement struct {
	SchemaVersion string `json:"schema_version"`
	Sequence      uint64 `json:"sequence"`
	Operation     string `json:"operation"`
	Status        string `json:"status"`
	Mode          string `json:"mode"`
}

func pluginID() string { return "hello-cheesesec-" + runtime.GOOS + "-" + runtime.GOARCH }

func objectFields(data []byte, fields ...string) (map[string]json.RawMessage, error) {
	decoder := json.NewDecoder(bytes.NewReader(data))
	first, err := decoder.Token()
	if err != nil || first != json.Delim('{') {
		return nil, errRequest
	}
	allowed := make(map[string]bool, len(fields))
	for _, field := range fields {
		allowed[field] = true
	}
	values := make(map[string]json.RawMessage, len(fields))
	for decoder.More() {
		key, err := decoder.Token()
		name, ok := key.(string)
		if err != nil || !ok || !allowed[name] {
			return nil, errRequest
		}
		if _, exists := values[name]; exists {
			return nil, errRequest
		}
		var raw json.RawMessage
		if decoder.Decode(&raw) != nil || bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
			return nil, errRequest
		}
		values[name] = raw
	}
	last, err := decoder.Token()
	if err != nil || last != json.Delim('}') || len(values) != len(fields) {
		return nil, errRequest
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return nil, errRequest
	}
	return values, nil
}

func parseRequest(data []byte) (request, error) {
	fields, err := objectFields(data, "schema_version", "sequence", "operation", "mode", "identity")
	if err != nil {
		return request{}, errRequest
	}
	if _, err := objectFields(fields["identity"], "plugin_id", "namespace", "version", "manifest_identity", "artifact_identity"); err != nil {
		return request{}, errRequest
	}
	var message request
	if json.Unmarshal(data, &message) != nil || message.SchemaVersion != protocol || message.Sequence == 0 || message.Identity.PluginID != pluginID() || message.Identity.Namespace != "official/"+pluginID() || message.Identity.Version != version || !digest(message.Identity.ManifestIdentity) || !digest(message.Identity.ArtifactIdentity) {
		return request{}, errRequest
	}
	return message, nil
}

func digest(value string) bool {
	if len(value) != 64 {
		return false
	}
	for _, character := range value {
		if !strings.ContainsRune("0123456789abcdef", character) {
			return false
		}
	}
	return true
}

func run(input io.Reader, output io.Writer) error {
	reader := bufio.NewReaderSize(input, maxFrameBytes)
	encoder := json.NewEncoder(output)
	var bound identity
	var lastSequence uint64
	mode := "observe"
	for {
		line, err := reader.ReadSlice('\n')
		if errors.Is(err, io.EOF) && len(line) == 0 && lastSequence == 0 {
			return nil
		}
		if err != nil || len(line) > maxFrameBytes {
			return errRequest
		}
		message, err := parseRequest(line)
		if err != nil || lastSequence == ^uint64(0) || message.Sequence != lastSequence+1 {
			return errRequest
		}
		if lastSequence == 0 {
			if message.Operation != "start" || message.Mode != "observe" {
				return errRequest
			}
			bound = message.Identity
		} else {
			if message.Identity != bound {
				return errRequest
			}
			switch message.Operation {
			case "mode":
				if !(mode == "observe" && message.Mode == "canary" || mode == "canary" && message.Mode == "active") {
					return errRequest
				}
				mode = message.Mode
			case "probe", "stop":
				if message.Mode != mode {
					return errRequest
				}
			default:
				return errRequest
			}
		}
		ack := acknowledgement{SchemaVersion: protocol, Sequence: message.Sequence, Operation: message.Operation, Status: "ok", Mode: mode}
		if err := encoder.Encode(ack); err != nil {
			return err
		}
		lastSequence = message.Sequence
		if message.Operation == "stop" {
			return nil
		}
	}
}

func main() {
	if len(os.Args) == 2 && os.Args[1] == "--describe" {
		err := json.NewEncoder(os.Stdout).Encode(struct {
			PluginID string `json:"plugin_id"`
			Version  string `json:"version"`
			Protocol string `json:"protocol"`
			Platform string `json:"platform"`
			Purpose  string `json:"purpose"`
		}{pluginID(), version, protocol, runtime.GOOS + "/" + runtime.GOARCH, "lifecycle demonstration; no protection or data collection"})
		if err != nil {
			os.Exit(2)
		}
		return
	}
	if len(os.Args) != 1 {
		_, _ = io.WriteString(os.Stderr, "usage: hello-cheesesec [--describe]\n")
		os.Exit(2)
	}
	if err := run(os.Stdin, os.Stdout); err != nil {
		_, _ = io.WriteString(os.Stderr, "hello-cheesesec: invalid sidecar session\n")
		os.Exit(2)
	}
}
