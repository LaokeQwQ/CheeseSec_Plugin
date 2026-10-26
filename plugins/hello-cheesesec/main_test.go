package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"runtime"
	"strings"
	"testing"
)

func identityJSON() string {
	id := "hello-cheesesec-" + runtime.GOOS + "-" + runtime.GOARCH
	return `{"plugin_id":"` + id + `","namespace":"official/` + id + `","version":"0.1.0","manifest_identity":"` + strings.Repeat("a", 64) + `","artifact_identity":"` + strings.Repeat("b", 64) + `"}`
}

func frame(sequence int, operation, mode string) string {
	return `{"schema_version":"cheesewaf-crp-sidecar-process.v1","sequence":` + jsonNumber(sequence) + `,"operation":"` + operation + `","mode":"` + mode + `","identity":` + identityJSON() + "}\n"
}

func jsonNumber(n int) string {
	data, _ := json.Marshal(n)
	return string(data)
}

func TestLifecycleMatchesHostProtocol(t *testing.T) {
	input := frame(1, "start", "observe") + frame(2, "probe", "observe") + frame(3, "mode", "canary") + frame(4, "probe", "canary") + frame(5, "mode", "active") + frame(6, "probe", "active") + frame(7, "stop", "active")
	var output bytes.Buffer
	if err := run(strings.NewReader(input), &output); err != nil {
		t.Fatalf("valid host lifecycle rejected: %v", err)
	}
	lines := strings.Split(strings.TrimSpace(output.String()), "\n")
	if len(lines) != 7 {
		t.Fatalf("got %d acknowledgements, want 7", len(lines))
	}
	wantOperations := []string{"start", "probe", "mode", "probe", "mode", "probe", "stop"}
	wantModes := []string{"observe", "observe", "canary", "canary", "active", "active", "active"}
	for i, line := range lines {
		var got map[string]any
		if err := json.Unmarshal([]byte(line), &got); err != nil {
			t.Fatal(err)
		}
		if len(got) != 5 || got["schema_version"] != "cheesewaf-crp-sidecar-process.v1" || got["sequence"] != float64(i+1) || got["operation"] != wantOperations[i] || got["mode"] != wantModes[i] || got["status"] != "ok" {
			t.Fatalf("unexpected acknowledgement: %s", line)
		}
	}
}

func TestInvalidInputsFailClosed(t *testing.T) {
	validStart := frame(1, "start", "observe")
	tests := map[string]string{
		"wrong schema":             strings.Replace(validStart, "process.v1", "process.v2", 1),
		"wrong plugin":             strings.Replace(validStart, `"plugin_id":"hello-cheesesec-`, `"plugin_id":"other-`, 1),
		"wrong namespace":          strings.Replace(validStart, "official/hello-cheesesec-", "personal/user/hello-cheesesec-", 1),
		"wrong version":            strings.Replace(validStart, "0.1.0", "9.9.9", 1),
		"bad digest":               strings.Replace(validStart, strings.Repeat("a", 64), strings.Repeat("g", 64), 1),
		"missing identity":         strings.Replace(validStart, `,"identity":`+identityJSON(), "", 1),
		"unknown field":            strings.Replace(validStart, `"sequence":1`, `"sequence":1,"command":"whoami"`, 1),
		"duplicate sequence":       strings.Replace(validStart, `"sequence":1`, `"sequence":1,"sequence":2`, 1),
		"duplicate identity field": strings.Replace(validStart, `"plugin_id":`, `"plugin_id":"other","plugin_id":`, 1),
		"null identity":            strings.Replace(validStart, identityJSON(), "null", 1),
		"negative sequence":        strings.Replace(validStart, `"sequence":1`, `"sequence":-1`, 1),
		"fractional sequence":      strings.Replace(validStart, `"sequence":1`, `"sequence":1.5`, 1),
		"trailing json":            strings.TrimSuffix(validStart, "\n") + "{}\n",
		"not object":               "[]\n",
		"empty frame":              "\n",
		"no newline":               strings.TrimSuffix(validStart, "\n"),
		"oversize frame":           strings.Repeat(" ", 64<<10) + validStart,
		"start active":             frame(1, "start", "active"),
		"probe before start":       frame(1, "probe", "observe"),
		"skip sequence":            validStart + frame(3, "stop", "observe"),
		"replay sequence":          validStart + frame(1, "stop", "observe"),
		"restart":                  validStart + frame(2, "start", "observe"),
		"skip canary":              validStart + frame(2, "mode", "active"),
		"probe changes mode":       validStart + frame(2, "probe", "canary"),
		"identity mutation":        validStart + strings.Replace(frame(2, "probe", "observe"), strings.Repeat("b", 64), strings.Repeat("c", 64), 1),
		"unexpected eof":           validStart,
	}
	for name, input := range tests {
		t.Run(name, func(t *testing.T) {
			var output bytes.Buffer
			if err := run(strings.NewReader(input), &output); err == nil {
				t.Fatal("untrusted request accepted")
			}
			if strings.Contains(output.String(), "whoami") || strings.Contains(output.String(), "manifest_identity") {
				t.Fatal("acknowledgement leaked request-controlled fields")
			}
		})
	}
}

func TestStopDoesNotConsumeAnotherFrame(t *testing.T) {
	input := frame(1, "start", "observe") + frame(2, "stop", "observe") + "not-json\n"
	if err := run(strings.NewReader(input), io.Discard); err != nil {
		t.Fatal(err)
	}
}

type failedWriter struct{}

func (failedWriter) Write([]byte) (int, error) { return 0, errors.New("broken pipe") }

func TestOutputFailureStopsProcess(t *testing.T) {
	if err := run(strings.NewReader(frame(1, "start", "observe")), failedWriter{}); err == nil {
		t.Fatal("output failure ignored")
	}
}
