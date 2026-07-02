package nats

import (
	"io"
	"log/slog"
	"strings"
	"testing"
)

func TestValidateSubjectToken(t *testing.T) {
	tests := []struct {
		name    string
		token   string
		wantErr bool
	}{
		{name: "simple cluster name", token: "prod-eu", wantErr: false},
		{name: "uuid cluster identity", token: "3f8a2c1e-9b7d-4e2a-8c1f-0d5e6a7b8c9d", wantErr: false}, // gitleaks:allow — sample UUID fixture
		{name: "dotted hostname keeps working", token: "ip-10-0-1-5.ec2.internal", wantErr: false},     // gitleaks:allow — sample hostname fixture
		{name: "empty token", token: "", wantErr: true},
		{name: "leading dot yields empty part", token: ".prod", wantErr: true},
		{name: "trailing dot yields empty part", token: "prod.", wantErr: true},
		{name: "double dot yields empty part", token: "prod..eu", wantErr: true},
		{name: "embedded space", token: "prod eu", wantErr: true},
		{name: "tab character", token: "prod\teu", wantErr: true},
		{name: "newline character", token: "prod\n", wantErr: true},
		{name: "star wildcard", token: "prod*", wantErr: true},
		{name: "gt wildcard", token: "prod>", wantErr: true},
		{name: "control character", token: "prod\x00", wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateSubjectToken(tt.token)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateSubjectToken(%q) error = %v, wantErr %v", tt.token, err, tt.wantErr)
			}
		})
	}
}

// TestNewPublisher_RejectsInvalidSubjectTokens is the regression test for the
// silent-drop bug: a default -cluster "" built the subject
// "tollwing.flows..host", NATS rejected every publish, and the agent
// warn-and-dropped each flow batch forever. Construction must fail loudly
// instead. Config validation runs before the NATS dial, so no server is needed.
func TestNewPublisher_RejectsInvalidSubjectTokens(t *testing.T) {
	log := slog.New(slog.NewTextHandler(io.Discard, nil))

	tests := []struct {
		name    string
		cluster string
		node    string
		wantSub string // substring the error must mention
	}{
		{name: "empty cluster", cluster: "", node: "node-1", wantSub: "cluster"},
		{name: "empty node", cluster: "prod", node: "", wantSub: "node"},
		{name: "wildcard cluster", cluster: "prod.*", node: "node-1", wantSub: "cluster"},
		{name: "whitespace node", cluster: "prod", node: "node 1", wantSub: "node"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pub, err := NewPublisher(PublisherConfig{
				Cluster: tt.cluster,
				Node:    tt.node,
			}, log)
			if err == nil {
				pub.Close()
				t.Fatalf("NewPublisher(cluster=%q, node=%q) = nil error, want construction failure", tt.cluster, tt.node)
			}
			if !strings.Contains(err.Error(), tt.wantSub) {
				t.Errorf("error %q does not name the offending field %q", err, tt.wantSub)
			}
		})
	}
}

func TestPublisherConfig_SetDefaults(t *testing.T) {
	cfg := PublisherConfig{Cluster: "prod", Node: "node-1"}
	cfg.setDefaults()

	if cfg.URL == "" {
		t.Error("URL default not applied")
	}
	if cfg.StreamReplicas != 1 {
		t.Errorf("StreamReplicas = %d, want 1", cfg.StreamReplicas)
	}
	if cfg.StreamMaxAge == 0 {
		t.Error("StreamMaxAge default not applied")
	}
	if cfg.StreamMaxBytes == 0 {
		t.Error("StreamMaxBytes default not applied")
	}
}
