package dns

import "testing"

func TestServiceMapper_AWS(t *testing.T) {
	m := NewServiceMapper()

	tests := []struct {
		domain string
		want   string
	}{
		{"my-bucket.s3.amazonaws.com", "S3"},             // bucket-prefix S3
		{"us-east-1.s3.amazonaws.com", "S3"},             // region-prefixed S3 path
		{"sqs.us-east-1.amazonaws.com", "SQS"},           // regional SQS endpoint
		{"my-queue.sqs.amazonaws.com", "SQS"},            // queue-prefix
		{"abc.dynamodb.amazonaws.com", "DynamoDB"},       // table-prefix
		{"dynamodb.us-east-1.amazonaws.com", "DynamoDB"}, // regional DynamoDB
		{"sns.eu-west-1.amazonaws.com", "SNS"},           // regional SNS
		{"xxx.cloudfront.net", "CloudFront"},
		{"d1234.cloudfront.net", "CloudFront"},
	}

	for _, tt := range tests {
		got := m.Lookup(tt.domain)
		if got != tt.want {
			t.Errorf("Lookup(%q) = %q, want %q", tt.domain, got, tt.want)
		}
	}
}

func TestServiceMapper_GCP(t *testing.T) {
	m := NewServiceMapper()

	tests := []struct {
		domain string
		want   string
	}{
		{"storage.googleapis.com", "Cloud Storage"},
		{"my-project.storage.googleapis.com", "Cloud Storage"},
		{"bigquery.googleapis.com", "BigQuery"},
		{"gcr.io", "Container Registry"},
		{"us-docker.pkg.dev", "Artifact Registry"},
	}

	for _, tt := range tests {
		got := m.Lookup(tt.domain)
		if got != tt.want {
			t.Errorf("Lookup(%q) = %q, want %q", tt.domain, got, tt.want)
		}
	}
}

func TestServiceMapper_Azure(t *testing.T) {
	m := NewServiceMapper()

	tests := []struct {
		domain string
		want   string
	}{
		{"myaccount.blob.core.windows.net", "Azure Blob"},
		{"mydb.database.windows.net", "Azure SQL"},
		{"myaccount.documents.azure.com", "Cosmos DB"},
		{"myvault.vault.azure.net", "Key Vault"},
		{"myregistry.azurecr.io", "Container Registry"},
	}

	for _, tt := range tests {
		got := m.Lookup(tt.domain)
		if got != tt.want {
			t.Errorf("Lookup(%q) = %q, want %q", tt.domain, got, tt.want)
		}
	}
}

func TestServiceMapper_Unknown(t *testing.T) {
	m := NewServiceMapper()

	if got := m.Lookup("example.com"); got != "" {
		t.Errorf("Lookup(example.com) = %q, want empty", got)
	}
}

func TestServiceMapper_CaseInsensitive(t *testing.T) {
	m := NewServiceMapper()

	if got := m.Lookup("MyBucket.S3.AMAZONAWS.COM"); got != "S3" {
		t.Errorf("Lookup with upper case = %q, want S3", got)
	}
}

func TestServiceMapper_AddRule(t *testing.T) {
	m := NewServiceMapper()
	m.AddRule(".internal.company.com", "Internal API")

	if got := m.Lookup("payments.internal.company.com"); got != "Internal API" {
		t.Errorf("Lookup custom rule = %q, want Internal API", got)
	}
}
