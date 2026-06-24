package dns

import "strings"

// ServiceMapper maps domain names to cloud service identifiers.
// Pattern matching supports suffix-based rules (e.g. *.s3.amazonaws.com → "S3").
type ServiceMapper struct {
	rules []mappingRule
}

type mappingRule struct {
	suffix  string
	service string
}

// NewServiceMapper creates a mapper with built-in rules for AWS, GCP, and Azure services.
func NewServiceMapper() *ServiceMapper {
	return &ServiceMapper{
		rules: []mappingRule{
			// AWS
			{".s3.amazonaws.com", "S3"},
			{".s3-accesspoint.amazonaws.com", "S3"},
			{".dynamodb.amazonaws.com", "DynamoDB"},
			{".sqs.amazonaws.com", "SQS"},
			{".sns.amazonaws.com", "SNS"},
			{".kinesis.amazonaws.com", "Kinesis"},
			{".rds.amazonaws.com", "RDS"},
			{".elasticache.amazonaws.com", "ElastiCache"},
			{".redshift.amazonaws.com", "Redshift"},
			{".lambda.amazonaws.com", "Lambda"},
			{".execute-api.amazonaws.com", "API Gateway"},
			{".elb.amazonaws.com", "ELB"},
			{".cloudfront.net", "CloudFront"},
			{".ecr.amazonaws.com", "ECR"},
			{".secretsmanager.amazonaws.com", "Secrets Manager"},
			{".monitoring.amazonaws.com", "CloudWatch"},
			{".logs.amazonaws.com", "CloudWatch Logs"},
			{".events.amazonaws.com", "EventBridge"},
			{".sts.amazonaws.com", "STS"},
			{".ec2.amazonaws.com", "EC2"},

			// GCP
			{".storage.googleapis.com", "Cloud Storage"},
			{".bigquery.googleapis.com", "BigQuery"},
			{".pubsub.googleapis.com", "Pub/Sub"},
			{".firestore.googleapis.com", "Firestore"},
			{".spanner.googleapis.com", "Spanner"},
			{".run.googleapis.com", "Cloud Run"},
			{".cloudfunctions.googleapis.com", "Cloud Functions"},
			{".container.googleapis.com", "GKE"},
			{".compute.googleapis.com", "Compute Engine"},
			{".sqladmin.googleapis.com", "Cloud SQL"},
			{".redis.googleapis.com", "Memorystore"},
			{".logging.googleapis.com", "Cloud Logging"},
			{".monitoring.googleapis.com", "Cloud Monitoring"},
			{".artifactregistry.googleapis.com", "Artifact Registry"},
			{".gcr.io", "Container Registry"},
			{".pkg.dev", "Artifact Registry"},

			// Azure
			{".blob.core.windows.net", "Azure Blob"},
			{".table.core.windows.net", "Azure Table"},
			{".queue.core.windows.net", "Azure Queue"},
			{".file.core.windows.net", "Azure Files"},
			{".database.windows.net", "Azure SQL"},
			{".documents.azure.com", "Cosmos DB"},
			{".redis.cache.windows.net", "Azure Cache for Redis"},
			{".servicebus.windows.net", "Service Bus"},
			{".azurecr.io", "Container Registry"},
			{".azurewebsites.net", "App Service"},
			{".vault.azure.net", "Key Vault"},
			{".cognitiveservices.azure.com", "Cognitive Services"},
			{".search.windows.net", "Azure Search"},
			{".eventgrid.azure.net", "Event Grid"},

			// Common third-party / CDN
			{".datadog.com", "Datadog"},
			{".datadoghq.com", "Datadog"},
			{".newrelic.com", "New Relic"},
			{".pagerduty.com", "PagerDuty"},
			{".slack.com", "Slack"},
			{".github.com", "GitHub"},
			{".docker.io", "Docker Hub"},
		},
	}
}

// Lookup returns the cloud service name for a domain, or empty string.
//
// Matches three shapes against each suffix rule:
//
//  1. Exact-tail: domain ends with rule.suffix.
//     `bucket.s3.amazonaws.com` matches `.s3.amazonaws.com`.
//
//  2. Bare hit:   domain equals rule.suffix without the leading dot.
//     `s3.amazonaws.com` matches `.s3.amazonaws.com`.
//
//  3. AWS regional-endpoint form: for rules of shape
//     `.<service>.amazonaws.com`, also match domains of shape
//     `<service>.<anything>.amazonaws.com` — this is the
//     canonical AWS regional endpoint format (dynamodb.us-east-
//     1.amazonaws.com, sqs.eu-west-1.amazonaws.com, etc.). The
//     bucket-prefix form (#1) handles S3 / cross-account
//     patterns; this branch handles the standard service
//     endpoint.
func (m *ServiceMapper) Lookup(domain string) string {
	lower := strings.ToLower(domain)
	const awsTail = ".amazonaws.com"
	hasAWSTail := strings.HasSuffix(lower, awsTail)
	for _, rule := range m.rules {
		if strings.HasSuffix(lower, rule.suffix) || lower == rule.suffix[1:] {
			return rule.service
		}
		// Regional-endpoint form: applies only to AWS rules
		// (suffix ends with .amazonaws.com).
		if !hasAWSTail || !strings.HasSuffix(rule.suffix, awsTail) {
			continue
		}
		// Extract the service token: ".dynamodb.amazonaws.com"
		// → "dynamodb". The rule's suffix starts with ".", and
		// the segment between that and ".amazonaws.com" is the
		// service name.
		token := rule.suffix[1 : len(rule.suffix)-len(awsTail)]
		if token == "" {
			continue
		}
		if strings.HasPrefix(lower, token+".") {
			return rule.service
		}
	}
	return ""
}

// AddRule adds a custom mapping rule. The suffix should start with a dot
// (e.g. ".my-service.internal").
func (m *ServiceMapper) AddRule(suffix, service string) {
	m.rules = append(m.rules, mappingRule{suffix: suffix, service: service})
}
