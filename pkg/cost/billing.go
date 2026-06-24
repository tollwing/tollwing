package cost

import "time"

// BillingData holds parsed billing records for reconciliation.
type BillingData struct {
	Provider  string
	Period    BillingPeriod
	LineItems []BillingLineItem
	TotalCost float64
}

// BillingPeriod represents the time range of billing data.
type BillingPeriod struct {
	Start time.Time
	End   time.Time
}

// BillingLineItem is a single line from a cloud bill.
type BillingLineItem struct {
	Timestamp   time.Time
	UsageType   string // e.g., "DataTransfer-Out-Bytes", "NatGateway-Bytes"
	Region      string
	Service     string  // e.g., "AmazonEC2", "AmazonS3"
	Resource    string  // resource ARN/ID
	UsageAmount float64 // GB
	CostUSD     float64
}
