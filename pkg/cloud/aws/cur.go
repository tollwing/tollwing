package aws

import (
	"compress/gzip"
	"context"
	"encoding/csv"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/tollwing/tollwing/pkg/cost"
)

// CUR (Cost and Usage Report) is AWS's detailed billing export. CURs are
// delivered to S3 as .csv.gz (legacy) or .parquet (v2). We support the CSV
// flavor here, reading either from S3 or a local file path.
//
// Expected column headers we look for (CUR v1 naming):
//   - lineItem/UsageStartDate
//   - lineItem/ProductCode              (e.g. "AmazonEC2")
//   - lineItem/UsageType                (e.g. "USW2-DataTransfer-Out-Bytes")
//   - lineItem/ResourceId
//   - lineItem/UsageAmount
//   - lineItem/UnblendedCost
//   - product/region

const (
	colUsageStart   = "lineItem/UsageStartDate"
	colProductCode  = "lineItem/ProductCode"
	colUsageType    = "lineItem/UsageType"
	colResourceID   = "lineItem/ResourceId"
	colUsageAmount  = "lineItem/UsageAmount"
	colUnblendedUSD = "lineItem/UnblendedCost"
	colRegion       = "product/region"
)

// ParseCURFile reads a single CUR CSV file (optionally gzipped) and returns
// a BillingData slice filtered to [start, end). Only network-related usage
// types are retained — compute, storage, etc. are skipped since they are not
// relevant to reconciliation.
func ParseCURFile(ctx context.Context, path string, start, end time.Time) (*cost.BillingData, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open CUR file: %w", err)
	}
	defer f.Close()

	var reader io.Reader = f
	if strings.HasSuffix(strings.ToLower(path), ".gz") {
		gz, err := gzip.NewReader(f)
		if err != nil {
			return nil, fmt.Errorf("gzip: %w", err)
		}
		defer gz.Close()
		reader = gz
	}

	return parseCURReader(reader, start, end)
}

// parseCURReader parses CUR CSV content from any io.Reader.
func parseCURReader(r io.Reader, start, end time.Time) (*cost.BillingData, error) {
	csvReader := csv.NewReader(r)
	csvReader.ReuseRecord = false

	header, err := csvReader.Read()
	if err != nil {
		return nil, fmt.Errorf("read CUR header: %w", err)
	}

	idx := indexColumns(header)
	if idx[colUsageType] < 0 || idx[colUnblendedUSD] < 0 {
		return nil, fmt.Errorf("CUR missing required columns (UsageType, UnblendedCost)")
	}

	data := &cost.BillingData{
		Provider: "aws",
		Period:   cost.BillingPeriod{Start: start, End: end},
	}

	for {
		row, err := csvReader.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			return data, fmt.Errorf("read CUR row: %w", err)
		}

		usageType := getCol(row, idx, colUsageType)
		if !isNetworkUsageType(usageType) {
			continue
		}

		ts := parseCURTime(getCol(row, idx, colUsageStart))
		if !ts.IsZero() {
			if !start.IsZero() && ts.Before(start) {
				continue
			}
			if !end.IsZero() && !ts.Before(end) {
				continue
			}
		}

		usageAmount, _ := strconv.ParseFloat(getCol(row, idx, colUsageAmount), 64)
		costUSD, _ := strconv.ParseFloat(getCol(row, idx, colUnblendedUSD), 64)

		item := cost.BillingLineItem{
			Timestamp:   ts,
			UsageType:   usageType,
			Region:      getCol(row, idx, colRegion),
			Service:     getCol(row, idx, colProductCode),
			Resource:    getCol(row, idx, colResourceID),
			UsageAmount: bytesToGB(usageType, usageAmount),
			CostUSD:     costUSD,
		}
		data.LineItems = append(data.LineItems, item)
		data.TotalCost += costUSD
	}

	return data, nil
}

// ParseCURDirectory parses every .csv / .csv.gz file under dir, merging
// their network line items into a single BillingData.
func ParseCURDirectory(ctx context.Context, dir string, start, end time.Time) (*cost.BillingData, error) {
	combined := &cost.BillingData{
		Provider: "aws",
		Period:   cost.BillingPeriod{Start: start, End: end},
	}

	err := filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return err
		}
		lower := strings.ToLower(info.Name())
		if !strings.HasSuffix(lower, ".csv") && !strings.HasSuffix(lower, ".csv.gz") {
			return nil
		}
		part, err := ParseCURFile(ctx, path, start, end)
		if err != nil {
			return fmt.Errorf("parse %s: %w", path, err)
		}
		combined.LineItems = append(combined.LineItems, part.LineItems...)
		combined.TotalCost += part.TotalCost
		return nil
	})
	if err != nil {
		return combined, err
	}
	return combined, nil
}

func indexColumns(header []string) map[string]int {
	idx := map[string]int{
		colUsageStart:   -1,
		colProductCode:  -1,
		colUsageType:    -1,
		colResourceID:   -1,
		colUsageAmount:  -1,
		colUnblendedUSD: -1,
		colRegion:       -1,
	}
	for i, name := range header {
		if _, ok := idx[name]; ok {
			idx[name] = i
		}
	}
	return idx
}

func getCol(row []string, idx map[string]int, col string) string {
	i := idx[col]
	if i < 0 || i >= len(row) {
		return ""
	}
	return row[i]
}

func parseCURTime(s string) time.Time {
	if s == "" {
		return time.Time{}
	}
	// CUR uses ISO 8601 with milliseconds, e.g. "2024-03-01T00:00:00Z".
	layouts := []string{
		time.RFC3339,
		"2006-01-02T15:04:05Z",
		"2006-01-02 15:04:05",
	}
	for _, layout := range layouts {
		if t, err := time.Parse(layout, s); err == nil {
			return t
		}
	}
	return time.Time{}
}

// isNetworkUsageType returns true for CUR usage types that represent
// network traffic we care about for reconciliation.
func isNetworkUsageType(usageType string) bool {
	if usageType == "" {
		return false
	}
	lower := strings.ToLower(usageType)
	keywords := []string{
		"datatransfer",
		"data-transfer",
		"bytes", // covers *-Bytes meters
		"natgateway",
		"nat-gateway",
		"vpcpeering",
		"transitgateway",
		"transit-gateway",
		"vpn",
	}
	for _, kw := range keywords {
		if strings.Contains(lower, kw) {
			return true
		}
	}
	return false
}

// bytesToGB converts usage amounts from bytes to GB when the usage type
// indicates a byte-denominated meter. CUR sometimes reports bytes for
// "*-Bytes" meters and GB for others — we normalize to GB.
func bytesToGB(usageType string, amount float64) float64 {
	if strings.HasSuffix(strings.ToLower(usageType), "-bytes") {
		return amount / (1024 * 1024 * 1024)
	}
	return amount
}
