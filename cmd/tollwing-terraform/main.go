// tollwing-terraform estimates the network cost impact of Terraform plan changes.
//
// Usage:
//
//	terraform show -json plan.out | tollwing-terraform --plan -
//	tollwing-terraform --plan plan.json
//	tollwing-terraform --plan plan.json --nat-egress-gb 500 --peering-gb 200
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/tollwing/tollwing/pkg/terraform"
)

func main() {
	var (
		planFile    = flag.String("plan", "", "path to terraform plan JSON (use - for stdin)")
		natEgressGB = flag.Float64("nat-egress-gb", 0, "monthly NAT egress in GB (0 = estimate)")
		peeringGB   = flag.Float64("peering-gb", 0, "monthly peering traffic in GB (0 = estimate)")
		transitGWGB = flag.Float64("transit-gw-gb", 0, "monthly transit gateway traffic in GB (0 = estimate)")
		outputJSON  = flag.Bool("json", false, "output as JSON")
	)
	flag.Parse()

	if *planFile == "" {
		fmt.Fprintln(os.Stderr, "usage: tollwing-terraform --plan <plan.json>")
		fmt.Fprintln(os.Stderr, "       terraform show -json plan.out | tollwing-terraform --plan -")
		os.Exit(1)
	}

	// Open plan file or stdin.
	var file *os.File
	if *planFile == "-" {
		file = os.Stdin
	} else {
		var err error
		file, err = os.Open(*planFile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "open plan: %v\n", err)
			os.Exit(1)
		}
		defer file.Close()
	}

	plan, err := terraform.ParsePlan(file)
	if err != nil {
		fmt.Fprintf(os.Stderr, "parse plan: %v\n", err)
		os.Exit(1)
	}

	changes := terraform.ExtractNetworkChanges(plan)
	if len(changes) == 0 {
		fmt.Println("No network-related changes found in plan.")
		return
	}

	traffic := &terraform.TrafficData{
		MonthlyNATEgressGB: *natEgressGB,
		MonthlyPeeringGB:   *peeringGB,
		MonthlyTransitGWGB: *transitGWGB,
	}

	result := terraform.Estimate(changes, traffic)

	if *outputJSON {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		enc.Encode(result)
		return
	}

	printResult(result)
}

func printResult(result terraform.EstimateResult) {
	fmt.Printf("Tollwing Terraform Cost Estimation\n")
	fmt.Printf("%s\n\n", strings.Repeat("=", 40))

	for i, c := range result.Changes {
		fmt.Printf("%d. %s\n", i+1, c.Change.Description)
		fmt.Printf("   Type:       %s\n", c.Change.Type)
		fmt.Printf("   Action:     %s\n", c.Change.Action)

		if c.EstimatedDeltaUSD != 0 {
			sign := "+"
			if c.EstimatedDeltaUSD < 0 {
				sign = ""
			}
			fmt.Printf("   Cost delta: %s$%.2f/month\n", sign, c.EstimatedDeltaUSD)
		}

		fmt.Printf("   Confidence: %s\n", c.Confidence)
		fmt.Printf("   Detail:     %s\n", c.Explanation)

		if len(c.AffectedServices) > 0 {
			fmt.Printf("   Affected:   %s\n", strings.Join(c.AffectedServices, ", "))
		}
		fmt.Println()
	}

	fmt.Printf("%s\n", strings.Repeat("-", 40))
	fmt.Printf("Network changes:     %d\n", result.NetworkChanges)
	fmt.Printf("Analyzed resources:  %d\n", result.AnalyzedResources)

	sign := "+"
	if result.TotalDeltaUSD < 0 {
		sign = ""
	}
	fmt.Printf("Estimated monthly:   %s$%.2f/month\n", sign, result.TotalDeltaUSD)
}
