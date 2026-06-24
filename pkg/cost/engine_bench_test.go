package cost

import (
	"testing"

	"github.com/tollwing/tollwing/pkg/classifier"
)

func BenchmarkEngine_Calculate(b *testing.B) {
	store := NewRateCardStore()
	store.Set(DefaultAWSRateCard("us-east-1"))
	engine := NewEngine(store)

	// Build a batch of 1000 FlowRecords with mixed traffic types.
	trafficTypes := []classifier.TrafficType{
		classifier.SameZone,
		classifier.CrossAZ,
		classifier.CrossRegion,
		classifier.InternetEgress,
		classifier.NATGatewayEgress,
		classifier.VPCPeering,
		classifier.TransitGateway,
		classifier.VPCEndpoint,
	}

	flows := make([]FlowRecord, 1000)
	for i := range flows {
		tt := trafficTypes[i%len(trafficTypes)]
		flows[i] = FlowRecord{
			TrafficType: tt,
			TxBytes:     uint64((i + 1)) * 1024 * 1024, // varying sizes
			RxBytes:     uint64((i + 1)) * 512 * 1024,
		}
	}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		// Reset billing period each iteration to avoid cumulative state
		// affecting benchmark consistency.
		engine.ResetBillingPeriod()
		engine.Calculate("aws", "us-east-1", flows)
	}
}
