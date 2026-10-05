// Package metricstest gives tests Metrics recorded in memory, and reads the
// recorded values back by instrument name and attributes.
package metricstest

import (
	"context"
	"crypto/tls"
	"testing"

	"github.com/dihedron/openstack-spiffe/internal/issuer/metrics"
	"go.opentelemetry.io/otel/attribute"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"
)

// Reader reads back what a Metrics recorded.
type Reader struct {
	reader *sdkmetric.ManualReader
}

// New returns Metrics recorded in memory, with the given configuration
// (project_attribute, max_projects; runtime metrics off), and their reader.
func New(t *testing.T, cfg metrics.Config) (*metrics.Metrics, *Reader) {
	t.Helper()
	reader := sdkmetric.NewManualReader()
	cfg.Runtime = false
	m, err := metrics.New(context.Background(), cfg, metrics.Resource{Component: "test"}, tls.VersionTLS13, metrics.WithReader(reader))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = m.Shutdown(context.Background()) })
	return m, &Reader{reader: reader}
}

// Point is a recorded data point: its attributes and its value (the sum of
// a counter, the value of a gauge, truncated to an integer, or the count of
// a histogram).
type Point struct {
	Attributes map[string]string
	Value      int64
}

// Points returns the data points of the named instrument.
func (r *Reader) Points(t *testing.T, name string) []Point {
	t.Helper()
	var rm metricdata.ResourceMetrics
	if err := r.reader.Collect(context.Background(), &rm); err != nil {
		t.Fatal(err)
	}
	var points []Point
	for _, sm := range rm.ScopeMetrics {
		for _, m := range sm.Metrics {
			if m.Name != name {
				continue
			}
			switch data := m.Data.(type) {
			case metricdata.Sum[int64]:
				for _, dp := range data.DataPoints {
					points = append(points, Point{Attributes: attributes(dp.Attributes), Value: dp.Value})
				}
			case metricdata.Gauge[int64]:
				for _, dp := range data.DataPoints {
					points = append(points, Point{Attributes: attributes(dp.Attributes), Value: dp.Value})
				}
			case metricdata.Gauge[float64]: // whole units: enough for the tests
				for _, dp := range data.DataPoints {
					points = append(points, Point{Attributes: attributes(dp.Attributes), Value: int64(dp.Value)})
				}
			case metricdata.Histogram[float64]:
				for _, dp := range data.DataPoints {
					points = append(points, Point{Attributes: attributes(dp.Attributes), Value: int64(dp.Count)})
				}
			case metricdata.Histogram[int64]:
				for _, dp := range data.DataPoints {
					points = append(points, Point{Attributes: attributes(dp.Attributes), Value: int64(dp.Count)})
				}
			default:
				t.Fatalf("%s: unsupported data type %T", name, m.Data)
			}
		}
	}
	return points
}

// Value returns the sum of the values of the named instrument's points whose
// attributes include every given one (key, value pairs).
func (r *Reader) Value(t *testing.T, name string, attrs ...string) int64 {
	t.Helper()
	if len(attrs)%2 != 0 {
		t.Fatalf("odd attribute list %v", attrs)
	}
	var total int64
	for _, p := range r.Points(t, name) {
		match := true
		for i := 0; i < len(attrs); i += 2 {
			match = match && p.Attributes[attrs[i]] == attrs[i+1]
		}
		if match {
			total += p.Value
		}
	}
	return total
}

func attributes(set attribute.Set) map[string]string {
	out := map[string]string{}
	for _, kv := range set.ToSlice() {
		out[string(kv.Key)] = kv.Value.String()
	}
	return out
}
