package config

import (
	"os"
	"path/filepath"
	"testing"
)

// TestExamples keeps the sample configurations in examples/ valid: they must
// pass every check except those on the referenced files, cross-file checks
// included, without warnings.
func TestExamples(t *testing.T) {
	dir := filepath.Join("..", "..", "..", "examples")
	read := func(name string) []byte {
		data, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			t.Fatalf("reading %s: %v", name, err)
		}
		return data
	}
	opts := CheckOptions{SkipFiles: true}
	signer := CheckSigner("signer.yaml", read("signer.yaml"), opts)
	aggregator := CheckAggregator("aggregator.yaml", read("aggregator.yaml"), opts)
	CrossCheck([]*Result[Signer]{signer}, aggregator)
	for _, findings := range [][]Finding{signer.Findings, aggregator.Findings} {
		if len(findings) != 0 {
			t.Errorf("findings in the examples:\n%s", dump(findings))
		}
	}
}
