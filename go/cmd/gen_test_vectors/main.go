// gen_test_vectors compiles a simple cubic circuit (x^3 + x + 5 == y),
// runs Groth16 and PLONK setup, and exports test vector files to
// ../../tests/test-vectors/ for use in Rust integration tests.
//
// Usage: go run ./cmd/gen_test_vectors
package main

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/backend/plonk"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/frontend/cs/scs"
	"github.com/consensys/gnark/test/unsafekzg"
)

// CubicCircuit defines x^3 + x + 5 == y
type CubicCircuit struct {
	X frontend.Variable `gnark:"X"`
	Y frontend.Variable `gnark:"Y,public"`
}

func (circuit *CubicCircuit) Define(api frontend.API) error {
	x3 := api.Mul(circuit.X, circuit.X, circuit.X)
	sum := api.Add(x3, circuit.X, 5)
	api.AssertIsEqual(sum, circuit.Y)
	return nil
}

func main() {
	outDir := filepath.Join("..", "tests", "test-vectors")
	if err := os.MkdirAll(outDir, 0o755); err != nil {
		panic(fmt.Sprintf("failed to create output dir: %v", err))
	}

	generateGroth16(outDir)
	generatePlonk(outDir)

	fmt.Println("Test vectors generated successfully in", outDir)
}

func generateGroth16(outDir string) {
	var circuit CubicCircuit
	cs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &circuit)
	if err != nil {
		panic(fmt.Sprintf("groth16: failed to compile circuit: %v", err))
	}

	pk, vk, err := groth16.Setup(cs)
	if err != nil {
		panic(fmt.Sprintf("groth16: failed to run setup: %v", err))
	}

	writeFile(filepath.Join(outDir, "cubic_circuit.r1cs"), func(f *os.File) {
		if _, err := cs.WriteTo(f); err != nil {
			panic(fmt.Sprintf("groth16: failed to write r1cs: %v", err))
		}
	})

	writeFile(filepath.Join(outDir, "cubic_circuit.pk"), func(f *os.File) {
		if _, err := pk.WriteRawTo(f); err != nil {
			panic(fmt.Sprintf("groth16: failed to write pk: %v", err))
		}
	})

	writeFile(filepath.Join(outDir, "cubic_circuit.vk"), func(f *os.File) {
		if _, err := vk.WriteTo(f); err != nil {
			panic(fmt.Sprintf("groth16: failed to write vk: %v", err))
		}
	})

	fmt.Println("  Groth16 test vectors generated")
}

func generatePlonk(outDir string) {
	var circuit CubicCircuit
	ccs, err := frontend.Compile(ecc.BN254.ScalarField(), scs.NewBuilder, &circuit)
	if err != nil {
		panic(fmt.Sprintf("plonk: failed to compile circuit: %v", err))
	}

	// Generate a test KZG SRS (NOT for production use).
	srs, srsLagrange, err := unsafekzg.NewSRS(ccs)
	if err != nil {
		panic(fmt.Sprintf("plonk: failed to generate SRS: %v", err))
	}

	pk, vk, err := plonk.Setup(ccs, srs, srsLagrange)
	if err != nil {
		panic(fmt.Sprintf("plonk: failed to run setup: %v", err))
	}

	writeFile(filepath.Join(outDir, "cubic_circuit_plonk.scs"), func(f *os.File) {
		if _, err := ccs.WriteTo(f); err != nil {
			panic(fmt.Sprintf("plonk: failed to write scs: %v", err))
		}
	})

	writeFile(filepath.Join(outDir, "cubic_circuit_plonk.pk"), func(f *os.File) {
		if _, err := pk.WriteRawTo(f); err != nil {
			panic(fmt.Sprintf("plonk: failed to write pk: %v", err))
		}
	})

	writeFile(filepath.Join(outDir, "cubic_circuit_plonk.vk"), func(f *os.File) {
		if _, err := vk.WriteTo(f); err != nil {
			panic(fmt.Sprintf("plonk: failed to write vk: %v", err))
		}
	})

	fmt.Println("  PLONK test vectors generated")
}

func writeFile(path string, fn func(*os.File)) {
	f, err := os.Create(path)
	if err != nil {
		panic(fmt.Sprintf("failed to create %s: %v", path, err))
	}
	defer f.Close()
	fn(f)
}

