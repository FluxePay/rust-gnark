package main

/*
#include <stdlib.h>

// Result struct for Groth16 proof generation.
// On success: proof and public_inputs are set, error is NULL.
// On failure: error is set, proof and public_inputs are NULL.
typedef struct {
    char *proof;          // hex-encoded binary proof (WriteTo serialization)
    char *public_inputs;  // hex-encoded binary public witness (MarshalBinary)
    char *error;          // error message or NULL on success
} C_Groth16ProofResult;

// Result struct for PLONK proof generation.
typedef struct {
    char *proof;
    char *public_inputs;
    char *error;
} C_PlonkProofResult;
*/
import "C"

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"runtime"
	"unsafe"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/backend/plonk"
	"github.com/consensys/gnark/backend/witness"
	"github.com/consensys/gnark/constraint"
	cs_bn254 "github.com/consensys/gnark/constraint/bn254"
)

//export gnark_init
func gnark_init() C.int {
	// On iOS debug builds, disable async preemption to prevent signal flood
	// crashes with the Go runtime.
	if runtime.GOOS == "ios" || runtime.GOOS == "darwin" {
		os.Setenv("GODEBUG", "asyncpreemptoff=1")
	}
	return 0
}

//export gnark_groth16_prove
func gnark_groth16_prove(
	r1cs_path *C.char,
	pk_path *C.char,
	witness_json *C.char,
) *C.C_Groth16ProofResult {
	result := (*C.C_Groth16ProofResult)(C.malloc(C.size_t(unsafe.Sizeof(C.C_Groth16ProofResult{}))))
	result.proof = nil
	result.public_inputs = nil
	result.error = nil

	cs := groth16.NewCS(ecc.BN254)
	r1csFile, err := os.Open(C.GoString(r1cs_path))
	if err != nil {
		result.error = C.CString(fmt.Sprintf("failed to open r1cs file: %v", err))
		return result
	}
	defer r1csFile.Close()

	if _, err := cs.ReadFrom(r1csFile); err != nil {
		result.error = C.CString(fmt.Sprintf("failed to read r1cs: %v", err))
		return result
	}

	// UnsafeReadFrom for speed -- trusted local file, skip validation
	pk := groth16.NewProvingKey(ecc.BN254)
	pkFile, err := os.Open(C.GoString(pk_path))
	if err != nil {
		result.error = C.CString(fmt.Sprintf("failed to open pk file: %v", err))
		return result
	}
	defer pkFile.Close()

	if _, err := pk.UnsafeReadFrom(pkFile); err != nil {
		result.error = C.CString(fmt.Sprintf("failed to read proving key: %v", err))
		return result
	}

	witnessJSON := C.GoString(witness_json)
	fullWitness, err := buildWitnessFromJSON(witnessJSON, cs)
	if err != nil {
		result.error = C.CString(fmt.Sprintf("failed to build witness: %v", err))
		return result
	}

	proof, err := groth16.Prove(cs, pk, fullWitness)
	if err != nil {
		result.error = C.CString(fmt.Sprintf("proof generation failed: %v", err))
		return result
	}

	var proofBuf bytes.Buffer
	if _, err := proof.WriteTo(&proofBuf); err != nil {
		result.error = C.CString(fmt.Sprintf("failed to serialize proof: %v", err))
		return result
	}
	result.proof = C.CString(hex.EncodeToString(proofBuf.Bytes()))

	pubWitness, err := fullWitness.Public()
	if err != nil {
		result.error = C.CString(fmt.Sprintf("failed to extract public witness: %v", err))
		return result
	}
	pubBin, err := pubWitness.MarshalBinary()
	if err != nil {
		result.error = C.CString(fmt.Sprintf("failed to marshal public witness: %v", err))
		return result
	}
	result.public_inputs = C.CString(hex.EncodeToString(pubBin))

	return result
}

//export gnark_groth16_verify
func gnark_groth16_verify(
	r1cs_path *C.char,
	vk_path *C.char,
	proof_hex *C.char,
	public_inputs_hex *C.char,
) *C.char {
	cs := groth16.NewCS(ecc.BN254)
	r1csFile, err := os.Open(C.GoString(r1cs_path))
	if err != nil {
		return C.CString(fmt.Sprintf("failed to open r1cs file: %v", err))
	}
	defer r1csFile.Close()

	if _, err := cs.ReadFrom(r1csFile); err != nil {
		return C.CString(fmt.Sprintf("failed to read r1cs: %v", err))
	}

	vk := groth16.NewVerifyingKey(ecc.BN254)
	vkFile, err := os.Open(C.GoString(vk_path))
	if err != nil {
		return C.CString(fmt.Sprintf("failed to open vk file: %v", err))
	}
	defer vkFile.Close()

	if _, err := vk.ReadFrom(vkFile); err != nil {
		return C.CString(fmt.Sprintf("failed to read verifying key: %v", err))
	}

	proofBytes, err := hex.DecodeString(C.GoString(proof_hex))
	if err != nil {
		return C.CString(fmt.Sprintf("failed to decode proof hex: %v", err))
	}
	proof := groth16.NewProof(ecc.BN254)
	if _, err := proof.ReadFrom(bytes.NewReader(proofBytes)); err != nil {
		return C.CString(fmt.Sprintf("failed to deserialize proof: %v", err))
	}

	pubBytes, err := hex.DecodeString(C.GoString(public_inputs_hex))
	if err != nil {
		return C.CString(fmt.Sprintf("failed to decode public inputs hex: %v", err))
	}
	pubWitness, err := witness.New(ecc.BN254.ScalarField())
	if err != nil {
		return C.CString(fmt.Sprintf("failed to create witness: %v", err))
	}
	if err := pubWitness.UnmarshalBinary(pubBytes); err != nil {
		return C.CString(fmt.Sprintf("failed to unmarshal public witness: %v", err))
	}

	if err := groth16.Verify(proof, vk, pubWitness); err != nil {
		return C.CString(fmt.Sprintf("invalid proof: %v", err))
	}

	// NULL = valid proof
	return nil
}

//export gnark_free_proof_result
func gnark_free_proof_result(r *C.C_Groth16ProofResult) {
	if r == nil {
		return
	}
	if r.proof != nil {
		C.free(unsafe.Pointer(r.proof))
	}
	if r.public_inputs != nil {
		C.free(unsafe.Pointer(r.public_inputs))
	}
	if r.error != nil {
		C.free(unsafe.Pointer(r.error))
	}
	C.free(unsafe.Pointer(r))
}

//export gnark_free_string
func gnark_free_string(s *C.char) {
	if s != nil {
		C.free(unsafe.Pointer(s))
	}
}

// getVariableNames extracts public and secret variable names from a BN254
// constraint system. Supports both R1CS (Groth16) and SparseR1CS (PLONK).
// Public[0] is always "1" (the constant wire) and is skipped.
func getVariableNames(cs constraint.ConstraintSystem) (publicNames []string, secretNames []string, err error) {
	// In gnark v0.14+ the R1CS and SparseR1CS types are unified.
	v, ok := cs.(*cs_bn254.R1CS)
	if !ok {
		return nil, nil, fmt.Errorf("unsupported BN254 constraint system type: %T", cs)
	}
	pub := v.Public
	// R1CS has "1" as Public[0] (constant wire) — skip it.
	// PLONK's SCS does not include this constant wire.
	if len(pub) > 0 && pub[0] == "1" {
		pub = pub[1:]
	}
	return pub, v.Secret, nil
}

// buildWitnessFromJSON creates a gnark witness from a JSON object mapping
// circuit variable names to decimal string values.
//
// The JSON format is: {"VarName": "decimal_value", ...}
// Variable names must match those defined in the circuit (via gnark struct tags).
//
// This function accesses the constraint system's variable name lists (Public/Secret)
// to determine the correct ordering, then uses witness.Fill to populate values.
func buildWitnessFromJSON(jsonStr string, cs constraint.ConstraintSystem) (witness.Witness, error) {
	var flatMap map[string]interface{}
	if err := json.Unmarshal([]byte(jsonStr), &flatMap); err != nil {
		return nil, fmt.Errorf("failed to parse witness JSON: %w", err)
	}

	publicNames, secretNames, err := getVariableNames(cs)
	if err != nil {
		return nil, err
	}

	nbPublic := len(publicNames)
	nbSecret := len(secretNames)

	// Create a buffered channel to feed values in witness order:
	// public variables first, then secret variables.
	values := make(chan any, nbPublic+nbSecret)

	for _, name := range publicNames {
		val, exists := flatMap[name]
		if !exists {
			return nil, fmt.Errorf("missing witness value for public variable %q", name)
		}
		values <- toFieldElement(val)
	}

	for _, name := range secretNames {
		val, exists := flatMap[name]
		if !exists {
			return nil, fmt.Errorf("missing witness value for secret variable %q", name)
		}
		values <- toFieldElement(val)
	}
	close(values)

	w, err := witness.New(cs.Field())
	if err != nil {
		return nil, fmt.Errorf("failed to create witness: %w", err)
	}

	if err := w.Fill(nbPublic, nbSecret, values); err != nil {
		return nil, fmt.Errorf("failed to fill witness: %w", err)
	}

	return w, nil
}

// toFieldElement converts a JSON value to a type gnark accepts as a field element.
// gnark field elements can be constructed from: string (decimal), int64, *big.Int.
func toFieldElement(v interface{}) interface{} {
	switch val := v.(type) {
	case string:
		return val // gnark accepts decimal strings directly
	case float64:
		// JSON numbers are decoded as float64 by default
		return int64(val)
	case json.Number:
		return val.String()
	default:
		return fmt.Sprintf("%v", val)
	}
}

//export gnark_plonk_prove
func gnark_plonk_prove(
	scs_path *C.char,
	pk_path *C.char,
	witness_json *C.char,
) *C.C_PlonkProofResult {
	result := (*C.C_PlonkProofResult)(C.malloc(C.size_t(unsafe.Sizeof(C.C_PlonkProofResult{}))))
	result.proof = nil
	result.public_inputs = nil
	result.error = nil

	cs := plonk.NewCS(ecc.BN254)
	scsFile, err := os.Open(C.GoString(scs_path))
	if err != nil {
		result.error = C.CString(fmt.Sprintf("failed to open scs file: %v", err))
		return result
	}
	defer scsFile.Close()

	if _, err := cs.ReadFrom(scsFile); err != nil {
		result.error = C.CString(fmt.Sprintf("failed to read scs: %v", err))
		return result
	}

	pk := plonk.NewProvingKey(ecc.BN254)
	pkFile, err := os.Open(C.GoString(pk_path))
	if err != nil {
		result.error = C.CString(fmt.Sprintf("failed to open pk file: %v", err))
		return result
	}
	defer pkFile.Close()

	if _, err := pk.UnsafeReadFrom(pkFile); err != nil {
		result.error = C.CString(fmt.Sprintf("failed to read plonk proving key: %v", err))
		return result
	}

	witnessJSON := C.GoString(witness_json)
	fullWitness, err := buildWitnessFromJSON(witnessJSON, cs)
	if err != nil {
		result.error = C.CString(fmt.Sprintf("failed to build witness: %v", err))
		return result
	}

	proof, err := plonk.Prove(cs, pk, fullWitness)
	if err != nil {
		result.error = C.CString(fmt.Sprintf("plonk proof generation failed: %v", err))
		return result
	}

	var proofBuf bytes.Buffer
	if _, err := proof.WriteTo(&proofBuf); err != nil {
		result.error = C.CString(fmt.Sprintf("failed to serialize plonk proof: %v", err))
		return result
	}
	result.proof = C.CString(hex.EncodeToString(proofBuf.Bytes()))

	pubWitness, err := fullWitness.Public()
	if err != nil {
		result.error = C.CString(fmt.Sprintf("failed to extract public witness: %v", err))
		return result
	}
	pubBin, err := pubWitness.MarshalBinary()
	if err != nil {
		result.error = C.CString(fmt.Sprintf("failed to marshal public witness: %v", err))
		return result
	}
	result.public_inputs = C.CString(hex.EncodeToString(pubBin))

	return result
}

//export gnark_plonk_verify
func gnark_plonk_verify(
	scs_path *C.char,
	vk_path *C.char,
	proof_hex *C.char,
	public_inputs_hex *C.char,
) *C.char {
	cs := plonk.NewCS(ecc.BN254)
	scsFile, err := os.Open(C.GoString(scs_path))
	if err != nil {
		return C.CString(fmt.Sprintf("failed to open scs file: %v", err))
	}
	defer scsFile.Close()

	if _, err := cs.ReadFrom(scsFile); err != nil {
		return C.CString(fmt.Sprintf("failed to read scs: %v", err))
	}

	vk := plonk.NewVerifyingKey(ecc.BN254)
	vkFile, err := os.Open(C.GoString(vk_path))
	if err != nil {
		return C.CString(fmt.Sprintf("failed to open vk file: %v", err))
	}
	defer vkFile.Close()

	if _, err := vk.ReadFrom(vkFile); err != nil {
		return C.CString(fmt.Sprintf("failed to read plonk verifying key: %v", err))
	}

	proofBytes, err := hex.DecodeString(C.GoString(proof_hex))
	if err != nil {
		return C.CString(fmt.Sprintf("failed to decode proof hex: %v", err))
	}
	proof := plonk.NewProof(ecc.BN254)
	if _, err := proof.ReadFrom(bytes.NewReader(proofBytes)); err != nil {
		return C.CString(fmt.Sprintf("failed to deserialize plonk proof: %v", err))
	}

	pubBytes, err := hex.DecodeString(C.GoString(public_inputs_hex))
	if err != nil {
		return C.CString(fmt.Sprintf("failed to decode public inputs hex: %v", err))
	}
	pubWitness, err := witness.New(ecc.BN254.ScalarField())
	if err != nil {
		return C.CString(fmt.Sprintf("failed to create witness: %v", err))
	}
	if err := pubWitness.UnmarshalBinary(pubBytes); err != nil {
		return C.CString(fmt.Sprintf("failed to unmarshal public witness: %v", err))
	}

	if err := plonk.Verify(proof, vk, pubWitness); err != nil {
		return C.CString(fmt.Sprintf("invalid proof: %v", err))
	}

	return nil
}

//export gnark_free_plonk_proof_result
func gnark_free_plonk_proof_result(r *C.C_PlonkProofResult) {
	if r == nil {
		return
	}
	if r.proof != nil {
		C.free(unsafe.Pointer(r.proof))
	}
	if r.public_inputs != nil {
		C.free(unsafe.Pointer(r.public_inputs))
	}
	if r.error != nil {
		C.free(unsafe.Pointer(r.error))
	}
	C.free(unsafe.Pointer(r))
}

func main() {} // required for c-archive build mode
