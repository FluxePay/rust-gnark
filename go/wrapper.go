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

// Result struct for Solidity calldata export.
// On success: proof and public_inputs are set, error is NULL.
//   - proof: hex-encoded, 32-byte-aligned proof calldata. For Groth16 this is
//     Ar|Bs|Krs (8 field elements) optionally followed by commitments (2 field
//     elements each) and the commitment proof-of-knowledge (2 field elements) --
//     reassembled from the proof fields, NOT the raw MarshalSolidity() bytes
//     (which embed a slice-length prefix). For PLONK it is MarshalSolidity()'s
//     raw proof byte blob, passed whole as the verifier's `bytes` argument.
//   - public_inputs: hex-encoded concatenation of the public witness field
//     elements, each a 32-byte big-endian value ready to pass as a uint256[].
//   - num_commitments: Groth16 Pedersen commitment count (0 for commitment-free
//     circuits and for PLONK), so the caller can split the Groth16 blob into
//     proof[8] | commitments[2*n] | commitmentPok[2].
typedef struct {
    char *proof;
    char *public_inputs;
    int num_commitments;
    char *error;
} C_SolidityCalldataResult;
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
	fr "github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark/backend"
	"github.com/consensys/gnark/backend/groth16"
	groth16_bn254 "github.com/consensys/gnark/backend/groth16/bn254"
	"github.com/consensys/gnark/backend/plonk"
	plonk_bn254 "github.com/consensys/gnark/backend/plonk/bn254"
	"github.com/consensys/gnark/backend/solidity"
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
	target_solidity C.int,
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

	// When targeting a Solidity verifier, gnark's Groth16 must hash the
	// commitment public input with legacy Keccak256 instead of the default
	// RFC-9380 hash-to-field. This only affects circuits that use Pedersen
	// commitments; for commitment-free circuits it is a no-op.
	var proverOpts []backend.ProverOption
	if target_solidity != 0 {
		proverOpts = append(proverOpts, solidity.WithProverTargetSolidityVerifier(backend.GROTH16))
	}

	proof, err := groth16.Prove(cs, pk, fullWitness, proverOpts...)
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
	target_solidity C.int,
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

	var verifierOpts []backend.VerifierOption
	if target_solidity != 0 {
		verifierOpts = append(verifierOpts, solidity.WithVerifierTargetSolidityVerifier(backend.GROTH16))
	}

	if err := groth16.Verify(proof, vk, pubWitness, verifierOpts...); err != nil {
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
	target_solidity C.int,
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

	// For PLONK the Solidity verifier is directly compatible with the default
	// prover options, so this option is a documented no-op; we thread it through
	// for symmetry with Groth16 and to stay correct if gnark changes that.
	var proverOpts []backend.ProverOption
	if target_solidity != 0 {
		proverOpts = append(proverOpts, solidity.WithProverTargetSolidityVerifier(backend.PLONK))
	}

	proof, err := plonk.Prove(cs, pk, fullWitness, proverOpts...)
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
	target_solidity C.int,
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

	var verifierOpts []backend.VerifierOption
	if target_solidity != 0 {
		verifierOpts = append(verifierOpts, solidity.WithVerifierTargetSolidityVerifier(backend.PLONK))
	}

	if err := plonk.Verify(proof, vk, pubWitness, verifierOpts...); err != nil {
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

// publicInputsToSolidityCalldata converts a hex-encoded gnark binary public
// witness (as produced by witness.MarshalBinary and returned from the prove
// functions) into a hex-encoded concatenation of raw 32-byte big-endian field
// elements, ready to be passed as a Solidity uint256[] public inputs array.
func publicInputsToSolidityCalldata(publicInputsHex string) (string, error) {
	pubBytes, err := hex.DecodeString(publicInputsHex)
	if err != nil {
		return "", fmt.Errorf("failed to decode public inputs hex: %w", err)
	}
	pubWitness, err := witness.New(ecc.BN254.ScalarField())
	if err != nil {
		return "", fmt.Errorf("failed to create witness: %w", err)
	}
	if err := pubWitness.UnmarshalBinary(pubBytes); err != nil {
		return "", fmt.Errorf("failed to unmarshal public witness: %w", err)
	}
	vec, ok := pubWitness.Vector().(fr.Vector)
	if !ok {
		return "", fmt.Errorf("unexpected public witness vector type: %T", pubWitness.Vector())
	}

	var buf bytes.Buffer
	for i := range vec {
		b := vec[i].Bytes() // [32]byte, big-endian
		buf.Write(b[:])
	}
	return hex.EncodeToString(buf.Bytes()), nil
}

//export gnark_groth16_solidity_calldata
func gnark_groth16_solidity_calldata(
	proof_hex *C.char,
	public_inputs_hex *C.char,
) *C.C_SolidityCalldataResult {
	result := (*C.C_SolidityCalldataResult)(C.malloc(C.size_t(unsafe.Sizeof(C.C_SolidityCalldataResult{}))))
	result.proof = nil
	result.public_inputs = nil
	result.num_commitments = 0
	result.error = nil

	proofBytes, err := hex.DecodeString(C.GoString(proof_hex))
	if err != nil {
		result.error = C.CString(fmt.Sprintf("failed to decode proof hex: %v", err))
		return result
	}
	proof := groth16.NewProof(ecc.BN254)
	if _, err := proof.ReadFrom(bytes.NewReader(proofBytes)); err != nil {
		result.error = C.CString(fmt.Sprintf("failed to deserialize proof: %v", err))
		return result
	}
	bn254Proof, ok := proof.(*groth16_bn254.Proof)
	if !ok {
		result.error = C.CString(fmt.Sprintf("unexpected groth16 proof type: %T", proof))
		return result
	}

	// We do NOT return MarshalSolidity() verbatim: for a committed proof it
	// embeds a 4-byte slice-length prefix before the commitments (from
	// gnark-crypto's slice encoder), which breaks 32-byte alignment. Instead we
	// assemble the exact on-chain layout as clean field elements:
	//   Ar|Bs|Krs (8) | commitments (2 per commitment) | commitmentPok (2)
	// so the caller can split it into verifyProof's uint256[8] / uint256[2n] /
	// uint256[2] arguments using num_commitments.
	numCommitments := len(bn254Proof.Commitments)
	var proofBuf bytes.Buffer
	// The first 8 field elements of MarshalSolidity are always Ar|Bs|Krs, with
	// no length prefix (that is exactly the no-commitment return value).
	solProof := bn254Proof.MarshalSolidity()
	proofBuf.Write(solProof[:8*fr.Bytes])
	for i := range bn254Proof.Commitments {
		m := bn254Proof.Commitments[i].Marshal() // uncompressed (x, y), 2 field elements
		proofBuf.Write(m)
	}
	if numCommitments > 0 {
		pok := bn254Proof.CommitmentPok.Marshal() // (x, y), 2 field elements
		proofBuf.Write(pok)
	}
	proofCalldata := hex.EncodeToString(proofBuf.Bytes())

	pubCalldata, err := publicInputsToSolidityCalldata(C.GoString(public_inputs_hex))
	if err != nil {
		result.error = C.CString(err.Error())
		return result
	}

	// Only publish outputs once everything succeeded, so callers never see a
	// partially-populated result alongside an error.
	result.proof = C.CString(proofCalldata)
	result.public_inputs = C.CString(pubCalldata)
	result.num_commitments = C.int(numCommitments)
	return result
}

//export gnark_plonk_solidity_calldata
func gnark_plonk_solidity_calldata(
	proof_hex *C.char,
	public_inputs_hex *C.char,
) *C.C_SolidityCalldataResult {
	result := (*C.C_SolidityCalldataResult)(C.malloc(C.size_t(unsafe.Sizeof(C.C_SolidityCalldataResult{}))))
	result.proof = nil
	result.public_inputs = nil
	result.num_commitments = 0
	result.error = nil

	proofBytes, err := hex.DecodeString(C.GoString(proof_hex))
	if err != nil {
		result.error = C.CString(fmt.Sprintf("failed to decode proof hex: %v", err))
		return result
	}
	proof := plonk.NewProof(ecc.BN254)
	if _, err := proof.ReadFrom(bytes.NewReader(proofBytes)); err != nil {
		result.error = C.CString(fmt.Sprintf("failed to deserialize plonk proof: %v", err))
		return result
	}
	bn254Proof, ok := proof.(*plonk_bn254.Proof)
	if !ok {
		result.error = C.CString(fmt.Sprintf("unexpected plonk proof type: %T", proof))
		return result
	}

	// The PLONK Solidity verifier takes the whole proof as a single `bytes`
	// argument, so there is no separate commitment split (num_commitments stays 0).
	proofCalldata := hex.EncodeToString(bn254Proof.MarshalSolidity())

	pubCalldata, err := publicInputsToSolidityCalldata(C.GoString(public_inputs_hex))
	if err != nil {
		result.error = C.CString(err.Error())
		return result
	}

	result.proof = C.CString(proofCalldata)
	result.public_inputs = C.CString(pubCalldata)
	return result
}

//export gnark_free_solidity_calldata_result
func gnark_free_solidity_calldata_result(r *C.C_SolidityCalldataResult) {
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
