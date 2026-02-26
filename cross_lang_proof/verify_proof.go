// cross_lang_proof/verify_proof.go
//
// GEF Cross-Language Proof — Go Verifier
// ========================================
//
// Reads proof_bundle.json written by emit_proof.py.
// Independently recomputes, using ONLY Go standard library + JCS:
//
//   1. canonical_bytes  = JCS(signing_dict)
//   2. chain_hash       = SHA-256(JCS(chain_dict))
//   3. signature valid  = Ed25519.Verify(public_key, canonical_bytes, signature)
//   4. NEGATIVE TEST    = flip one byte → signature must FAIL
//
// JCS library: github.com/gowebpki/jcs v1.0.1 (RFC 8785 compliant, tagged release)
// API: jcs.Transform([]byte) ([]byte, error)
//   Takes already-marshaled JSON bytes, returns canonical JSON bytes.

package main

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"

	"github.com/gowebpki/jcs"
)

// ── Proof bundle structure ────────────────────────────────────────────────────

type ProofBundle struct {
	Description       string                 `json:"_description"`
	GEFVersion        string                 `json:"gef_version"`
	PublicKeyHex      string                 `json:"public_key_hex"`
	SigningDict        map[string]interface{} `json:"signing_dict"`
	CanonicalBytesHex string                 `json:"canonical_bytes_hex"`
	ChainDict         map[string]interface{} `json:"chain_dict"`
	ChainBytesHex     string                 `json:"chain_bytes_hex"`
	CausalHashOfThis  string                 `json:"causal_hash_of_this"`
	SignatureB64URL   string                 `json:"signature_b64url"`
	SignatureHex      string                 `json:"signature_hex"`
	EnvelopeJSON      string                 `json:"envelope_json"`
}

// ── Result tracking ───────────────────────────────────────────────────────────

type CheckResult struct {
	Name    string
	Passed  bool
	Details string
}

var results []CheckResult

func check(name string, passed bool, details string) {
	results = append(results, CheckResult{name, passed, details})
	icon := "✅"
	if !passed {
		icon = "❌"
	}
	fmt.Printf("  %s  %-50s %s\n", icon, name, details)
}

// ── JCS helper — gowebpki API ─────────────────────────────────────────────────

// canonicalize takes a map, marshals to JSON, then applies RFC 8785 JCS.
// gowebpki/jcs.Transform takes []byte, not interface{} — this is the adapter.
func canonicalize(v map[string]interface{}) ([]byte, error) {
	raw, err := json.Marshal(v)
	if err != nil {
		return nil, fmt.Errorf("json.Marshal: %w", err)
	}
	canonical, err := jcs.Transform(raw)
	if err != nil {
		return nil, fmt.Errorf("jcs.Transform: %w", err)
	}
	return canonical, nil
}

// ── Main ──────────────────────────────────────────────────────────────────────

func main() {
	bar := "════════════════════════════════════════════════════════════════"
	fmt.Println()
	fmt.Println(bar)
	fmt.Println("  GEF Cross-Language Proof — Go Verifier")
	fmt.Println("  JCS: github.com/gowebpki/jcs v1.0.1 (RFC 8785)")
	fmt.Println(bar)
	fmt.Println()

	// ── Load bundle ──────────────────────────────────────────
	bundlePath := "proof_bundle.json"
	if len(os.Args) > 1 {
		bundlePath = os.Args[1]
	}

	data, err := os.ReadFile(bundlePath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "FATAL: cannot read %s: %v\n", bundlePath, err)
		os.Exit(1)
	}

	var bundle ProofBundle
	if err := json.Unmarshal(data, &bundle); err != nil {
		fmt.Fprintf(os.Stderr, "FATAL: cannot parse proof bundle: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("  Bundle loaded from : %s\n", bundlePath)
	fmt.Printf("  GEF version        : %s\n", bundle.GEFVersion)
	fmt.Printf("  Public key         : %s...\n", bundle.PublicKeyHex[:16])
	fmt.Println()

	// ── Decode shared inputs ──────────────────────────────────
	pubKeyBytes, err := hex.DecodeString(bundle.PublicKeyHex)
	if err != nil || len(pubKeyBytes) != 32 {
		fmt.Fprintf(os.Stderr, "FATAL: invalid public key hex: %v\n", err)
		os.Exit(1)
	}
	pubKey := ed25519.PublicKey(pubKeyBytes)

	sigB64 := bundle.SignatureB64URL
	for len(sigB64)%4 != 0 {
		sigB64 += "="
	}
	sigBytes, err := base64.URLEncoding.DecodeString(sigB64)
	if err != nil || len(sigBytes) != 64 {
		fmt.Fprintf(os.Stderr, "FATAL: invalid signature base64url: %v\n", err)
		os.Exit(1)
	}

	// ════════════════════════════════════════════════════════
	// CHECK 1 — Canonical bytes (JCS)
	// Proves: RFC 8785 JCS is byte-identical across Python and Go.
	// ════════════════════════════════════════════════════════
	fmt.Println("  CONTRACT 1 — Canonical Bytes (RFC 8785 JCS)")
	fmt.Println("  " + "────────────────────────────────────────────────────────────")

	goCanonicalBytes, err := canonicalize(bundle.SigningDict)
	if err != nil {
		fmt.Fprintf(os.Stderr, "FATAL: canonicalize signing_dict: %v\n", err)
		os.Exit(1)
	}
	goCanonicalHex     := hex.EncodeToString(goCanonicalBytes)
	pythonCanonicalHex := bundle.CanonicalBytesHex
	canonicalMatch     := goCanonicalHex == pythonCanonicalHex

	check(
		"canonical_bytes match",
		canonicalMatch,
		fmt.Sprintf("go=%s...  python=%s...",
			goCanonicalHex[:16], pythonCanonicalHex[:16]),
	)

	if !canonicalMatch {
		fmt.Printf("\n  Go     canonical: %s\n", goCanonicalHex)
		fmt.Printf("  Python canonical: %s\n\n", pythonCanonicalHex)
	}

	// ════════════════════════════════════════════════════════
	// CHECK 2 — Chain hash (SHA-256 of JCS chain dict)
	// Proves: causal_hash is byte-identical in Python and Go.
	// ════════════════════════════════════════════════════════
	fmt.Println()
	fmt.Println("  CONTRACT 2 — Chain Hash (SHA-256 of JCS chain dict)")
	fmt.Println("  " + "────────────────────────────────────────────────────────────")

	goChainCanonicalBytes, err := canonicalize(bundle.ChainDict)
	if err != nil {
		fmt.Fprintf(os.Stderr, "FATAL: canonicalize chain_dict: %v\n", err)
		os.Exit(1)
	}

	goChainHash    := sha256.Sum256(goChainCanonicalBytes)
	goChainHashHex := hex.EncodeToString(goChainHash[:])
	chainHashMatch := goChainHashHex == bundle.CausalHashOfThis

	check(
		"chain_hash match",
		chainHashMatch,
		fmt.Sprintf("go=%s...  python=%s...",
			goChainHashHex[:16], bundle.CausalHashOfThis[:16]),
	)

	if !chainHashMatch {
		fmt.Printf("\n  Go     chain hash: %s\n", goChainHashHex)
		fmt.Printf("  Python chain hash: %s\n\n", bundle.CausalHashOfThis)
	}

	goChainBytesHex := hex.EncodeToString(goChainCanonicalBytes)
	chainBytesMatch := goChainBytesHex == bundle.ChainBytesHex

	check(
		"chain_canonical_bytes match",
		chainBytesMatch,
		fmt.Sprintf("go=%s...  python=%s...",
			goChainBytesHex[:16], bundle.ChainBytesHex[:16]),
	)

	// ════════════════════════════════════════════════════════
	// CHECK 3 — Ed25519 signature verification (positive)
	// Proves: Python Ed25519 signatures verify in Go crypto/ed25519.
	// ════════════════════════════════════════════════════════
	fmt.Println()
	fmt.Println("  CONTRACT 3 — Ed25519 Signature Verification (positive)")
	fmt.Println("  " + "────────────────────────────────────────────────────────────")

	sigValid := ed25519.Verify(pubKey, goCanonicalBytes, sigBytes)
	check(
		"signature valid (Go canonical bytes)",
		sigValid,
		fmt.Sprintf("pubkey=%s...  sig=%s...",
			bundle.PublicKeyHex[:8],
			bundle.SignatureB64URL[:16]),
	)

	pythonCanonicalDecoded, _ := hex.DecodeString(pythonCanonicalHex)
	sigValidPythonBytes := ed25519.Verify(pubKey, pythonCanonicalDecoded, sigBytes)
	check(
		"signature valid (Python canonical bytes)",
		sigValidPythonBytes,
		"cross-check: Go verifies Python's raw bytes directly",
	)

	// ════════════════════════════════════════════════════════
	// CHECK 4 — Signing dict == Chain dict (field identity)
	// Proves: to_signing_dict() == to_chain_dict() by GEF-SPEC-v1.0.
	// ════════════════════════════════════════════════════════
	fmt.Println()
	fmt.Println("  CONTRACT 4 — Signing Dict == Chain Dict")
	fmt.Println("  " + "────────────────────────────────────────────────────────────")

	signingJSON, _ := json.Marshal(bundle.SigningDict)
	chainJSON, _   := json.Marshal(bundle.ChainDict)
	dictsEqual     := string(signingJSON) == string(chainJSON)

	check(
		"signing_dict == chain_dict",
		dictsEqual,
		"GEF-SPEC-v1.0: both dicts are identical by design",
	)

	_, sigInDict := bundle.SigningDict["signature"]
	check(
		"signature NOT in signing_dict",
		!sigInDict,
		"signature field must be excluded from signed payload",
	)

	// ════════════════════════════════════════════════════════
	// CHECK 5 — Field count (no extra or missing fields)
	// Proves: no silent field injection or omission across the boundary.
	// ════════════════════════════════════════════════════════
	fmt.Println()
	fmt.Println("  CONTRACT 5 — Field Count (signing dict completeness)")
	fmt.Println("  " + "────────────────────────────────────────────────────────────")

	expectedFields := []string{
		"agent_id", "causal_hash", "gef_version", "nonce",
		"payload", "record_id", "record_type", "sequence",
		"signer_public_key", "timestamp",
	}
	fieldCountOK := len(bundle.SigningDict) == len(expectedFields)
	check(
		"signing_dict has exactly 10 fields",
		fieldCountOK,
		fmt.Sprintf("got %d, expected %d",
			len(bundle.SigningDict), len(expectedFields)),
	)

	allPresent := true
	for _, f := range expectedFields {
		if _, ok := bundle.SigningDict[f]; !ok {
			allPresent = false
			check(
				fmt.Sprintf("field '%s' present", f),
				false,
				"MISSING — signing_dict is incomplete",
			)
		}
	}
	if allPresent {
		check(
			"all 10 required fields present",
			true,
			"agent_id causal_hash gef_version nonce payload "+
				"record_id record_type sequence signer_public_key timestamp",
		)
	}

	// ════════════════════════════════════════════════════════
	// CHECK 6 — NEGATIVE TEST: flipped byte must NOT verify
	//
	// The most important single check in this file.
	//
	// Procedure:
	//   1. Copy Go's canonical bytes
	//   2. Flip ONE byte at midpoint (XOR 0xFF — all 8 bits)
	//   3. Ed25519.Verify on corrupted bytes → must return FALSE
	//   4. Flip ONE bit at position 1 → must also return FALSE
	//   5. Verify original bytes still pass (copy correctness check)
	//
	// Why this matters:
	//   Passing CHECK 3 but failing CHECK 6 would mean something is
	//   silently normalizing data before verification — making ALL
	//   positive results untrustworthy.
	//   Both passing together means:
	//   "The signature is bound to exactly these bytes.
	//    Any single-bit mutation breaks it."
	//   That is the definition of tamper-evident.
	// ════════════════════════════════════════════════════════
	fmt.Println()
	fmt.Println("  CONTRACT 6 — NEGATIVE TEST: Single Byte Flip Must Fail")
	fmt.Println("  " + "────────────────────────────────────────────────────────────")

	// Sub-test A: flip all 8 bits at midpoint
	corruptedA    := make([]byte, len(goCanonicalBytes))
	copy(corruptedA, goCanonicalBytes)
	flipIdx       := len(corruptedA) / 2
	origByte      := corruptedA[flipIdx]
	corruptedA[flipIdx] ^= 0xFF

	sigOnCorruptedA   := ed25519.Verify(pubKey, corruptedA, sigBytes)
	negativePassedA   := !sigOnCorruptedA

	check(
		"corrupted bytes rejected (8-bit flip at mid)",
		negativePassedA,
		fmt.Sprintf("pos=%d orig=0x%02X flipped=0x%02X verify=%v (must be false)",
			flipIdx, origByte, corruptedA[flipIdx], sigOnCorruptedA),
	)

	// Sub-test B: flip 1 bit at position 1 (weakest possible corruption)
	corruptedB   := make([]byte, len(goCanonicalBytes))
	copy(corruptedB, goCanonicalBytes)
	corruptedB[1] ^= 0x01

	sigOnCorruptedB := ed25519.Verify(pubKey, corruptedB, sigBytes)
	negativePassedB := !sigOnCorruptedB

	check(
		"corrupted bytes rejected (1-bit flip at pos 1)",
		negativePassedB,
		fmt.Sprintf("pos=1 orig=0x%02X flipped=0x%02X verify=%v (must be false)",
			goCanonicalBytes[1], corruptedB[1], sigOnCorruptedB),
	)

	// Sub-test C: original still verifies — confirms A and B used copies
	restoredVerifies := ed25519.Verify(pubKey, goCanonicalBytes, sigBytes)
	check(
		"original bytes still verify after corruption test",
		restoredVerifies,
		"confirms copies were used — original was never mutated",
	)

	// ════════════════════════════════════════════════════════
	// FINAL VERDICT
	// ════════════════════════════════════════════════════════
	fmt.Println()
	fmt.Println(bar)

	total  := len(results)
	passed := 0
	for _, r := range results {
		if r.Passed {
			passed++
		}
	}

	if passed == total {
		fmt.Printf("  ✅  CROSS-LANGUAGE PROOF PASSED  (%d/%d checks)\n\n",
			passed, total)
		fmt.Println("  GEF is a protocol — not a Python library.")
		fmt.Println("  RFC 8785 JCS          → byte-identical: Python == Go")
		fmt.Println("  SHA-256 chain hash    → byte-identical: Python == Go")
		fmt.Println("  Ed25519 signature     → Python-signed verifies in Go")
		fmt.Println("  Negative test         → 1-byte corruption breaks verification")
		fmt.Println("  Result                → tamper-evidence is real, not accidental")
		fmt.Println(bar)
		fmt.Println()
		os.Exit(0)
	} else {
		fmt.Printf("  ❌  CROSS-LANGUAGE PROOF FAILED  (%d/%d checks passed)\n\n",
			passed, total)
		for _, r := range results {
			if !r.Passed {
				fmt.Printf("  FAILED : %s\n", r.Name)
				fmt.Printf("  Detail : %s\n\n", r.Details)
			}
		}
		fmt.Println(bar)
		fmt.Println()
		os.Exit(1)
	}
}
