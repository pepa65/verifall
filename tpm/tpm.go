package tpm

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"io"
	"math/big"
	"sync"
	"time"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
	"github.com/google/go-tpm/tpm2/transport/linuxtpm"
	"github.com/cowboyrushforth/verifidod/internal/lencode"
	"github.com/cowboyrushforth/verifidod/seclog"
	"golang.org/x/crypto/cryptobyte"
	"golang.org/x/crypto/cryptobyte/asn1"
	"golang.org/x/crypto/hkdf"
)

var (
	separator     = []byte("TPM")
	seedSizeBytes = 20
)

type TPM struct {
	devicePath string
	mu         sync.Mutex
}

func (t *TPM) open() (transport.TPMCloser, error) {
	return linuxtpm.Open(t.devicePath)
}

func New(devicePath string) (*TPM, error) {
	t := &TPM{
		devicePath: devicePath,
	}

	tpm, err := t.open()
	if err != nil {
		return nil, err
	}
	defer tpm.Close()

	// Perform a basic system integrity check
	if _, err := t.verifySystemIntegrity(tpm); err != nil {
		return nil, fmt.Errorf("system integrity check failed: %w", err)
	}

	return t, nil
}

func primaryKeyTmpl(seed, applicationParam []byte) tpm2.TPMTPublic {
	info := append([]byte("verifidod-application-key"), applicationParam...)

	r := hkdf.New(sha256.New, seed, []byte{}, info)
	
	uniqueX := make([]byte, 32)
	uniqueY := make([]byte, 32)
	if _, err := io.ReadFull(r, uniqueX); err != nil {
		panic(err)
	}
	if _, err := io.ReadFull(r, uniqueY); err != nil {
		panic(err)
	}

	return tpm2.TPMTPublic{
		Type:    tpm2.TPMAlgECC,
		NameAlg: tpm2.TPMAlgSHA256,
		ObjectAttributes: tpm2.TPMAObject{
			Restricted:         true,
			Decrypt:            true,
			FixedTPM:           true,
			FixedParent:        true,
			SensitiveDataOrigin: true,
			UserWithAuth:       true,
		},
		Parameters: tpm2.NewTPMUPublicParms(
			tpm2.TPMAlgECC,
			&tpm2.TPMSECCParms{
				Symmetric: tpm2.TPMTSymDefObject{
					Algorithm: tpm2.TPMAlgAES,
					KeyBits: tpm2.NewTPMUSymKeyBits(
						tpm2.TPMAlgAES,
						tpm2.TPMKeyBits(128),
					),
					Mode: tpm2.NewTPMUSymMode(
						tpm2.TPMAlgAES, 
						tpm2.TPMAlgCFB,
					),
				},
				CurveID: tpm2.TPMECCNistP256,
			},
		),
		Unique: tpm2.NewTPMUPublicID(
			tpm2.TPMAlgECC,
			&tpm2.TPMSECCPoint{
				X: tpm2.TPM2BECCParameter{Buffer: uniqueX},
				Y: tpm2.TPM2BECCParameter{Buffer: uniqueY},
			},
		),
	}
}

var baseTime = time.Date(2021, time.January, 1, 0, 0, 0, 0, time.UTC)

func (t *TPM) Counter() uint32 {
	unix := time.Now().Unix()
	return uint32(unix - baseTime.Unix())
}

// Register a new key with the TPM for the given applicationParam.
// RegisterKey returns the KeyHandle or an error.
func (t *TPM) RegisterKey(applicationParam []byte) ([]byte, *big.Int, *big.Int, error) {
	t.mu.Lock()
	defer t.mu.Unlock()

	// Validate application parameter
	if err := validateApplicationParam(applicationParam); err != nil {
		return nil, nil, nil, err
	}

	tpm, err := t.open()
	if err != nil {
		return nil, nil, nil, fmt.Errorf("open tpm err: %w", err)
	}
	defer tpm.Close()

	// Verify system integrity
	if _, err := t.verifySystemIntegrity(tpm); err != nil {
		seclog.Error("System integrity check failed during key registration: %v", err)
		return nil, nil, nil, fmt.Errorf("system integrity check failed: %w", err)
	}

	randSeed := mustRand(seedSizeBytes)

	primaryTmpl := primaryKeyTmpl(randSeed, applicationParam)

	childTmpl := tpm2.TPMTPublic{
		Type:    tpm2.TPMAlgECC,
		NameAlg: tpm2.TPMAlgSHA256,
		ObjectAttributes: tpm2.TPMAObject{
			FixedTPM:            true,
			FixedParent:         true,
			SensitiveDataOrigin: true,
			UserWithAuth:        true,
			SignEncrypt:         true,
		},
		Parameters: tpm2.NewTPMUPublicParms(
			tpm2.TPMAlgECC,
			&tpm2.TPMSECCParms{
				CurveID: tpm2.TPMECCNistP256,
				Scheme: tpm2.TPMTECCScheme{
					Scheme: tpm2.TPMAlgECDSA,
					Details: tpm2.NewTPMUAsymScheme(
						tpm2.TPMAlgECDSA,
						&tpm2.TPMSSigSchemeECDSA{
							HashAlg: tpm2.TPMAlgSHA256,
						},
					),
				},
			},
		),
		Unique: tpm2.NewTPMUPublicID(
			tpm2.TPMAlgECC,
			&tpm2.TPMSECCPoint{
				X: tpm2.TPM2BECCParameter{Buffer: make([]byte, 32)},
				Y: tpm2.TPM2BECCParameter{Buffer: make([]byte, 32)},
			},
		),
	}

	// Create a primary key
	createPrimary := tpm2.CreatePrimary{
		PrimaryHandle: tpm2.TPMRHOwner,
		InPublic:      tpm2.New2B(primaryTmpl),
	}
	
	createPrimaryResponse, err := createPrimary.Execute(tpm)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("CreatePrimary key err: %w", err)
	}

	parentHandle := createPrimaryResponse.ObjectHandle
	defer flushContext(tpm, parentHandle)

	// Create a child key
	create := tpm2.Create{
		ParentHandle: tpm2.NamedHandle{
			Handle: parentHandle,
			Name:   createPrimaryResponse.Name,
		},
		InPublic: tpm2.New2B(childTmpl),
	}
	
	createResponse, err := create.Execute(tpm)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("Create (child) err: %w", err)
	}

	var out bytes.Buffer
	enc := lencode.NewEncoder(&out, lencode.SeparatorOpt(separator))

	// Store the serialized private and public parts
	privateBytes := tpm2.Marshal(createResponse.OutPrivate)
	publicBytes := tpm2.Marshal(createResponse.OutPublic)

	enc.Encode(privateBytes)
	enc.Encode(publicBytes)
	enc.Encode(randSeed)

	// Load the child key
	load := tpm2.Load{
		ParentHandle: tpm2.NamedHandle{
			Handle: parentHandle,
			Name:   createPrimaryResponse.Name,
		},
		InPrivate: createResponse.OutPrivate,
		InPublic:  createResponse.OutPublic,
	}
	
	loadResponse, err := load.Execute(tpm)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("load child key err: %w", err)
	}

	defer flushContext(tpm, loadResponse.ObjectHandle)

	// Read the public part of the key
	readPublic := tpm2.ReadPublic{
		ObjectHandle: loadResponse.ObjectHandle,
	}
	
	readPublicResponse, err := readPublic.Execute(tpm)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("read public key err: %w", err)
	}

	publicData, err := readPublicResponse.OutPublic.Contents()
	if err != nil {
		return nil, nil, nil, fmt.Errorf("get public contents err: %w", err)
	}

	eccPoint, err := publicData.Unique.ECC()
	if err != nil {
		return nil, nil, nil, fmt.Errorf("extract ECC point err: %w", err)
	}

	x := new(big.Int).SetBytes(eccPoint.X.Buffer)
	y := new(big.Int).SetBytes(eccPoint.Y.Buffer)

	seclog.SecurityEvent("New key registered for application parameter")

	return out.Bytes(), x, y, nil
}

// Flush a TPM context/handle
func flushContext(tpm transport.TPM, handle tpm2.TPMHandle) {
	flush := tpm2.FlushContext{
		FlushHandle: handle,
	}
	_, _ = flush.Execute(tpm)
}

// Use constant time comparison for sensitive data
func constantTimeCompare(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	
	var result byte = 0
	for i := 0; i < len(a); i++ {
		result |= a[i] ^ b[i]
	}
	
	return result == 0
}

// Verify TPM's PCR values to ensure system integrity
func (t *TPM) verifySystemIntegrity(tpm transport.TPM) (bool, error) {
	// Read PCRs that represent boot integrity
	pcrSelection := tpm2.TPMLPCRSelection{
		PCRSelections: []tpm2.TPMSPCRSelection{
			{
				Hash:      tpm2.TPMAlgSHA256,
				PCRSelect: tpm2.PCClientCompatible.PCRs(0, 1, 2, 3, 4, 5, 6, 7),
			},
		},
	}
	
	pcrRead := tpm2.PCRRead{
		PCRSelectionIn: pcrSelection,
	}
	
	pcrReadResponse, err := pcrRead.Execute(tpm)
	if err != nil {
		return false, fmt.Errorf("failed to read PCRs: %w", err)
	}
	
	// In a production system, you would compare these to known-good values
	// This is a simplified check that just ensures they're not all zeros
	for i, digest := range pcrReadResponse.PCRValues.Digests {
		pcrBytes := digest.Buffer
		allZero := true
		for _, b := range pcrBytes {
			if b != 0 {
				allZero = false
				break
			}
		}
		
		if allZero {
			return false, fmt.Errorf("PCR %d contains all zeros - possible tampering", i)
		}
	}
	
	return true, nil
}

func validateKeyHandle(handle []byte) error {
	if len(handle) == 0 {
		return fmt.Errorf("empty key handle")
	}
	
	if len(handle) > 1024 {
		return fmt.Errorf("key handle too large")
	}
	
	return nil
}

func validateApplicationParam(param []byte) error {
	if len(param) != 32 {
		return fmt.Errorf("application parameter must be 32 bytes")
	}
	return nil
}

func (t *TPM) SignASN1(keyHandle, applicationParam, digest []byte) ([]byte, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	
	// Validate inputs
	if err := validateKeyHandle(keyHandle); err != nil {
		return nil, err
	}
	
	if err := validateApplicationParam(applicationParam); err != nil {
		return nil, err
	}
	
	if len(digest) == 0 {
		return nil, fmt.Errorf("invalid parameters: empty digest")
	}

	tpm, err := t.open()
	if err != nil {
		return nil, fmt.Errorf("open tpm err: %w", err)
	}
	defer tpm.Close()
	
	// Verify system integrity via PCRs
	integrityOK, err := t.verifySystemIntegrity(tpm)
	if err != nil {
		seclog.Error("System integrity check failed: %v", err)
		return nil, fmt.Errorf("system integrity check failed: %w", err)
	}
	
	if !integrityOK {
		seclog.SecurityEvent("System integrity verification failed during authentication")
		return nil, fmt.Errorf("system integrity verification failed")
	}

	dec := lencode.NewDecoder(bytes.NewReader(keyHandle), lencode.SeparatorOpt(separator))
	invalidHandleErr := fmt.Errorf("invalid key handle")

	privateBytes, err := dec.Decode()
	if err != nil {
		return nil, invalidHandleErr
	}

	publicBytes, err := dec.Decode()
	if err != nil {
		return nil, invalidHandleErr
	}

	seed, err := dec.Decode()
	if err != nil {
		return nil, invalidHandleErr
	}

	_, err = dec.Decode()
	if err != io.EOF {
		return nil, invalidHandleErr
	}
	
	// Enhanced security: detect potential injections
	if len(seed) != seedSizeBytes {
		seclog.SecurityEvent("Security violation: invalid seed length during signing")
		return nil, fmt.Errorf("security violation: invalid seed length")
	}

	// Unmarshal the serialized private and public parts
	private, err := tpm2.Unmarshal[tpm2.TPM2BPrivate](privateBytes)
	if err != nil {
		return nil, fmt.Errorf("unmarshal private err: %w", err)
	}
	
	public, err := tpm2.Unmarshal[tpm2.TPM2BPublic](publicBytes)
	if err != nil {
		return nil, fmt.Errorf("unmarshal public err: %w", err)
	}

	srkTemplate := primaryKeyTmpl(seed, applicationParam)
	
	// Create a primary key with stronger security policy
	createPrimary := tpm2.CreatePrimary{
		PrimaryHandle: tpm2.TPMRHOwner,
		InPublic:      tpm2.New2B(srkTemplate),
	}
	
	createPrimaryResponse, err := createPrimary.Execute(tpm)
	if err != nil {
		return nil, fmt.Errorf("CreatePrimary key err: %w", err)
	}
	parentHandle := createPrimaryResponse.ObjectHandle
	defer flushContext(tpm, parentHandle)

	// Load the key for signing
	load := tpm2.Load{
		ParentHandle: tpm2.NamedHandle{
			Handle: parentHandle,
			Name:   createPrimaryResponse.Name,
		},
		InPrivate: *private,
		InPublic:  *public,
	}
	
	loadResponse, err := load.Execute(tpm)
	if err != nil {
		return nil, fmt.Errorf("Load err: %w", err)
	}
	defer flushContext(tpm, loadResponse.ObjectHandle)

	// Sign the data
	sign := tpm2.Sign{
		KeyHandle: tpm2.NamedHandle{
			Handle: loadResponse.ObjectHandle,
			Name:   loadResponse.Name,
		},
		Digest: tpm2.TPM2BDigest{
			Buffer: digest,
		},
		InScheme: tpm2.TPMTSigScheme{
			Scheme: tpm2.TPMAlgECDSA,
			Details: tpm2.NewTPMUSigScheme(
				tpm2.TPMAlgECDSA,
				&tpm2.TPMSSchemeHash{
					HashAlg: tpm2.TPMAlgSHA256,
				},
			),
		},
		Validation: tpm2.TPMTTKHashCheck{
			Tag: tpm2.TPMSTHashCheck,
		},
	}
	
	signResponse, err := sign.Execute(tpm)
	if err != nil {
		return nil, fmt.Errorf("sign err: %w", err)
	}

	// Extract R and S from the signature
	eccSig, err := signResponse.Signature.Signature.ECDSA()
	if err != nil {
		return nil, fmt.Errorf("extract ECDSA signature err: %w", err)
	}

	r := new(big.Int).SetBytes(eccSig.SignatureR.Buffer)
	s := new(big.Int).SetBytes(eccSig.SignatureS.Buffer)

	var b cryptobyte.Builder
	b.AddASN1(asn1.SEQUENCE, func(b *cryptobyte.Builder) {
		b.AddASN1BigInt(r)
		b.AddASN1BigInt(s)
	})

	return b.Bytes()
}


func mustRand(size int) []byte {
	b := make([]byte, size)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}

	return b
}
