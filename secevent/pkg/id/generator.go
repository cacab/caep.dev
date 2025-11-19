package id

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"sync/atomic"
	"time"

	"github.com/google/uuid"
)

// Generator defines the interface for ID generation
type Generator interface {
	Generate() string
}

// UUIDGenerator generates UUIDs for SecEvent IDs
type UUIDGenerator struct{}

func NewUUIDGenerator() *UUIDGenerator {
	return &UUIDGenerator{}
}

func (g *UUIDGenerator) Generate() string {
	return uuid.New().String()
}

// SequentialGenerator generates sequential IDs with a prefix
type SequentialGenerator struct {
	prefix    string
	sequence  uint64
	padLength int
}

func NewSequentialGenerator(prefix string, padLength int) *SequentialGenerator {
	return &SequentialGenerator{
		prefix:    prefix,
		sequence:  0,
		padLength: padLength,
	}
}

func (g *SequentialGenerator) Generate() string {
	seq := atomic.AddUint64(&g.sequence, 1)

	return fmt.Sprintf("%s%0*d", g.prefix, g.padLength, seq)
}

// TimestampGenerator generates timestamp-based IDs
type TimestampGenerator struct {
	prefix string
	suffix Generator // Optional suffix generator
}

func NewTimestampGenerator(prefix string) *TimestampGenerator {
	return &TimestampGenerator{
		prefix: prefix,
	}
}

func (g *TimestampGenerator) WithSuffix(suffix Generator) *TimestampGenerator {
	g.suffix = suffix

	return g
}

func (g *TimestampGenerator) Generate() string {
	timestamp := time.Now().UnixNano()
	if g.suffix != nil {
		return fmt.Sprintf("%s%d%s", g.prefix, timestamp, g.suffix.Generate())
	}

	return fmt.Sprintf("%s%d", g.prefix, timestamp)
}

// RandomGenerator generates random IDs
type RandomGenerator struct {
	length   int
	encoding Encoding
	prefix   string // Optional prefix
}

// Encoding represents the encoding for random IDs
type Encoding int

const (
	EncodingHex Encoding = iota
	EncodingBase64
	EncodingBase64URL
)

func NewRandomGenerator(length int, encoding Encoding) *RandomGenerator {
	return &RandomGenerator{
		length:   length,
		encoding: encoding,
	}
}

func (g *RandomGenerator) WithPrefix(prefix string) *RandomGenerator {
	g.prefix = prefix

	return g
}

func (g *RandomGenerator) Generate() string {
	byteLength := g.length
	switch g.encoding {
	case EncodingBase64, EncodingBase64URL:
		byteLength = (g.length * 3) / 4
	case EncodingHex:
		byteLength = g.length / 2
	}

	bytes := make([]byte, byteLength)
	if _, err := rand.Read(bytes); err != nil {
		// Fallback to UUID in case of error
		return g.prefix + uuid.New().String()
	}

	var encoded string
	switch g.encoding {
	case EncodingBase64:
		encoded = base64.StdEncoding.EncodeToString(bytes)[:g.length]
	case EncodingBase64URL:
		encoded = base64.URLEncoding.EncodeToString(bytes)[:g.length]
	default:
		encoded = hex.EncodeToString(bytes)[:g.length]
	}

	return g.prefix + encoded
}

// Common generators
var (
	// UUID generates standard UUIDs
	UUID = NewUUIDGenerator()

	// Random32 generates 32-character random hex strings
	Random32 = NewRandomGenerator(32, EncodingHex)

	// Base64URL20 generates 20-character base64url-encoded random strings
	Base64URL20 = NewRandomGenerator(20, EncodingBase64URL)

	// TimestampHex generates timestamp-based IDs with random hex suffixes
	TimestampHex = NewTimestampGenerator("").WithSuffix(
		NewRandomGenerator(8, EncodingHex),
	)
)

// Predefined prefixes for sequential generators
const (
	PrefixSET = "set_"
	PrefixTXN = "txn_"
)

// Additional helper generators
var (
	// Sequential generates IDs like "set_00000001"
	SetSequential = NewSequentialGenerator(PrefixSET, 8)

	// TransactionSequential generates IDs like "txn_00000001"
	TransactionSequential = NewSequentialGenerator(PrefixTXN, 8)
)
