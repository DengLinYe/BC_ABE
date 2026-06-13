package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/csv"
	"fmt"
	"io"
	"math"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

const (
	benchSeed       = "bc-abe-demo-seed"
	defaultPolicy   = "(hour@auth1 == 16) /\\ (Vitality@auth1 /\\ locschool@auth1)"
	multiAuthPolicy = "(Vitality@auth0 /\\ locschool@auth1)"
)

var (
	defaultAttrs   = []string{"hour=16@auth1", "Vitality@auth1", "locschool@auth1"}
	multiAuthAttrs = []struct {
		engine int
		attr   string
	}{{0, "Vitality@auth0"}, {1, "locschool@auth1"}}
)

type csvWriter struct {
	path string
	f    *os.File
	w    *csv.Writer
}

func newCSV(outDir, name string, header []string) (*csvWriter, error) {
	if err := os.MkdirAll(outDir, 0o755); err != nil {
		return nil, err
	}
	path := filepath.Join(outDir, name)
	f, err := os.Create(path)
	if err != nil {
		return nil, err
	}
	w := csv.NewWriter(f)
	if err := w.Write(header); err != nil {
		f.Close()
		return nil, err
	}
	return &csvWriter{path: path, f: f, w: w}, nil
}

func (c *csvWriter) row(cols ...string) error { return c.w.Write(cols) }

func (c *csvWriter) close() error {
	c.w.Flush()
	err := c.w.Error()
	if e := c.f.Close(); err == nil {
		err = e
	}
	if err == nil {
		fmt.Println("wrote", c.path)
	}
	return err
}

func msSince(t time.Time) string {
	return fmt.Sprintf("%.3f", float64(time.Since(t).Microseconds())/1000.0)
}

func depthPolicy(n int) string {
	if n < 1 {
		n = 1
	}
	parts := make([]string, n)
	for i := range parts {
		parts[i] = fmt.Sprintf("attr%d@auth1", i)
	}
	return "(" + strings.Join(parts, " /\\ ") + ")"
}

func depthAttrs(n int) []string {
	attrs := make([]string, n)
	for i := range attrs {
		attrs[i] = fmt.Sprintf("attr%d@auth1", i)
	}
	return attrs
}

func gpswPolicyForDepth(l, depth int) (gamma []int, expr string) {
	gamma = make([]int, depth)
	clauses := make([]string, depth)
	for i := range gamma {
		gamma[i] = i
		clauses[i] = fmt.Sprintf("%d", i)
	}
	if depth == 1 {
		return gamma, "0"
	}
	return gamma, "(" + strings.Join(clauses, " AND ") + ")"
}

func aesEncrypt(key [32]byte, plain []byte) ([]byte, error) {
	block, err := aes.NewCipher(key[:])
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}
	return gcm.Seal(nonce, nonce, plain, nil), nil
}

func aesDecrypt(key [32]byte, ct []byte) ([]byte, error) {
	block, err := aes.NewCipher(key[:])
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	if len(ct) < gcm.NonceSize() {
		return nil, fmt.Errorf("ciphertext too short")
	}
	nonce, body := ct[:gcm.NonceSize()], ct[gcm.NonceSize():]
	return gcm.Open(nil, nonce, body, nil)
}

func percentile(sorted []float64, p float64) float64 {
	if len(sorted) == 0 {
		return 0
	}
	idx := int(math.Ceil(p*float64(len(sorted)))) - 1
	if idx < 0 {
		return 0
	}
	if idx >= len(sorted) {
		idx = len(sorted) - 1
	}
	return sorted[idx]
}

func sortFloats(a []float64) { sort.Float64s(a) }
