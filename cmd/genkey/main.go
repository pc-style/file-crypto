package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"flag"
	"fmt"
	"os"
	"path/filepath"
)

func main() {
	var (
		name     string
		bits     int
		outDir   string
	)

	flag.StringVar(&name, "name", "", "Name label for key files (required). Files will be 'public-<name>' and 'private-<name>'")
	flag.IntVar(&bits, "bits", 4096, "RSA key size in bits")
	flag.StringVar(&outDir, "out", ".", "Output directory for generated files")
	flag.Parse()

	if name == "" {
		fmt.Fprintln(os.Stderr, "error: -name is required (e.g., -name docker)")
		os.Exit(2)
	}
	if bits < 2048 {
		fmt.Fprintln(os.Stderr, "error: bits must be >= 2048")
		os.Exit(2)
	}

	if err := os.MkdirAll(outDir, 0o755); err != nil {
		fmt.Fprintf(os.Stderr, "failed to create output directory: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("🔑 Generating RSA-%d key pair...\n", bits)
	priv, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to generate key: %v\n", err)
		os.Exit(1)
	}

	// Private key: PKCS#8 PEM
	privDER, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to marshal private key: %v\n", err)
		os.Exit(1)
	}
	privPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privDER})

	// Public key: PKIX DER -> Base64 (single line), ideal for PUBKEY_B64 embedding
	pubDER, err := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to marshal public key: %v\n", err)
		os.Exit(1)
	}
	pubB64 := base64.StdEncoding.EncodeToString(pubDER)

	privPath := filepath.Join(outDir, fmt.Sprintf("private-%s", name))
	pubPath := filepath.Join(outDir, fmt.Sprintf("public-%s", name))

	if err := os.WriteFile(privPath, privPEM, 0o600); err != nil {
		fmt.Fprintf(os.Stderr, "failed to write %s: %v\n", privPath, err)
		os.Exit(1)
	}
	if err := os.WriteFile(pubPath, []byte(pubB64+"\n"), 0o644); err != nil {
		fmt.Fprintf(os.Stderr, "failed to write %s: %v\n", pubPath, err)
		os.Exit(1)
	}

	fmt.Println("✅ Keys generated:")
	fmt.Printf("   • %s (PEM, mode 600)\n", privPath)
	fmt.Printf("   • %s (Base64 DER, single line)\n", pubPath)
	fmt.Println()
	fmt.Println("Usage examples:")
	fmt.Printf("  docker build --build-arg PUBKEY_B64=\"$(cat %s)\" -t file-crypto:pub .\n", pubPath)
	fmt.Printf("  ./build/decrypt -dir /path -key %s\n", privPath)
}
