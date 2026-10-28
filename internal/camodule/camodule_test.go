package camodule_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/yinkoshield/pinscan/internal/camodule"
	"github.com/yinkoshield/pinscan/internal/certmint"
)

func caPEM(t *testing.T, cn string) []byte {
	t.Helper()
	ca, err := certmint.NewCA(cn)
	if err != nil {
		t.Fatalf("NewCA: %v", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ca.Cert().Raw})
}

func find(files []camodule.File, suffix string) (camodule.File, bool) {
	for _, f := range files {
		if strings.HasSuffix(f.Path, suffix) {
			return f, true
		}
	}
	return camodule.File{}, false
}

func TestGenerateStructure(t *testing.T) {
	t.Parallel()

	files, err := camodule.Generate(caPEM(t, "pinscan selftest CA"), "pinscan-ca", "pinscan research CA")
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}

	prop, ok := find(files, "module.prop")
	if !ok || !strings.Contains(string(prop.Content), "id=pinscan-ca") {
		t.Errorf("module.prop missing or wrong: %q", prop.Content)
	}

	script, ok := find(files, "post-fs-data.sh")
	if !ok || !script.Executable {
		t.Errorf("post-fs-data.sh missing or not executable: %+v", script)
	}

	svc, ok := find(files, "service.sh")
	if !ok || !svc.Executable {
		t.Errorf("service.sh missing or not executable: %+v", svc)
	}

	if _, ok := find(files, "README.md"); !ok {
		t.Error("README.md not generated")
	}
}

// TestGenerateCertFile checks the certificate is written where Android looks
// for it: under cacerts, named <subject_hash_old>.0.
func TestGenerateCertFile(t *testing.T) {
	t.Parallel()

	files, err := camodule.Generate(caPEM(t, "pinscan selftest CA"), "pinscan-ca", "pinscan research CA")
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	cacert, ok := find(files, ".0")
	if !ok {
		t.Fatal("no cacerts/<hash>.0 file generated")
	}
	if !strings.HasPrefix(cacert.Path, "system/etc/security/cacerts/") {
		t.Errorf("cacert path = %q, want under system/etc/security/cacerts/", cacert.Path)
	}
	if !regexp.MustCompile(`/[0-9a-f]{8}\.0$`).MatchString(cacert.Path) {
		t.Errorf("cacert filename is not an 8-hex-digit hash: %q", cacert.Path)
	}
	if !strings.Contains(string(cacert.Content), "BEGIN CERTIFICATE") {
		t.Error("cacert file does not contain a PEM certificate")
	}
}

// TestGenerateAPEXOverlayPlacement pins down where the Android 14+ Conscrypt
// APEX overlay runs and what it has to do. Every assertion here was a real
// failure on a device: a bind mount placed in post-fs-data.sh is discarded when
// apexd mounts the APEX afterwards, and a mount made only in the global
// namespace never reaches an app, which is forked from zygote's own mount
// namespace. Either way the CA is silently untrusted and every host reads
// inconclusive, which is the one outcome this module must never produce.
func TestGenerateAPEXOverlayPlacement(t *testing.T) {
	t.Parallel()

	files, err := camodule.Generate(caPEM(t, "pinscan selftest CA"), "pinscan-ca", "pinscan research CA")
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	svc, ok := find(files, "service.sh")
	if !ok {
		t.Fatal("service.sh not generated")
	}
	post, ok := find(files, "post-fs-data.sh")
	if !ok {
		t.Fatal("post-fs-data.sh not generated")
	}

	for _, want := range []string{"conscrypt", "sys.boot_completed", "mount -o bind", "nsenter", "zygote"} {
		if !strings.Contains(string(svc.Content), want) {
			t.Errorf("service.sh should contain %q", want)
		}
	}
	if strings.Contains(string(post.Content), "mount -o bind") {
		t.Error("post-fs-data.sh must not bind-mount the APEX: apexd remounts it afterwards")
	}
}

func TestSubjectHashDependsOnSubjectNotKey(t *testing.T) {
	t.Parallel()

	// Two CAs with the same subject (same CN) but independent keys hash the same;
	// a different subject hashes differently.
	a, err := certmint.NewCA("Same Name")
	if err != nil {
		t.Fatal(err)
	}
	b, err := certmint.NewCA("Same Name")
	if err != nil {
		t.Fatal(err)
	}
	c, err := certmint.NewCA("Different Name")
	if err != nil {
		t.Fatal(err)
	}
	ha, hb, hc := camodule.SubjectHashOld(a.Cert()), camodule.SubjectHashOld(b.Cert()), camodule.SubjectHashOld(c.Cert())
	if ha != hb {
		t.Errorf("same subject hashed differently: %s vs %s", ha, hb)
	}
	if ha == hc {
		t.Errorf("different subjects hashed the same: %s", ha)
	}
	if !regexp.MustCompile(`^[0-9a-f]{8}$`).MatchString(ha) {
		t.Errorf("hash %q is not 8 hex digits", ha)
	}
}

func TestGenerateRejectsNonCA(t *testing.T) {
	t.Parallel()

	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "leaf.example.com"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		// IsCA is false.
	}
	der, _ := x509.CreateCertificate(rand.Reader, tmpl, tmpl, key.Public(), key)
	leafPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})

	if _, err := camodule.Generate(leafPEM, "x", "x"); err == nil {
		t.Error("Generate accepted a non-CA certificate, want an error")
	}
}

func TestGenerateRejectsNoCert(t *testing.T) {
	t.Parallel()

	if _, err := camodule.Generate([]byte("not a pem"), "x", "x"); err == nil {
		t.Error("Generate accepted junk input, want an error")
	}
}
