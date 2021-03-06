package main

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"math/big"
	"testing"
	"time"

	"github.com/letsencrypt/boulder/core"
	"github.com/letsencrypt/boulder/test"
)

var (
	email1 = mustParseAcmeURL("mailto:one@example.com")
	email2 = mustParseAcmeURL("mailto:two@example.com")
)

func mustParseAcmeURL(acmeURL string) *core.AcmeURL {
	c, err := core.ParseAcmeURL(acmeURL)
	if err != nil {
		panic(fmt.Sprintf("unable to parse as AcmeURL %#v: %s", acmeURL, err))
	}
	return c
}

func TestSendEarliestCertInfo(t *testing.T) {
	expiresIn := 24 * time.Hour
	ctx := setup(t, []time.Duration{expiresIn})
	defer ctx.cleanUp()

	rawCertA := newX509Cert("happy A",
		ctx.fc.Now().AddDate(0, 0, 5),
		[]string{"example-A.com", "SHARED-example.com"},
		1337,
	)
	rawCertB := newX509Cert("happy B",
		ctx.fc.Now().AddDate(0, 0, 2),
		[]string{"shared-example.com", "example-b.com"},
		1337,
	)

	ctx.m.sendNags([]*core.AcmeURL{email1, email2}, []*x509.Certificate{rawCertA, rawCertB})
	if len(ctx.mc.Messages) != 2 {
		t.Errorf("num of messages, want %d, got %d", 2, len(ctx.mc.Messages))
	}
	if len(ctx.mc.Messages) == 0 {
		t.Fatalf("no message sent")
	}
	domains := "example-a.com\nexample-b.com\nshared-example.com"
	expected := fmt.Sprintf(`hi, cert for DNS names %s is going to expire in 2 days (%s)`,
		domains,
		rawCertB.NotAfter.Format(time.RFC822Z))
	test.AssertEquals(t, expected, ctx.mc.Messages[0])
}

func newX509Cert(commonName string, notAfter time.Time, dnsNames []string, serial int64) *x509.Certificate {
	return &x509.Certificate{
		Subject: pkix.Name{
			CommonName: commonName,
		},
		NotAfter:     notAfter,
		DNSNames:     dnsNames,
		SerialNumber: big.NewInt(serial),
	}

}
