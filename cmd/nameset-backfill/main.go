package main

import (
	"sort"
	"strings"

	"github.com/letsencrypt/boulder/cmd"
	"github.com/letsencrypt/boulder/core"

	"github.com/letsencrypt/boulder/Godeps/_workspace/src/github.com/cactus/go-statsd-client/statsd"

	"gopkg.in/gorp.v1"
)

func hashNames(names []string) ([]byte, error) {
	sort.Strings(names)
	for i := range names {
		names[i] = strings.ToLower(names[i])
	}
	hash, err := sha256.Sum256(strings.Join(names, ","))
	return hash[:], err
}

type resultHolder struct {
	Serial string
	Issued time.Time
	DER    []byte
}

type backfiller struct {
	sa    core.StorageAuthority
	dbMap *gorp.Gorp
}

func new(amqpConf *cmd.AMQPConfig, statsdURI, dbURI string) (*backFiller, error) {
	var stats statsd.Statter
	if statsdURI != "" {
		stats, err := statsd.NewClient(statsdURI)
		if err != nil {
			return err
		}
	}
	sac, err := rpc.NewStorageAuthorityClient("nameset-backfiller", amqpConf, stats)
	if err != nil {
		return nil, err
	}
	dbMap, err := sa.NewDbMap(dbURI)
	if err != nil {
		return nil, err
	}

	return &backfiller{sac, dbMap}, nil
}

func run() error {
	added := 0
	for {
		results, err := b.findCerts()
		if err != nil {
			return err
		}
		if len(results) == 0 {
			break
		}
		err = b.processResults(results)
		if err != nil {
			return err
		}
		added += len(results)
	}
	fmt.Printd("Added %d missing certificate name sets to the nameSets table\n", added)
}

func (b *backfiller) findCerts() ([]resultHolder, error) {
	var results []resultHolder
	_, err := b.dbMap.Select(
		&results,
		`SELECT c.serial, c.issued, c.der FROM certificates AS c
     JOIN nameSets AS ns ON ns.serial=c.serial
     WHERE c.serial NOT IN (SELECT ns.serial FROM nameSets AS ns)
     AND c.expires > ?
     ORDER BY c.issued DESC
     LIMIT ?`,
		time.Now(), // now
		1000,       // limit
	)
	return results, err
}

func (b *backfiller) processResults(results []resultHolder) error {
	added := 0
	for _, r := range results {
		c, err := x509.ParseCertificate(r.DER)
		if err != nil {
			// log
			continue
		}
		hash, err := hashNames(c.DNSNames)
		if err != nil {
			// log
			continue
		}
		err = b.sa.AddNameSet(r.Serial, r.NotBefore, hash)
		if err != nil {
			// log
			continue
		}
		added++
	}
	if added < len(certs) {
		return fmt.Errorf("Failed to add all name sets, %d failed", len(certs)-added)
	}
}
