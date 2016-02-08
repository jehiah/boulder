package main

import (
	"crypto/x509"
	"fmt"
	"time"

	"github.com/letsencrypt/boulder/cmd"
	"github.com/letsencrypt/boulder/core"
	"github.com/letsencrypt/boulder/rpc"
	"github.com/letsencrypt/boulder/sa"

	"github.com/letsencrypt/boulder/Godeps/_workspace/src/github.com/cactus/go-statsd-client/statsd"
	"github.com/letsencrypt/boulder/Godeps/_workspace/src/gopkg.in/gorp.v1"
)

type resultHolder struct {
	Serial string
	Issued time.Time
	DER    []byte
}

type backfiller struct {
	sa    core.StorageAuthority
	dbMap *gorp.DbMap
	stats statsd.Statter
}

func new(amqpConf *cmd.AMQPConfig, statsdURI, dbURI string) (*backfiller, error) {
	var stats statsd.Statter
	var err error
	if statsdURI != "" {
		stats, err = statsd.NewClient(statsdURI, "Boulder")
		if err != nil {
			return nil, err
		}
	} else {
		stats, _ = statsd.NewNoopClient(nil)
	}
	sac, err := rpc.NewStorageAuthorityClient("nameset-backfiller", amqpConf, stats)
	if err != nil {
		return nil, err
	}
	dbMap, err := sa.NewDbMap(dbURI)
	if err != nil {
		return nil, err
	}
	return &backfiller{sac, dbMap, stats}, nil
}

func (b *backfiller) run() error {
	added := 0
	defer fmt.Printf("Added %d missing certificate name sets to the nameSets table\n", added)
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
	return nil
}

func (b *backfiller) findCerts() ([]resultHolder, error) {
	var results []resultHolder
	_, err := b.dbMap.Select(
		&results,
		// idk left outer join instead?
		`SELECT c.serial, c.issued, c.der FROM certificates AS c
     WHERE c.serial NOT IN (SELECT ns.serial FROM nameSets AS ns)
     AND c.expires > ?
     ORDER BY c.issued DESC
     LIMIT ?`,
		time.Now(), // now
		1000,       // limit
	)
	b.stats.Inc("db-backfill.nameSets.missing-found", int64(len(results)), 1.0)
	return results, err
}

func (b *backfiller) processResults(results []resultHolder) error {
	numResults := len(results)
	added := 0
	for _, r := range results {
		c, err := x509.ParseCertificate(r.DER)
		if err != nil {
			// log
			continue
		}
		err = b.sa.AddNameSet(core.NameSet{core.HashNames(c.DNSNames), r.Serial, r.Issued})
		if err != nil {
			// log
			continue
		}
		added++
		b.stats.Inc("db-backfill.nameSets.added", 1, 1.0)
	}
	if added < numResults {
		return fmt.Errorf("Didn'd add all name sets, %d out of %d failed", numResults-added, numResults)
	}
	return nil
}

func main() {
	amqpConf := &cmd.AMQPConfig{
		ServerURLFile: "test/secrets/amqp_url",
		Insecure:      true,
		SA: &cmd.RPCServerConfig{
			Server:     "SA.server",
			RPCTimeout: cmd.ConfigDuration{time.Second * 15},
		},
	}
	statsdURI := "localhost:8125"
	dbURI := "mysql+tcp://backfiller@localhost:3306/boulder_sa_integration"
	b, err := new(amqpConf, statsdURI, dbURI)
	cmd.FailOnError(err, "Failed to create backfiller")
	err = b.run()
	cmd.FailOnError(err, "Failed to backfill nameSets table")
}
