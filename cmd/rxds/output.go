// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 x-stp

package main

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"os"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/rs/zerolog/log"

	"github.com/x-stp/rxds/scan/syn"
)

func startWriter(ctx context.Context, results <-chan result, bufw *bufio.Writer) *sync.WaitGroup {
	var wg sync.WaitGroup
	wg.Go(func() {
		runWriter(ctx, results, bufw)
	})
	return &wg
}

func runWriter(_ context.Context, results <-chan result, bufw *bufio.Writer) {
	var buf []byte
	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case r, ok := <-results:
			if !ok {
				return
			}
			buf = r.appendJSONL(buf[:0])
			if _, err := bufw.Write(buf); err != nil {
				log.Fatal().Err(err).Msg("output write failed")
			}
		case <-ticker.C:
			if err := bufw.Flush(); err != nil {
				log.Fatal().Err(err).Msg("output flush failed")
			}
		}
	}
}

func (r *result) appendJSONL(buf []byte) []byte {
	buf = append(buf, '{')
	buf = appendKV(buf, "ip", r.IP)
	buf = append(buf, ',')
	buf = appendKU16(buf, "port", r.Port)
	if r.SNI != "" {
		buf = append(buf, ',')
		buf = appendKV(buf, "sni", r.SNI)
	}
	buf = append(buf, ',')
	buf = appendKV(buf, "cn", r.CN)
	buf = append(buf, ',')
	buf = appendKArr(buf, "sans", r.SANs)
	buf = append(buf, ',')
	buf = appendKV(buf, "org", r.Org)
	buf = append(buf, ',')
	buf = appendKV(buf, "apex_domain", r.ApexDomain)
	buf = append(buf, ',')
	buf = appendKArr(buf, "root_domains", r.RootDomains)
	buf = append(buf, ',')
	buf = appendKV(buf, "fuzzy_hash", r.FuzzyHash)
	if r.SHA256Fingerprint != "" {
		buf = append(buf, ',')
		buf = appendKV(buf, "sha256", r.SHA256Fingerprint)
	}
	if r.JARM != "" {
		buf = append(buf, ',')
		buf = appendKV(buf, "jarm", r.JARM)
	}
	if r.Err != "" {
		buf = append(buf, ',')
		buf = appendKV(buf, "err", r.Err)
	}
	buf = append(buf, '}', '\n')
	return buf
}

func appendKV(buf []byte, key, val string) []byte {
	buf = append(buf, '"')
	buf = append(buf, key...)
	buf = append(buf, '"', ':')
	buf = strconv.AppendQuote(buf, val)
	return buf
}

func appendKU16(buf []byte, key string, val uint16) []byte {
	buf = append(buf, '"')
	buf = append(buf, key...)
	buf = append(buf, '"', ':')
	buf = strconv.AppendUint(buf, uint64(val), 10)
	return buf
}

func appendKArr(buf []byte, key string, vals []string) []byte {
	buf = append(buf, '"')
	buf = append(buf, key...)
	buf = append(buf, '"', ':', '[')
	for i, v := range vals {
		if i > 0 {
			buf = append(buf, ',')
		}
		buf = strconv.AppendQuote(buf, v)
	}
	buf = append(buf, ']')
	return buf
}

func runStats(ctx context.Context, start time.Time, total uint64, att, succ *atomic.Uint64, scanner *syn.Scanner, done chan struct{}) {
	defer close(done)
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()
	var lastAtt, lastSynTx uint64
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			a := att.Load()
			s := succ.Load()
			elapsed := time.Since(start)
			rate := float64(a-lastAtt) / 2.0

			ev := log.Info().
				Str("elapsed", elapsed.Truncate(time.Second).String()).
				Float64("rate", rate).
				Uint64("attempts", a).
				Uint64("certs", s)

			if a > 0 {
				ev = ev.Str("hit_rate", fmt.Sprintf("%.2f%%", 100*float64(s)/float64(a)))
			}

			if scanner != nil {
				tx, rx := scanner.Stats()
				ev = ev.
					Uint64("syn_tx", tx).
					Uint64("syn_rx", rx).
					Float64("syn_rate", float64(tx-lastSynTx)/2.0)
				if tx > 0 {
					ev = ev.Str("syn_hit_rate", fmt.Sprintf("%.2f%%", 100*float64(rx)/float64(tx)))
				}
				lastSynTx = tx
			}

			if total > 0 && rate > 0 {
				pct := float64(a) / float64(total) * 100.0
				remaining := time.Duration(float64(total-a)/rate) * time.Second
				ev = ev.Str("progress", fmt.Sprintf("%.4f%%", pct)).
					Str("eta", remaining.Truncate(time.Second).String())
			}

			ev.Msg("stats")
			lastAtt = a
		}
	}
}

func openOutput(path string) io.WriteCloser {
	if path == "" {
		return os.Stdout
	}
	f, err := os.Create(path)
	if err != nil {
		log.Fatal().Err(err).Str("out", path).Msg("failed to create output file")
	}
	return f
}
