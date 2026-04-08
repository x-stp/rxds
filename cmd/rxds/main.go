// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 x-stp

package main

import (
	"bufio"
	"context"
	"crypto/rand"
	"encoding/binary"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/netip"
	"os"
	"os/signal"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"

	"github.com/x-stp/rxds"
	"github.com/x-stp/rxds/tls"
)

const banner = `
 _ ____  __   / / /_| (_)___| | __ _ ___| |_ _ __ ___  __ _ _ __ ___   ___ _ __
| '__\ \/ /  / / / _` + "`" + ` | / __| |/ _` + "`" + ` / __| __| '__/ _ \/ _` + "`" + ` | '_ ` + "`" + ` _ \ / _ \ '__|
| |   >  <  / / / (_| | \__ \ | (_| \__ \ |_| | |  __/ (_| | | | | | |  __/ |
|_|  /_/\_\/_/_/ \__,_|_|___/_|\__,_|___/\__|_|  \___|\__,_|_| |_| |_|\___|_|

`

func main() {
	var (
		outPath     = flag.String("out", "", "output JSONL file (default: stdout)")
		cidrsPath   = flag.String("cidrs", "", "file with CIDRs/IPs to scan")
		denyPath    = flag.String("denylist", "", "file with CIDRs/IPs to skip")
		concurrency = flag.Int("concurrency", 256, "concurrent dials")
		timeout     = flag.Duration("timeout", 5*time.Second, "per-target timeout")
		sni         = flag.String("sni", "", "SNI to send")
		sslv2hello  = flag.Bool("sslv2hello", false, "SSLv2-framed ClientHello")
		port        = flag.Uint("port", 443, "default port")
		printErrors = flag.Bool("print-errors", false, "emit JSONL for errors")
		printEmpty  = flag.Bool("print-empty", false, "emit JSONL even if no CN/SANs")
		cloud       = flag.String("cloud", "", "cloud source(s) (default: cf)")
		cloudSample = flag.Int("cloud-sample", 0, "sample N targets from cloud ranges")
		cloudWeight = flag.Int("cloud-weight", 8, "cloud scheduling weight")
		noGlobal    = flag.Bool("no-global", false, "disable default global scan (read stdin instead)")
		enableJARM  = flag.Bool("jarm", false, "JARM fingerprint (10 extra conns/host)")
	)
	flag.Usage = func() {
		fmt.Fprint(os.Stderr, banner)
		fmt.Fprintf(os.Stderr, "Usage: %s [flags]\n\nScans all public IPv4 by default. Use -cidrs or -no-global for targeted scans.\n\n", os.Args[0])
		flag.PrintDefaults()
	}
	flag.Parse()

	if *concurrency < 1 {
		log.Fatal().Msg("-concurrency must be >= 1")
	}
	if *port > 65535 || *port == 0 {
		log.Fatal().Uint("port", *port).Msg("-port must be in 1..65535")
	}

	global := !*noGlobal && *cidrsPath == "" && *cloudSample == 0
	stdinMode := *noGlobal && *cidrsPath == "" && *cloudSample == 0

	if stdinMode && isTerminal(os.Stdin) {
		flag.Usage()
		os.Exit(0)
	}

	seed := cryptoSeed()

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	go func() {
		<-ctx.Done()
		sig := make(chan os.Signal, 1)
		signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
		<-sig
		fmt.Fprintln(os.Stderr, "\nforce quit")
		os.Exit(1)
	}()

	rxds.PreHeatCPU()

	zerolog.TimeFieldFormat = time.RFC3339Nano
	log.Logger = log.Output(zerolog.ConsoleWriter{Out: os.Stderr, TimeFormat: time.RFC3339Nano})

	var deny *denylist
	if *denyPath != "" {
		var err error
		deny, err = loadDenylist(*denyPath)
		if err != nil {
			log.Fatal().Err(err).Str("denylist", *denyPath).Msg("failed to load denylist")
		}
		log.Info().Int("entries", deny.Len()).Str("file", *denyPath).Msg("denylist loaded")
	}

	cfg := &tls.Config{
		CertsOnly:          true,
		InsecureSkipVerify: true,
		SSLv2ClientHello:   *sslv2hello,
		ServerName:         *sni,
	}

	out := openOutput(*outPath)
	bufw := bufio.NewWriterSize(out, 1<<20)
	defer bufw.Flush()

	targets := make(chan target, *concurrency*8)
	results := make(chan result, *concurrency*8)

	var attempts, success atomic.Uint64

	var wg sync.WaitGroup
	for range *concurrency {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for t := range targets {
				attempts.Add(1)
				res := scanOne(ctx, t, cfg, *timeout, uint16(*port), *enableJARM)
				if shouldEmit(res, *printErrors, *printEmpty) {
					success.Add(1)
					select {
					case results <- res:
					case <-ctx.Done():
						return
					}
				}
			}
		}()
	}

	startTime := time.Now()
	var totalTargets uint64
	if global {
		totalTargets = 1 << 32
	}

	statsDone := make(chan struct{})
	go runStats(ctx, startTime, totalTargets, &attempts, &success, statsDone)

	var writeWG sync.WaitGroup
	writeWG.Add(1)
	go func() {
		defer writeWG.Done()
		enc := json.NewEncoder(bufw)
		ticker := time.NewTicker(1 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case r, ok := <-results:
				if !ok {
					return
				}
				_ = enc.Encode(r)
			case <-ticker.C:
				bufw.Flush()
			}
		}
	}()

	var nTargets atomic.Uint64
	userQ := make(chan target, *concurrency*16)
	cloudQ := make(chan target, *concurrency*16)

	addTarget := func(q chan<- target, addr netip.Addr, p uint16) {
		if !isGlobalIP(addr) {
			return
		}
		if deny != nil && deny.Contains(addr) {
			return
		}
		select {
		case q <- target{IP: addr, Port: p}:
		case <-ctx.Done():
		}
	}

	var muxWG sync.WaitGroup
	muxWG.Add(1)
	go runMux(ctx, userQ, cloudQ, targets, &nTargets, *cloudWeight, seed, &muxWG)

	var prodWG sync.WaitGroup
	if *cloudSample > 0 {
		prodWG.Add(1)
		go func() {
			defer prodWG.Done()
			src := strings.TrimSpace(*cloud)
			if src == "" {
				src = "cf"
			}
			_ = emitCloudSamples(ctx, strings.Split(src, ","), *cloudSample, seed, uint16(*port), func(addr netip.Addr, p uint16) {
				addTarget(cloudQ, addr, p)
			})
		}()
	}

	prodWG.Add(1)
	go func() {
		defer prodWG.Done()
		p := uint16(*port)
		if global {
			expandCIDR(ctx, "0.0.0.0/1", seed, func(addr netip.Addr) { addTarget(userQ, addr, p) })
			expandCIDR(ctx, "128.0.0.0/1", seed, func(addr netip.Addr) { addTarget(userQ, addr, p) })
		}
		if *cidrsPath != "" {
			_ = readCIDRFile(ctx, *cidrsPath, seed, func(addr netip.Addr) { addTarget(userQ, addr, p) })
		}
		if stdinMode {
			_ = readTargets(os.Stdin, p, func(addr netip.Addr, port uint16) { addTarget(userQ, addr, port) })
		}
	}()

	prodWG.Wait()
	close(userQ)
	close(cloudQ)
	muxWG.Wait()

	wg.Wait()
	close(results)
	writeWG.Wait()

	stop()
	<-statsDone
	bufw.Flush()

	elapsed := time.Since(startTime).Truncate(time.Second)
	log.Info().Uint64("targets", nTargets.Load()).Uint64("certs", success.Load()).Str("elapsed", elapsed.String()).Msg("done")
}

func runStats(ctx context.Context, start time.Time, total uint64, att, succ *atomic.Uint64, done chan struct{}) {
	defer close(done)
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()
	var lastAtt, lastSucc uint64
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			a := att.Load()
			s := succ.Load()
			elapsed := time.Since(start)
			dps := float64(a-lastAtt) / 2.0
			rps := float64(s-lastSucc) / 2.0

			ev := log.Info().
				Str("elapsed", elapsed.Truncate(time.Second).String()).
				Float64("dps", dps).
				Float64("rps", rps).
				Uint64("att", a).
				Uint64("certs", s)

			if total > 0 && dps > 0 {
				pct := float64(a) / float64(total) * 100.0
				remaining := time.Duration(float64(total-a)/dps) * time.Second
				ev = ev.Str("progress", fmt.Sprintf("%.4f%%", pct)).
					Str("eta", remaining.Truncate(time.Second).String())
			}

			ev.Msg("stats")
			lastAtt = a
			lastSucc = s
		}
	}
}

func cryptoSeed() uint32 {
	var b [4]byte
	rand.Read(b[:])
	return binary.BigEndian.Uint32(b[:])
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

func isTerminal(f *os.File) bool {
	fi, err := f.Stat()
	if err != nil {
		return false
	}
	return fi.Mode()&os.ModeCharDevice != 0
}
