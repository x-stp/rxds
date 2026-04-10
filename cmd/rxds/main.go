// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 x-stp

package main

import (
	"bufio"
	"context"
	"crypto/rand"
	"encoding/binary"
	"flag"
	"fmt"
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

var banner = strings.Join([]string{
	"               __  _ _       _     _                                      ",
	" _ ____  __   / /_| (_) __ _| |___| |_ _ __ ___  __ _ _ __ ___   ___ _ __ ",
	"| '__\\ \\/ /  / / _` | |/ _` | / __| __| '__/ _ \\/ _` | '_ ` _ \\ / _ \\ '__|",
	"| |   >  <  / / (_| | | (_| | \\__ \\ |_| | |  __/ (_| | | | | | |  __/ |   ",
	"|_|  /_/\\_\\/_/ \\__,_|_|\\__,_|_|___/\\__|_|  \\___|\\__,_|_| |_| |_|\\___|_|   ",
	"",
}, "\n")

type options struct {
	outPath     string
	cidrsPath   string
	denyPath    string
	concurrency int
	timeout     time.Duration
	sni         string
	sslv2hello  bool
	port        uint16
	portRaw     uint
	printErrors bool
	printEmpty  bool
	cloud       string
	cloudSample int
	cloudWeight int
	noGlobal    bool
	enableJARM  bool
}

func main() {
	opts := parseOptions()
	validateOptions(opts)

	global := opts.noGlobal == false && opts.cidrsPath == "" && opts.cloudSample == 0
	stdinMode := opts.noGlobal && opts.cidrsPath == "" && opts.cloudSample == 0
	if stdinMode && isTerminal(os.Stdin) {
		flag.Usage()
		os.Exit(0)
	}

	ctx, stop := newSignalContext()
	defer stop()

	configureLogger()
	rxds.PreHeatCPU()

	deny := loadDenylistOrExit(opts.denyPath)
	cfg := newBaseConfig(opts)
	seed := cryptoSeed()

	out := openOutput(opts.outPath)
	bufw := bufio.NewWriterSize(out, 1<<20)
	defer bufw.Flush()

	targets := make(chan target, opts.concurrency*8)
	results := make(chan result, opts.concurrency*8)

	var attempts atomic.Uint64
	var certs atomic.Uint64

	workers := startWorkers(ctx, opts, cfg, targets, results, &attempts, &certs)
	startTime := time.Now()

	var totalTargets uint64
	if global {
		totalTargets = 1 << 32
	}

	statsDone := make(chan struct{})
	go runStats(ctx, startTime, totalTargets, &attempts, &certs, statsDone)

	writeWG := startWriter(ctx, results, bufw)

	var queued atomic.Uint64
	userQ := make(chan target, opts.concurrency*16)
	cloudQ := make(chan target, opts.concurrency*16)

	addTarget := newTargetAdder(ctx, deny)

	var muxWG sync.WaitGroup
	muxWG.Add(1)
	go runMux(ctx, userQ, cloudQ, targets, &queued, opts.cloudWeight, seed, &muxWG)

	producers := startProducers(ctx, opts, seed, global, stdinMode, addTarget, userQ, cloudQ)
	producers.Wait()

	close(userQ)
	close(cloudQ)
	muxWG.Wait()

	workers.Wait()
	close(results)
	writeWG.Wait()

	stop()
	<-statsDone
	bufw.Flush()

	logDone(startTime, queued.Load(), attempts.Load(), certs.Load())
}

func parseOptions() options {
	var opts options

	flag.StringVar(&opts.outPath, "out", "", "output JSONL file (default: stdout)")
	flag.StringVar(&opts.cidrsPath, "cidrs", "", "file with CIDRs/IPs to scan")
	flag.StringVar(&opts.denyPath, "denylist", "", "file with CIDRs/IPs to skip")
	flag.IntVar(&opts.concurrency, "concurrency", 256, "concurrent dials")
	flag.DurationVar(&opts.timeout, "timeout", 5*time.Second, "per-target timeout")
	flag.StringVar(&opts.sni, "sni", "", "SNI to send")
	flag.BoolVar(&opts.sslv2hello, "sslv2hello", false, "SSLv2-framed ClientHello")

	flag.UintVar(&opts.portRaw, "port", 443, "default port")
	flag.BoolVar(&opts.printErrors, "print-errors", false, "emit JSONL for errors")
	flag.BoolVar(&opts.printEmpty, "print-empty", false, "emit JSONL even if no CN/SANs")
	flag.StringVar(&opts.cloud, "cloud", "", "cloud source(s) (default: cf)")
	flag.IntVar(&opts.cloudSample, "cloud-sample", 0, "sample N targets from cloud ranges")
	flag.IntVar(&opts.cloudWeight, "cloud-weight", 8, "cloud scheduling weight")
	flag.BoolVar(&opts.noGlobal, "no-global", false, "disable default global scan (read stdin instead)")
	flag.BoolVar(&opts.enableJARM, "jarm", false, "JARM fingerprint (10 extra conns/host)")

	flag.Usage = func() {
		fmt.Fprint(os.Stderr, banner)
		fmt.Fprintf(os.Stderr, "Usage: %s [flags]\n\nScans all public IPv4 by default. Use -cidrs or -no-global for targeted scans.\n\n", os.Args[0])
		flag.PrintDefaults()
	}

	flag.Parse()
	opts.port = uint16(opts.portRaw)
	return opts
}

func validateOptions(opts options) {
	if opts.concurrency < 1 {
		log.Fatal().Msg("-concurrency must be >= 1")
	}
	if opts.portRaw == 0 || opts.portRaw > 65535 {
		log.Fatal().Uint("port", opts.portRaw).Msg("-port must be in 1..65535")
	}
}

func newSignalContext() (context.Context, context.CancelFunc) {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	go waitForForceQuit(ctx)
	return ctx, stop
}

func waitForForceQuit(ctx context.Context) {
	<-ctx.Done()

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	<-sig

	fmt.Fprintln(os.Stderr, "\nforce quit")
	os.Exit(1)
}

func configureLogger() {
	zerolog.TimeFieldFormat = time.RFC3339Nano
	log.Logger = log.Output(zerolog.ConsoleWriter{
		Out:        os.Stderr,
		TimeFormat: time.RFC3339Nano,
	})
}

func loadDenylistOrExit(path string) *denylist {
	if path == "" {
		return nil
	}

	deny, err := loadDenylist(path)
	if err != nil {
		log.Fatal().Err(err).Str("denylist", path).Msg("failed to load denylist")
	}
	log.Info().Int("entries", deny.Len()).Str("file", path).Msg("denylist loaded")
	return deny
}

func newBaseConfig(opts options) *tls.Config {
	return &tls.Config{
		CertsOnly:          true,
		InsecureSkipVerify: true,
		SSLv2ClientHello:   opts.sslv2hello,
		ServerName:         opts.sni,
	}
}

func startWorkers(
	ctx context.Context,
	opts options,
	cfg *tls.Config,
	targets <-chan target,
	results chan<- result,
	attempts *atomic.Uint64,
	certs *atomic.Uint64,
) *sync.WaitGroup {
	var wg sync.WaitGroup

	for i := 0; i < opts.concurrency; i++ {
		w := newWorker(cfg, opts.timeout)
		wg.Go(func() {
			for t := range targets {
				attempts.Add(1)
				res := w.scanOne(ctx, t, opts.enableJARM)
				if res.Err == "" {
					certs.Add(1)
				}
				if !shouldEmit(res, opts.printErrors, opts.printEmpty) {
					continue
				}
				select {
				case results <- res:
				case <-ctx.Done():
					return
				}
			}
		})
	}

	return &wg
}

func newTargetAdder(ctx context.Context, deny *denylist) func(chan<- target, netip.Addr, uint16) {
	return func(q chan<- target, addr netip.Addr, port uint16) {
		if !isGlobalIP(addr) || deny.Contains(addr) {
			return
		}
		select {
		case q <- target{IP: addr, Port: port}:
		case <-ctx.Done():
		}
	}
}

func startProducers(
	ctx context.Context,
	opts options,
	seed uint32,
	global, stdinMode bool,
	addTarget func(chan<- target, netip.Addr, uint16),
	userQ, cloudQ chan<- target,
) *sync.WaitGroup {
	var wg sync.WaitGroup

	if opts.cloudSample > 0 {
		wg.Go(func() {
			src := strings.TrimSpace(opts.cloud)
			if src == "" {
				src = "cf"
			}
			_ = emitCloudSamples(ctx, strings.Split(src, ","), opts.cloudSample, seed, opts.port, func(addr netip.Addr, port uint16) {
				addTarget(cloudQ, addr, port)
			})
		})
	}

	wg.Go(func() {
		if global {
			expandCIDR(ctx, "0.0.0.0/1", seed, func(addr netip.Addr) { addTarget(userQ, addr, opts.port) })
			expandCIDR(ctx, "128.0.0.0/1", seed, func(addr netip.Addr) { addTarget(userQ, addr, opts.port) })
		}
		if opts.cidrsPath != "" {
			_ = readCIDRFile(ctx, opts.cidrsPath, seed, func(addr netip.Addr) { addTarget(userQ, addr, opts.port) })
		}
		if stdinMode {
			_ = readTargets(os.Stdin, opts.port, func(addr netip.Addr, port uint16) { addTarget(userQ, addr, port) })
		}
	})

	return &wg
}

func logDone(start time.Time, queued, attempts, certs uint64) {
	elapsed := time.Since(start).Truncate(time.Second)
	entry := log.Info().
		Uint64("queued", queued).
		Uint64("attempts", attempts).
		Uint64("certs", certs).
		Str("elapsed", elapsed.String())
	if attempts > 0 {
		entry = entry.Str("hit_rate", fmt.Sprintf("%.2f%%", 100*float64(certs)/float64(attempts)))
	}
	entry.Msg("done")
}

func cryptoSeed() uint32 {
	var b [4]byte
	rand.Read(b[:])
	return binary.BigEndian.Uint32(b[:])
}

func isTerminal(f *os.File) bool {
	fi, err := f.Stat()
	if err != nil {
		return false
	}
	return fi.Mode()&os.ModeCharDevice != 0
}
