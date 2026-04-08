// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 x-stp

package main

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"math"
	"math/rand"
	"net"
	"net/http"
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
	"github.com/x-stp/rxds/jarm"
	"github.com/x-stp/rxds/normalize"
	"github.com/x-stp/rxds/tls"
)

type target struct {
	IP   net.IP
	Port uint16
}

type result struct {
	IP   string `json:"ip"`
	Port uint16 `json:"port"`
	SNI  string `json:"sni,omitempty"`
	// Always present (normalized): empty string/array if not present in cert.
	CN                string   `json:"cn"`
	SANs              []string `json:"sans"`
	Org               string   `json:"org"`
	ApexDomain        string   `json:"apex_domain"`
	RootDomains       []string `json:"root_domains"`
	FuzzyHash         string   `json:"fuzzy_hash"`
	SHA256Fingerprint string   `json:"sha256,omitempty"`
	JARM              string   `json:"jarm,omitempty"`
	Err               string   `json:"err,omitempty"`
}

func main() {
	var (
		outPath     = flag.String("out", "", "output JSONL file (default: stdout)")
		cidrsPath   = flag.String("cidrs", "", "optional file containing CIDRs/IPs (one per line) to expand into targets")
		concurrency = flag.Int("concurrency", 256, "number of concurrent dials")
		timeout     = flag.Duration("timeout", 5*time.Second, "per-target timeout")
		sni         = flag.String("sni", "", "SNI to use (default: none; for IP targets set this explicitly to get correct cert)")
		sslv2hello  = flag.Bool("sslv2hello", false, "send SSLv2-framed ClientHello for legacy compatibility")
		port        = flag.Uint("port", 443, "default port for bare IP targets")
		cidrSeed    = flag.Uint("cidr-seed", 1, "seed for CIDR permutation (changes scan order)")
		printErrors = flag.Bool("print-errors", false, "emit JSONL lines for dial/handshake errors")
		printEmpty  = flag.Bool("print-empty", false, "emit JSONL lines even if cert has no CN and no SANs")
		cloud       = flag.String("cloud", "", "cloud range source(s) to sample from (comma-separated); default: cf when -cloud-sample > 0")
		cloudSample = flag.Int("cloud-sample", 0, "if >0, sample N targets from cloud ranges and schedule them with priority (IPv4 only)")
		cloudWeight = flag.Int("cloud-weight", 8, "when both cloud and non-cloud targets are available, pick cloud with weight W vs 1 (higher => higher priority)")
		global      = flag.Bool("global", false, "scan all public IPv4 ranges (0.0.0.0/0); excludes private IPs")
		enableJARM  = flag.Bool("jarm", false, "also compute JARM TLS fingerprint for each target (10 extra TCP connections per host)")
	)
	flag.Parse()

	if *concurrency < 1 {
		log.Fatal().Msg("-concurrency must be >= 1")
	}
	if *port > 65535 || *port == 0 {
		log.Fatal().Uint("port", *port).Msg("-port must be in 1..65535")
	}
	if *cidrSeed > math.MaxUint32 {
		log.Fatal().Msg("-cidr-seed overflows uint32")
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	rxds.PreHeatCPU()

	zerolog.TimeFieldFormat = time.RFC3339Nano
	log.Logger = log.Output(zerolog.ConsoleWriter{Out: os.Stderr, TimeFormat: time.RFC3339Nano})

	cfg := &tls.Config{
		CertsOnly:          true,
		InsecureSkipVerify: true,
		SSLv2ClientHello:   *sslv2hello,
		ServerName:         *sni,
	}

	var out io.Writer = os.Stdout
	var f *os.File
	if *outPath != "" {
		var err error
		f, err = os.Create(*outPath)
		if err != nil {
			log.Fatal().Err(err).Str("out", *outPath).Msg("failed to create output file")
		}
		defer f.Close()
		out = f
	}
	bufw := bufio.NewWriterSize(out, 1<<20)
	defer bufw.Flush()

	targets := make(chan target, *concurrency*8)
	results := make(chan result, *concurrency*8)

	var (
		attempts atomic.Uint64
		success  atomic.Uint64
	)
	var wg sync.WaitGroup
	for i := 0; i < *concurrency; i++ {
		wg.Add(1)
		go func(worker int) {
			defer wg.Done()
			for t := range targets {
				attempts.Add(1)
				res := scanOne(t, cfg, *timeout, *enableJARM)
				if shouldEmit(res, *printErrors, *printEmpty) {
					success.Add(1)
					results <- res
				}
			}
		}(i)
	}

	// Stats logger (stops when ctx is canceled)
	statsDone := make(chan struct{})
	go func() {
		defer close(statsDone)
		ticker := time.NewTicker(2 * time.Second)
		defer ticker.Stop()
		var lastAttempts uint64
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				curAttempts := attempts.Load()
				curSuccess := success.Load()
				delta := curAttempts - lastAttempts
				rate := float64(delta) / 2.0
				log.Info().
					Uint64("att", curAttempts).
					Uint64("succ", curSuccess).
					Float64("rate", rate).
					Msg("stats")
				lastAttempts = curAttempts
			}
		}
	}()

	// Writer goroutine
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
				if err := enc.Encode(r); err != nil {
					log.Error().Err(err).Msg("failed to encode result")
				}
			case <-ticker.C:
				bufw.Flush()
			}
		}
	}()

	// Producer: stdin targets + optional CIDR file expansion.
	var nTargets atomic.Uint64
	userQ := make(chan target, *concurrency*16)
	cloudQ := make(chan target, *concurrency*16)

	addUserTarget := func(ip net.IP, p uint16) {
		if ip == nil {
			return
		}
		ip = ip.To16()
		if ip == nil {
			return
		}
		if !isGlobalIP(ip) {
			return
		}
		userQ <- target{IP: ip, Port: p}
	}
	addCloudTarget := func(ip net.IP, p uint16) {
		if ip == nil {
			return
		}
		ip = ip.To16()
		if ip == nil {
			return
		}
		if !isGlobalIP(ip) {
			return
		}
		cloudQ <- target{IP: ip, Port: p}
	}

	// Mux: schedule cloud with higher priority, but still interleave non-cloud.
	var muxWG sync.WaitGroup
	muxWG.Add(1)
	go func() {
		defer muxWG.Done()

		w := *cloudWeight
		if w < 0 {
			w = 0
		}
		rng := rand.New(rand.NewSource(int64(uint32(*cidrSeed) ^ 0x9e3779b9)))

		cloudOpen, userOpen := true, true
		send := func(t target) {
			targets <- t
			nTargets.Add(1)
		}

		for cloudOpen || userOpen {
			// If both are open, probabilistically prefer cloud.
			if cloudOpen && userOpen {
				preferCloud := w > 0 && rng.Intn(w+1) < w
				if preferCloud {
					select {
					case t, ok := <-cloudQ:
						if !ok {
							cloudOpen = false
							continue
						}
						send(t)
						continue
					default:
					}
				}
				select {
				case t, ok := <-userQ:
					if !ok {
						userOpen = false
						continue
					}
					send(t)
					continue
				default:
				}
				// Block until we get something (avoid busy spin).
				select {
				case t, ok := <-cloudQ:
					if !ok {
						cloudOpen = false
						continue
					}
					send(t)
				case t, ok := <-userQ:
					if !ok {
						userOpen = false
						continue
					}
					send(t)
				}
				continue
			}

			if cloudOpen {
				t, ok := <-cloudQ
				if !ok {
					cloudOpen = false
					continue
				}
				send(t)
				continue
			}
			if userOpen {
				t, ok := <-userQ
				if !ok {
					userOpen = false
					continue
				}
				send(t)
				continue
			}
		}
		close(targets)
	}()

	// Cloud producer (optional).
	var prodWG sync.WaitGroup
	if *cloudSample > 0 {
		prodWG.Add(1)
		go func() {
			defer prodWG.Done()
			src := strings.TrimSpace(*cloud)
			if src == "" {
				src = "cf"
			}
			if err := emitCloudSamples(context.Background(), strings.Split(src, ","), *cloudSample, uint32(*cidrSeed), uint16(*port), addCloudTarget); err != nil {
				log.Error().Err(err).Msg("cloud sampling failed")
			}
		}()
	}

	// User producer (stdin + optional CIDR file).
	prodWG.Add(1)
	go func() {
		defer prodWG.Done()
		if *global {
			// Split 0.0.0.0/0 into two /1 blocks to avoid uint32 overflow in permutation logic.
			expandCIDR("0.0.0.0/1", uint32(*cidrSeed), func(ip net.IP) { addUserTarget(ip, uint16(*port)) })
			expandCIDR("128.0.0.0/1", uint32(*cidrSeed), func(ip net.IP) { addUserTarget(ip, uint16(*port)) })
		}
		if *cidrsPath != "" {
			if err := readCIDRFile(*cidrsPath, uint32(*cidrSeed), func(ip net.IP) { addUserTarget(ip, uint16(*port)) }); err != nil {
				log.Error().Err(err).Str("cidrs", *cidrsPath).Msg("failed to read cidr file")
			}
		}
		if !*global && *cidrsPath == "" {
			if err := readTargets(os.Stdin, uint16(*port), func(ip net.IP, p uint16) { addUserTarget(ip, p) }); err != nil {
				log.Error().Err(err).Msg("failed to read stdin targets")
			}
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

	log.Info().Uint64("targets", nTargets.Load()).Msg("done")
}

func scanOne(t target, baseCfg *tls.Config, timeout time.Duration, doJARM bool) result {
	ipStr := t.IP.String()
	r := result{
		IP:          ipStr,
		Port:        t.Port,
		SNI:         baseCfg.ServerName,
		SANs:        make([]string, 0),
		RootDomains: make([]string, 0),
	}

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	addr := net.JoinHostPort(ipStr, u16toa(t.Port))
	certs, err := rxds.DialForCert(ctx, "tcp", addr, baseCfg)
	if err != nil {
		r.Err = err.Error()
		return r
	}
	if len(certs) == 0 {
		r.Err = "no_certs"
		return r
	}

	leaf := certs[0]
	n := normalize.NormalizeCert(leaf)
	r.CN = n.CN
	r.SANs = n.SANs
	r.Org = n.Org
	r.ApexDomain = n.ApexDomain
	r.RootDomains = n.RootDomains
	r.FuzzyHash = n.FuzzyHash
	sum := sha256.Sum256(leaf.Raw)
	r.SHA256Fingerprint = hex.EncodeToString(sum[:])

	if doJARM {
		host := baseCfg.ServerName
		if host == "" {
			host = ipStr
		}
		fp, err := jarm.Fingerprint(ctx, host, t.Port, timeout)
		if err == nil {
			r.JARM = fp
		}
	}

	return r
}

func shouldEmit(r result, printErrors, printEmpty bool) bool {
	if r.Err != "" {
		return printErrors
	}
	if printEmpty {
		return true
	}
	return r.CN != "" || len(r.SANs) > 0
}

func readTargets(r io.Reader, defaultPort uint16, emit func(ip net.IP, port uint16)) error {
	sc := bufio.NewScanner(r)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		ip, port, ok := parseIPPort(line, defaultPort)
		if !ok {
			// Ignore invalid lines to keep scanning robust.
			continue
		}
		emit(ip, port)
	}
	return sc.Err()
}

func parseIPPort(s string, defaultPort uint16) (ip net.IP, port uint16, ok bool) {
	// Accept "ip" or "ip:port". We do not accept hostnames here.
	if strings.Count(s, ":") == 0 {
		ip = net.ParseIP(s)
		if ip == nil {
			return nil, 0, false
		}
		return ip, defaultPort, true
	}

	host, p, err := net.SplitHostPort(s)
	if err != nil {
		// Try raw IPv6 without brackets is not supported; require bracket form.
		return nil, 0, false
	}
	ip = net.ParseIP(host)
	if ip == nil {
		return nil, 0, false
	}
	pp := parsePort(p, defaultPort)
	if pp == 0 {
		return nil, 0, false
	}
	return ip, pp, true
}

func readCIDRFile(path string, seed uint32, emit func(ip net.IP)) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()

	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		// CIDR or single IP.
		if strings.Contains(line, "/") {
			expandCIDR(line, seed, emit)
			continue
		}
		ip := net.ParseIP(line)
		if ip == nil {
			continue
		}
		emit(ip)
	}
	return sc.Err()
}

func expandCIDR(cidr string, seed uint32, emit func(ip net.IP)) {
	_, n, err := net.ParseCIDR(cidr)
	if err != nil {
		log.Warn().Str("cidr", cidr).Err(err).Msg("skipping invalid CIDR")
		return
	}
	ip4 := n.IP.To4()
	if ip4 == nil || len(n.Mask) != 4 {
		log.Warn().Str("cidr", cidr).Msg("IPv6 CIDR expansion not supported, skipping")
		return
	}
	base := binary.BigEndian.Uint32(ip4) & binary.BigEndian.Uint32(n.Mask)
	ones, bits := n.Mask.Size()
	if bits != 32 || ones < 0 {
		return
	}
	if ones == 0 {
		return
	}
	size := uint32(1) << uint32(32-ones)
	for i := uint32(0); i < size; i++ {
		j := permuteIndex(i, size, seed^base)
		ip := make(net.IP, 4)
		binary.BigEndian.PutUint32(ip, base+j)
		emit(ip)
	}
}

func parsePort(s string, def uint16) uint16 {
	if s == "" {
		return def
	}
	// fast parse uint16
	var n uint32
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c < '0' || c > '9' {
			return 0
		}
		n = n*10 + uint32(c-'0')
		if n > 65535 {
			return 0
		}
	}
	if n == 0 {
		return 0
	}
	return uint16(n)
}

func u16toa(p uint16) string {
	// tiny helper: avoid fmt for hot path
	var b [5]byte
	n := int(p)
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	if i == len(b) {
		return "0"
	}
	return string(b[i:])
}

// permuteIndex returns a pseudo-random permutation of i in [0,size),
// implemented as cycle-walking over a 32-bit Feistel permutation.
func permuteIndex(i, size, key uint32) uint32 {
	if size == 0 {
		return 0
	}
	x := feistel32(i, key)
	for x >= size {
		x = feistel32(x, key)
	}
	return x
}

func feistel32(x, key uint32) uint32 {
	l := uint16(x >> 16)
	r := uint16(x)
	for round := uint32(0); round < 4; round++ {
		f := feistelF(r, key+round*0x9e37)
		l, r = r, l^f
	}
	return uint32(l)<<16 | uint32(r)
}

func feistelF(x uint16, k uint32) uint16 {
	// simple mixing function; not crypto, just a permutation driver
	v := uint32(x) ^ k
	v ^= v >> 13
	v *= 0x85ebca6b
	v ^= v >> 16
	return uint16(v)
}

func isGlobalIP(ip net.IP) bool {
	addr, ok := netip.AddrFromSlice(ip)
	if !ok {
		return false
	}
	addr = addr.Unmap()
	return addr.IsGlobalUnicast()
}

func emitCloudSamples(
	ctx context.Context,
	sources []string,
	n int,
	seed uint32,
	port uint16,
	emit func(ip net.IP, p uint16),
) error {
	// Currently supported: cf (Cloudflare).
	var prefixes []netip.Prefix
	for _, s := range sources {
		s = strings.ToLower(strings.TrimSpace(s))
		if s == "" {
			continue
		}
		switch s {
		case "cf", "cloudflare":
			ps, err := fetchCloudflareIPv4Prefixes(ctx)
			if err != nil {
				return err
			}
			prefixes = append(prefixes, ps...)
		default:
			return &unsupportedCloudSourceError{Source: s}
		}
	}
	if len(prefixes) == 0 || n <= 0 {
		return nil
	}

	// Weighted by prefix size (IPv4 only).
	type wp struct {
		prefix netip.Prefix
		weight uint32
	}
	weighted := make([]wp, 0, len(prefixes))
	var total uint64
	for _, p := range prefixes {
		p = p.Masked()
		if !p.Addr().Is4() {
			continue
		}
		bits := p.Bits()
		if bits < 0 || bits > 32 {
			continue
		}
		w := uint32(1) << uint32(32-bits)
		weighted = append(weighted, wp{prefix: p, weight: w})
		total += uint64(w)
	}
	if total == 0 || len(weighted) == 0 {
		return nil
	}

	rng := rand.New(rand.NewSource(int64(seed)))
	for i := 0; i < n; i++ {
		r := uint64(rng.Uint32()) % total
		var chosen netip.Prefix
		for _, w := range weighted {
			if r < uint64(w.weight) {
				chosen = w.prefix
				break
			}
			r -= uint64(w.weight)
		}
		if !chosen.IsValid() {
			continue
		}
		base := binary.BigEndian.Uint32(chosen.Addr().AsSlice())
		span := uint32(1) << uint32(32-chosen.Bits())
		off := rng.Uint32() % span
		var b [4]byte
		binary.BigEndian.PutUint32(b[:], base+off)
		ip := net.IPv4(b[0], b[1], b[2], b[3]).To4()
		emit(ip, port)
	}
	return nil
}

type unsupportedCloudSourceError struct{ Source string }

func (e *unsupportedCloudSourceError) Error() string { return "unsupported cloud source: " + e.Source }

const cloudflareIPv4URL = "https://www.cloudflare.com/ips-v4"

func fetchCloudflareIPv4Prefixes(ctx context.Context) ([]netip.Prefix, error) {
	// Official: https://www.cloudflare.com/ips-v4
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, cloudflareIPv4URL, nil)
	if err != nil {
		return nil, err
	}
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("fetch %s: HTTP %d", cloudflareIPv4URL, resp.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, err
	}
	lines := strings.Split(string(body), "\n")
	out := make([]netip.Prefix, 0, len(lines))
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		p, err := netip.ParsePrefix(line)
		if err != nil {
			continue
		}
		if !p.Addr().Is4() {
			continue
		}
		out = append(out, p)
	}
	return out, nil
}
