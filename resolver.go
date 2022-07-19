package doh

import (
	"context"
	"errors"
	"math"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"

	madns "github.com/multiformats/go-multiaddr-dns"
)

type Resolver struct {
	proof chan proofEntry
	mx    sync.Mutex
	url   string

	// RR cache
	ipCache       map[string]ipAddrEntry
	txtCache      map[string]txtEntry
	proofCache    map[string]proofEntry
	dnssecEnabled bool
	maxCacheTTL   time.Duration
}

type ipAddrEntry struct {
	ips    []net.IPAddr
	expire time.Time
}

type txtEntry struct {
	txt    []string
	expire time.Time
}

type proofEntry struct {
	proof  []dns.RR
	expire time.Time
}

type Option func(*Resolver) error

// Specifies the maximum time entries are valid in the cache
// A maxCacheTTL of zero is equivalent to `WithCacheDisabled`
func WithMaxCacheTTL(maxCacheTTL time.Duration) Option {
	return func(tr *Resolver) error {
		tr.maxCacheTTL = maxCacheTTL
		return nil
	}
}

func WithCacheDisabled() Option {
	return func(tr *Resolver) error {
		tr.maxCacheTTL = 0
		return nil
	}
}

func WithDNSSECEnabled() Option {
	return func(tr *Resolver) error {
		tr.dnssecEnabled = true
		tr.proof = make(chan proofEntry, 1)
		return nil
	}
}

func NewResolver(url string, opts ...Option) (*Resolver, error) {
	if !strings.HasPrefix(url, "https:") {
		url = "https://" + url
	}

	r := &Resolver{
		url:           url,
		ipCache:       make(map[string]ipAddrEntry),
		txtCache:      make(map[string]txtEntry),
		proofCache:    make(map[string]proofEntry),
		maxCacheTTL:   time.Duration(math.MaxUint32) * time.Second,
		dnssecEnabled: false,
	}

	for _, o := range opts {
		if err := o(r); err != nil {
			return nil, err
		}
	}

	return r, nil
}

var _ madns.BasicResolver = (*Resolver)(nil)

func (r *Resolver) LookupIPAddr(ctx context.Context, domain string) (result []net.IPAddr, err error) {
	result, ok := r.getCachedIPAddr(domain)
	if ok {
		return result, nil
	}

	type response struct {
		ips []net.IPAddr
		ttl uint32
		err error
	}

	resch := make(chan response, 2)
	go func() {
		ip4, ttl, err := doRequestA(ctx, r.url, domain)
		resch <- response{ip4, ttl, err}
	}()

	go func() {
		ip6, ttl, err := doRequestAAAA(ctx, r.url, domain)
		resch <- response{ip6, ttl, err}
	}()

	var ttl uint32
	for i := 0; i < 2; i++ {
		r := <-resch
		if r.err != nil {
			return nil, r.err
		}

		result = append(result, r.ips...)
		if ttl == 0 || r.ttl < ttl {
			ttl = r.ttl
		}
	}

	cacheTTL := minTTL(time.Duration(ttl)*time.Second, r.maxCacheTTL)
	r.cacheIPAddr(domain, result, cacheTTL)
	return result, nil
}

// Get TXT record using DNSSEC
func (r *Resolver) secureLookupTXT(ctx context.Context, domain string) ([]string, error) {
	txt, txtOk := r.getCachedTXT(domain)
	proof, proofOk := r.getCachedProof(domain)
	if !txtOk || !proofOk {
		txt, proof, ttl, err := doRequestTXTSecure(ctx, r.url, domain)
		if err != nil {
			return nil, err
		}

		cacheTTL := minTTL(time.Duration(ttl)*time.Second, r.maxCacheTTL)
		r.cacheTXT(domain, txt, cacheTTL)
		r.cacheProof(domain, proof, cacheTTL)

		r.clearOldProof()

		// Add new proof to channel
		r.proof <- proofEntry{proof, time.Now().Add(cacheTTL)}
		return txt, nil
	}

	r.clearOldProof()
	r.proof <- proofEntry{proof, time.Now()}
	return txt, nil
}

// Make sure there is nothing in the channel, otherwise it will block. If there
// is something in the channel, the consumer wasn't interested in it as
// evidenced by them calling for a new TXT and proof.
func (r *Resolver) clearOldProof() {
	select {
	case <-r.proof:
	default:
	}
	return
}

func (r *Resolver) LookupTXT(ctx context.Context, domain string) ([]string, error) {
	if r.dnssecEnabled {
		return r.secureLookupTXT(ctx, domain)
	}
	return r.insecureLookupTXT(ctx, domain)
}

func (r *Resolver) insecureLookupTXT(ctx context.Context, domain string) ([]string, error) {
	result, ok := r.getCachedTXT(domain)
	if ok {
		return result, nil
	}

	result, ttl, err := doRequestTXTInsecure(ctx, r.url, domain)
	if err != nil {
		return nil, err
	}

	cacheTTL := minTTL(time.Duration(ttl)*time.Second, r.maxCacheTTL)
	r.cacheTXT(domain, result, cacheTTL)
	return result, nil
}

func (r *Resolver) getCachedIPAddr(domain string) ([]net.IPAddr, bool) {
	r.mx.Lock()
	defer r.mx.Unlock()

	fqdn := dns.Fqdn(domain)
	entry, ok := r.ipCache[fqdn]
	if !ok {
		return nil, false
	}

	if time.Now().After(entry.expire) {
		delete(r.ipCache, fqdn)
		return nil, false
	}

	return entry.ips, true
}

func (r *Resolver) cacheIPAddr(domain string, ips []net.IPAddr, ttl time.Duration) {
	if ttl == 0 {
		return
	}

	r.mx.Lock()
	defer r.mx.Unlock()

	fqdn := dns.Fqdn(domain)
	r.ipCache[fqdn] = ipAddrEntry{ips, time.Now().Add(ttl)}
}

func (r *Resolver) getCachedProof(domain string) ([]dns.RR, bool) {
	r.mx.Lock()
	defer r.mx.Unlock()

	fqdn := dns.Fqdn(domain)
	entry, ok := r.proofCache[fqdn]
	if !ok {
		return nil, false
	}

	if time.Now().After(entry.expire) {
		delete(r.proofCache, fqdn)
		return nil, false
	}

	return entry.proof, true
}

func (r *Resolver) getCachedTXT(domain string) ([]string, bool) {
	r.mx.Lock()
	defer r.mx.Unlock()

	fqdn := dns.Fqdn(domain)
	entry, ok := r.txtCache[fqdn]
	if !ok {
		return nil, false
	}

	if time.Now().After(entry.expire) {
		delete(r.txtCache, fqdn)
		return nil, false
	}

	return entry.txt, true
}

func (r *Resolver) cacheTXT(domain string, txt []string, ttl time.Duration) {
	if ttl == 0 {
		return
	}

	r.mx.Lock()
	defer r.mx.Unlock()

	fqdn := dns.Fqdn(domain)
	r.txtCache[fqdn] = txtEntry{txt, time.Now().Add(ttl)}
}

func (r *Resolver) cacheProof(domain string, proof []dns.RR, ttl time.Duration) {
	if ttl == 0 {
		return
	}

	r.mx.Lock()
	defer r.mx.Unlock()

	fqdn := dns.Fqdn(domain)
	r.proofCache[fqdn] = proofEntry{proof, time.Now().Add(ttl)}
}

func minTTL(a, b time.Duration) time.Duration {
	if a < b {
		return a
	}
	return b
}

func (r *Resolver) GetProof() ([]dns.RR, error) {
	select {
	case p := <-r.proof:
		return p.proof, nil
	default:
		return nil, errors.New("No proof available. Are you using the DNSSEC enabled resolver?")
	}
}
