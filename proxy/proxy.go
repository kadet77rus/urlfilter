package proxy

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"log"
	"net/http"
	"os"
	"sync"

	"github.com/ameshkov/goproxy"

	"github.com/AdguardTeam/urlfilter"
)

var defaultInjectionsHost = "injections.adguard.org"

// Config contains the MITM proxy configuration
type Config struct {
	// CertKeyPair is the X509 cert/key pair that is used in the MITM proxy
	CertKeyPair tls.Certificate

	// Paths to the filtering rules
	FiltersPaths map[int]string

	// InjectionHost is used for injecting custom CSS/JS into web pages.
	//
	// Here's how it works:
	// * The proxy injects `<script src="//INJECTIONS_HOST/content-script.js?domain=HOSTNAME&flags=FLAGS"></script>`
	// * Depending on the FLAGS and the HOSTNAME, it either injects cosmetic rules or not
	// * Proxy handles requests to this host
	// * The content script content depends on the FLAGS value
	InjectionHost string
}

// Server contains the current server state
type Server struct {
	// the MITM proxy server instance
	proxyHTTPServer *goproxy.ProxyHttpServer

	// TODO: Replace with the urlfilter.Engine when it's ready
	networkEngine *urlfilter.NetworkEngine

	// The list of current sessions
	sessions      map[int64]*urlfilter.Session
	sessionsGuard *sync.Mutex

	Config // Server configuration
}

// NewServer creates a new instance of the MITM server
func NewServer(config Config) (*Server, error) {
	if config.InjectionHost == "" {
		config.InjectionHost = defaultInjectionsHost
	}

	s := &Server{
		Config:        config,
		sessions:      map[int64]*urlfilter.Session{},
		sessionsGuard: &sync.Mutex{},
	}

	networkEngine, err := buildNetworkEngine(config)
	if err != nil {
		return nil, err
	}

	s.networkEngine = networkEngine
	err = setCA(config.CertKeyPair)
	if err != nil {
		return nil, err
	}

	s.proxyHTTPServer = goproxy.NewProxyHttpServer()
	s.proxyHTTPServer.OnRequest().HandleConnect(goproxy.AlwaysMitm)
	s.proxyHTTPServer.OnRequest().DoFunc(s.onRequest)
	s.proxyHTTPServer.OnResponse().DoFunc(s.onResponse)

	// TODO: TEMPORARY, FIX LOGGING
	s.proxyHTTPServer.Verbose = true
	s.proxyHTTPServer.Logger = log.New(os.Stderr, "proxy", log.LstdFlags)

	return s, nil
}

// ListenAndServe listens on the TCP network address addr
// It always returns a non-nil error.
func (s *Server) ListenAndServe(addr string) error {
	return http.ListenAndServe(addr, s.proxyHTTPServer)
}

// onRequest handles the outgoing HTTP requests
func (s *Server) onRequest(r *http.Request, ctx *goproxy.ProxyCtx) (*http.Request, *http.Response) {
	session := urlfilter.NewSession(ctx.Session, r)

	ctx.Logf("Adding session %d", ctx.Session)
	s.sessionsGuard.Lock()
	s.sessions[session.ID] = session
	s.sessionsGuard.Unlock()

	rule, ok := s.networkEngine.Match(session.Request)
	if ok && !rule.Whitelist {
		ctx.Logf("blocked: %s", session.Request.URL)
		return r, goproxy.NewResponse(r, goproxy.ContentTypeText, http.StatusInternalServerError, "Blocked")
	}

	return r, nil
}

// onResponse handles all the responses
func (s *Server) onResponse(r *http.Response, ctx *goproxy.ProxyCtx) *http.Response {
	s.sessionsGuard.Lock()
	session, ok := s.sessions[ctx.Session]
	s.sessionsGuard.Unlock()

	if !ok {
		ctx.Warnf("could not find session %d", ctx.Session)
		return r
	}

	// Update the session -- this will cause requestType re-calc
	session.SetResponse(r)

	if session.Request.RequestType == urlfilter.TypeDocument {
		s.filterHTML(session, ctx)
	}

	ctx.Logf("Removing session %d", ctx.Session)
	s.sessionsGuard.Lock()
	delete(s.sessions, ctx.Session)
	s.sessionsGuard.Unlock()
	return r
}

// buildNetworkEngine builds a new network engine
func buildNetworkEngine(config Config) (*urlfilter.NetworkEngine, error) {
	var lists []urlfilter.RuleList

	for filterID, path := range config.FiltersPaths {
		list, err := urlfilter.NewFileRuleList(filterID, path, false)
		if err != nil {
			return nil, fmt.Errorf("failed to create rule list %d: %s", filterID, err)
		}
		lists = append(lists, list)
	}

	ruleStorage, err := urlfilter.NewRuleStorage(lists)
	if err != nil {
		return nil, fmt.Errorf("cannot initialize rule storage: %s", err)
	}

	return urlfilter.NewNetworkEngine(ruleStorage), nil
}

func setCA(goproxyCa tls.Certificate) error {
	var err error
	if goproxyCa.Leaf, err = x509.ParseCertificate(goproxyCa.Certificate[0]); err != nil {
		return fmt.Errorf("failed to set goproxy CA: %s", err)
	}
	goproxy.GoproxyCa = goproxyCa
	goproxy.OkConnect = &goproxy.ConnectAction{Action: goproxy.ConnectAccept, TLSConfig: goproxy.TLSConfigFromCA(&goproxyCa)}
	goproxy.MitmConnect = &goproxy.ConnectAction{Action: goproxy.ConnectMitm, TLSConfig: goproxy.TLSConfigFromCA(&goproxyCa)}
	goproxy.HTTPMitmConnect = &goproxy.ConnectAction{Action: goproxy.ConnectHTTPMitm, TLSConfig: goproxy.TLSConfigFromCA(&goproxyCa)}
	goproxy.RejectConnect = &goproxy.ConnectAction{Action: goproxy.ConnectReject, TLSConfig: goproxy.TLSConfigFromCA(&goproxyCa)}
	return nil
}
