package scanner

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"

	"github.com/aristosMiliaressis/cors-scanner/internal/input"
	"github.com/aristosMiliaressis/httpc/pkg/httpc"
	"github.com/projectdiscovery/gologger"
)

type Scanner struct {
	Client       httpc.HttpClient
	Config       input.Config
	cancel       context.CancelFunc
	corsSettings []CorsSettings
}

func NewScanner(conf input.Config) Scanner {
	ctx, cancel := context.WithCancel(context.Background())

	return Scanner{
		Client: *httpc.NewHttpClient(conf.Http, ctx),
		Config: conf,
		cancel: cancel,
	}
}

func (s *Scanner) Scan() {

	s.FollowRedirectsToSameSiteRoot()

	preflightSupport := s.testPreflightSupport()
	if !preflightSupport {
		s.testResponseReadCapabilities("GET")

		s.printTrustedOrigins()
		return
	}

	s.PrintResult(Result{Type: CAPABILITY, Name: "preflight-support"})

	s.testAllCapabilities()

	s.printTrustedOrigins()
}

func (s *Scanner) testPreflightSupport() bool {

	req, _ := http.NewRequest("OPTIONS", s.Config.Url, nil)
	req.Header.Set("Origin", "https://example.com")

	msg := s.GetResponse(req)

	return msg.Response.StatusCode >= 200 && msg.Response.StatusCode < 300
}

func (s *Scanner) testAllCapabilities() {
	s.testRequestSendCapabilities()

	s.testResponseReadCapabilities("OPTIONS")
}

func (s *Scanner) testResponseReadCapabilities(method string) {
	found := s.testAribitaryOriginTrust(method)
	if found {
		s.testCRLFInjection(ACAO_SUBDOMAIN, method, s.Config.Url)
		return
	}

	trustedOrigins := s.Search(func(stng CorsSettings) bool {
		return stng.ACAO != "*" && stng.ACAO != "null" && stng.ACAO != s.Config.Url && stng.ACAO != ""
	})

	trustedOrigins = append(trustedOrigins, CorsSettings{ACAO: s.Config.Url})

	for _, stng := range trustedOrigins {
		found = s.testSubdomainReflection(method, stng.ACAO)
		if found {
			s.testSubdomainReflectionBypass(method, stng.ACAO)

			s.testCRLFInjection(ACAO_SUBDOMAIN, method, stng.ACAO)
		}

		found = s.testSuffixReflection(method, stng.ACAO)
		if found {
			s.testPortReflectionBypass(method, stng.ACAO)

			s.testCRLFInjection(ACAO_PORT, method, stng.ACAO)
		}

		s.testRegexDotBypass(method, stng.ACAO)

		if strings.HasPrefix(s.Config.Url, "https:") {
			s.testHttpOriginTrust(method, stng.ACAO)
		}
	}
}

func (s *Scanner) testSuffixReflection(method, origin string) bool {
	originUrl, _ := url.Parse(origin)
	originUrl.Host = fmt.Sprintf("%s:1337", originUrl.Hostname())

	req, _ := http.NewRequest(method, s.Config.Url, nil)
	req.Header.Set("Origin", originUrl.String())

	msg := s.GetResponse(req)

	corsSettings := s.getCorsSettings(msg.Response)
	modifiers := []ImpactModifier{}
	if corsSettings.ACAC == "true" {
		modifiers = append(modifiers, ALLOWED_CREDENTIALS)
	}

	if corsSettings.ACAO == originUrl.String() {
		if !strings.Contains(strings.ToLower(corsSettings.Vary), "origin") {
			modifiers = append(modifiers, NO_VARY)
		}

		s.PrintResult(Result{Type: CAPABILITY, Name: "cors-port-reflection", Modifiers: modifiers})
		return true
	}

	return false
}

func (s *Scanner) testPortReflectionBypass(method, origin string) {

	suffixedOrigin := fmt.Sprintf("%s.example.com", origin)

	req, _ := http.NewRequest(method, s.Config.Url, nil)
	req.Header.Set("Origin", suffixedOrigin)

	msg := s.GetResponse(req)
	corsSettings := s.getCorsSettings(msg.Response)
	modifiers := []ImpactModifier{}
	if corsSettings.ACAC == "true" {
		modifiers = append(modifiers, ALLOWED_CREDENTIALS)
	}

	if corsSettings.ACAO == suffixedOrigin {
		if !strings.Contains(strings.ToLower(corsSettings.Vary), "origin") {
			modifiers = append(modifiers, NO_VARY)
		}

		s.PrintResult(Result{Type: CAPABILITY, Name: "cors-port-reflection-suffix-bypass", Value: corsSettings.ACAO, Modifiers: modifiers})
		return
	}

	fuzzChars := []rune{
		'.', '`', '!', '%', '_', ' ', ',', '&', '\'', '"', ';', '$',
		'^', '*', '(', ')', '+', '=', '~', '-', '=', '|', '{', '}',
		'\x00', '\x01', '\x02', '\x03', '\x04', '\x05', '\x06', '\x07', '\x08',
		'\x0b', '\x0c', '\x0e', '\x0f', '\x10', '\x11', '\x12', '\x13', '\x14',
		'\x15', '\x16', '\x17', '\x18', '\x19', '\x1a', '\x1b', '\x1c', '\x1d',
		'\x1e', '\x1f', '\x7f',
	}

	wg := sync.WaitGroup{}

	for _, char := range fuzzChars {
		req, _ := http.NewRequest(method, s.Config.Url, nil)
		req.Header.Set("Origin", fmt.Sprintf("%s%s.example.com", origin, string(char)))

		wg.Add(1)
		go func() {
			defer wg.Done()

			msg := s.GetResponse(req)
			corsSettings := s.getCorsSettings(msg.Response)
			modifiers := []ImpactModifier{}
			if corsSettings.ACAC == "true" {
				modifiers = append(modifiers, ALLOWED_CREDENTIALS)
			}

			if corsSettings.ACAO == suffixedOrigin {
				if !strings.Contains(strings.ToLower(corsSettings.Vary), "origin") {
					modifiers = append(modifiers, NO_VARY)
				}

				s.PrintResult(Result{Type: CAPABILITY, Name: "cors-port-reflection-suffix-bypass", Value: corsSettings.ACAO, Modifiers: modifiers})
				return
			}
		}()
	}
	wg.Wait()
}

func (s *Scanner) testHttpOriginTrust(method, origin string) {
	originUrl, _ := url.Parse(origin)
	originUrl.Host = fmt.Sprintf("http://%s", originUrl.Host)

	req, _ := http.NewRequest(method, s.Config.Url, nil)
	req.Header.Set("Origin", originUrl.String())

	msg := s.GetResponse(req)

	corsSettings := s.getCorsSettings(msg.Response)
	modifiers := []ImpactModifier{}
	if corsSettings.ACAC == "true" {
		modifiers = append(modifiers, ALLOWED_CREDENTIALS)
	}

	if corsSettings.ACAO == originUrl.String() {
		s.PrintResult(Result{Type: CAPABILITY, Name: "cors-http-origin-trust", Value: corsSettings.ACAO, Modifiers: modifiers})
	}
}

func (s *Scanner) testRegexDotBypass(method, origin string) {

	originUrl, _ := url.Parse(origin)

	for i := 0; i < strings.Count(originUrl.Hostname(), "."); i++ {
		parts := strings.Split(originUrl.Hostname(), ".")
		newOrigin := ""

		if i > 0 {
			newOrigin = strings.Join(parts[0:i], ".") + "."
		}

		newOrigin += parts[i] + "a" + parts[i+1]
		if len(parts) > i+2 {
			newOrigin += "." + strings.Join(parts[(i+2):], ".")
		}

		req, _ := http.NewRequest(method, s.Config.Url, nil)
		req.Header.Set("Origin", newOrigin)

		msg := s.GetResponse(req)

		corsSettings := s.getCorsSettings(msg.Response)
		modifiers := []ImpactModifier{}
		if corsSettings.ACAC == "true" {
			modifiers = append(modifiers, ALLOWED_CREDENTIALS)
		}

		if corsSettings.ACAO == newOrigin {
			if !strings.Contains(strings.ToLower(corsSettings.Vary), "origin") {
				modifiers = append(modifiers, NO_VARY)
			}

			s.PrintResult(Result{Type: CAPABILITY, Name: "cors-regex-dot-bypass", Modifiers: modifiers})
		}
	}
}

func (s *Scanner) printTrustedOrigins() {
	wildcards := s.Search(func(stng CorsSettings) bool {
		return stng.ACAO == "*"
	})
	if len(wildcards) > 0 {
		s.PrintResult(Result{Type: CAPABILITY, Name: "cors-wildcard-origin"})
	}

	settings := s.Search(func(stng CorsSettings) bool {
		return stng.ACAO != "*" && stng.ACAO != "null" && stng.ACAO != s.Config.Url && stng.ACAO != ""
	})

	modifiers := []ImpactModifier{}
	trustedOrigins := []string{}
	for _, stng := range settings {

		if stng.ACAC == "true" && !Contains(modifiers, ALLOWED_CREDENTIALS) {
			modifiers = append(modifiers, ALLOWED_CREDENTIALS)
		}

		if !Contains(trustedOrigins, stng.ACAO) {
			trustedOrigins = append(trustedOrigins, stng.ACAO)
		}
	}

	for _, origin := range trustedOrigins {
		s.PrintResult(Result{Type: CAPABILITY, Name: "cors-fixed-origin", Value: origin, Modifiers: modifiers})
	}

	settings = s.Search(func(stng CorsSettings) bool {
		return stng.ACEH != ""
	})

	modifiers = []ImpactModifier{}
	exposedHeaders := []string{}
	for _, stng := range settings {

		if stng.ACAC == "true" && !Contains(modifiers, ALLOWED_CREDENTIALS) {
			modifiers = append(modifiers, ALLOWED_CREDENTIALS)
		}

		if !Contains(exposedHeaders, stng.ACEH) {
			exposedHeaders = append(exposedHeaders, stng.ACEH)
		}
	}

	for _, aceh := range exposedHeaders {
		s.PrintResult(Result{Type: CAPABILITY, Name: "cors-fixed-aceh", Value: aceh, Modifiers: modifiers})
	}
}

func (s *Scanner) FollowRedirectsToSameSiteRoot() {
	i := 0
	baseUrl, _ := url.Parse(s.Config.Url)
	var msg *httpc.MessageDuplex
	for {
		req, _ := http.NewRequest("GET", baseUrl.String(), nil)

		msg = s.GetResponse(req)
		if msg.Response != nil && msg.Response.StatusCode >= 300 && msg.Response.StatusCode < 400 {
			baseUrl, _ = msg.Response.Location()
		} else {
			break
		}
		i++

		if i >= 5 {
			if msg.Response == nil {
				gologger.Fatal().Msgf("Received error %s when requesting landing page, exiting.", msg.TransportError)
			}

			gologger.Fatal().Msgf("Received status code %d when requesting landing page, exiting.", msg.Response.StatusCode)
		}
	}

	msgPtr := msg
	for {
		s.Config.Url = msgPtr.Request.URL.String()

		if msgPtr.Prev == nil {
			break
		}

		msgPtr = msg.Prev
	}
}
