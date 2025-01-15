package scanner

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"regexp"
	"strings"
	"sync"

	"github.com/aristosMiliaressis/cors-scanner/internal/input"
	"github.com/aristosMiliaressis/httpc/pkg/httpc"
	"github.com/projectdiscovery/gologger"
	"golang.org/x/net/publicsuffix"
)

type Scanner struct {
	Client       httpc.HttpClient
	BaseRequest  *http.Request
	Config       input.Config
	cancel       context.CancelFunc
	corsSettings []CorsSettings
}

func NewScanner(conf input.Config) Scanner {
	ctx, cancel := context.WithCancel(context.Background())

	scanner := Scanner{
		Client: *httpc.NewHttpClient(conf.Http, ctx),
		Config: conf,
		cancel: cancel,
	}

	if conf.RequestFile != "" {
		requestText, err := os.ReadFile(conf.RequestFile)
		if err != nil {
			gologger.Fatal().Msgf("input: error while trying to access request file: %s", err)
		}

		requestText = []byte(strings.Replace(string(requestText), "HTTP/2", "HTTP/1.1", 1))
		reader := bufio.NewReader(bytes.NewReader(requestText))
		baseRequest, err := http.ReadRequest(reader)
		if err != nil {
			gologger.Fatal().Msgf("input: error while parsing request: %s", err)
		}

		scanner.BaseRequest, _ = http.NewRequest(baseRequest.Method, conf.Url, baseRequest.Body)
		for name, values := range baseRequest.Header {
			scanner.BaseRequest.Header.Add(name, strings.Join(values, ","))
		}
	} else {
		scanner.BaseRequest, _ = http.NewRequest("GET", conf.Url, nil)
	}

	newUrl, _ := url.Parse(conf.Url)
	if newUrl.Scheme == "https" && newUrl.Port() == "443" || newUrl.Scheme == "http" && newUrl.Port() == "80" {
		scanner.Config.Url = strings.Replace(conf.Url, regexp.MustCompile(":(80|443)").FindString(conf.Url), "", 1)
	}

	return scanner
}

func (s *Scanner) Scan() {

	s.FollowRedirectsToSameSiteRoot()

	preflightSupport := s.testPreflightSupport()
	if !preflightSupport {
		s.testResponseReadCapabilities("GET")

		s.printACEH()
		return
	}

	s.PrintResult(Result{Type: CAPABILITY, Name: "preflight-support"})

	s.testAllCapabilities()

	s.printACEH()

	if len(s.Config.Origins) != 0 {
		s.bruteforceOrigins()
	}
}

func (s *Scanner) testPreflightSupport() bool {

	req := s.BaseRequest.Clone(context.Background())
	req.Method = "OPTIONS"
	req.Header.Set("Origin", "https://example.com")

	msg := s.GetResponse(req)
	if msg.Response == nil {
		gologger.Fatal().Msg("Failed to receive a response, exiting.")
	}

	return msg.Response.StatusCode >= 200 && msg.Response.StatusCode < 300 &&
		msg.Response.Header.Get("Access-Control-Allow-Origin") != ""
}

func (s *Scanner) testAllCapabilities() {
	s.testRequestSendCapabilities()

	s.testResponseReadCapabilities("OPTIONS")
}

func (s *Scanner) testResponseReadCapabilities(method string) {
	found := s.testArbitaryOriginTrust(method)
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

		found = s.testPortReflection(method, stng.ACAO)
		s.testSuffixReflectionBypass(method, stng.ACAO)
		if found {
			s.testCRLFInjection(ACAO_PORT, method, stng.ACAO)
		}

		s.testRegexDotBypass(method, stng.ACAO)

		s.testS3Trust(method)

		if strings.HasPrefix(s.Config.Url, "https:") {
			s.testHttpOriginTrust(method, stng.ACAO)
		}
	}
}

func (s *Scanner) testPortReflection(method, origin string) bool {
	originUrl, _ := url.Parse(origin)
	originUrl.Host = fmt.Sprintf("%s:1337", originUrl.Hostname())

	req := s.BaseRequest.Clone(context.Background())
	req.Method = method
	req.Header.Set("Origin", originUrl.String())

	msg := s.GetResponse(req)

	corsSettings := s.getCorsSettings(msg.Response)
	if corsSettings.ACAO == originUrl.String() {
		rawReq, _ := httputil.DumpRequestOut(msg.Response.Request, true)
		rawResp, _ := httputil.DumpResponse(msg.Response, true)

		poc := fmt.Sprintf("%s\n---- ↑ Request ---- Response ↓ ----\n\n%s", string(rawReq), string(rawResp))

		if !strings.Contains(strings.ToLower(corsSettings.Vary), "origin") {
			s.PrintResult(Result{Type: MISCONFIG, Name: "acao-port-reflection", AllowedCredentials: corsSettings.ACAC == "true", MissingVary: true, POC: poc})
		} else {
			s.PrintResult(Result{Type: CAPABILITY, Name: "acao-port-reflection", AllowedCredentials: corsSettings.ACAC == "true", POC: poc})
		}

		return true
	}

	return false
}

func (s *Scanner) testSuffixReflectionBypass(method, origin string) {

	originUrl, _ := url.Parse(origin)
	suffixedOrigin := fmt.Sprintf("%s://%s.example.com", originUrl.Scheme, originUrl.Hostname())

	req := s.BaseRequest.Clone(context.Background())
	req.Method = method
	req.Header.Set("Origin", suffixedOrigin)

	msg := s.GetResponse(req)
	corsSettings := s.getCorsSettings(msg.Response)
	if corsSettings.ACAO == suffixedOrigin {
		rawReq, _ := httputil.DumpRequestOut(msg.Response.Request, true)
		rawResp, _ := httputil.DumpResponse(msg.Response, true)

		poc := fmt.Sprintf("%s\n---- ↑ Request ---- Response ↓ ----\n\n%s", string(rawReq), string(rawResp))

		s.PrintResult(Result{Type: VULNERABILITY, Name: "acao-port-reflection-suffix-bypass", Value: corsSettings.ACAO, AllowedCredentials: corsSettings.ACAC == "true", MissingVary: !strings.Contains(strings.ToLower(corsSettings.Vary), "origin"), POC: poc})
		return
	}

	req = s.BaseRequest.Clone(context.Background())
	req.Method = method
	req.Header.Set("Origin", "http://localhost.example.com")

	msg = s.GetResponse(req)
	corsSettings = s.getCorsSettings(msg.Response)
	if corsSettings.ACAO == suffixedOrigin {
		rawReq, _ := httputil.DumpRequestOut(msg.Response.Request, true)
		rawResp, _ := httputil.DumpResponse(msg.Response, true)

		poc := fmt.Sprintf("%s\n---- ↑ Request ---- Response ↓ ----\n\n%s", string(rawReq), string(rawResp))

		s.PrintResult(Result{Type: VULNERABILITY, Name: "acao-localhost-suffix-bypass", Value: corsSettings.ACAO, AllowedCredentials: corsSettings.ACAC == "true", MissingVary: !strings.Contains(strings.ToLower(corsSettings.Vary), "origin"), POC: poc})
		return
	}

	req = s.BaseRequest.Clone(context.Background())
	req.Method = method
	req.Header.Set("Origin", "https://localhost.example.com")

	msg = s.GetResponse(req)
	corsSettings = s.getCorsSettings(msg.Response)
	if corsSettings.ACAO == suffixedOrigin {
		rawReq, _ := httputil.DumpRequestOut(msg.Response.Request, true)
		rawResp, _ := httputil.DumpResponse(msg.Response, true)

		poc := fmt.Sprintf("%s\n---- ↑ Request ---- Response ↓ ----\n\n%s", string(rawReq), string(rawResp))

		s.PrintResult(Result{Type: VULNERABILITY, Name: "acao-localhost-suffix-bypass", Value: corsSettings.ACAO, AllowedCredentials: corsSettings.ACAC == "true", MissingVary: !strings.Contains(strings.ToLower(corsSettings.Vary), "origin"), POC: poc})
		return
	}

	fuzzChars := []rune{
		'.', '`', '!', '%', '_', ' ', ',', '&', '\'', '"', ';', '$',
		'^', '*', '(', ')', '+', '=', '~', '-', '=', '|', '{', '}', '@',
		'\x00', '\x01', '\x02', '\x03', '\x04', '\x05', '\x06', '\x07', '\x08',
		'\x0b', '\x0c', '\x0e', '\x0f', '\x10', '\x11', '\x12', '\x13', '\x14',
		'\x15', '\x16', '\x17', '\x18', '\x19', '\x1a', '\x1b', '\x1c', '\x1d',
		'\x1e', '\x1f', '\x7f',
	}

	wg := sync.WaitGroup{}

	for _, char := range fuzzChars {
		req := s.BaseRequest.Clone(context.Background())
		req.Method = method
		req.Header.Set("Origin", fmt.Sprintf("%s://%s%s.%s", originUrl.Scheme, originUrl.Hostname(), string(char), originUrl.Hostname()))

		wg.Add(1)
		go func() {
			defer wg.Done()

			rawReq, _ := httputil.DumpRequest(req, true)
			msg := s.Client.SendRaw(string(rawReq), s.Config.Url)
			<-msg.Resolved

			corsSettings := s.getCorsSettings(msg.Response)
			if corsSettings.ACAO == suffixedOrigin {
				rawResp, _ := httputil.DumpResponse(msg.Response, true)

				poc := fmt.Sprintf("%s\n---- ↑ Request ---- Response ↓ ----\n\n%s", string(rawReq), string(rawResp))

				s.PrintResult(Result{Type: VULNERABILITY, Name: "acao-port-reflection-suffix-bypass",
					Value: corsSettings.ACAO, AllowedCredentials: corsSettings.ACAC == "true",
					MissingVary: !strings.Contains(strings.ToLower(corsSettings.Vary), "origin"), POC: poc})
				return
			}
		}()
	}
	wg.Wait()
}

func (s *Scanner) testHttpOriginTrust(method, origin string) {
	originUrl, _ := url.Parse(origin)
	originUrl.Scheme = "http"

	req := s.BaseRequest.Clone(context.Background())
	req.Method = method
	req.Header.Set("Origin", originUrl.String())

	msg := s.GetResponse(req)

	corsSettings := s.getCorsSettings(msg.Response)
	if corsSettings.ACAO == originUrl.String() {
		rawReq, _ := httputil.DumpRequestOut(msg.Response.Request, true)
		rawResp, _ := httputil.DumpResponse(msg.Response, true)

		poc := fmt.Sprintf("%s\n---- ↑ Request ---- Response ↓ ----\n\n%s", string(rawReq), string(rawResp))
		s.PrintResult(Result{Type: MISCONFIG, Name: "acao-http-origin-trust", Value: corsSettings.ACAO, AllowedCredentials: corsSettings.ACAC == "true", POC: poc})
	}
}

func (s *Scanner) testRegexDotBypass(method, origin string) {

	originUrl, _ := url.Parse(origin)
	apexHostname, err := publicsuffix.EffectiveTLDPlusOne(originUrl.Hostname())
	if err != nil {
		return
	}

	for i := strings.Count(originUrl.Hostname(), ".") - strings.Count(apexHostname, ".") - 1; i <= strings.Count(originUrl.Hostname(), ".")-1; i++ {
		if i == -1 {
			i = 0
		}

		parts := strings.Split(originUrl.Hostname(), ".")
		newOrigin := ""

		if i > 0 {
			newOrigin = strings.Join(parts[0:i], ".") + "."
		}

		newOrigin += parts[i] + "a" + parts[i+1]
		if len(parts) > i+2 {
			newOrigin += "." + strings.Join(parts[(i+2):], ".")
		}

		req := s.BaseRequest.Clone(context.Background())
		req.Method = method
		req.Header.Set("Origin", newOrigin)

		msg := s.GetResponse(req)

		corsSettings := s.getCorsSettings(msg.Response)
		if corsSettings.ACAO == newOrigin {
			rawReq, _ := httputil.DumpRequestOut(msg.Response.Request, true)
			rawResp, _ := httputil.DumpResponse(msg.Response, true)

			poc := fmt.Sprintf("%s\n---- ↑ Request ---- Response ↓ ----\n\n%s", string(rawReq), string(rawResp))

			s.PrintResult(Result{Type: VULNERABILITY, Name: "acao-regex-dot-bypass", Value: corsSettings.ACAO, AllowedCredentials: corsSettings.ACAC == "true", MissingVary: !strings.Contains(strings.ToLower(corsSettings.Vary), "origin"), POC: poc})
		}
	}
}

func (s *Scanner) printACEH() {
	settings := s.Search(func(stng CorsSettings) bool {
		return stng.ACEH != ""
	})

	exposedHeaders := []string{}
	allowedCreds := false
	for _, stng := range settings {

		if stng.ACAC == "true" {
			allowedCreds = true
		}

		if !Contains(exposedHeaders, stng.ACEH) {
			exposedHeaders = append(exposedHeaders, stng.ACEH)
		}
	}

	for _, aceh := range exposedHeaders {
		s.PrintResult(Result{Type: CAPABILITY, Name: "aceh-fixed", Value: aceh, AllowedCredentials: allowedCreds})
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

func (s *Scanner) bruteforceOrigins() {
	var wg sync.WaitGroup
	for _, origin := range s.Config.Origins {
		if origin == "" {
			continue
		}

		lOrigin := origin
		wg.Add(1)

		go func() {
			defer wg.Done()

			s.testOriginTrust(lOrigin)
		}()
	}
	wg.Wait()
}

func (s *Scanner) testOriginTrust(origin string) {
	originUrl, _ := url.Parse(origin)

	req := s.BaseRequest.Clone(context.Background())
	req.Method = "GET"
	req.Header.Set("Origin", originUrl.String())

	msg := s.GetResponse(req)

	corsSettings := s.getCorsSettings(msg.Response)
	if corsSettings.ACAO == originUrl.String() {
		rawReq, _ := httputil.DumpRequestOut(msg.Response.Request, true)
		rawResp, _ := httputil.DumpResponse(msg.Response, true)

		poc := fmt.Sprintf("%s\n---- ↑ Request ---- Response ↓ ----\n\n%s", string(rawReq), string(rawResp))
		s.PrintResult(Result{Type: MISCONFIG, Name: "acao-http-origin-trust", Value: corsSettings.ACAO, AllowedCredentials: corsSettings.ACAC == "true", POC: poc})
	}
}
