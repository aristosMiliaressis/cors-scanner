package scanner

import (
	"fmt"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"sync"

	"golang.org/x/net/publicsuffix"
)

type CorsSettings struct {
	ACAO string
	ACAC string
	ACAH string
	ACAM string
	ACEH string
	Vary string
}

type ReflectionPosition int

const (
	ACAO_SUBDOMAIN ReflectionPosition = iota
	ACAO_PORT
	ACAH
	ACAM
)

func (c ReflectionPosition) String() string {
	return []string{"acao-subdomain", "acao-port", "acah", "acam"}[c]
}

func (s *Scanner) getCorsSettings(resp *http.Response) CorsSettings {
	if resp == nil {
		return CorsSettings{}
	}

	settings := CorsSettings{
		ACAO: resp.Header.Get("Access-Control-Allow-Origin"),
		ACAC: resp.Header.Get("Access-Control-Allow-Credentials"),
		ACAH: resp.Header.Get("Access-Control-Allow-Headers"),
		ACAM: resp.Header.Get("Access-Control-Allow-Methods"),
		ACEH: resp.Header.Get("Access-Control-Expose-Headers"),
		Vary: resp.Header.Get("Vary"),
	}
	s.corsSettings = append(s.corsSettings, settings)

	return settings
}

func (s *Scanner) testArbitaryOriginTrust(method string) bool {

	fullReflection := false

	req, _ := http.NewRequest(method, s.Config.Url, nil)
	req.Header.Set("Origin", "https://example.com")

	msg := s.GetResponse(req)

	corsSettings := s.getCorsSettings(msg.Response)
	if corsSettings.ACAO == "https://example.com" {
		fullReflection = true
		s.PrintResult(Result{Type: MISCONFIG, Name: "acao-reflection", AllowedCredentials: corsSettings.ACAC == "true", MissingVary: !strings.Contains(strings.ToLower(corsSettings.Vary), "origin")})
	} else if corsSettings.ACAO == "*" {
		s.PrintResult(Result{Type: CAPABILITY, Name: "acao-wildcard", Value: corsSettings.ACAO, AllowedCredentials: corsSettings.ACAC == "true"})
	} else if corsSettings.ACAO != "" {
		s.PrintResult(Result{Type: CAPABILITY, Name: "acao-fixed", Value: corsSettings.ACAO, AllowedCredentials: corsSettings.ACAC == "true"})
	}

	req, _ = http.NewRequest(method, s.Config.Url, nil)
	req.Header.Set("Origin", "null")

	msg = s.GetResponse(req)

	corsSettings = s.getCorsSettings(msg.Response)
	if corsSettings.ACAO == "null" {
		s.PrintResult(Result{Type: MISCONFIG, Name: "acao-null", AllowedCredentials: corsSettings.ACAC == "true"})
	}

	return fullReflection
}

func (s *Scanner) testSubdomainReflection(method, origin string) bool {

	originUrl, _ := url.Parse(origin)
	origin = fmt.Sprintf("%s://notexistent.%s", originUrl.Scheme, originUrl.Host)

	req, _ := http.NewRequest(method, s.Config.Url, nil)
	req.Header.Set("Origin", origin)

	msg := s.GetResponse(req)

	corsSettings := s.getCorsSettings(msg.Response)
	if corsSettings.ACAO == origin {
		if !strings.Contains(strings.ToLower(corsSettings.Vary), "origin") {
			s.PrintResult(Result{Type: MISCONFIG, Name: "acao-subdomain-reflection", AllowedCredentials: corsSettings.ACAC == "true", MissingVary: true})
		} else {
			s.PrintResult(Result{Type: CAPABILITY, Name: "acao-subdomain-reflection", AllowedCredentials: corsSettings.ACAC == "true"})
		}

		return true
	}

	return false
}

func (s *Scanner) testS3Trust(method string) {
	regions := []string{"us-east-2", "us-east-1", "us-west-1", "us-west-2", "af-south-1",
		"ap-east-1", "ap-south-2", "ap-southeast-3", "ap-southeast-4", "ap-south-1",
		"ap-northeast-3", "ap-northeast-2", "ap-southeast-1", "ap-southeast-2", "ap-northeast-1",
		"ca-central-1", "eu-central-1", "eu-west-1", "eu-west-2", "eu-south-1", "eu-west-3",
		"eu-south-2", "eu-north-1", "eu-central-2", "il-central-1", "me-south-1", "me-central-1",
		"sa-east-1", "us-gov-east-1", "us-gov-west-1",
	}

	wg := sync.WaitGroup{}

	for _, region := range regions {

		wg.Add(1)

		origin := fmt.Sprintf("https://bucket-name.s3.%s.amazonaws.com/", region)
		go func() {
			defer wg.Done()

			req, _ := http.NewRequest(method, s.Config.Url, nil)
			req.Header.Set("Origin", origin)

			msg := s.GetResponse(req)

			corsSettings := s.getCorsSettings(msg.Response)
			if corsSettings.ACAO == origin {
				s.PrintResult(Result{Type: MISCONFIG, Name: "acao-s3-trust", Value: origin, AllowedCredentials: corsSettings.ACAC == "true", MissingVary: !strings.Contains(strings.ToLower(corsSettings.Vary), "origin")})
			}
		}()
	}

	for _, region := range regions {

		wg.Add(1)

		origin := fmt.Sprintf("https://s3.%s.amazonaws.com/", region)
		go func() {
			defer wg.Done()

			req, _ := http.NewRequest(method, s.Config.Url, nil)
			req.Header.Set("Origin", origin)

			msg := s.GetResponse(req)

			corsSettings := s.getCorsSettings(msg.Response)
			if corsSettings.ACAO == origin {
				s.PrintResult(Result{Type: MISCONFIG, Name: "acao-s3-trust", Value: origin, AllowedCredentials: corsSettings.ACAC == "true", MissingVary: !strings.Contains(strings.ToLower(corsSettings.Vary), "origin")})
			}
		}()
	}

	wg.Wait()
}

func (s *Scanner) testSubdomainReflectionBypass(method, origin string) {

	originUrl, _ := url.Parse(origin)
	apexHostname, err := publicsuffix.EffectiveTLDPlusOne(originUrl.Hostname())
	if err != nil {
		return
	}

	origin = fmt.Sprintf("%s://notexistent%s", originUrl.Scheme, apexHostname)

	req, _ := http.NewRequest(method, s.Config.Url, nil)
	req.Header.Set("Origin", origin)

	msg := s.GetResponse(req)

	corsSettings := s.getCorsSettings(msg.Response)
	if corsSettings.ACAO == origin {
		s.PrintResult(Result{Type: VULNERABILITY, Name: "acao-subdomain-reflection-prefix-bypass", AllowedCredentials: corsSettings.ACAC == "true", MissingVary: !strings.Contains(strings.ToLower(corsSettings.Vary), "origin")})
	}
}

func (s *Scanner) testCRLFInjection(pos ReflectionPosition, method, origin string) {

	chars := []rune{'\r', '\n'}
	for _, char := range chars {
		req, _ := http.NewRequest(method, s.Config.Url, nil)
		switch pos {
		case ACAO_SUBDOMAIN:
			originUrl, _ := url.Parse(origin)
			req.Header.Set("Origin", fmt.Sprintf("%s://ABCDE%sFGHIJ.%s", string(char), originUrl.Scheme, originUrl.Host))
		case ACAO_PORT:
			originUrl, _ := url.Parse(origin)
			req.Header.Set("Origin", fmt.Sprintf("%s://%s:13%s37", originUrl.Scheme, originUrl.Host, string(char)))
		case ACAH:
			req.Header.Set("Access-Control-Request-Headers", fmt.Sprintf("ABCDE%sFGHIJ", string(char)))
		case ACAM:
			req.Header.Set("Access-Control-Request-Method", fmt.Sprintf("ABCDE%sFGHIJ", string(char)))
		}

		rawReq, _ := httputil.DumpRequest(req, true)
		msg := s.Client.SendRaw(string(rawReq), s.Config.Url)
		<-msg.Resolved

		corsSettings := s.getCorsSettings(msg.Response)
		responseBytes, _ := httputil.DumpResponse(msg.Response, false)
		if strings.Contains(string(responseBytes), fmt.Sprintf("ABCDE%sFGHIJ", string(char))) ||
			strings.Contains(string(responseBytes), fmt.Sprintf(":13%s37", string(char))) {
			s.PrintResult(Result{Type: VULNERABILITY, Name: fmt.Sprintf("%s-crlf-injection", pos), AllowedCredentials: corsSettings.ACAC == "true"})
		}
	}
}

func (s *Scanner) testRequestSendCapabilities() {

	trustedOrigin := "https://example.com"
	if len(s.corsSettings) != 0 {
		trustedOrigin = s.corsSettings[0].ACAO
	}

	req, _ := http.NewRequest("OPTIONS", s.Config.Url, nil)
	req.Header.Set("Origin", trustedOrigin)
	req.Header.Set("Access-Control-Request-Method", "PUT")

	msg := s.GetResponse(req)

	corsSettings := s.getCorsSettings(msg.Response)
	if corsSettings.ACAM == "PUT" {
		s.PrintResult(Result{Type: CAPABILITY, Name: "acam-reflection", AllowedCredentials: corsSettings.ACAC == "true", MissingVary: !strings.Contains(strings.ToLower(corsSettings.Vary), "access-control-request-method")})

		s.testCRLFInjection(ACAM, "OPTIONS", "")
	} else if corsSettings.ACAM == "*" {
		s.PrintResult(Result{Type: CAPABILITY, Name: "acam-wildcard", AllowedCredentials: corsSettings.ACAC == "true"})
	} else if corsSettings.ACAM != "" {
		s.PrintResult(Result{Type: CAPABILITY, Name: "acam-fixed", Value: corsSettings.ACAM, AllowedCredentials: corsSettings.ACAC == "true"})
	}

	req, _ = http.NewRequest("OPTIONS", s.Config.Url, nil)
	req.Header.Set("Origin", trustedOrigin)
	req.Header.Set("Access-Control-Request-Headers", "x-test")

	msg = s.GetResponse(req)

	corsSettings = s.getCorsSettings(msg.Response)
	if corsSettings.ACAH == "x-test" {
		s.PrintResult(Result{Type: CAPABILITY, Name: "acah-reflection", AllowedCredentials: corsSettings.ACAC == "true", MissingVary: !strings.Contains(strings.ToLower(corsSettings.Vary), "access-control-request-headers")})

		s.testCRLFInjection(ACAH, "OPTIONS", "")
	} else if corsSettings.ACAH == "*" {
		s.PrintResult(Result{Type: CAPABILITY, Name: "acah-wildcard", AllowedCredentials: corsSettings.ACAC == "true"})
	} else if corsSettings.ACAH != "" {
		s.PrintResult(Result{Type: CAPABILITY, Name: "acah-fixed", Value: corsSettings.ACAH, AllowedCredentials: corsSettings.ACAC == "true"})
	}
}
