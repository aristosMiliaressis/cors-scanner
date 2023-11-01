package scanner

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"sync"
)

type CorsSettings struct {
	ACAO string
	ACAC string
	ACAH string
	ACAM string
	ACEH string
	Vary string
}

type ImpactModifier int

const (
	ALLOWED_CREDENTIALS ImpactModifier = iota
	NO_VARY
)

func (c ImpactModifier) String() string {
	return []string{"allowed-credentials", "no-vary"}[c]
}

func (c ImpactModifier) MarshalJSON() ([]byte, error) {
	return json.Marshal(c.String())
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

func (s *Scanner) testAribitaryOriginTrust(method string) bool {

	fullReflection := false

	req, _ := http.NewRequest(method, s.Config.Url, nil)
	req.Header.Set("Origin", "https://example.com")

	msg := s.GetResponse(req)

	corsSettings := s.getCorsSettings(msg.Response)
	modifiers := []ImpactModifier{}
	if corsSettings.ACAC == "true" {
		modifiers = append(modifiers, ALLOWED_CREDENTIALS)
	}

	if corsSettings.ACAO == "https://example.com" {
		fullReflection = true
		if !strings.Contains(strings.ToLower(corsSettings.Vary), "origin") {
			modifiers = append(modifiers, NO_VARY)
		}
		s.PrintResult(Result{Type: MISCONFIG, Name: "cors-origin-reflection", Modifiers: modifiers})
	}

	req, _ = http.NewRequest(method, s.Config.Url, nil)
	req.Header.Set("Origin", "null")

	msg = s.GetResponse(req)

	corsSettings = s.getCorsSettings(msg.Response)
	if corsSettings.ACAC == "true" {
		modifiers = []ImpactModifier{ALLOWED_CREDENTIALS}
	}

	if corsSettings.ACAO == "null" {
		s.PrintResult(Result{Type: MISCONFIG, Name: "cors-null-origin", Modifiers: modifiers})
	}

	s.testS3Trust(method)

	return fullReflection
}

func (s *Scanner) testSubdomainReflection(method, origin string) bool {

	originUrl, _ := url.Parse(origin)
	origin = fmt.Sprintf("https://notexistent.%s", originUrl.Host)

	req, _ := http.NewRequest(method, s.Config.Url, nil)
	req.Header.Set("Origin", origin)

	msg := s.GetResponse(req)

	corsSettings := s.getCorsSettings(msg.Response)
	modifiers := []ImpactModifier{}
	if corsSettings.ACAC == "true" {
		modifiers = append(modifiers, ALLOWED_CREDENTIALS)
	}

	if corsSettings.ACAO == origin {
		if !strings.Contains(strings.ToLower(corsSettings.Vary), "origin") {
			modifiers = append(modifiers, NO_VARY)
		}

		s.PrintResult(Result{Type: CAPABILITY, Name: "cors-subdomain-reflection", Modifiers: modifiers})
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
			modifiers := []ImpactModifier{}
			if corsSettings.ACAC == "true" {
				modifiers = append(modifiers, ALLOWED_CREDENTIALS)
			}

			if corsSettings.ACAO == origin {
				if !strings.Contains(strings.ToLower(corsSettings.Vary), "origin") {
					modifiers = append(modifiers, NO_VARY)
				}

				s.PrintResult(Result{Type: CAPABILITY, Name: "cors-all-s3-buckets-trusted", Value: origin, Modifiers: modifiers})
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
			modifiers := []ImpactModifier{}
			if corsSettings.ACAC == "true" {
				modifiers = append(modifiers, ALLOWED_CREDENTIALS)
			}

			if corsSettings.ACAO == origin {
				if !strings.Contains(strings.ToLower(corsSettings.Vary), "origin") {
					modifiers = append(modifiers, NO_VARY)
				}

				s.PrintResult(Result{Type: CAPABILITY, Name: "cors-all-s3-buckets-trusted", Value: origin, Modifiers: modifiers})
			}
		}()
	}

	wg.Wait()
}

func (s *Scanner) testSubdomainReflectionBypass(method, origin string) {
	origin = fmt.Sprintf("https://notexistent%s", origin)

	req, _ := http.NewRequest(method, s.Config.Url, nil)
	req.Header.Set("Origin", origin)

	msg := s.GetResponse(req)

	corsSettings := s.getCorsSettings(msg.Response)
	modifiers := []ImpactModifier{}
	if corsSettings.ACAC == "true" {
		modifiers = append(modifiers, ALLOWED_CREDENTIALS)
	}

	if corsSettings.ACAO == origin {
		if !strings.Contains(strings.ToLower(corsSettings.Vary), "origin") {
			modifiers = append(modifiers, NO_VARY)
		}

		s.PrintResult(Result{Type: VULNERABILITY, Name: "cors-subdomain-reflection-prefix-bypass", Modifiers: modifiers})
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
			modifiers := []ImpactModifier{}
			if !strings.Contains(strings.ToLower(corsSettings.Vary), "origin") {
				modifiers = append(modifiers, NO_VARY)
			}

			s.PrintResult(Result{Type: VULNERABILITY, Name: fmt.Sprintf("%s-crlf-injection", pos), Modifiers: modifiers})
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
	modifiers := []ImpactModifier{}
	if corsSettings.ACAC == "true" {
		modifiers = append(modifiers, ALLOWED_CREDENTIALS)
	}

	if corsSettings.ACAM == "PUT" {
		if !strings.Contains(strings.ToLower(corsSettings.Vary), "access-control-request-method") {
			modifiers = append(modifiers, NO_VARY)
		}

		s.PrintResult(Result{Type: CAPABILITY, Name: "cors-acam-reflection", Modifiers: modifiers})

		s.testCRLFInjection(ACAM, "OPTIONS", "")
	} else if corsSettings.ACAM == "*" {
		s.PrintResult(Result{Type: CAPABILITY, Name: "cors-acam-wildcard", Modifiers: modifiers})
	} else if corsSettings.ACAM != "" {
		s.PrintResult(Result{Type: CAPABILITY, Name: "cors-acam-fixed", Value: corsSettings.ACAM, Modifiers: modifiers})
	}

	req, _ = http.NewRequest("OPTIONS", s.Config.Url, nil)
	req.Header.Set("Origin", trustedOrigin)
	req.Header.Set("Access-Control-Request-Headers", "x-test")

	msg = s.GetResponse(req)

	corsSettings = s.getCorsSettings(msg.Response)
	if corsSettings.ACAC == "true" {
		modifiers = []ImpactModifier{ALLOWED_CREDENTIALS}
	}

	if corsSettings.ACAH == "x-test" {
		if !strings.Contains(strings.ToLower(corsSettings.Vary), "access-control-request-headers") {
			modifiers = append(modifiers, NO_VARY)
		}

		s.PrintResult(Result{Type: CAPABILITY, Name: "cors-acah-reflection", Modifiers: modifiers})

		s.testCRLFInjection(ACAH, "OPTIONS", "")
	} else if corsSettings.ACAH == "*" {
		s.PrintResult(Result{Type: CAPABILITY, Name: "cors-acah-wildcard", Modifiers: modifiers})
	} else if corsSettings.ACAH != "" {
		s.PrintResult(Result{Type: CAPABILITY, Name: "cors-acah-fixed", Value: corsSettings.ACAH, Modifiers: modifiers})
	}
}
