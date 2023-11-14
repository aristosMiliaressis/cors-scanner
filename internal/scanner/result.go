package scanner

import (
	"encoding/json"
	"fmt"
)

type Result struct {
	Type               ResultType
	Name               string
	Value              string `json:",omitempty"`
	AllowedCredentials bool
	MissingVary        bool   `json:",omitempty"`
	POC                string `json:",omitempty"`
}

type ResultType int

const (
	CAPABILITY ResultType = iota
	MISCONFIG
	VULNERABILITY
)

func (c ResultType) String() string {
	return []string{"Capability", "Misconfig", "Vulnerability"}[c]
}

func (c ResultType) MarshalJSON() ([]byte, error) {
	return json.Marshal(c.String())
}

func (s *Scanner) PrintResult(r Result) {
	if !s.Config.IncludePOC {
		r.POC = ""
	}

	jsonResult, _ := json.Marshal(r)

	fmt.Println(string(jsonResult))
}
