package main

import (
	"github.com/aristosMiliaressis/cors-scanner/internal/input"
	"github.com/aristosMiliaressis/cors-scanner/internal/scanner"
	"github.com/projectdiscovery/gologger"
)

var git_hash = "unset"

func main() {
	conf, err := input.ParseCliFlags(git_hash)
	if err != nil {
		gologger.Fatal().Msg(err.Error())
	}

	s := scanner.NewScanner(conf)

	s.Scan()
}
