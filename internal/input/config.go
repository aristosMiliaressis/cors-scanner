package input

import (
	"fmt"
	"net/url"
	"strings"

	"github.com/aristosMiliaressis/httpc/pkg/httpc"
	"github.com/projectdiscovery/goflags"
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/gologger/levels"
)

const version = "1.0.0"

type Config struct {
	Url        string
	Debug      bool
	IncludePOC bool
	Http       httpc.ClientOptions
}

func ParseCliFlags() (Config, error) {

	dfltOpts := Config{}
	dfltOpts.Http = httpc.DefaultOptions
	var headers goflags.StringSlice

	flagSet := goflags.NewFlagSet()
	flagSet.SetDescription("CORS Scanner v" + version)

	flagSet.CreateGroup("general", "General",
		flagSet.StringVarP(&dfltOpts.Url, "url", "u", "", "Base Url to scan."),
		flagSet.StringVarP(&dfltOpts.Http.Connection.ProxyUrl, "proxy", "x", dfltOpts.Http.Connection.ProxyUrl, "Proxy URL. For example: http://127.0.0.1:8080"),
		flagSet.StringSliceVarP(&headers, "header", "H", nil, "Add request header.", goflags.FileStringSliceOptions),
		flagSet.BoolVarP(&dfltOpts.Debug, "debug", "d", false, "Enable debug logging."),
		flagSet.BoolVarP(&dfltOpts.IncludePOC, "poc", "p", false, "Include POC Request/Response in output."),
	)

	err := flagSet.Parse()
	if err != nil {
		return Config{}, fmt.Errorf("invalid arguments: %s", err)
	}

	var u *url.URL
	u, err = url.Parse(dfltOpts.Url)
	if err != nil || strings.Contains(u.Hostname(), "*") ||
		strings.HasSuffix(u.Hostname(), ".") || dfltOpts.Url == "" {
		return Config{}, fmt.Errorf("invalid url provided: %s", err)
	}

	_, err = url.Parse(dfltOpts.Http.Connection.ProxyUrl)
	if err != nil && dfltOpts.Http.Connection.ProxyUrl != "" {
		return Config{}, fmt.Errorf("invalid proxy url provided: %s", err)
	}

	for _, v := range headers {
		if headerParts := strings.SplitN(v, ":", 2); len(headerParts) >= 2 {
			dfltOpts.Http.DefaultHeaders[strings.Trim(headerParts[0], " ")] = strings.Trim(headerParts[1], " ")
		}
	}

	if dfltOpts.Debug {
		gologger.DefaultLogger.SetMaxLevel(levels.LevelVerbose)
	}

	return dfltOpts, nil
}
