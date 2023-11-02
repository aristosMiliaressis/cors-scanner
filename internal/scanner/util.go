package scanner

import (
	"net/http"

	"github.com/aristosMiliaressis/httpc/pkg/httpc"
)

func (s *Scanner) GetResponse(req *http.Request) *httpc.MessageDuplex {

	maxTry := 5

	var msg *httpc.MessageDuplex
	for {
		msg = s.Client.Send(req)
		<-msg.Resolved

		if msg.Response != nil || maxTry == 0 {
			break
		}

		maxTry = maxTry - 1
	}
	return msg
}

func (scnr *Scanner) Search(where func(s CorsSettings) bool) []CorsSettings {
	found := []CorsSettings{}
	for _, stng := range scnr.corsSettings {
		if where(stng) {
			found = append(found, stng)
		}
	}

	return found
}

func Contains[T string](s []T, e T) bool {
	for _, a := range s {
		if a == e {
			return true
		}
	}
	return false
}
