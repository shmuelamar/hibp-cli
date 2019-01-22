package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"sort"
	"strconv"
	"time"
)

// returns haveibeenpwned breaches and pastes for the given user or error upon failure
func (api *HIBPClient) GetHIBPLeaks(account string) ([]HIBPBreach, []HIBPPaste, error) {
	breaches, err := api.GetHIBPBreaches(account)
	if err != nil {
		return nil, nil, err
	}

	pastes, err := api.GetHIBPPastes(account)
	if err != nil {
		return nil, nil, err
	}

	return breaches, pastes, nil
}

const (
	HIBPBaseURL               = "https://haveibeenpwned.com"
	HIBPGetAccountBreachesURL = "/api/v2/breachedaccount/%s"
	HIBPGetAccountPastesURL   = "/api/v2/pasteaccount/%s"
	DefaultMaxRetries         = 10
	DefaultRequestDelay       = 10 * time.Second
	DefaultHTTPTimeout        = 10 * time.Second
)

var logger *log.Logger

type HIBPBreach struct {
	Name         string
	Title        string
	Domain       string
	BreachDate   string
	AddedDate    time.Time
	ModifiedDate time.Time
	PwnCount     uint64
	Description  string
	DataClasses  []string
	IsVerified   bool
	IsFabricated bool
	IsSensitive  bool
	IsRetired    bool
	IsSpamList   bool
	LogoPath     string
}

type HIBPPaste struct {
	Source     string
	Id         string
	Title      string
	Date       time.Time
	EmailCount uint64
}

type HIBPClient struct {
	Client       *http.Client // TODO: maybe make private
	MaxRetries   uint
	RequestDelay time.Duration
	baseURL      string
	nextSleep    time.Duration
}

func NewHIBPClient() *HIBPClient {
	return &HIBPClient{
		&http.Client{Timeout: DefaultHTTPTimeout},
		DefaultMaxRetries,
		DefaultRequestDelay,
		HIBPBaseURL,
		0,
	}
}

func (api *HIBPClient) getHIBPResp(urlTemplate, account string, respObject interface{}) (error) {
	url := api.baseURL + fmt.Sprintf(urlTemplate, account)

	for retries := uint(0); retries <= api.MaxRetries; retries++ {
		if api.nextSleep > 0 {
			logger.Printf("sleeping %s", api.nextSleep.String())
			time.Sleep(api.nextSleep)
		}
		logger.Printf("requesting %s\n", url)

		resp, err := api.Client.Get(url)
		// HIBP will block our IP if we do too many requests in short time
		api.nextSleep = api.RequestDelay

		if err != nil {
			logger.Printf("network error %s", err.Error())
			continue
		}

		if resp.StatusCode == 404 {
			return nil
		}
		if resp.StatusCode != 200 {
			// read Retry After header if exists and sleep that many seconds
			retryAfter := resp.Header.Get("Retry-After")
			backoffSeconds, err := strconv.ParseUint(retryAfter, 10, 64)
			if err == nil {
				// add 1 second for safety
				api.nextSleep = time.Duration(backoffSeconds+1) * time.Second
			}
			logger.Printf("got http error %d for url %s (Retry-After %s)", resp.StatusCode, url, retryAfter)
			continue
		}

		buf, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			logger.Printf("error reading server response: %s", err.Error())
			continue
		}

		return json.Unmarshal(buf, &respObject)
	}

	return errors.New(fmt.Sprintf("max retries exceeded (%d) for %s", api.MaxRetries, url))
}

// returns haveibeenpwned breaches for the given user or error upon failure
func (api *HIBPClient) GetHIBPBreaches(account string) ([]HIBPBreach, error) {
	var breaches []HIBPBreach
	if err := api.getHIBPResp(HIBPGetAccountBreachesURL, account, &breaches); err != nil {
		return nil, err
	}

	sort.Slice(breaches, func(i, j int) bool {
		return breaches[i].BreachDate > breaches[j].BreachDate
	})

	return breaches, nil
}

// returns haveibeenpwned pastes for the given user or error upon failure
func (api *HIBPClient) GetHIBPPastes(account string) ([]HIBPPaste, error) {
	var pastes []HIBPPaste
	if err := api.getHIBPResp(HIBPGetAccountPastesURL, account, &pastes); err != nil {
		return nil, err
	}

	sort.Slice(pastes, func(i, j int) bool {
		return pastes[i].Date.After(pastes[j].Date)
	})
	return pastes, nil
}
