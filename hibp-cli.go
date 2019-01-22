package main

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/jessevdk/go-flags"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"
)

/*
  TODO: logs (color)
  TODO: tests
  TODO: modules
  TODO: nicer formatting (color / emoji)
  TODO: single account
*/
const (
	HIBPBaseURL               = "https://haveibeenpwned.com"
	HIBPGetAccountBreachesURL = "/api/v2/breachedaccount/%s"
	HIBPGetAccountPastesURL   = "/api/v2/pasteaccount/%s"
	DefaultMaxRetries         = 10
	DefaultRequestDelay       = 10
	DefaultErrorBackoff       = time.Duration(7) * time.Second
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
	ErrorBackoff time.Duration
	RequestDelay time.Duration
	baseURL      string
}

func NewHIBPClient() *HIBPClient {
	return &HIBPClient{
		&http.Client{Timeout: time.Second * 10},
		DefaultMaxRetries,
		DefaultErrorBackoff,
		DefaultRequestDelay,
		HIBPBaseURL,
	}
}

func (api *HIBPClient) getHIBPResp(urlTemplate, account string, respObject interface{}) (error) {
	url := api.baseURL + fmt.Sprintf(urlTemplate, account)

	for retries := uint(0); retries <= api.MaxRetries; retries++ {
		logger.Printf("requesting %s\n", url)

		resp, err := api.Client.Get(url)
		if err != nil {
			logger.Printf("network error %s. sleeping %s", err.Error(), api.ErrorBackoff.String())
			time.Sleep(api.ErrorBackoff)
			continue
		}

		if resp.StatusCode == 404 {
			return nil
		}
		if resp.StatusCode != 200 {
			retryAfter := resp.Header.Get("Retry-After")
			backoffSeconds, err := strconv.ParseUint(retryAfter, 10, 64)

			// if no retry after use default
			var backoff time.Duration
			if err != nil {
				backoff = api.ErrorBackoff
			} else {
				// add 1 second for safety
				backoff = time.Duration(backoffSeconds+1) * time.Second
			}
			logger.Printf("got http error %d for url %s. sleeping %s", resp.StatusCode, url, backoff.String())
			time.Sleep(backoff)
			continue
		}

		buf, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			err = err
			logger.Printf("error parsing json %s. sleeping %s", err.Error(), api.ErrorBackoff.String())
			time.Sleep(api.ErrorBackoff)
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

// returns true iff l contains s
func contains(l []string, s string) bool {
	for _, a := range l {
		if a == s {
			return true
		}
	}
	return false
}

// returns unique copy of s with duplicate values removed
func uniq(s []string) []string {
	uniqueItems := make(map[string]bool)
	for _, item := range s {
		uniqueItems[item] = true
	}

	keys := make([]string, len(uniqueItems))

	i := 0
	for k := range uniqueItems {
		keys[i] = k
		i++
	}
	return keys
}

func hibpAccountLeaksFormatter(account string, breaches []HIBPBreach, pastes []HIBPPaste) (string, error) {
	if len(breaches) == 0 && len(pastes) == 0 {
		return fmt.Sprintf("%s: no leaks\n", account), nil
	}

	var msg strings.Builder

	msg.WriteString(fmt.Sprintf("%s: ", account))
	if len(breaches) == 0 {
		msg.WriteString("no breaches")
	} else {
		firstBreach, lastBreach := breaches[0], breaches[len(breaches)-1]

		var lastTitle string
		if lastBreach.Domain != "" {
			lastTitle = lastBreach.Domain
		} else {
			lastTitle = lastBreach.Title
		}

		var hasPassword string
		if contains(lastBreach.DataClasses, "Passwords") {
			hasPassword = "password"
		} else {
			hasPassword = "account only"
		}

		var verified string
		if lastBreach.IsVerified {
			verified = "verified"
		} else {
			verified = "unverified"
		}
		msg.WriteString(fmt.Sprintf("%d breaches between %s-%s. latest from %s [%s %s]", len(breaches),
			firstBreach.BreachDate[:4], lastBreach.BreachDate[:4], lastTitle, verified, hasPassword))
	}

	if len(pastes) == 0 {
		return msg.String(), nil
	}

	pastesSources := make([]string, len(pastes))
	for i, p := range pastes {
		pastesSources[i] = p.Source
	}
	sources := strings.Join(uniq(pastesSources), ",")
	msg.WriteString(fmt.Sprintf(" | %d pastes from %s\n", len(pastes), sources))

	return msg.String(), nil
}

func jsonHIBPAccountLeaksFormatter(account string, breaches []HIBPBreach, pastes []HIBPPaste) (string, error) {
	leaksMap := map[string]interface{}{"account": account, "breaches": breaches, "pastes": pastes}

	leaksJSON, err := json.Marshal(&leaksMap)
	if err != nil {
		return "", err
	}
	return string(leaksJSON), nil
}

type outputFunc func(string, []HIBPBreach, []HIBPPaste) (string, error)

func getHIBPAccountsLeaks(fp io.Reader, outputFn outputFunc) (error) {
	reader := bufio.NewReader(fp)
	HIBPClient := NewHIBPClient()

	for {
		line, err := reader.ReadString('\n')

		if err == io.EOF {
			return nil
		}
		if err != nil {
			return err
		}

		account := strings.TrimSpace(line)

		if account == "" {
			continue
		}

		// FIXME: now
		time.Sleep(time.Second * DefaultRequestDelay) // TODO: expose as arg

		breaches, pastes, err := HIBPClient.GetHIBPLeaks(account)
		if err != nil {
			return err
		}

		msg, err := outputFn(account, breaches, pastes)
		if err != nil {
			return err
		}

		fmt.Println(msg)
	}
}

type options struct {
	Account string `short:"a" long:"account" description:"account to search leaks for"`
	InFile  string `short:"i" long:"input-file" description:"input file of account to search, one account per line"`
	//OutFile      string `short:"o" long:"output-file" description:"output file, defaults to stdout" required:"false"`
	OutputFormat string `short:"f" long:"format" description:"output format, one of text or jsonl (json lines)" default:"text" choice:"text" choice:"jsonl"`
}

func parseArgs(args []string) (options) {
	var opts options

	_, err := flags.ParseArgs(&opts, args)

	if err != nil {
		os.Exit(2)
	}

	if (opts.InFile == "") == (opts.Account == "") {
		logger.Println("please choose either --account or --input-file")
		os.Exit(2)
	}
	return opts
}

func printHIBPLeaks(opts options) {
	fin, err := os.Open(opts.InFile)
	defer fin.Close()

	if err != nil {
		logger.Fatalf("cannot read file %s: %s", opts.InFile, err.Error())
	}

	var outputFn outputFunc
	if opts.OutputFormat == "jsonl" {
		outputFn = jsonHIBPAccountLeaksFormatter
	} else {
		outputFn = hibpAccountLeaksFormatter
	}
	getHIBPAccountsLeaks(fin, outputFn)
}

func main() {
	logger = log.New(os.Stderr, "", log.Ltime|log.Lshortfile)
	opts := parseArgs(os.Args)
	printHIBPLeaks(opts)
}
