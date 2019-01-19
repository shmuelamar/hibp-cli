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
  TODO: tests
  TODO: nicer formatting
*/
const (
	HIBPGetAccountBreachesURL = "https://haveibeenpwned.com/api/v2/breachedaccount/%s"
	HIBPGetAccountPastesURL   = "https://haveibeenpwned.com/api/v2/pasteaccount/%s"
	MaxRetries                = 10
	DefaultBackoff            = time.Duration(7) * time.Second
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

func getHIBPResp(urlTemplate, account string, respObject interface{}, maxRetries uint) (error) {
	url := fmt.Sprintf(urlTemplate, account)

	for retries := uint(0); retries <= maxRetries; retries++ {
		logger.Printf("requesting %s\n", url)
		netClient := &http.Client{
			Timeout: time.Second * 10,
		}

		resp, err := netClient.Get(url)
		if err != nil {
			logger.Printf("network error %s. sleeping %s", err.Error(), DefaultBackoff.String())
			time.Sleep(DefaultBackoff)
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
				backoff = DefaultBackoff
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
			logger.Printf("error parsing json %s. sleeping %s", err.Error(), DefaultBackoff.String())
			time.Sleep(DefaultBackoff)
			continue
		}

		return json.Unmarshal(buf, &respObject)
	}

	return errors.New(fmt.Sprintf("max retries exceeded (%d) for %s", maxRetries, url))
}

func getHIBPBreaches(account string) ([]HIBPBreach, error) {
	var breaches []HIBPBreach
	if err := getHIBPResp(HIBPGetAccountBreachesURL, account, &breaches, MaxRetries); err != nil {
		return nil, err
	}

	sort.Slice(breaches, func(i, j int) bool {
		return breaches[i].BreachDate > breaches[j].BreachDate
	})

	return breaches, nil
}

func getHIBPPastes(account string) ([]HIBPPaste, error) {
	var pastes []HIBPPaste
	if err := getHIBPResp(HIBPGetAccountPastesURL, account, &pastes, MaxRetries); err != nil {
		return nil, err
	}

	sort.Slice(pastes, func(i, j int) bool {
		return pastes[i].Date.After(pastes[j].Date)
	})
	return pastes, nil
}

func getHIBPLeaks(account string) ([]HIBPBreach, []HIBPPaste, error) {
	breaches, err := getHIBPBreaches(account)
	if err != nil {
		return nil, nil, err
	}

	pastes, err := getHIBPPastes(account)
	if err != nil {
		return nil, nil, err
	}

	return breaches, pastes, nil
}

func hibpAccountLeaksFormatter(account string, breaches []HIBPBreach, pastes []HIBPPaste) (string, error) {
	if len(breaches) == 0 && len(pastes) == 0 {
		return fmt.Sprintf("%s: no leaks\n", account), nil
	}

	var msg strings.Builder
	for _, breach := range breaches {
		msg.WriteString(fmt.Sprintf("%s: %s - %s\n", breach.BreachDate, breach.Domain, breach.Title))
	}

	msg.WriteString("\npastes:\n")
	for _, paste := range pastes {
		msg.WriteString(fmt.Sprintf("%s: %s - %s\n", paste.Date, paste.Source, paste.Title))
	}

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

		time.Sleep(time.Second * 2)

		breaches, pastes, err := getHIBPLeaks(account)
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
