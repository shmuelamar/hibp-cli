package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"github.com/jessevdk/go-flags"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"sort"
	"strconv"
	"time"
)

/*
  cli definition:
  hibp-cli <email>
  hibp-cli -f <file> -o output --format=json/text
 */

/*
  TODO: logs
  TODO: tests
  TODO: cli flags
  TODO: err handling http 429 + backoff
  TODO: nicer formatting
*/
const (
	HIBPGetAccountBreachesURL = "https://haveibeenpwned.com/api/v2/breachedaccount/%s"
	HIBPGetAccountPastesURL   = "https://haveibeenpwned.com/api/v2/pasteaccount/%s"
	MaxRetries                = 10
	DefaultBackoff            = time.Duration(7) * time.Second
)

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

//func (d *date) UnmarshalJSON(b []byte) error {
//	s := strings.Trim(string(b), "\"")
//	t, err := time.Parse("2006-01-02", s)
//	if err != nil {
//		return err
//	}
//	*d = date(t)
//	return nil
//}
//
//func (d date) MarshalJSON() ([]byte, error) {
//	return json.Marshal(d)
//}
//
//// Maybe a Format function for printing your date
//func (d date) Format(s string) string {
//	t := time.Time(d)
//	return t.Format(s)
//}

// TODO: simplify
func getHIBPResp(urlTemplate, account string, respObject interface{}, maxRetries uint) (error) {
	url := fmt.Sprintf(urlTemplate, account)

	for retries := uint(0); retries <= maxRetries; retries++ {
		fmt.Printf("requesting %s\n", url)
		netClient := &http.Client{
			Timeout: time.Second * 10,
		}

		resp, err := netClient.Get(url)
		if err != nil {
			log.Printf("network error %s. sleeping %s", err.Error(), DefaultBackoff.String())
			time.Sleep(DefaultBackoff)
			continue
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
			log.Printf("got http error %d for url %s. sleeping %s", resp.StatusCode, url, backoff.String())
			time.Sleep(backoff)
			continue
		}

		buf, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			err = err
			log.Printf("error parsing json %s. sleeping %s", err.Error(), DefaultBackoff.String())
			time.Sleep(DefaultBackoff)
			continue
		}

		return json.Unmarshal(buf, &respObject)
	}

	return errors.New(fmt.Sprintf("max retries exceeded (%d) for %s", maxRetries, url))
}

func getHIBPBreaches(account string) (*[]HIBPBreach, error) {
	var breaches []HIBPBreach
	if err := getHIBPResp(HIBPGetAccountBreachesURL, account, &breaches, MaxRetries); err != nil {
		return nil, err
	}

	sort.Slice(breaches, func(i, j int) bool {
		return breaches[i].BreachDate > breaches[j].BreachDate
	})

	return &breaches, nil
}

func getHIBPPastes(account string) (*[]HIBPPaste, error) {
	var pastes []HIBPPaste
	if err := getHIBPResp(HIBPGetAccountPastesURL, account, &pastes, MaxRetries); err != nil {
		return nil, err
	}

	sort.Slice(pastes, func(i, j int) bool {
		return pastes[i].Date.After(pastes[j].Date)
	})
	return &pastes, nil
}

func printHIBPAccountLeaks(account string) {
	breaches, err := getHIBPBreaches(account)

	if err != nil {
		fmt.Printf("error occurred: %s\n", err)
		return
	}

	pastes, err := getHIBPPastes(account)
	if err != nil {
		fmt.Printf("error occurred: %s\n", err)
		return
	}

	for _, breach := range *breaches {
		fmt.Printf("%s: %s - %s\n", breach.BreachDate, breach.Domain, breach.Title)
	}

	fmt.Println("\npastes: ")
	for _, paste := range *pastes {
		fmt.Printf("%s: %s - %s\n", paste.Date, paste.Source, paste.Title)
	}
}

func main() {
	// TODO: implement all functions
	var opts struct {
		Account      string `short:"a" long:"account" description:"account to search leaks for"`
		InFile       string `short:"i" long:"input-file" description:"input file of account to search, one account per line"`
		OutFile      string `short:"o" long:"output-file" description:"output file, defaults to stdout" required:"false"`
		OutputFormat string `short:"f" long:"format" description:"output format" default:"text" choice:"text" choice:"json"`
	}

	_, err := flags.ParseArgs(&opts, os.Args)

	if err != nil {
		return
	}

	if (opts.InFile == "") == (opts.Account == "") {
		fmt.Println("please choose either --account or --input-file")
		os.Exit(2)
	}

	printHIBPAccountLeaks(opts.Account)
}
