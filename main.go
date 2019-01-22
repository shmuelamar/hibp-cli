package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"github.com/jessevdk/go-flags"
	"io"
	"log"
	"os"
	"strings"
)

/*
  TODO: logs (color)
  TODO: nicer formatting (color / emoji)
  TODO: single account
*/

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

func getHIBPAccountsLeaks(fp io.Reader, outputFn outputFunc) error {
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

// TODO: -f filename -o output.jsonl -q -d 5 <account>
type options struct {
	Account string `short:"a" long:"account" description:"account to search leaks for"`
	InFile  string `short:"f" long:"filename" description:"input filename of account to search, one account per line"`
	//OutFile      string `short:"o" long:"output-file" description:"output file, defaults to stdout" required:"false"`
	OutputFormat string `long:"format" description:"output format, one of text or jsonl (json lines)" default:"text" choice:"text" choice:"jsonl"`
}

func parseArgs(args []string) options {
	var opts options

	_, err := flags.ParseArgs(&opts, args)

	if err != nil {
		os.Exit(2)
	}

	if (opts.InFile == "") == (opts.Account == "") {
		logger.Println("please choose either --account or --filename")
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
