package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"github.com/jessevdk/go-flags"
	"io"
	"log"
	"os"
	"strings"
	"time"
)

/*
  TODO: logs (color)
  TODO: nicer formatting (color / emoji)
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

func jsonHIBPAccountLeaksFormatter(account string, breaches []HIBPBreach, pastes []HIBPPaste) ([]byte, error) {
	leaksMap := map[string]interface{}{"account": account, "breaches": breaches, "pastes": pastes}

	leaksJSON, err := json.Marshal(&leaksMap)
	if err != nil {
		return []byte(""), err
	}

	leaksJSON = append(leaksJSON, byte('\n'))
	return leaksJSON, nil
}

func getHIBPAccountsLeaks(fin io.Reader, fout io.Writer, detailedOutput bool, requestDelay time.Duration) error {
	reader := bufio.NewReader(fin)
	HIBPClient := NewHIBPClient()
	HIBPClient.RequestDelay = requestDelay

	for {
		line, err := reader.ReadString('\n')

		if err == io.EOF {
			return nil
		}
		if err != nil {
			return err
		}

		account := strings.TrimSpace(line)

		// skip empty lines
		if account == "" {
			continue
		}

		// get leaks for current account
		breaches, pastes, err := HIBPClient.GetHIBPLeaks(account)
		if err != nil {
			return err
		}

		// print results to stdout
		msg, err := hibpAccountLeaksFormatter(account, breaches, pastes)
		if err != nil {
			return err
		}
		fmt.Println(msg)

		// if output file - print results to json-lines file
		if !detailedOutput {
			continue
		}

		jsonmsg, err := jsonHIBPAccountLeaksFormatter(account, breaches, pastes)
		if err != nil {
			return err
		}

		_, err = fout.Write(jsonmsg)
		if err != nil {
			return err
		}
	}
}

// TODO: -f filename -o output.jsonl -q -d 5 -a <account>
type options struct {
	Account      string        `short:"a" long:"account" description:"account to search leaks for"`
	InFile       string        `short:"f" long:"filename" description:"input filename of account to search, one account per line"`
	OutFile      string        `short:"o" long:"output" description:"output filename for detailed json-lines response" required:"false"`
	RequestDelay time.Duration `short:"d" long:"request-delay" description:"request delay between each api call, default 10s" required:"false"`
	//Quiet        bool          `short:"q" long:"quiet" description:"disable all log messages and only print leaks info"`
}

func parseArgs(args []string) options {
	var opts options

	_, err := flags.ParseArgs(&opts, args)

	if err != nil {
		os.Exit(2)
	}

	if (opts.InFile == "") == (opts.Account == "") {
		fmt.Println("please choose either --account or --filename")
		os.Exit(2)
	}

	if opts.RequestDelay == 0 {
		opts.RequestDelay = DefaultRequestDelay
	}
	return opts
}

func printHIBPLeaks(opts options) {
	var fin io.Reader
	if opts.InFile != "" {
		fin, err := os.Open(opts.InFile)

		if err != nil {
			logger.Fatalf("cannot read file %s: %s", opts.InFile, err.Error())
		}
		defer fin.Close()
	} else {
		fin = bytes.NewReader(append([]byte(opts.Account), byte('\n')))
	}

	var fout *bufio.Writer = nil
	if opts.OutFile != "" {
		logger.Printf("writing detailed responses to %s", opts.OutFile)
		output, err := os.Create(opts.OutFile)
		if err != nil {
			logger.Fatalf("cannot write to file %s: %s", opts.OutFile, err.Error())
		}
		fout = bufio.NewWriter(output)
		defer output.Close()
		defer fout.Flush()
	}
	detailedOutput := fout != nil

	getHIBPAccountsLeaks(fin, fout, detailedOutput, opts.RequestDelay)
}

func main() {
	logger = log.New(os.Stderr, "", log.Ltime|log.Lshortfile)
	opts := parseArgs(os.Args)
	printHIBPLeaks(opts)
}
