package main

import (
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
)

const testAccount = "troyhunt@gmail.com"

var path2resp = map[string][]byte{
	"/api/v2/breachedaccount/" + testAccount: []byte(`[{"Name":"RiverCityMedia","Title":"River City Media Spam List","Domain":"rivercitymediaonline.com","BreachDate":"2017-01-01","AddedDate":"2017-03-08T23:49:53Z","ModifiedDate":"2017-03-08T23:49:53Z","PwnCount":393430309,"Description":"In January 2017, \u003ca href=\"https://mackeeper.com/blog/post/339-spammergate-the-fall-of-an-empire\" target=\"_blank\" rel=\"noopener\"\u003ea massive trove of data from River City Media was found exposed online\u003c/a\u003e. The data was found to contain almost 1.4 billion records including email and IP addresses, names and physical addresses, all of which was used as part of an enormous spam operation. Once de-duplicated, there were 393 million unique email addresses within the exposed data.","DataClasses":["Email addresses","IP addresses","Names","Physical addresses"],"IsVerified":true,"IsFabricated":false,"IsSensitive":false,"IsRetired":false,"IsSpamList":true,"LogoPath":"https://haveibeenpwned.com/Content/Images/PwnedLogos/Email.png"},{"Name":"ModernBusinessSolutions","Title":"Modern Business Solutions","Domain":"modbsolutions.com","BreachDate":"2016-10-08","AddedDate":"2016-10-12T09:09:11Z","ModifiedDate":"2016-10-12T09:09:11Z","PwnCount":58843488,"Description":"In October 2016, a large Mongo DB file containing tens of millions of accounts \u003ca href=\"https://twitter.com/0x2Taylor/status/784544208879292417\" target=\"_blank\" rel=\"noopener\"\u003ewas shared publicly on Twitter\u003c/a\u003e (the file has since been removed). The database contained over 58M unique email addresses along with IP addresses, names, home addresses, genders, job titles, dates of birth and phone numbers. The data was subsequently \u003ca href=\"http://news.softpedia.com/news/hacker-steals-58-million-user-records-from-data-storage-provider-509190.shtml\" target=\"_blank\" rel=\"noopener\"\u003eattributed to \u0026quot;Modern Business Solutions\u0026quot;\u003c/a\u003e, a company that provides data storage and database hosting solutions. They've yet to acknowledge the incident or explain how they came to be in possession of the data.","DataClasses":["Dates of birth","Email addresses","Genders","IP addresses","Job titles","Names","Phone numbers","Physical addresses"],"IsVerified":true,"IsFabricated":false,"IsSensitive":false,"IsRetired":false,"IsSpamList":false,"LogoPath":"https://haveibeenpwned.com/Content/Images/PwnedLogos/ModernBusinessSolutions.png"}]`),
	"/api/v2/pasteaccount/" + testAccount:    []byte(`[]`),
}

func NewTestServer(t *testing.T) *httptest.Server {
	// Starts a local HTTP server
	return httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		// Test request parameters
		url := req.URL.String()
		resp, ok := path2resp[url]
		if ok {
			// Send response to be tested
			rw.Write(resp)
		} else {
			t.Fatalf("requested invalid path: %s", url)
		}
	}))
}

func TestMain(m *testing.M) {
	logger = log.New(os.Stderr, "", log.Ltime|log.Lshortfile)
	retCode := m.Run()
	logger = nil
	os.Exit(retCode)
}

func TestHIBPClient_GetHIBPBreaches(t *testing.T) {
	server := NewTestServer(t)
	defer server.Close()

	api := HIBPClient{
		Client:       &http.Client{Timeout: DefaultHTTPTimeout},
		MaxRetries:   0,
		RequestDelay: 0,
		baseURL:      server.URL,
		nextSleep:    0,
	}
	breaches, pastes, err := api.GetHIBPLeaks(testAccount)

	if err != nil {
		t.Fatalf("error handling request: %s", err.Error())
	}

	if len(breaches) != 2 {
		t.Fatalf("expected 2 breaches got %d", len(breaches))
	}

	if breaches[0].Name != "RiverCityMedia" || breaches[1].Name != "ModernBusinessSolutions" {
		t.Fatalf("got invalid breach names")
	}

	if len(pastes) != 0 {
		t.Fatalf("expected zero pastes got %d", len(pastes))
	}
}
