package main

import "testing"

var needles = map[string]bool{"ab": true, "ad": false, "EF": false, "ef": true}

func Test_contains(t *testing.T) {
	haystack := []string{"ab", "cd", "ef"}

	for needle, found := range needles {
		if contains(haystack, needle) != found {
			t.Fatalf("expected %t but got %t", found, !found)
		}
	}
}

func Test_uniq(t *testing.T) {
	lst := []string{"ab", "ab", "cd", "ef", "cd"}
	expected := []string{"ab", "cd", "ef"}

	uniqLst := uniq(lst)
	if len(uniqLst) != len(expected) {
		t.Fatalf("unexpected length")
	}

	for i, v := range expected {
		if v != uniqLst[i] {
			t.Fatalf("expected %s got %s", v, uniqLst[i])
		}
	}
}
