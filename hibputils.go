package main

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
