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

// returns unique copy of s with duplicate values removed keeping the original slice order
func uniq(s []string) []string {
	uniqueItems := make(map[string]bool)
	var keys []string

	for _, item := range s {
		if _, ok := uniqueItems[item]; !ok {
			keys = append(keys, item)
			uniqueItems[item] = true
		}
	}
	return keys
}
