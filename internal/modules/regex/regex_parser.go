package regex

import (
	"regexp"
)

// ExtractTags extracts certain tags from the given HTML.
func ExtractTags(html string) []string {
	// Define the regular expression pattern to match the desired tags.
	pattern := `<(meta|script)[^>]*>(.*?)<\/(meta|script)>` // Change this line to match the desired tags.

	// Compile the regular expression pattern.
	regex := regexp.MustCompile(pattern)

	// Find all matches in the HTML.
	matches := regex.FindAllStringSubmatch(html, -1)

	// Extract the matched tags.
	tags := make([]string, len(matches))
	for i, match := range matches {
		tags[i] = match[0]
	}

	return tags
}
