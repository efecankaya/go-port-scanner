package techfinder

import (
	"fmt"

	"github.com/efecankaya/go-port-scanner/internal/utils"
)

func HttpAnalyze(http_response_body string, http_response_header string) []string {
	//Analyze http/https response
	var tags = []string{"link", "script", "meta"}
	html_tag_extract, err := utils.ExtractTags(http_response_body, tags)
	if err != nil {
		fmt.Println("Error: ", err)
	}

	return html_tag_extract
}
