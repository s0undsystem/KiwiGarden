package ui

import (
	"io/fs"
	"regexp"
	"strings"
	"testing"
)

// Strings that look like URLs but are not network requests.
var allowedURLs = []string{
	"http://www.w3.org/",          // XML namespaces used by three.js
	"https://jcgt.org/published/", // citation in a three.js shader comment
}

var urlRe = regexp.MustCompile(`https?://[^\s"'` + "`" + `)<>]*`)

func TestBundleHasNoThirdPartyRequests(t *testing.T) {
	f := FS()
	if f == nil {
		t.Skip("UI not built (run make ui)")
	}
	index, err := fs.ReadFile(f, "index.html")
	if err != nil {
		t.Fatal(err)
	}
	html := string(index)
	if strings.Contains(html, "<script>") || regexp.MustCompile(`<script[^>]*>[^<]`).MatchString(html) {
		t.Error("index.html contains an inline script")
	}
	if strings.Contains(html, "http://") || strings.Contains(html, "https://") {
		t.Error("index.html references an absolute URL")
	}
	if strings.Contains(html, "onclick") || strings.Contains(html, "javascript:") {
		t.Error("index.html contains inline handlers")
	}
	err = fs.WalkDir(f, ".", func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		b, err := fs.ReadFile(f, p)
		if err != nil {
			return err
		}
		if strings.HasSuffix(p, ".bin") {
			return nil
		}
		for _, m := range urlRe.FindAllString(string(b), -1) {
			ok := false
			for _, a := range allowedURLs {
				if strings.HasPrefix(m, a) {
					ok = true
				}
			}
			if !ok {
				t.Errorf("%s references %s", p, m)
			}
		}
		if strings.HasSuffix(p, ".js") {
			for _, sink := range []string{".innerHTML", ".outerHTML", "insertAdjacentHTML", "document.write(", "eval(", "new Function("} {
				if strings.Contains(string(b), sink) {
					t.Errorf("%s uses %s", p, sink)
				}
			}
		}
		if strings.Contains(string(b), "data:image") || strings.Contains(string(b), "data:font") {
			t.Errorf("%s embeds a data: URI (CSP would block it)", p)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}
