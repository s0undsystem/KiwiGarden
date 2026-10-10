// Package ui embeds the built front end. Run `npm run build` in web/ (or
// `make ui`) to populate dist/ before building the binary.
package ui

import (
	"embed"
	"io/fs"
)

//go:embed all:dist
var dist embed.FS

// FS returns the built assets rooted at dist/, or nil if the UI has not
// been built (only the placeholder is present).
func FS() fs.FS {
	sub, err := fs.Sub(dist, "dist")
	if err != nil {
		return nil
	}
	if _, err := fs.Stat(sub, "index.html"); err != nil {
		return nil
	}
	return sub
}
