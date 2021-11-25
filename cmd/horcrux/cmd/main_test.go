package cmd

import (
	"os"
	"testing"

	"github.com/mitchellh/go-homedir"
)

func TestMain(m *testing.M) {
	// Disable caching mechanism from go-homedir for all "cmd" package tests.
	homedir.DisableCache = true
	code := m.Run()
	homedir.DisableCache = false
	os.Exit(code)
}
