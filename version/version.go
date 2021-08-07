// Package version is a convenience utility that provides horcrux
// consumers with a ready-to-use version command that
// produces versioning information based on flags
// passed at compile time.
//
// Configure the version command
//
// The version command can be just added to your cobra root command.
// At build time, the variables Name, Version, Commit, and BuildTags
// can be passed as build flags as shown in the following example:
//
//  go build -X github.com/strangelove-ventures/horcrux/version.Version=1.0 \
//   -X github.com/strangelove-ventures/horcrux/version.Commit=f0f7b7dab7e36c20b757cebce0e8f4fc5b95de60 \
//   -X github.com/strangelove-ventures/horcrux/version.SDKVersion=v0.43.9 \
//   -X github.com/strangelove-ventures/horcrux/version.TMVersion=v0.34.1
package version

import (
	"fmt"
	"runtime"
)

var (
	// application's version string
	Version = ""
	// commit
	Commit = ""
	// sdk version
	SDKVersion = ""
	// tendermint version
	TMVersion = ""
)

// Info defines the application version information.
type Info struct {
	Version           string `json:"version" yaml:"version"`
	GitCommit         string `json:"commit" yaml:"commit"`
	GoVersion         string `json:"go_version" yaml:"go_version"`
	CosmosSdkVersion  string `json:"cosmos_sdk_version" yaml:"cosmos_sdk_version"`
	TendermintVersion string `json:"tendermint_version" yaml:"tendermint_version"`
}

func NewInfo() Info {
	return Info{
		Version:           Version,
		GitCommit:         Commit,
		GoVersion:         fmt.Sprintf("%s %s/%s", runtime.Version(), runtime.GOOS, runtime.GOARCH),
		CosmosSdkVersion:  SDKVersion,
		TendermintVersion: TMVersion,
	}
}

func (vi Info) String() string {
	return fmt.Sprintf(`horcrux: %s
git commit: %s
go version: %s
tm version: %s
sdk version: %s
`,
		vi.Version, vi.GitCommit, vi.GoVersion, vi.CosmosSdkVersion, vi.TendermintVersion)
}
