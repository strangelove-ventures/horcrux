/*
Copyright © 2021 NAME HERE <EMAIL ADDRESS>

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/
package cmd

import (
	"encoding/json"
	"fmt"
	"runtime"
	dbg "runtime/debug"

	"github.com/spf13/cobra"
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

func init() {
	rootCmd.AddCommand(versionCmd)
}

// Info defines the application version information.
type Info struct {
	Version           string `json:"version" yaml:"version"`
	GitCommit         string `json:"commit" yaml:"commit"`
	GoVersion         string `json:"go_version" yaml:"go_version"`
	CosmosSdkVersion  string `json:"cosmos_sdk_version" yaml:"cosmos_sdk_version"`
	TendermintVersion string `json:"tendermint_version" yaml:"tendermint_version"`
}

func NewInfo() Info {
	bi, _ := dbg.ReadBuildInfo()

	dependencyVersions := map[string]string{}

	for _, dep := range bi.Deps {
		dependencyVersions[dep.Path] = dep.Version
	}

	return Info{
		Version:           Version,
		GitCommit:         Commit,
		GoVersion:         fmt.Sprintf("%s %s/%s", runtime.Version(), runtime.GOOS, runtime.GOARCH),
		CosmosSdkVersion:  dependencyVersions["github.com/cosmos/cosmos-sdk"],
		TendermintVersion: dependencyVersions["github.com/tendermint/tendermint"],
	}
}

// versionCmd represents the version command
var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Version information for horcrux",
	RunE: func(cmd *cobra.Command, args []string) error {
		bz, err := json.MarshalIndent(NewInfo(), "", "  ")
		if err != nil {
			return err
		}
		cmd.Println(string(bz))
		return nil
	},
}
