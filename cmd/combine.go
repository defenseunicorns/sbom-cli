// Copyright © 2021 NAME HERE <EMAIL ADDRESS>
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package cmd

import (
	"encoding/json"
	"fmt"

	"github.com/defenseunicorns/spdx-cli/pkg/sbom"
	"github.com/spf13/cobra"

	cyclonedx "github.com/CycloneDX/cyclonedx-go"
)

// combineCmd represents the combine command
var combineCmd = &cobra.Command{
	Use:   "combine",
	Short: "A brief description of your command",
	Long: `A longer description that spans multiple lines and likely contains examples
and usage of using your command. For example:

Cobra is a CLI library for Go that empowers applications.
This application is a tool to generate the needed files
to quickly create a Cobra application.`,
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println("combine called")
		inputFiles, err := cmd.Flags().GetStringSlice("input-files")
		if err != nil {
			panic(err)
		}
		boms := make([]*cyclonedx.BOM, len(inputFiles))
		for index, i := range inputFiles {
			fmt.Printf("Input File: %v\n", i)
			format, _ := cmd.Flags().GetString("format")
			switch format {
			case "spdx":
				doc, err := sbom.ReadSPDX(i)
				if err != nil {
					panic(err)
				}
				b, _ := json.MarshalIndent(doc, "", "\t")
				fmt.Println(string(b))
			case "cyclonedx":
				bom, err := sbom.ReadCycloneDX(i)
				if err != nil {
					panic(err)
				}
				boms[index] = bom
			}
		}
		merged, _ := sbom.MergeCycloneDX(boms, "istio")
		oFile, _ := cmd.Flags().GetString("output-file")
		if oFile != "" {
			sbom.WriteCycloneDX(oFile, merged)
		} else {
			b, _ := json.MarshalIndent(merged, "", "\t")
			fmt.Println(string(b))
		}
	},
}

func init() {
	rootCmd.AddCommand(combineCmd)

	// Here you will define your flags and configuration settings.

	// Cobra supports Persistent Flags which will work for this command
	// and all subcommands, e.g.:
	combineCmd.Flags().StringSlice("input-files", []string{}, "A help for foo")
	combineCmd.Flags().String("format", "spdx", "BOM Format, spdx or cyclonedx")
	combineCmd.Flags().String("output-file", "", "output file for merged content")

	// Cobra supports local flags which will only run when this command
	// is called directly, e.g.:
	// combineCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")
}
