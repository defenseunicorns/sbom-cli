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

	"github.com/CycloneDX/cyclonedx-go"
	"github.com/defenseunicorns/spdx-cli/pkg/sbom"
	"github.com/spf13/cobra"
)

// addAsDependencyCmd represents the addAsDependency command
var addAsDependencyCmd = &cobra.Command{
	Use:   "addAsDependency",
	Short: "Adds the bom to the chart.  Currently only supporting cyclonedx",
	Long: `Command to be used to add a bill of materials to a larger bill of material.   
	 Useful for adding image SBOMs to a Helm Chart BOM, or Helm Chart BOMs to other Helm BOMs`,
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println("addAsDependency called")

		// if input is empty, create an empty BOM
		inputFilename, _ := cmd.Flags().GetString("input")
		rootBom, err := sbom.ReadCycloneDX(inputFilename)
		if err != nil {
			panic(err)
		}

		// read the bom @bom.
		bomFilename, _ := cmd.Flags().GetString("bom")
		leafBom, err := sbom.ReadCycloneDX(bomFilename)
		if err != nil {
			panic(err)
		}
		var comp []cyclonedx.Component
		if rootBom.Components == nil {
			comp = make([]cyclonedx.Component, 0)
		} else {
			comp = *rootBom.Components
		}
		// Add the component in the leafBom's metadata as a component
		comp = append(comp, *leafBom.Metadata.Component)
		// Add each component in the leaf bom as a component
		for _, c := range *leafBom.Components {
			comp = append(comp, c)
		}
		rootBom.Components = &comp

		rootDeps := *rootBom.Dependencies

		// add the objects of Bom as components
		for i, dep := range rootDeps {
			//find the dependncy for the root and add the leaf as a dependency
			if dep.Ref == rootBom.Metadata.Component.BOMRef {
				var tmp []cyclonedx.Dependency
				if dep.Dependencies == nil {
					tmp = make([]cyclonedx.Dependency, 0)
				} else {
					tmp = *dep.Dependencies
				}
				tmp = append(tmp, cyclonedx.Dependency{
					Ref: leafBom.Metadata.Component.BOMRef,
				})
				rootDeps[i].Dependencies = &tmp

			}
		}
		// add the dependency object of the BOM as a depdnency of the top level

		rootDeps = append(rootDeps, cyclonedx.Dependency{
			Ref:          leafBom.Metadata.Component.BOMRef,
			Dependencies: leafBom.Dependencies,
		})
		rootBom.Dependencies = &rootDeps

		outFilename, _ := cmd.Flags().GetString("output")
		if outFilename != "" {
			sbom.WriteCycloneDX(outFilename, rootBom)
		} else {
			b, _ := json.MarshalIndent(rootBom, "", "\t")
			fmt.Printf("%v\n", string(b))
		}
	},
}

func init() {
	rootCmd.AddCommand(addAsDependencyCmd)

	// Here you will define your flags and configuration settings.

	// Cobra supports Persistent Flags which will work for this command
	// and all subcommands, e.g.:
	// addAsDependencyCmd.PersistentFlags().String("foo", "", "A help for foo")

	// Cobra supports local flags which will only run when this command
	// is called directly, e.g.:
	addAsDependencyCmd.Flags().String("bom", "", "Bill of Materials to add")
	addAsDependencyCmd.Flags().String("name", "", "Name of component")
	addAsDependencyCmd.Flags().String("input", "", "input file to load BOM from")
	addAsDependencyCmd.Flags().String("output", "", "output file to write new BOM")
	addAsDependencyCmd.Flags().Bool("overwrite", false, "Should the output file be overwritten?")
}
