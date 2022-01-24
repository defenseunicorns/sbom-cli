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
	"strings"
	"time"

	"github.com/CycloneDX/cyclonedx-go"
	"github.com/defenseunicorns/spdx-cli/pkg/helm"
	"github.com/defenseunicorns/spdx-cli/pkg/sbom"
	"github.com/defenseunicorns/spdx-cli/pkg/syft"

	"github.com/spdx/tools-golang/spdx"
	"github.com/spf13/cobra"
)

// createCmd represents the create command
var createCmd = &cobra.Command{
	Use:   "create",
	Short: "A brief description of your command",
	Long: `A longer description that spans multiple lines and likely contains examples
and usage of using your command. For example:

Cobra is a CLI library for Go that empowers applications.
This application is a tool to generate the needed files
to quickly create a Cobra application.`,
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println("create called")

		p, _ := cmd.Flags().GetString("path")
		fmt.Printf("Helm chart at path %v\n", p)
		chart, err := helm.Read(p)
		if err != nil {
			panic(err)
		}

		imageList := helm.Images(chart)
		imageMap := make(map[string]*spdx.Document2_2)
		chartBom := spdx.Document2_2{
			CreationInfo: &spdx.CreationInfo2_2{
				// 2.1: SPDX Version; should be in the format "SPDX-2.2"
				// Cardinality: mandatory, one
				SPDXVersion: "SPDX-2.2",

				// 2.2: Data License; should be "CC0-1.0"
				// Cardinality: mandatory, one
				DataLicense: "CC0-1.0",

				// 2.3: SPDX Identifier; should be "DOCUMENT" to represent mandatory identifier of SPDXRef-DOCUMENT
				// Cardinality: mandatory, one
				SPDXIdentifier: spdx.ElementID("DOCUMENT"),

				// 2.4: Document Name
				// Cardinality: mandatory, one
				DocumentName: chart.Metadata.Name,

				// 2.5: Document Namespace
				// Cardinality: mandatory, one
				// Purpose: Provide an SPDX document specific namespace as a unique absolute Uniform Resource
				// Identifier (URI) as specified in RFC-3986, with the exception of the ‘#’ delimiter. The SPDX
				// Document URI cannot contain a URI "part" (e.g. the "#" character), since the ‘#’ is used in SPDX
				// element URIs (packages, files, snippets, etc) to separate the document namespace from the
				// element’s SPDX identifier. Additionally, a scheme (e.g. “https:”) is required.

				// The URI must be unique for the SPDX document including the specific version of the SPDX document.
				// If the SPDX document is updated, thereby creating a new version, a new URI for the updated
				// document must be used. There can only be one URI for an SPDX document and only one SPDX document
				// for a given URI.

				// Note that the URI does not have to be accessible. It is only intended to provide a unique ID.
				// In many cases, the URI will point to a web accessible document, but this should not be assumed
				// to be the case.

				DocumentNamespace: fmt.Sprintf("https://bigbang.dev/chart/%s", chart.Metadata.Name),

				// 2.6: External Document References
				// Cardinality: optional, one or many
				ExternalDocumentReferences: nil,

				// 2.7: License List Version
				// Cardinality: optional, one
				// LicenseListVersion: spdxlicense.Version,

				// 2.8: Creators: may have multiple keys for Person, Organization
				//      and/or Tool
				// Cardinality: mandatory, one or many
				CreatorPersons:       nil,
				CreatorOrganizations: []string{"Defenuse Unicorns"},
				CreatorTools:         []string{"sbom-cli"},

				// 2.9: Created: data format YYYY-MM-DDThh:mm:ssZ
				// Cardinality: mandatory, one
				Created: time.Now().UTC().Format(time.RFC3339),

				// 2.10: Creator Comment
				// Cardinality: optional, one
				CreatorComment: "",

				// 2.11: Document Comment
				// Cardinality: optional, one
				DocumentComment: "",
			},
			Packages: make(map[spdx.ElementID]*spdx.Package2_2),
		}
		for _, image := range imageList {
			fmt.Printf("Found an image: %v\n", image)
			doc, err := syft.Scan(image)
			if err != nil {
				panic(err)
			}
			imageMap[image] = doc
			//add entry for the image
			chartBom.Packages[spdx.ElementID(fmt.Sprintf("image-%v", image))] = sbom.ImageToPackage(doc.CreationInfo.DocumentName)
			// Add all the packages from the image too
			fmt.Printf("The image %v has %v packages inside of it\n", image, len(doc.Packages))
			for k, v := range doc.Packages {
				chartBom.Packages[k] = v
			}
		}
		// Add CPEs:

		for _, cpe := range helm.CPEs(chart) {
			ext := spdx.PackageExternalReference2_2{
				RefType: string(syft.Cpe23ExternalRefType),
				Locator: cpe,
			}
			parts := strings.Split(cpe, ":")
			ar := []*spdx.PackageExternalReference2_2{&ext}
			chartBom.Packages[spdx.ElementID(fmt.Sprintf("cpe-%v", cpe))] = &spdx.Package2_2{
				PackageName:               parts[3],
				PackageSPDXIdentifier:     spdx.ElementID(fmt.Sprintf("cpe-%v", cpe)),
				PackageExternalReferences: ar,
			}
		}

		file, err := cmd.Flags().GetString("output-file")
		if err != nil {
			panic(err)
		}
		if file != "" {
			//check  output format
			format, _ := cmd.Flags().GetString("output-format")
			if format == "cyclonedx" {
				cycloneBom := sbom.ToCycloneDX(&chartBom)
				cycloneBom.Metadata.Component = &cyclonedx.Component{
					Name:    chart.Metadata.Name,
					Version: chart.Metadata.Version,
					//Authors, etc
					BOMRef: chart.Metadata.Name,
				}

				// chartDependency.Dependencies = &tmpDep
				// imageRefs := make([]cyclonedx.Dependency, len(imageList))

				// For each image in the list, make an entry that the image is a dependency of the chart
				chartDependency := cyclonedx.Dependency{
					Ref: chart.Metadata.Name,
				}
				imagesInChart := make([]cyclonedx.Dependency, 0)
				for _, image := range imageList {
					// imageRefs[i].Ref = image
					imagesInChart = append(imagesInChart, cyclonedx.Dependency{
						Ref: fmt.Sprintf("image-%v", image), //matches the ElementID for spdx
					})
				}
				chartDependency.Dependencies = &imagesInChart

				//Add the images as a dependency of the chart
				cycloneBom.Dependencies = &[]cyclonedx.Dependency{chartDependency}

				// For each image in the list, make a list of dependencies of the image.
				for image, doc := range imageMap {
					imageDep := cyclonedx.Dependency{
						Ref: fmt.Sprintf("image-%v", image), //matches the ElementID for spdx
					}
					packageRefs := make([]cyclonedx.Dependency, 0)
					//add this image as a dependency of the package
					//Adding dependencies for image
					for k := range doc.Packages {
						tmp := append(packageRefs, cyclonedx.Dependency{
							Ref: string(k),
						})
						packageRefs = tmp
					}
					imageDep.Dependencies = &packageRefs
					tmp := append(*cycloneBom.Dependencies, imageDep)
					cycloneBom.Dependencies = &tmp
				}

				sbom.WriteCycloneDX(file, cycloneBom)
			} else {
				sbom.WriteSPDX(file, &chartBom)
			}
			//
		} else { //stdout
			b, _ := json.MarshalIndent(chartBom, "", "\t")
			fmt.Printf("%v\n", string(b))
		}
	},
}

func init() {
	rootCmd.AddCommand(createCmd)

	// Here you will define your flags and configuration settings.

	// Cobra supports Persistent Flags which will work for this command
	// and all subcommands, e.g.:
	createCmd.Flags().String("path", "", "for the chart")
	createCmd.Flags().String("output-file", "", "output file for merged content")
	createCmd.Flags().String("output-format", "spdx", "output file format, spdx or cyclonedx")

	// Cobra supports local flags which will only run when this command
	// is called directly, e.g.:
	// createCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")
}
