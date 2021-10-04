package sbom

import (
	"fmt"
	"os"

	cyclonedx "github.com/CycloneDX/cyclonedx-go"
)

func ReadCycloneDX(filename string) (*cyclonedx.BOM, error) {
	r, err := os.Open(filename)
	if err != nil {
		fmt.Printf("Error while opening %v for reading: %v", filename, err)
		return nil, err
	}
	defer r.Close()

	bom := &cyclonedx.BOM{}
	bomDecoder := cyclonedx.NewBOMDecoder(r, cyclonedx.BOMFileFormatXML)
	err = bomDecoder.Decode(bom)
	if err != nil {
		return bom, err
	}
	return bom, err
}

func WriteCycloneDX(filename string, bom *cyclonedx.BOM) error {
	r, err := os.OpenFile(filename, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		fmt.Printf("Error while opening %v for writing: %v", filename, err)
		return err
	}
	defer r.Close()

	encoder := cyclonedx.NewBOMEncoder(r, cyclonedx.BOMFileFormatXML)
	return encoder.Encode(bom)

}

func MergeCycloneDX(boms []*cyclonedx.BOM, name string) (*cyclonedx.BOM, error) {
	meta := &cyclonedx.Metadata{
		Component: &cyclonedx.Component{
			Name: name,
		},
		// Tools:     "sbom-cli",
	}
	merged := cyclonedx.NewBOM()
	merged.Metadata = meta

	mComponents := make([]cyclonedx.Component, 0)

	for _, bom := range boms {
		for _, c := range *bom.Components {
			if !present(mComponents, c) {
				fmt.Printf("Adding new component: %v\n", c.Name)
				mComponents = append(mComponents, c)
			}
		}
	}

	merged.Components = &mComponents

	//deduplicate?

	//
	return merged, nil
}

func present(current []cyclonedx.Component, new cyclonedx.Component) bool {
	for _, c := range current {

		if c.PackageURL != "" && new.PackageURL != "" && c.PackageURL == new.PackageURL {
			return true
		}

		if c.CPE != "" && new.CPE != "" && c.CPE == new.CPE {
			return true
		}
	}

	return false
}
