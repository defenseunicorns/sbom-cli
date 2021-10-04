package sbom

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/spdx/tools-golang/spdx"
	"github.com/spdx/tools-golang/spdxlib"
	"github.com/spdx/tools-golang/tvloader"
	"github.com/spdx/tools-golang/tvsaver"

	"github.com/defenseunicorns/spdx-cli/pkg/syft"

	// "github.com/CycloneDX/cyclonedx-go"
	"github.com/CycloneDX/cyclonedx-go"
)

func ReadSPDX(filename string) (*spdx.Document2_2, error) {
	// open the SPDX file
	r, err := os.Open(filename)
	if err != nil {
		fmt.Printf("Error while opening %v for reading: %v", filename, err)
		return nil, err
	}
	defer r.Close()

	// try to load the SPDX file's contents as a tag-value file, version 2.2
	doc, err := tvloader.Load2_2(r)
	if err != nil {
		fmt.Printf("Error while parsing %v: %v", filename, err)
		return nil, err
	}

	// if we got here, the file is now loaded into memory.
	fmt.Printf("Successfully loaded %s\n\n", filename)

	// we can now take a look at its contents via the various data
	// structures representing the SPDX document's sections.

	// print the struct containing the SPDX file's Creation Info section data
	fmt.Printf("==============\n")
	fmt.Printf("Creation info:\n")
	fmt.Printf("==============\n")
	fmt.Printf("%#v\n\n", doc.CreationInfo)

	// check whether the SPDX file has at least one package that it describes
	pkgIDs, err := spdxlib.GetDescribedPackageIDs2_2(doc)
	if err != nil {
		fmt.Printf("Unable to get describe packages from SPDX document: %v\n", err)
		return nil, err
	}

	// it does, so we'll go through each one
	for _, pkgID := range pkgIDs {
		pkg, ok := doc.Packages[pkgID]
		if !ok {
			fmt.Printf("Package %s has described relationship but ID not found\n", string(pkgID))
			continue
		}

		// check whether the package had its files analyzed
		if !pkg.FilesAnalyzed {
			fmt.Printf("Package %s (%s) had FilesAnalyzed: false\n", string(pkgID), pkg.PackageName)
			continue
		}

		// also check whether the package has any files present
		if pkg.Files == nil || len(pkg.Files) < 1 {
			fmt.Printf("Package %s (%s) has no Files\n", string(pkgID), pkg.PackageName)
			continue
		}

		// if we got here, there's at least one file
		// print the filename and license info for the first 50
		fmt.Printf("============================\n")
		fmt.Printf("Package %s (%s)\n", string(pkgID), pkg.PackageName)
		fmt.Printf("File info (up to first 50):\n")
		i := 1
		for _, f := range pkg.Files {
			// note that these will be in random order, since we're pulling
			// from a map. if we care about order, we should first pull the
			// IDs into a slice, sort it, and then print the ordered files.
			fmt.Printf("- File %d: %s\n", i, f.FileName)
			fmt.Printf("    License from file: %v\n", f.LicenseInfoInFile)
			fmt.Printf("    License concluded: %v\n", f.LicenseConcluded)
			i++
			if i > 50 {
				break
			}
		}
	}

	return doc, err
}

func WriteSPDX(filename string, doc *spdx.Document2_2) error {
	r, err := os.OpenFile(filename, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		fmt.Printf("Error while opening %v for writing: %v", filename, err)
		return err
	}
	defer r.Close()

	return tvsaver.Save2_2(doc, r)
}

func ImageToPackage(image string) *spdx.Package2_2 {
	parts := strings.Split(image, ":")
	id := fmt.Sprintf("image-%v", image)
	return &spdx.Package2_2{

		// NOT PART OF SPEC
		// flag: does this "package" contain files that were in fact "unpackaged",
		// e.g. included directly in the Document without being in a Package?
		IsUnpackaged: false,

		// 3.1: Package Name
		// Cardinality: mandatory, one
		PackageName: parts[0],

		// 3.2: Package SPDX Identifier: "SPDXRef-[idstring]"
		// Cardinality: mandatory, one
		PackageSPDXIdentifier: spdx.ElementID(id),

		// 3.3: Package Version
		// Cardinality: optional, one
		PackageVersion: parts[1],

		// 3.4: Package File Name
		// Cardinality: optional, one
		PackageFileName: "",

		// 3.5: Package Supplier: may have single result for either Person or Organization,
		//                        or NOASSERTION
		// Cardinality: optional, one
		PackageSupplierPerson:       "",
		PackageSupplierOrganization: "",
		PackageSupplierNOASSERTION:  false,

		// 3.6: Package Originator: may have single result for either Person or Organization,
		//                          or NOASSERTION
		// Cardinality: optional, one
		PackageOriginatorPerson:       "",
		PackageOriginatorOrganization: "",
		PackageOriginatorNOASSERTION:  false,

		// 3.7: Package Download Location
		// Cardinality: mandatory, one
		// NONE if there is no download location whatsoever.
		// NOASSERTION if:
		//   (i) the SPDX file creator has attempted to but cannot reach a reasonable objective determination;
		//   (ii) the SPDX file creator has made no attempt to determine this field; or
		//   (iii) the SPDX file creator has intentionally provided no information (no meaning should be implied by doing so).
		PackageDownloadLocation: "NOASSERTION",

		// 3.8: FilesAnalyzed
		// Cardinality: optional, one; default value is "true" if omitted

		// Purpose: Indicates whether the file content of this package has been available for or subjected to
		// analysis when creating the SPDX document. If false, indicates packages that represent metadata or
		// URI references to a project, product, artifact, distribution or a component. If false, the package
		// must not contain any files.

		// Intent: A package can refer to a project, product, artifact, distribution or a component that is
		// external to the SPDX document.
		FilesAnalyzed: false,
		// NOT PART OF SPEC: did FilesAnalyzed tag appear?
		IsFilesAnalyzedTagPresent: true,

		// 3.9: Package Verification Code
		// Cardinality: mandatory, one if filesAnalyzed is true / omitted;
		//              zero (must be omitted) if filesAnalyzed is false
		PackageVerificationCode: "",
		// Spec also allows specifying a single file to exclude from the
		// verification code algorithm; intended to enable exclusion of
		// the SPDX document file itself.
		PackageVerificationCodeExcludedFile: "",

		// 3.10: Package Checksum: may have keys for SHA1, SHA256 and/or MD5
		// Cardinality: optional, one or many

		// 3.10.1 Purpose: Provide an independently reproducible mechanism that permits unique identification of
		// a specific package that correlates to the data in this SPDX file. This identifier enables a recipient
		// to determine if any file in the original package has been changed. If the SPDX file is to be included
		// in a package, this value should not be calculated. The SHA-1 algorithm will be used to provide the
		// checksum by default.

		// 3.11: Package Home Page
		// Cardinality: optional, one
		PackageHomePage: "",

		// 3.12: Source Information
		// Cardinality: optional, one
		PackageSourceInfo: "",

		// 3.13: Concluded License: SPDX License Expression, "NONE" or "NOASSERTION"
		// Cardinality: mandatory, one
		// Purpose: Contain the license the SPDX file creator has concluded as governing the
		// package or alternative values, if the governing license cannot be determined.
		PackageLicenseConcluded: "NOASSERTION",

		// 3.14: All Licenses Info from Files: SPDX License Expression, "NONE" or "NOASSERTION"
		// Cardinality: mandatory, one or many if filesAnalyzed is true / omitted;
		//              zero (must be omitted) if filesAnalyzed is false
		PackageLicenseInfoFromFiles: nil,

		// 3.15: Declared License: SPDX License Expression, "NONE" or "NOASSERTION"
		// Cardinality: mandatory, one
		// Purpose: List the licenses that have been declared by the authors of the package.
		// Any license information that does not originate from the package authors, e.g. license
		// information from a third party repository, should not be included in this field.
		PackageLicenseDeclared: "NOASSERTION",

		// 3.16: Comments on License
		// Cardinality: optional, one
		PackageLicenseComments: "",

		// 3.17: Copyright Text: copyright notice(s) text, "NONE" or "NOASSERTION"
		// Cardinality: mandatory, one
		// Purpose: Identify the copyright holders of the package, as well as any dates present. This will be a free form text field extracted from package information files. The options to populate this field are limited to:
		//
		// Any text related to a copyright notice, even if not complete;
		// NONE if the package contains no copyright information whatsoever; or
		// NOASSERTION, if
		//   (i) the SPDX document creator has made no attempt to determine this field; or
		//   (ii) the SPDX document creator has intentionally provided no information (no meaning should be implied by doing so).
		//
		PackageCopyrightText: "NOASSERTION",

		// 3.18: Package Summary Description
		// Cardinality: optional, one
		PackageSummary: "",

		// 3.19: Package Detailed Description
		// Cardinality: optional, one
		PackageDescription: "",

		// 3.20: Package Comment
		// Cardinality: optional, one
		PackageComment: "",

		// 3.21: Package External Reference
		// Cardinality: optional, one or many
		// PackageExternalReferences: formatSPDXExternalRefs(p),

		// 3.22: Package External Reference Comment
		// Cardinality: conditional (optional, one) for each External Reference
		// contained within PackageExternalReference2_1 struct, if present

		// 3.23: Package Attribution Text
		// Cardinality: optional, one or many
		PackageAttributionTexts: nil,

		// Files contained in this Package
		Files: nil,
	}
}

func ToCycloneDX(spdxBom *spdx.Document2_2) *cyclonedx.BOM {
	cyclone := &cyclonedx.BOM{
		// BOMFormat: "",
		XMLNS: "http://cyclonedx.org/schema/bom/1.2",
	}
	components := make([]cyclonedx.Component, 0)
	// cyclone.Version = spdxBom.CreationInfo.P
	cyclone.Metadata = &cyclonedx.Metadata{
		Timestamp: spdxBom.CreationInfo.Created, //
		Component: &cyclonedx.Component{
			Name: spdxBom.CreationInfo.DocumentName,
			// Version:

		},
	}
	for _, pack := range spdxBom.Packages {
		components = append(components, SPDXPackageToCycloneComponent(pack))
	}
	cyclone.Components = &components

	return cyclone
}

func SPDXPackageToCycloneComponent(p *spdx.Package2_2) cyclonedx.Component {
	fmt.Printf("Converting SPDX Package %v to Component\n", p.PackageName)

	component := cyclonedx.Component{
		Name:    p.PackageName,
		Version: p.PackageVersion,
		//TODO @runyontr see how we pull this out
		Type: "container",
		// CPE: p. SPDX has multiple CPEs... What do we do here?
		// PackageURL: p.PURL,
		// PackageURL: p.

	}

	//look for image
	if strings.Contains(string(p.PackageSPDXIdentifier), "-image-") { //how we made them from the helm chart
		component.Type = cyclonedx.ComponentTypeContainer
	}
	if strings.Contains(string(p.PackageSPDXIdentifier), "cpe-") {
		component.Type = cyclonedx.ComponentTypeApplication
	}

	b, _ := json.MarshalIndent(p, "", "\t")
	fmt.Println(string(b))
	refs := p.PackageExternalReferences
	for _, ext := range refs {
		b, _ = json.MarshalIndent(ext, "", "\t")
		fmt.Println(string(b))
		if ext.RefType == string(syft.Cpe23ExternalRefType) || ext.RefType == string(syft.Cpe22ExternalRefType) {
			component.CPE = ext.Locator // take the last one or something for now
			// component.CPEs = append(components.CPEs, SPDXPackageExternalReferenceToCycloneDXPackageExternalReference())
		}
		if ext.RefType == string(syft.PurlExternalRefType) {
			component.PackageURL = ext.Locator
		}
	}
	return component
}

// func SPDXPackageExternalReferenceToCycloneDXPackageExternalReference(ext *spdx.PackageExternalReference2_2) cyclonedx.ExternalReference {

// 	ret := cyclonedx.ExternalReference{

// 	}
// 	//if CPE
// 	if ext.CPe{
// 		ReferenceCategory: SecurityReferenceCategory,
// 		ret.ReferenceType: Cpe23ExternalRefType,
// 		ReferenceLocator: ext.ExternalRefComment,
// 	}
// }
