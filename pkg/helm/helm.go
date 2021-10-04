package helm

import (
	"bufio"
	"fmt"
	"strings"

	"helm.sh/helm/v3/pkg/chart"
	"helm.sh/helm/v3/pkg/chart/loader"
)

const imagesKey = "bigbang.dev/images"
const cpeKey = "bigbang.dev/cpe"

func Read(path string) (*chart.Chart, error) {
	chart, err := loader.LoadDir(path)
	if err != nil {
		return chart, nil
	}

	fmt.Printf("Loaded chart %v\n", chart.Metadata.Name)
	fmt.Printf("Annotations: \n")
	for k, v := range chart.Metadata.Annotations {
		fmt.Printf("%v -> %v\n", k, v)
	}
	return chart, nil
}

func CPEs(chart *chart.Chart) []string {
	list := chart.Metadata.Annotations[cpeKey]

	cpes := make([]string, 0)
	scanner := bufio.NewScanner(strings.NewReader(list))
	for scanner.Scan() {
		parts := strings.Split(scanner.Text(), ":")
		if len(parts) < 3 {
			continue
		}
		if strings.Contains(parts[0], "cpe") {
			cpes = append(cpes, strings.Join(parts[1:], ":"))
		}

	}
	return cpes
}

func Images(chart *chart.Chart) []string {
	list := chart.Metadata.Annotations[imagesKey]

	images := make([]string, 0)
	scanner := bufio.NewScanner(strings.NewReader(list))
	for scanner.Scan() {
		parts := strings.Split(scanner.Text(), ":")
		if len(parts) < 3 {
			continue
		}
		if strings.Contains(parts[0], "image") {
			images = append(images, strings.Trim(parts[1], " ")+":"+parts[2])
		}

	}

	return images
}
