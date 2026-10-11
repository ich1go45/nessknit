// Package nessustest builds small .nessus documents for tests and parses
// merged output back into plain values that tests can compare.
package nessustest

import (
	"encoding/xml"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// File returns a complete .nessus document. hosts are the strings
// returned by Host.
func File(policy, report string, hosts ...string) string {
	return `<?xml version="1.0" ?>
<NessusClientData_v2>
<Policy><policyName>` + policy + `</policyName></Policy>
<Report name="` + report + `" xmlns:cm="http://www.nessus.org/cm">
` + strings.Join(hosts, "") + `</Report>
</NessusClientData_v2>
`
}

// Host returns a ReportHost element. children are the strings returned
// by Props and Item, in the order they should appear.
func Host(name string, children ...string) string {
	return `<ReportHost name="` + name + `">` + "\n" + strings.Join(children, "") + "</ReportHost>\n"
}

// Props returns a HostProperties element holding tags built with Tag.
func Props(tags ...string) string {
	return "<HostProperties>\n" + strings.Join(tags, "") + "</HostProperties>\n"
}

// Tag returns one HostProperties tag.
func Tag(name, value string) string {
	return fmt.Sprintf("<tag name=\"%s\">%s</tag>\n", name, value)
}

// Item returns a ReportItem. output is written as-is, so it may contain
// entities or a CDATA section.
func Item(plugin, port, proto, severity, output string) string {
	return fmt.Sprintf("<ReportItem port=\"%s\" svc_name=\"general\" protocol=\"%s\" severity=\"%s\" pluginID=\"%s\" pluginName=\"plugin %s\" pluginFamily=\"General\">\n<description>d</description>\n<plugin_output>%s</plugin_output>\n</ReportItem>\n",
		port, proto, severity, plugin, plugin, output)
}

// Write stores content as dir/name and returns the path.
func Write(t testing.TB, dir, name, content string) string {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

// Doc is a parsed .nessus file reduced to what the merge rules govern.
type Doc struct {
	Policy     string
	ReportName string
	Hosts      []HostData
}

type HostData struct {
	Name  string
	Tags  []TagData
	Items []ItemData
}

type TagData struct{ Name, Value string }

// ItemData holds a finding's identity. Output has surrounding
// whitespace removed.
type ItemData struct{ Plugin, Port, Proto, Severity, Output string }

type xFile struct {
	XMLName xml.Name `xml:"NessusClientData_v2"`
	Policy  struct {
		Name string `xml:"policyName"`
	} `xml:"Policy"`
	Report struct {
		Name  string  `xml:"name,attr"`
		Hosts []xHost `xml:"ReportHost"`
	} `xml:"Report"`
}

type xHost struct {
	Name string `xml:"name,attr"`
	Tags []struct {
		Name  string `xml:"name,attr"`
		Value string `xml:",chardata"`
	} `xml:"HostProperties>tag"`
	Items []struct {
		Plugin   string `xml:"pluginID,attr"`
		Port     string `xml:"port,attr"`
		Proto    string `xml:"protocol,attr"`
		Severity string `xml:"severity,attr"`
		Output   string `xml:"plugin_output"`
	} `xml:"ReportItem"`
}

// Parse reads a .nessus file. It fails the test if the file is not
// well-formed.
func Parse(t testing.TB, path string) Doc {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return ParseBytes(t, data)
}

// ParseBytes is Parse for content already in memory.
func ParseBytes(t testing.TB, data []byte) Doc {
	t.Helper()
	var x xFile
	if err := xml.Unmarshal(data, &x); err != nil {
		t.Fatalf("output is not well-formed: %v", err)
	}
	doc := Doc{Policy: x.Policy.Name, ReportName: x.Report.Name}
	for _, h := range x.Report.Hosts {
		hd := HostData{Name: h.Name}
		for _, tg := range h.Tags {
			hd.Tags = append(hd.Tags, TagData{tg.Name, tg.Value})
		}
		for _, it := range h.Items {
			hd.Items = append(hd.Items, ItemData{it.Plugin, it.Port, it.Proto, it.Severity, strings.TrimSpace(it.Output)})
		}
		doc.Hosts = append(doc.Hosts, hd)
	}
	return doc
}
