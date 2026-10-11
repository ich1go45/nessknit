package merge

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ich1go45/nessknit/internal/index"
)

// writeBigFile generates a .nessus file of hosts*items findings and
// returns its size in bytes. Odd-numbered items differ between seeds,
// so two files with different seeds overlap by half.
func writeBigFile(t *testing.T, path string, hosts, items, seed int) int64 {
	t.Helper()
	fh, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	w := bufio.NewWriterSize(fh, 1<<20)
	filler := strings.Repeat("lorem ipsum dolor sit amet ", 12)
	fmt.Fprint(w, "<?xml version=\"1.0\" ?>\n<NessusClientData_v2>\n<Policy><policyName>big</policyName></Policy>\n<Report name=\"big\">\n")
	for h := 0; h < hosts; h++ {
		fmt.Fprintf(w, "<ReportHost name=\"10.%d.%d.%d\">\n<HostProperties>\n<tag name=\"HOST_END\">seed %d</tag>\n</HostProperties>\n", h>>16, h>>8&255, h&255, seed)
		for i := 0; i < items; i++ {
			variant := 0
			if i%2 == 1 {
				variant = seed
			}
			fmt.Fprintf(w, "<ReportItem port=\"%d\" svc_name=\"general\" protocol=\"tcp\" severity=\"%d\" pluginID=\"%d\" pluginName=\"p\">\n<description>%s</description>\n<plugin_output>variant %d %s</plugin_output>\n</ReportItem>\n",
				i, i%5, 10000+i, filler, variant, filler)
		}
		fmt.Fprint(w, "</ReportHost>\n")
	}
	fmt.Fprint(w, "</Report>\n</NessusClientData_v2>\n")
	if err := w.Flush(); err != nil {
		t.Fatal(err)
	}
	st, err := fh.Stat()
	if err != nil {
		t.Fatal(err)
	}
	if err := fh.Close(); err != nil {
		t.Fatal(err)
	}
	return st.Size()
}

// The merge must not hold its inputs in memory: peak heap stays under a
// bound far below the input size.
func TestPeakMemoryDoesNotGrowWithInputSize(t *testing.T) {
	if testing.Short() {
		t.Skip("generates about 150 MB of input")
	}
	const (
		hosts, items = 800, 120
		heapLimit    = 32 << 20
	)
	dir := t.TempDir()
	var total int64
	var files []*index.File
	measure := startHeapSampler()
	for seed := 1; seed <= 2; seed++ {
		path := filepath.Join(dir, fmt.Sprintf("big%d.nessus", seed))
		total += writeBigFile(t, path, hosts, items, seed)
		f, err := index.Scan(path)
		if err != nil {
			t.Fatal(err)
		}
		files = append(files, f)
	}
	sum, err := Write(io.Discard, files, Options{ReportName: "big"})
	if err != nil {
		t.Fatal(err)
	}
	peak := measure()

	if total < 4*heapLimit {
		t.Fatalf("input is only %d MB; too small to prove anything against a %d MB limit", total>>20, heapLimit>>20)
	}
	if wantFindings := hosts*items + hosts*items/2; sum.Hosts != hosts || sum.Findings != wantFindings {
		t.Errorf("hosts %d, findings %d; want %d and %d", sum.Hosts, sum.Findings, hosts, wantFindings)
	}
	if dups := sum.Files[1].Duplicates; dups != hosts*items/2 {
		t.Errorf("duplicates = %d, want %d", dups, hosts*items/2)
	}
	t.Logf("input %d MB, peak heap %d MB", total>>20, peak>>20)
	if peak > heapLimit {
		t.Errorf("peak heap %d MB exceeds the %d MB limit (input was %d MB)", peak>>20, heapLimit>>20, total>>20)
	}
}

// startHeapSampler polls the heap size in the background. The returned
// function stops it and reports the largest value seen.
func startHeapSampler() func() uint64 {
	var (
		peak uint64
		wg   sync.WaitGroup
		done = make(chan struct{})
	)
	sample := func() {
		var ms runtime.MemStats
		runtime.ReadMemStats(&ms)
		if ms.HeapAlloc > peak {
			peak = ms.HeapAlloc
		}
	}
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			select {
			case <-done:
				return
			case <-time.After(2 * time.Millisecond):
				sample()
			}
		}
	}()
	return func() uint64 {
		close(done)
		wg.Wait()
		sample()
		return peak
	}
}
