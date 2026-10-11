//go:build unix

package merge

import (
	"bytes"
	"fmt"
	"syscall"
	"testing"

	nt "github.com/ich1go45/nessknit/internal/nessustest"
)

// Merging more files than the process may hold open must still work.
func TestManyInputsDoNotExhaustFileDescriptors(t *testing.T) {
	var limit syscall.Rlimit
	if err := syscall.Getrlimit(syscall.RLIMIT_NOFILE, &limit); err != nil {
		t.Skip(err)
	}
	lowered := limit
	lowered.Cur = 64
	if err := syscall.Setrlimit(syscall.RLIMIT_NOFILE, &lowered); err != nil {
		t.Skip(err)
	}
	t.Cleanup(func() { syscall.Setrlimit(syscall.RLIMIT_NOFILE, &limit) })

	const n = 200
	srcs := make([]string, n)
	for i := range srcs {
		srcs[i] = nt.File("p", "r",
			nt.Host(fmt.Sprintf("only-%d", i), item("1", "0", "x")),
			nt.Host("shared", item("2", fmt.Sprint(i), "x")),
		)
	}
	var out bytes.Buffer
	sum, err := Write(&out, scanAll(t, srcs...), Options{ReportName: "r"})
	if err != nil {
		t.Fatal(err)
	}
	if sum.Hosts != n+1 || sum.Findings != 2*n {
		t.Errorf("hosts %d, findings %d; want %d and %d", sum.Hosts, sum.Findings, n+1, 2*n)
	}
	doc := nt.ParseBytes(t, out.Bytes())
	if len(doc.Hosts) != n+1 || doc.Hosts[1].Name != "shared" || len(doc.Hosts[1].Items) != n {
		t.Errorf("parsed %d hosts; second is %q with %d items", len(doc.Hosts), doc.Hosts[1].Name, len(doc.Hosts[1].Items))
	}
}
