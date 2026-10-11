package logx

import (
	"bytes"
	"testing"
)

func TestLevels(t *testing.T) {
	cases := []struct {
		level Level
		want  string
	}{
		{Quiet, "[!] w 1\n"},
		{Normal, "[!] w 1\n[*] i 2\n"},
		{Debug, "[!] w 1\n[*] i 2\n[debug] d 3\n"},
	}
	for _, c := range cases {
		var buf bytes.Buffer
		l := New(&buf, c.level)
		l.Warnf("w %d", 1)
		l.Infof("i %d", 2)
		l.Debugf("d %d", 3)
		if buf.String() != c.want {
			t.Errorf("level %d: got %q, want %q", c.level, buf.String(), c.want)
		}
	}
}

func TestNilLoggerIsSilent(t *testing.T) {
	var l *Logger
	l.Warnf("x")
	l.Infof("x")
	l.Debugf("x")
}
