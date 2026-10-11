// Package logx is the small leveled logger nessknit writes to stderr.
package logx

import (
	"fmt"
	"io"
)

// Level selects how much a Logger prints.
type Level int

const (
	Quiet  Level = iota // warnings only
	Normal              // warnings and progress
	Debug               // everything
)

// Logger writes prefixed lines to one writer. A nil *Logger discards
// everything, so callers never need to check for it.
type Logger struct {
	w     io.Writer
	level Level
}

func New(w io.Writer, level Level) *Logger {
	return &Logger{w: w, level: level}
}

// Warnf always prints.
func (l *Logger) Warnf(format string, a ...any) { l.print(Quiet, "[!] ", format, a) }

// Infof prints progress unless the level is Quiet.
func (l *Logger) Infof(format string, a ...any) { l.print(Normal, "[*] ", format, a) }

// Debugf prints only at the Debug level.
func (l *Logger) Debugf(format string, a ...any) { l.print(Debug, "[debug] ", format, a) }

func (l *Logger) print(min Level, prefix, format string, a []any) {
	if l == nil || l.level < min {
		return
	}
	fmt.Fprintf(l.w, prefix+format+"\n", a...)
}
