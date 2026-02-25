package handshake

import (
	stderrors "errors"
)

// ErrKind categorizes handshake errors so callers can decide how to react.
// For example, KindNotReflex should typically trigger fallback (Step4) ONLY when it is safe,
// i.e., when the caller has NOT consumed bytes from the connection yet (Peek-based detection).
// while KindUnauthenticated should reply with a normal-looking 403 and close.
type ErrKind uint8

const (
	KindNotReflex ErrKind = iota + 1
	KindInvalidHandshake
	KindUnauthenticated
	KindReplay
	KindInternal
)

type Error struct {
	Kind  ErrKind
	Msg   string
	Inner error
}

func (e *Error) Error() string {
	if e == nil {
		return "<nil>"
	}
	if e.Inner == nil {
		return e.Msg
	}
	return e.Msg + ": " + e.Inner.Error()
}

func (e *Error) Unwrap() error { return e.Inner }

func New(kind ErrKind, msg string) *Error {
	return &Error{Kind: kind, Msg: msg}
}

func Wrap(kind ErrKind, msg string, inner error) *Error {
	return &Error{Kind: kind, Msg: msg, Inner: inner}
}

func IsKind(err error, kind ErrKind) bool {
	var he *Error
	if stderrors.As(err, &he) {
		return he.Kind == kind
	}
	return false
}
