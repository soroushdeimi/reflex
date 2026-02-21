package reflex

import (
	"io"

	"github.com/xtls/xray-core/transport"
)

type MuxSession struct {
	link *transport.Link
}

func NewMuxSession(link *transport.Link) *MuxSession {
	return &MuxSession{link: link}
}

func (m *MuxSession) Read(p []byte) (int, error) {
	return m.link.Reader.Read(p)
}

func (m *MuxSession) Write(p []byte) (int, error) {
	return m.link.Writer.Write(p)
}

func (m *MuxSession) Close() error {
	_ = m.link.Reader.Close()
	_ = m.link.Writer.Close()
	return nil
}

var _ io.Reader = (*MuxSession)(nil)
var _ io.Writer = (*MuxSession)(nil)
