package inbound

import (
	"bufio"
	"context"
	"fmt"
	stdnet "net"

	singbufio "github.com/sagernet/sing/common/bufio"
	E "github.com/sagernet/sing/common/exceptions"

	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/transport/internet/stat"
)

// preloadedConn wraps a stat.Connection but sources reads from a bufio.Reader.
// This ensures bytes previously Peek()'ed (and now buffered in reader) will still
// be forwarded to the fallback upstream without being lost.
type preloadedConn struct {
	Reader *bufio.Reader
	stat.Connection
}

func (pc *preloadedConn) Read(b []byte) (int, error)  { return pc.Reader.Read(b) }
func (pc *preloadedConn) Write(b []byte) (int, error) { return pc.Connection.Write(b) }

// handleFallback proxies the inbound conn to a local fallback TCP server.
//
// IMPORTANT:
//   - It must use the SAME bufio.Reader used for handshake decision,
//     so buffered bytes are preserved.
//   - It should only be called when KindNotReflex is returned before consuming bytes.
func (h *Handler) handleFallback(ctx context.Context, reader *bufio.Reader, conn stat.Connection) error {
	fb := h.config.GetFallback()
	if fb == nil || fb.GetDest() == 0 {
		_ = conn.Close()
		// Info-level because this is a config issue, not a transport failure.
		return errors.New("reflex inbound: fallback not configured").AtInfo()
	}

	targetAddr := fmt.Sprintf("127.0.0.1:%d", fb.GetDest())

	var d stdnet.Dialer
	target, err := d.DialContext(ctx, "tcp", targetAddr)
	if err != nil {
		_ = conn.Close()
		return errors.New("reflex inbound: fallback dial failed").Base(err).AtInfo()
	}
	defer target.Close()
	defer conn.Close()

	wrapped := &preloadedConn{Reader: reader, Connection: conn}

	// CopyConn handles bidirectional relay and should return when either side closes.
	if err := singbufio.CopyConn(ctx, wrapped, target); err != nil {
		// For normal shutdown paths, avoid noisy errors.
		if E.IsClosedOrCanceled(err) || ctx.Err() != nil {
			return nil
		}
		return errors.New("reflex inbound: fallback relay ended").Base(err).AtInfo()
	}
	return nil
}
