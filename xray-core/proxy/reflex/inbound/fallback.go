package inbound

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/signal"
	"github.com/xtls/xray-core/common/task"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/features/policy"
	"github.com/xtls/xray-core/transport/internet/stat"
)

// preloadedConn wraps bufio.Reader to preserve peeked bytes
type preloadedConn struct {
	*bufio.Reader
	stat.Connection
}

// Read reads from the buffered reader (includes peeked bytes)
func (pc *preloadedConn) Read(b []byte) (int, error) {
	return pc.Reader.Read(b)
}

// Write writes to the underlying connection
func (pc *preloadedConn) Write(b []byte) (int, error) {
	return pc.Connection.Write(b)
}

// isHTTPPostLike checks if data looks like HTTP POST request
func (h *Handler) isHTTPPostLike(data []byte) bool {
	// Check for "POST" at the beginning
	if len(data) < 4 {
		return false
	}

	// Check HTTP method
	if string(data[0:4]) != "POST" {
		return false
	}

	// Check for HTTP version (HTTP/1.1 or HTTP/2)
	// Look for "HTTP/" in the first 64 bytes
	searchLen := len(data)
	if searchLen > 64 {
		searchLen = 64
	}

	dataStr := string(data[:searchLen])
	return strings.Contains(dataStr, "HTTP/")
}

// isReflexHandshake checks if data is a Reflex handshake
func (h *Handler) isReflexHandshake(data []byte) bool {
	// First check magic number (faster)
	if h.isReflexMagic(data) {
		return true
	}

	// Then check HTTP POST-like (more stealthy)
	if h.isHTTPPostLike(data) {
		return true
	}

	return false
}

// handleFallback sends connection to fallback web server
func (h *Handler) handleFallback(ctx context.Context, reader *bufio.Reader, conn stat.Connection) error {
	if h.fallback == nil {
		return errors.New("no fallback configured")
	}

	// Create a wrapper that preserves peeked bytes
	wrappedConn := &preloadedConn{
		Reader:     reader,
		Connection: conn,
	}

	// Connect to local web server
	targetAddr := fmt.Sprintf("127.0.0.1:%d", h.fallback.Dest)
	target, err := net.DialTimeout("tcp", targetAddr, 5*time.Second)
	if err != nil {
		return errors.New("failed to connect to fallback server").Base(err)
	}
	defer target.Close()

	// Log fallback access
	errors.LogInfo(ctx, "fallback to ", targetAddr)

	// Get policy for timeout management
	v := core.MustFromContext(ctx)
	policyManager := v.GetFeature(policy.ManagerType()).(policy.Manager)
	plcy := policyManager.ForLevel(0)

	// Set up context with timeout
	ctx, cancel := context.WithCancel(ctx)
	timer := signal.CancelAfterInactivity(ctx, cancel, plcy.Timeouts.ConnectionIdle)
	defer timer.SetTimeout(0)

	// Forward request to web server
	requestDone := func() error {
		defer timer.SetTimeout(plcy.Timeouts.DownlinkOnly)

		// Copy all data from client to web server
		// This includes the peeked bytes
		clientReader := buf.NewReader(wrappedConn)
		serverWriter := buf.NewWriter(target)
		if err := buf.Copy(clientReader, serverWriter, buf.UpdateActivity(timer)); err != nil {
			return errors.New("failed to forward request to fallback").Base(err)
		}
		return nil
	}

	// Forward response from web server to client
	responseDone := func() error {
		defer timer.SetTimeout(plcy.Timeouts.UplinkOnly)

		serverReader := buf.NewReader(target)
		clientWriter := buf.NewWriter(conn)
		if err := buf.Copy(serverReader, clientWriter, buf.UpdateActivity(timer)); err != nil {
			return errors.New("failed to forward response from fallback").Base(err)
		}
		return nil
	}

	// Run both directions concurrently
	requestDonePost := task.OnSuccess(requestDone, task.Close(target))
	if err := task.Run(ctx, requestDonePost, responseDone); err != nil {
		_ = common.Interrupt(target)
		return errors.New("fallback connection ends").Base(err)
	}

	return nil
}

