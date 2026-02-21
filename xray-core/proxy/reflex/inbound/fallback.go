package inbound

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net"

	"github.com/xtls/xray-core/transport/internet/stat"
)

type preloadedConn struct {
    *bufio.Reader
    stat.Connection
}

func (pc *preloadedConn) Read(b []byte) (int, error) {
    return pc.Reader.Read(b)
}

func (pc *preloadedConn) Write(b []byte) (int, error) {
    return pc.Connection.Write(b)
}

func (h *Handler) handleFallback(ctx context.Context, reader *bufio.Reader, conn stat.Connection) error {
    if h.fallback == nil {
        return errors.New("no fallback configured")
    }
    
    // ساخت یک connection wrapper که reader رو wrap می‌کنه
    // این باعث می‌شه بایت‌های peek شده هم خوانده بشن
    wrappedConn := &preloadedConn{
        Reader: reader,
        Connection: conn,
    }
    
    // اتصال به وب‌سرور محلی
    target, err := net.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", h.fallback.Dest))
    if err != nil {
        return err
    }
    defer target.Close()
    
    // کپی کردن داده‌ها بین دو connection
    go io.Copy(target, wrappedConn)
    io.Copy(wrappedConn, target)
    
    return nil
}