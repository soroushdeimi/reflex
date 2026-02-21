package reflex

import (
	"fmt"
	"net"
)

// --------------------
// Config
// --------------------

type Config struct {
	// فعلاً خالی – بعداً می‌تونی فیلد اضافه کنی
}

// --------------------
// Handler
// --------------------

type Handler struct {
	config *Config
}

// سازنده Handler
func NewHandler(config *Config) *Handler {
	return &Handler{
		config: config,
	}
}

// --------------------
// Handshake Processor
// --------------------

func (h *Handler) ProcessHandshake(conn net.Conn) error {
	defer conn.Close()

	buf := make([]byte, 1024)

	n, err := conn.Read(buf)
	if err != nil {
		return err
	}

	if n == 0 {
		return fmt.Errorf("empty handshake")
	}

	// اینجا فعلاً فقط بررسی می‌کنیم دیتا رسیده
	// بعداً می‌تونی validate واقعی اضافه کنی

	return nil
}
