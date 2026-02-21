package reflex

import (
	"bufio"
	"io"

	"github.com/xtls/xray-core/transport/internet/stat"
)

type ObfsReader struct {
	r *bufio.Reader
}

type ObfsWriter struct {
	w stat.Connection
}

func WrapObfsReader(r *bufio.Reader) *ObfsReader {
	return &ObfsReader{r: r}
}

func WrapObfsWriter(c stat.Connection) *ObfsWriter {
	return &ObfsWriter{w: c}
}

func (o *ObfsReader) Read(p []byte) (int, error) {
	// نسخهٔ نهایی می‌تواند padding / disguise اضافه کند
	return o.r.Read(p)
}

func (o *ObfsWriter) Write(p []byte) (int, error) {
	// نسخهٔ نهایی می‌تواند padding / disguise اضافه کند
	return o.w.Write(p)
}

func (o *ObfsWriter) Close() error {
	return o.w.Close()
}

var _ io.Reader = (*ObfsReader)(nil)
var _ io.Writer = (*ObfsWriter)(nil)
