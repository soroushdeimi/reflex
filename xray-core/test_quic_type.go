
package main
import (
	"context"
	"fmt"
	"github.com/quic-go/quic-go"
)
func main() {
	l, _ := quic.ListenAddr("127.0.0.1:0", nil, nil)
	c, _ := l.Accept(context.Background())
	fmt.Printf("%T", c)
}
