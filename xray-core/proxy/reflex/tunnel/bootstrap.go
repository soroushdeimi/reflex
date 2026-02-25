package tunnel

import (
	"io"

	"github.com/xtls/xray-core/common/errors"
	xnet "github.com/xtls/xray-core/common/net"
)

const maxInitialSkipFrames = 32

// ReadInitialDestination reads frames until it finds the first DATA frame, then decodes the
// destination header from the beginning of its plaintext payload.
//
// It ignores PADDING and TIMING frames. CLOSE before any destination returns io.EOF.
// It also enforces an upper bound on the number of non-DATA frames it will skip to avoid DoS.
func ReadInitialDestination(sess *Session, r io.Reader, dc DestinationCodec) (xnet.Destination, []byte, error) {
	if sess == nil {
		return xnet.Destination{}, nil, errors.New("reflex tunnel: nil session")
	}
	if r == nil {
		return xnet.Destination{}, nil, errors.New("reflex tunnel: nil reader")
	}
	if dc == nil {
		return xnet.Destination{}, nil, errors.New("reflex tunnel: nil destination codec")
	}

	skipped := 0
	for {
		if skipped > maxInitialSkipFrames {
			return xnet.Destination{}, nil, errors.New("reflex tunnel: too many non-data frames before destination")
		}

		f, err := sess.ReadFrame(r)
		if err != nil {
			return xnet.Destination{}, nil, err
		}

		switch f.Type {
		case FrameTypeData:
			if len(f.Payload) == 0 {
				return xnet.Destination{}, nil, errors.New("reflex tunnel: empty data frame before destination")
			}

			dest, headerLen, err := dc.Decode(f.Payload)
			if err != nil {
				return xnet.Destination{}, nil, err
			}
			if headerLen < 0 || headerLen > len(f.Payload) {
				return xnet.Destination{}, nil, errors.New("reflex tunnel: invalid destination header length")
			}
			if !dest.IsValid() {
				return xnet.Destination{}, nil, errors.New("reflex tunnel: decoded invalid destination")
			}
			return dest, f.Payload[headerLen:], nil

		case FrameTypePadding, FrameTypeTiming:
			skipped++
			continue

		case FrameTypeClose:
			return xnet.Destination{}, nil, io.EOF

		default:
			return xnet.Destination{}, nil, errors.New("reflex tunnel: unknown frame type")
		}
	}
}

// WriteInitialDestination writes the first DATA frame for a stream.
// The plaintext payload is: [encoded-destination][initialPayload].
func WriteInitialDestination(sess *Session, w io.Writer, dc DestinationCodec, dest xnet.Destination, initialPayload []byte) error {
	if sess == nil {
		return errors.New("reflex tunnel: nil session")
	}
	if w == nil {
		return errors.New("reflex tunnel: nil writer")
	}
	if dc == nil {
		return errors.New("reflex tunnel: nil destination codec")
	}
	if !dest.IsValid() {
		return errors.New("reflex tunnel: invalid destination")
	}

	head, err := dc.Encode(dest)
	if err != nil {
		return err
	}

	// Build combined payload without mutating caller slices.
	payload := make([]byte, 0, len(head)+len(initialPayload))
	payload = append(payload, head...)
	if len(initialPayload) > 0 {
		payload = append(payload, initialPayload...)
	}

	return sess.WriteFrame(w, FrameTypeData, payload)
}
