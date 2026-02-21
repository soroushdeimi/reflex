package scenarios

import (
	"os"
	"testing"
)

func TestMain(m *testing.M) {
	if os.Getenv("XRAY_RUN_SCENARIO_TESTS") != "1" {
		os.Exit(0)
	}
	genTestBinaryPath()
	defer testBinaryCleanFn()

	os.Exit(m.Run())
}
