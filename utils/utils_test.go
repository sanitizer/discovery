package utils_test

import (
	"fmt"
	"github.com/sanitizer/discovery/utils"
	"strconv"
	"testing"
)

func TestGetConnectionString(t *testing.T) {
	result := utils.GetConnectionString("x", "1")

	fmt.Printf("GetConnectionString(x, 1) == %q\n", result)

	if result != "x:1" {
		t.Errorf("GetConnectionString(x, 1) == %q, wanted x:1", result)
	}
}

func TestConnectionIsLive(t *testing.T) {
	result := utils.ConnectionIsLive("tcp", "1", "2")

	if result {
		t.Errorf("ConnectionIsLive(tcp, 1, 2) == %q, wanted: false", strconv.FormatBool(result))
	}
}
