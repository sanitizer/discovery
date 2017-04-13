package security

import (
	"fmt"
	"gitlab.com/moonshiners/discovery/model"
	"strconv"
	"testing"
)

func TestSecurity_generateDiscoReqTokenSeed(t *testing.T) {
	fmt.Println("running private test 1")

	// the first test just needs to make sure that different date will generate a different seed
	s1 := Security{SeedValue: discomodel.DEFAULT_SEED_VALUE}
	result1, e1 := s1.generateDiscoReqTokenSeed()

	s2 := Security{SeedValue: discomodel.DEFAULT_SEED_VALUE, Offset: 24 * 3600}
	result2, e2 := s2.generateDiscoReqTokenSeed()

	fmt.Println("result1:", strconv.Itoa(int(result1)))
	fmt.Println("result2:", strconv.Itoa(int(result2)))

	if result1 == result2 || e1 != nil || e2 != nil {
		t.Error("Expected result1 != result2, actual result1: " + strconv.Itoa(int(result1)) + ", actual result2: " + strconv.Itoa(int(result2)))
	}

	//this test makes sure that if you wont set a seed for security, the default seed will be used
	s3 := Security{}
	result3, e3 := s3.generateDiscoReqTokenSeed()

	fmt.Println("result3:", strconv.Itoa(int(result3)))

	if result3 != result1 || e3 != nil {
		t.Error("Expected result1 != result2, actual result1: " + strconv.Itoa(int(result1)) + ", actual result3: " + strconv.Itoa(int(result3)))
	}
}
