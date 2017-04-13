package security_test

import (
	"fmt"
	"gitlab.com/moonshiners/discovery/model"
	"gitlab.com/moonshiners/discovery/security"
	"strconv"
	"strings"
	"testing"
)

const encryptedString = "\x8b\x9c\xac\u007f"
const stringToEncrypt = "test"

func TestSecurity_EncryptCFB(t *testing.T) {
	s := new(security.Security)
	result, _ := s.EncryptCFB([]byte(stringToEncrypt))

	fmt.Printf("Encrypted %q into %q\n", stringToEncrypt, result)

	if result != encryptedString {
		t.Errorf("Encrypt(%q) == %q, want smth else", stringToEncrypt, result)
	}
}

func TestSecurity_DecryptCFB(t *testing.T) {
	s := new(security.Security)
	result, _ := s.DecryptCFB([]byte(encryptedString), len(stringToEncrypt))

	fmt.Printf("Decrypted %q into %q\n", encryptedString, result)

	if result != stringToEncrypt {
		t.Errorf("Decrypt(%q) == %q, want smth else", encryptedString, result)
	}
}

func TestSecurity_FindLengthInCFBEncryptedString(t *testing.T) {
	s := new(security.Security)
	str := "HelloWorld////345////GodDamnRight3530GOTDIS&Y#//345//YQHGD"
	result, err := s.FindLengthInCFBEncryptedString(str)
	if err != nil {
		fmt.Printf("Error: %q", err.Error())
	}
	fmt.Printf("Expect: ////345////. Actual: %q\n", result)
	fmt.Printf("Original: " + str + "\nResult: " + strings.Replace(str, "////345////", "", 1) + "\n")
	r, _ := s.RemovePatternAttrsFromLength(result)
	fmt.Printf("Replaced: %d\n", r)
}

func TestSecurity_HideLengthInCFBEncryptedString(t *testing.T) {
	s := new(security.Security)
	str := "HelloWorldGodDamnRight3530GOTDIS&Y#//345//YQHGD"
	result := s.HideLengthInCFBEncryptedString(str, 345)
	fmt.Printf("Expect: HelloWorldGodDamn////345////Right3530GOTDIS&Y#//345//YQHGD. \nActual: %s\n", result)
}

func TestSecurity_RemovePatternAttrsFromLength(t *testing.T) {
	s := new(security.Security)
	str := "//5//"
	result, e := s.RemovePatternAttrsFromLength(str)

	if result != 5 || e != nil {
		t.Error("Expected result for RemovePatternAttrsFromLength('//5//'): 5, actual: " + strconv.Itoa(result))
		if e != nil {
			t.Error("Error was not nil as expected. Error: " + e.Error())
		}
	}

	str2 := "hello world"
	_, e1 := s.RemovePatternAttrsFromLength(str2)

	if e1 == nil {
		t.Error("Expected error for RemovePatternAttrsFromLength('hello world')")
	}
}

func TestSecurity_RemoveLengthFromCFBEncryptedData(t *testing.T) {
	s := new(security.Security)
	str := "hello //5//world"
	pattern := "//5//"
	result := s.RemoveLengthFromCFBEncryptedData(str, pattern)

	if result != "hello world" {
		t.Error("Expected result for RemoveLengthFromEncryptedData('hello //5//5world', '//5//'): 'hello world', actual: " + result)
	}

	str2 := "hello world"
	result2 := s.RemoveLengthFromCFBEncryptedData(str2, pattern)

	if result2 != "hello world" {
		t.Error("Expected result2 for RemoveLengthFromEncryptedData('hello world', '//5//'): 'hello world', actual: " + result)
	}
}

func TestSecurity_GenerateDiscoReqToken(t *testing.T) {
	s1 := security.Security{SeedValue: discomodel.DEFAULT_SEED_VALUE}
	result1, e1 := s1.GenerateDiscoReqToken()

	s2 := security.Security{SeedValue: discomodel.DEFAULT_SEED_VALUE}
	result2, e2 := s2.GenerateDiscoReqToken()

	fmt.Println("Generated token1:", result1)
	fmt.Println("Generated token2:", result2)

	if result1 != result2 || e1 != nil || e2 != nil {
		t.Error("Expected result1 == result2, actual result1: " + result1 + ", actual result2: " + result2)
	}

	s3 := security.Security{SeedValue: discomodel.DEFAULT_SEED_VALUE, Offset: 24 * 3600}
	result3, e3 := s3.GenerateDiscoReqToken()

	fmt.Println("Generated token3:", result3)

	if result1 == result3 || e3 != nil {
		t.Error("Expected result1 != result3, actual result1: " + result1 + ", actual result3: " + result3)
	}
}
