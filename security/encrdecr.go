package security

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"errors"
	"math/rand"
	"regexp"
	"strconv"
	"strings"
	"time"
	// gitlab apis
	"gitlab.com/moonshiners/discovery/model"
)

type Security struct {
	SeedValue string
	Offset    int
}

const PATTERN = "//"
const PATTERN_REGEX = "//[0-9]*//"

// given by a code example(i do not know what that is and why is it here. need research)
var commonIV = []byte{0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f}

/*
	CFB - Ciphertext feedback,
	is a mode of operation for a block cipher. In contrast to the cipher block chaining (CBC) mode,
	which encrypts a set number of bits of plaintext at a time, it is at times desirable to encrypt
	and transfer some plaintext values instantly one at a time, for which ciphertext feedback is a method
	(searchsecurity.techtarget.com/definition/ciphertext-feedback)
*/
func (this *Security) EncryptCFB(plainText []byte) (string, error) {
	key := "IwTbLbY!0@9*7^JyTtPtWyPmPmDyPmMf"

	//Create aes encryption algorithm
	c, err := aes.NewCipher([]byte(key))

	if err != nil {
		return "", err
	}

	cfb := cipher.NewCFBEncrypter(c, commonIV)
	encryptedText := make([]byte, len(plainText))
	cfb.XORKeyStream(encryptedText, plainText)
	return string(encryptedText[:]), nil
}

/*
	CFB - Ciphertext feedback,
	is a mode of operation for a block cipher. In contrast to the cipher block chaining (CBC) mode,
	which encrypts a set number of bits of plaintext at a time, it is at times desirable to encrypt
	and transfer some plaintext values instantly one at a time, for which ciphertext feedback is a method
	(searchsecurity.techtarget.com/definition/ciphertext-feedback)
*/
func (this *Security) DecryptCFB(encryptedText []byte, dataLen int) (string, error) {
	key := "IwTbLbY!0@9*7^JyTtPtWyPmPmDyPmMf"

	//Create aes encryption algorithm
	c, err := aes.NewCipher([]byte(key))

	if err != nil {
		return "", err
	}

	cfb := cipher.NewCFBDecrypter(c, commonIV)
	plainText := make([]byte, dataLen)
	cfb.XORKeyStream(plainText, encryptedText)
	return string(plainText[:]), nil
}

// searches using regex for injected length of original encrypted data in encrypted string
func (this *Security) FindLengthInCFBEncryptedString(encryptedData string) (string, error) {
	re := regexp.MustCompile(PATTERN_REGEX)
	result := re.FindAllStringSubmatch(encryptedData, -1)

	if len(result) > 0 && len(result[0]) > 0 {
		return result[0][0], nil
	}

	return "", errors.New("Was not able to find a substring in encrypted string")
}

// clears the pattern from the length that was injected into the encrypted string
func (this *Security) RemovePatternAttrsFromLength(length string) (int, error) {
	result, err := strconv.Atoi(strings.Replace(length, PATTERN, "", 2))
	return result, err
}

// injects length of original encrypted data into encrypted string
func (this *Security) HideLengthInCFBEncryptedString(encryptedData string, originalLength int) string {
	halfOfData := encryptedData[0:int(len(encryptedData)/2)]
	result := strings.Replace(encryptedData, halfOfData, string(halfOfData+PATTERN+strconv.Itoa(originalLength)+PATTERN), 1)
	return result
}

// removes the injected length of original encrypted data from encrypted string
func (this *Security) RemoveLengthFromCFBEncryptedData(encryptedData string, patternToRemove string) string {
	return strings.Replace(encryptedData, patternToRemove, "", 1)
}

func (this *Security) generateDiscoReqTokenSeed() (int64, error) {

	if this.SeedValue == "" {
		this.SeedValue = discomodel.DEFAULT_SEED_VALUE
	}

	var strBuilder bytes.Buffer
	location := time.FixedZone(this.SeedValue, this.Offset)
	tm := time.Now().In(location)

	/*
		building a token based on current date in GMT time zone
		format is MonthDayYear which is returned as a string
		This sting will be an int64 seed for rand int generator
	*/
	strBuilder.WriteString(strconv.Itoa(int(tm.Month())))
	strBuilder.WriteString(strconv.Itoa(tm.Day()))
	strBuilder.WriteString(strconv.Itoa(tm.Year()))
	result, e := strconv.Atoi(strBuilder.String())

	return int64(result), e
}

func (this *Security) GenerateDiscoReqToken() (string, error) {
	seed, e := this.generateDiscoReqTokenSeed()

	if e != nil {
		return "", errors.New("Error generating seed for rand: " + e.Error())
	}

	rand.Seed(seed)
	return strconv.Itoa(rand.Int()), nil
}
