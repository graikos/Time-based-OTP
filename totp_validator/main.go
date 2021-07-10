package main

import (
	"bufio"
	"crypto/rand"
	"encoding/binary"
	"flag"
	"fmt"
	"log"
	"math"
	"os"
	"strconv"
	"time"
	"totp_validator/hmac"
)

// getting variables from flags
var epochDuration = flag.Int("epoch", 5, "Sets epoch duration in seconds.")
var digitsF = flag.Int("digits", 6, "Sets the OTP's number of decimal digits.")

func getRandomKey(size int) ([]byte, error) {
	b := make([]byte, size)
	_, err := rand.Read(b)
	if err != nil {
		return nil, err
	}
	return b, nil
}

func truncate(mac []byte) uint32 {
	// using the 4 least significant bits as offset
	offset := int(mac[len(mac)-1]) % 16
	// keeping 4 bytes only, not removing MSB since uint is used so number will be unsigned
	mac = mac[offset : offset+4]
	// constructing the uint from byte string
	return uint32(mac[0])*256*256*256 + uint32(mac[1])*256*256 + uint32(mac[2])*256 + uint32(mac[3])
}

func getHotpValue(key, msg []byte, digits int) uint32 {
	return truncate(hmac.HMAC(key, msg)) % uint32(math.Pow(10, float64(digits)))
}

func getCounterValue(epoch uint64) uint64 {
	now := uint64(time.Now().Unix())
	// getting number of epochs to use as counter
	return now / epoch
}

func validateHotpValue(key []byte, value uint32, digits int, epoch uint64, epochSkew int) bool {
	// saving current counter value to prevent change during execution
	currentCounter := getCounterValue(epoch)

	if epochSkew < 0 {
		log.Fatal("invalid epoch skew")
	}

	// this loop calculates some previous and some next values to acccount for time skew
	for i := (-1) * epochSkew; i <= epochSkew; i++ {
		b := make([]byte, 8)
		binary.BigEndian.PutUint64(b, uint64(int64(currentCounter)+int64(i)))
		val := getHotpValue(key, b, digits)
		if val == value {
			return true
		}
	}

	return false
}

func runValidator() {
	// generating random secret key
	secret, _ := getRandomKey(32)
	var epoch = uint64(*epochDuration)
	digits := *digitsF

	fmt.Printf("This is the key: %x \n", secret)
	scanner := bufio.NewScanner(os.Stdin)

	for true {
		fmt.Print("Enter value to validate: ")
		scanner.Scan()
		tmpstr := scanner.Text()
		valueGiven, err := strconv.ParseInt(tmpstr, 10, 0)
		if err != nil {
			log.Fatal(err)
		}
		isValid := validateHotpValue(secret, uint32(valueGiven), digits, epoch, 1)
		if isValid {
			fmt.Println("Code is valid.")
		} else {
			fmt.Println("Code is invalid.")
		}
	}
}

func main() {
	flag.Parse()
	runValidator()
}
