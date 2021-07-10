package main

import (
	"bufio"
	"encoding/binary"
	"encoding/hex"
	"flag"
	"fmt"
	"math"
	"os"
	"strconv"
	"time"
	"totp_generator/hmac"
)

// getting variables from flags
var epochDuration = flag.Int("epoch", 5, "Sets epoch duration in seconds.")
var digitsF = flag.Int("digits", 6, "Sets the OTP's number of decimal digits.")

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

func runGenerator() {
	scanner := bufio.NewScanner(os.Stdin)
	fmt.Print("Enter key (hex): ")
	// reading the key as a hex string from console
	scanner.Scan()
	keystr := scanner.Text()
	secret, _ := hex.DecodeString(keystr)

	var epoch = uint64(*epochDuration)
	digits := *digitsF

	fmt.Println("Generating OTPs...")
	for true {
		b := make([]byte, 8)
		// converting counter value to byte array
		binary.BigEndian.PutUint64(b, getCounterValue(epoch))
		// number must be padded according to the number of decimal digits
		fmt.Printf("%0"+strconv.Itoa(digits)+"d", getHotpValue(secret, b, digits))
		time.Sleep(time.Duration(epoch) * time.Second)
		// clearing the line to show the new code in-place
		fmt.Printf("\r")
	}
}

func main() {
	flag.Parse()
	runGenerator()
}
