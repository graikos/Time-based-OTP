package hmac

import "crypto/sha256"

func HMAC(key, msg []byte) []byte {
	if len(key) > sha256.BlockSize {
		// hashing down if key lengths exceeds block size
		tmp := sha256.Sum256(key)
		key = tmp[:]
	}
	if len(key) < sha256.BlockSize {
		// padding to the right with zeros if key lengths is less than block size
		temp := make([]byte, sha256.BlockSize-len(key))
		// creating a byte slice of remaining length will initialize with zeros
		// appending the key to this slice will pad it appropriately
		key = append(temp, key...)
	}
	// creating pads
	opad := make([]byte, sha256.BlockSize)
	ipad := make([]byte, sha256.BlockSize)
	for ind := range opad {
		// populating the pads
		opad[ind] = 0x5c
		ipad[ind] = 0x36
	}

	keyOpad := make([]byte, sha256.BlockSize)
	keyIpad := make([]byte, sha256.BlockSize)
	for ind := range key {
		// performing the XOR
		keyOpad[ind] = opad[ind] ^ key[ind]
		keyIpad[ind] = ipad[ind] ^ key[ind]
	}

	var conc []byte
	// concatenating the byte arrays
	conc = append(conc, keyOpad...)
	// calculating the internal hash and concatenating
	internal := sha256.Sum256(keyIpad)
	conc = append(conc, internal[:]...)
	conc = append(conc, msg...)
	res := sha256.Sum256(conc)
	// res is a 32-byte array, using the colon to convert to byte slice
	return res[:]
}
