package paillier

import (
	"crypto/rand"
	"fmt"
	"math/big"
)

// This example demonstrates basic usage of this library.
// Features shown:
//   * Encrypt/Decrypt
//   * Homomorphic cipher text addition
//   * Homomorphic addition with constant
//   * Homomorphic multiplication with constant
func main() {
	// Generate a 128-bit private key.
	privKey, err := GenerateKey(rand.Reader, 128)
	if err != nil {
		fmt.Println(err)
		return
	}

	// Encrypt the number "15".
	m15 := new(big.Int).SetInt64(15)
	c15, err := Encrypt(&privKey.PublicKey, m15.Bytes())
	if err != nil {
		fmt.Println(err)
		return
	}

	// Decrypt the number "15".
	d, err := Decrypt(privKey, c15)
	if err != nil {
		fmt.Println(err)
		return
	}
	plainText := new(big.Int).SetBytes(d)
	fmt.Println("Decryption Result of 15: ", plainText.String())

	// Now for the fun stuff.
	// Encrypt the number "20".
	m20 := new(big.Int).SetInt64(20)
	c20, err := Encrypt(&privKey.PublicKey, m20.Bytes())
	if err != nil {
		fmt.Println(err)
		return
	}

	// Add the encrypted integers 15 and 20 together.
	plusM16M20 := AddCipher(&privKey.PublicKey, c15, c20)
	decryptedAddition, err := Decrypt(privKey, plusM16M20)
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Println("Result of 15+20 after decryption: ",
		new(big.Int).SetBytes(decryptedAddition).String()) // 35

	// Add the encrypted integer 15 to plaintext constant 10.
	plusE15and10 := Add(&privKey.PublicKey, c15, new(big.Int).SetInt64(10).Bytes())
	decryptedAddition, err = Decrypt(privKey, plusE15and10)
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Println("Result of 15+10 after decryption: ",
		new(big.Int).SetBytes(decryptedAddition).String()) // 25

	// Multiply the encrypted integer 15 by the plaintext constant 10.
	mulE15and10 := Mul(&privKey.PublicKey, c15, new(big.Int).SetInt64(10).Bytes())
	decryptedMul, err := Decrypt(privKey, mulE15and10)
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Println("Result of 15*10 after decryption: ", new(big.Int).SetBytes(decryptedMul).String()) // 150

	for c := 0; c < 10; c++ {
		for i := 0; i < 100; i++ {
			fmt.Println("======================", c, i, "============================")
			test(512, i) // when bit size <= 32, will has wrong result
		} // recommand bit size should be 2048, reference from https://crypto.stackexchange.com/questions/44804/pailliers-cryptosystem-secure-key-size
	}
}

func test(length int, count int) {
	privKey, err := GenerateKey(rand.Reader, length)
	if err != nil {
		fmt.Println(err)
		return
	}

	o := new(big.Int).SetInt64(0)
	e, err := Encrypt(&privKey.PublicKey, o.Bytes())
	if err != nil {
		fmt.Println(err)
		return
	}
	for i := 0; i < count; i++ {
		bs := make([]byte, length/8/2)
		_, err = rand.Read(bs)
		if err != nil {
			fmt.Println(err)
			return
		}
		m := new(big.Int).SetBytes(bs)

		mc, err := Encrypt(&privKey.PublicKey, m.Bytes())
		if err != nil {
			fmt.Println(err)
			return
		}
		// fmt.Println(i, len(m.Bytes()), m.Bytes(), m.String(), mc)

		o.Add(o, m)
		e = AddCipher(&privKey.PublicKey, e, mc)
	}

	ms, err := Decrypt(privKey, e)
	if err != nil {
		fmt.Println(err)
		return
	}
	r := new(big.Int).SetBytes(ms)
	fmt.Println("r", len(r.Bytes()), r.Bytes(), r.String(), e)
	fmt.Println(o.String(), r.String(), privKey.n, privKey.p, privKey.q, privKey.hp, privKey.hq, privKey.pinvq)
	if o.Cmp(r) != 0 {
		fmt.Println("=================")
		fmt.Println("PublicKey.N", privKey.PublicKey.N)
		fmt.Println("PublicKey.G", privKey.PublicKey.G)
		fmt.Println("PublicKey.NSquared", privKey.PublicKey.NSquared)
		fmt.Println("p", privKey.p)
		fmt.Println("pp", privKey.pp)
		fmt.Println("pminusone", privKey.pminusone)
		fmt.Println("q", privKey.q)
		fmt.Println("qq", privKey.qq)
		fmt.Println("qminusone", privKey.qminusone)
		fmt.Println("pinvq", privKey.pinvq)
		fmt.Println("hp", privKey.hp)
		fmt.Println("hq", privKey.hq)
		fmt.Println("n", privKey.n)
		panic("error")
	}
}
