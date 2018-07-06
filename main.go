package main

import (
	"bytes"
	"crypto/cipher"
	"crypto/aes"
	"encoding/base64"
	"fmt"
	"os"
)

func PKCS7Padding(ciphertext []byte, blockSize int) []byte {
	padding := blockSize - len(ciphertext) % blockSize
	padtext := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(ciphertext, padtext...)
}

func PKCS7UnPadding(origData []byte) []byte {
	length := len(origData)
	unpadding := int(origData[length-1])
	return origData[:(length - unpadding)]
}

func AesEncrypt(origData, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	blockSize := block.BlockSize()
	origData = PKCS7Padding(origData, blockSize)
	blockMode := cipher.NewCBCEncrypter(block, key[:blockSize])
	crypted := make([]byte, len(origData))
	blockMode.CryptBlocks(crypted, origData)
	return crypted, nil
}

func AesDecrypt(crypted, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	blockSize := block.BlockSize()
	blockMode := cipher.NewCBCDecrypter(block, key[:blockSize])
	origData := make([]byte, len(crypted))
	blockMode.CryptBlocks(origData, crypted)
	origData = PKCS7UnPadding(origData)
	return origData, nil
}

func Base64AesDecrypt(crypted string) ([]byte, error) {
	key := []byte("f2c85e0140a47415")
	r1, err:= base64.URLEncoding.DecodeString(crypted)
	if err != nil {
		fmt.Println(err)
		return []byte{}, err
	}
	return AesDecrypt(r1, key)
}


func main() {
	key := []byte("f2c85e0140a47415")
	result, err := AesEncrypt([]byte("hello world"), key)
	if err != nil {
		panic(err)
	}
	f, err := os.OpenFile("120.log", os.O_RDWR|os.O_CREATE, 0755)
	f.Write(result)
	defer f.Close()
	fmt.Println(base64.StdEncoding.EncodeToString(result))
	fmt.Println(base64.URLEncoding.EncodeToString(result))
	origData, err := AesDecrypt(result, key)
	if err != nil {
		panic(err)
	}

	fmt.Println(string(origData))

	c := "PG_4V53n_Sa5rpfPW46AfZ_suztgUc3-YAuLGljntaVdbe9Wa8GB9UQHpe9-FUx0-im-1Jbthshc90X46FIGvcbb5f5qi0QnwnLNZDVtJOSOC9i-QsULr1rrX2mtqYW1Y6KsZRhier7Vcnzwr6F7tA=="
	r1, err:= base64.URLEncoding.DecodeString(c)
	if err != nil {
		fmt.Println(err)
		return
	}
	origData, err = AesDecrypt(r1, key)
	if err != nil {
		panic(err)
	}

	fmt.Println(string(origData))
	d, err := Base64AesDecrypt(c)
	fmt.Println(string(d))
	fmt.Println(err)
}
