package AesEncrypte

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/md5"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"sort"
	"strings"
)

func generateKey(key []byte) (genKey []byte) {
	genKey = make([]byte, 16)
	copy(genKey, key)
	for i := 16; i < len(key); {
		for j := 0; j < 16 && i < len(key); j, i = j+1, i+1 {
			genKey[j] ^= key[i]
		}
	}
	return genKey
}

// =================== ECB ======================
func AesEncryptedECB(origData []byte, key []byte) (encrypted []byte) {
	cipher, _ := aes.NewCipher(generateKey(key))
	length := (len(origData) + aes.BlockSize) / aes.BlockSize
	plain := make([]byte, length*aes.BlockSize)
	copy(plain, origData)
	pad := byte(len(plain) - len(origData))
	for i := len(origData); i < len(plain); i++ {
		plain[i] = pad
	}
	encrypted = make([]byte, len(plain))
	// 分组分块加密
	for bs, be := 0, cipher.BlockSize(); bs <= len(origData); bs, be = bs+cipher.BlockSize(), be+cipher.BlockSize() {
		cipher.Encrypt(encrypted[bs:be], plain[bs:be])
	}
	return encrypted
}

func AesDecryptECB(encrypted []byte, key []byte) (decrypted []byte) {
	cipher, _ := aes.NewCipher(generateKey(key))
	decrypted = make([]byte, len(encrypted))
	//
	for bs, be := 0, cipher.BlockSize(); bs < len(encrypted); bs, be = bs+cipher.BlockSize(), be+cipher.BlockSize() {
		cipher.Decrypt(decrypted[bs:be], encrypted[bs:be])
	}

	bEnd := SearchByteSliceIndex(decrypted, 0)

	return decrypted[:bEnd]
}

// =================== CBC ======================
func AesEncryptCBC(origData []byte, key []byte) (encrypted []byte) {
	// 分组秘钥
	// NewCipher该函数限制了输入k的长度必须为16, 24或者32
	block, _ := aes.NewCipher(key)
	blockSize := block.BlockSize()                              // 获取秘钥块的长度
	origData = pkcs5Padding(origData, blockSize)                // 补全码
	blockMode := cipher.NewCBCEncrypter(block, key[:blockSize]) // 加密模式
	encrypted = make([]byte, len(origData))                     // 创建数组
	blockMode.CryptBlocks(encrypted, origData)                  // 加密
	return encrypted
}

func AesDecryptCBC(encrypted []byte, key []byte) (decrypted []byte) {
	block, _ := aes.NewCipher(key)                              // 分组秘钥
	blockSize := block.BlockSize()                              // 获取秘钥块的长度
	blockMode := cipher.NewCBCDecrypter(block, key[:blockSize]) // 加密模式
	decrypted = make([]byte, len(encrypted))                    // 创建数组
	blockMode.CryptBlocks(decrypted, encrypted)                 // 解密
	decrypted = pkcs5UnPadding(decrypted)                       // 去除补全码
	return decrypted
}

// =================== CFB ======================
func AesEncryptCFB(origData []byte, key []byte) (encrypted []byte) {
	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}
	encrypted = make([]byte, aes.BlockSize+len(origData))
	iv := encrypted[:aes.BlockSize]
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		panic(err)
	}
	stream := cipher.NewCFBEncrypter(block, iv)
	stream.XORKeyStream(encrypted[aes.BlockSize:], origData)
	return encrypted
}
func AesDecryptCFB(encrypted []byte, key []byte) (decrypted []byte) {
	block, _ := aes.NewCipher(key)
	if len(encrypted) < aes.BlockSize {
		panic("ciphertext too short")
	}
	iv := encrypted[:aes.BlockSize]
	encrypted = encrypted[aes.BlockSize:]

	stream := cipher.NewCFBDecrypter(block, iv)
	stream.XORKeyStream(encrypted, encrypted)
	return encrypted
}

func pkcs5Padding(ciphertext []byte, blockSize int) []byte {
	padding := blockSize - len(ciphertext)%blockSize
	padtext := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(ciphertext, padtext...)
}

func pkcs5UnPadding(origData []byte) []byte {
	length := len(origData)
	unpadding := int(origData[length-1])
	return origData[:(length - unpadding)]
}

// []byte 字节切片 循环查找
func SearchByteSliceIndex(bSrc []byte, b byte) int {
	for i := 0; i < len(bSrc); i++ {
		if bSrc[i] == b {
			return i
		}
	}

	return -1
}

//使用PKCS7进行填充，IOS也是7
func PKCS7Padding(ciphertext []byte, blockSize int) []byte {
	padding := blockSize - len(ciphertext)%blockSize
	padtext := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(ciphertext, padtext...)
}

func PKCS7UnPadding(origData []byte) []byte {
	length := len(origData)
	unpadding := int(origData[length-1])
	return origData[:(length - unpadding)]
}

func AesCBCDncrypt(encryptData, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}

	blockSize := block.BlockSize()

	if len(encryptData) < blockSize {
		panic("ciphertext too short")
	}
	iv := encryptData[:blockSize]
	encryptData = encryptData[blockSize:]

	// CBC mode always works in whole blocks.
	if len(encryptData)%blockSize != 0 {
		panic("ciphertext is not a multiple of the block size")
	}

	mode := cipher.NewCBCDecrypter(block, iv)

	// CryptBlocks can work in-place if the two arguments are the same.
	mode.CryptBlocks(encryptData, encryptData)
	//解填充
	encryptData = PKCS7UnPadding(encryptData)
	return encryptData, nil
}

func Encrypt(rawData string, key []byte) (string, error) {
	data, err := AesCBCEncrypt(rawData, key)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString([]byte(data)), nil
}

func Decrypt(rawData string, key []byte) (string, error) {
	data, err := base64.StdEncoding.DecodeString(rawData)
	if err != nil {
		return "", err
	}
	dnData, err := AesCBCDncrypt(data, key)
	if err != nil {
		return "", err
	}
	return string(dnData), nil
}

func EcbDecrypt(data, key []byte) []byte {
	block, _ := aes.NewCipher(key)
	decrypted := make([]byte, len(data))
	size := block.BlockSize()

	for bs, be := 0, size; bs < len(data); bs, be = bs+size, be+size {
		block.Decrypt(decrypted[bs:be], data[bs:be])
	}

	return PKCS7UnPadding(decrypted)
}

func EcbEncrypt(data, key []byte) []byte {
	block, _ := aes.NewCipher(key)
	data = PKCS7Padding(data, block.BlockSize())
	decrypted := make([]byte, len(data))
	size := block.BlockSize()

	for bs, be := 0, size; bs < len(data); bs, be = bs+size, be+size {
		block.Encrypt(decrypted[bs:be], data[bs:be])
	}

	return decrypted
}

func ByteString(p []byte) string {
	for i := 0; i < len(p); i++ {
		if p[i] == 0 {
			return string(p[0:i])
		}
	}
	return string(p)
}

func Base64URLDecode(data string) ([]byte, error) {
	var missing = (4 - len(data)%4) % 4
	data += strings.Repeat("=", missing)
	res, err := base64.URLEncoding.DecodeString(data)
	fmt.Println("  decodebase64urlsafe is :", string(res), err)
	return base64.URLEncoding.DecodeString(data)
}

func Base64UrlSafeEncode(source []byte) string {
	// Base64 Url Safe is the same as Base64 but does not contain '/' and '+' (replaced by '_' and '-') and trailing '=' are removed.
	bytearr := base64.StdEncoding.EncodeToString(source)
	safeurl := strings.Replace(string(bytearr), "/", "_", -1)
	safeurl = strings.Replace(safeurl, "+", "-", -1)
	safeurl = strings.Replace(safeurl, "=", "", -1)
	return safeurl
}

func AesDecrypt(crypted, key []byte) []byte {
	block, err := aes.NewCipher(key)
	if err != nil {
		fmt.Println("err is:", err)
	}
	blockMode := NewECBDecrypter(block)
	origData := make([]byte, len(crypted))
	blockMode.CryptBlocks(origData, crypted)
	origData = PKCS5UnPadding(origData)
	fmt.Println("source is :", origData, string(origData))
	return origData
}

func AesEncrypt(src, key string) []byte {
	block, err := aes.NewCipher([]byte(key))
	if err != nil {
		fmt.Println("key error1", err)
	}
	if src == "" {
		fmt.Println("plain content empty")
	}
	ecb := NewECBEncrypter(block)
	content := []byte(src)
	content = PKCS5Padding(content, block.BlockSize())
	crypted := make([]byte, len(content))
	ecb.CryptBlocks(crypted, content)
	// 普通base64编码加密 区别于urlsafe base64
	fmt.Println("base64 result:", base64.StdEncoding.EncodeToString(crypted))

	fmt.Println("base64UrlSafe result:", Base64UrlSafeEncode(crypted))
	return crypted
}

func PKCS5Padding(ciphertext []byte, blockSize int) []byte {
	padding := blockSize - len(ciphertext)%blockSize
	padtext := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(ciphertext, padtext...)
}

func PKCS5UnPadding(origData []byte) []byte {
	length := len(origData)
	// 去掉最后一个字节 unpadding 次
	unpadding := int(origData[length-1])
	return origData[:(length - unpadding)]
}

type ecbEncrypter ecb

// NewECBEncrypter returns a BlockMode which encrypts in electronic code book
// mode, using the given Block.
func NewECBEncrypter(b cipher.Block) cipher.BlockMode {
	return (*ecbEncrypter)(newECB(b))
}
func (x *ecbEncrypter) BlockSize() int { return x.blockSize }
func (x *ecbEncrypter) CryptBlocks(dst, src []byte) {
	if len(src)%x.blockSize != 0 {
		panic("crypto/cipher: input not full blocks")
	}
	if len(dst) < len(src) {
		panic("crypto/cipher: output smaller than input")
	}
	for len(src) > 0 {
		x.b.Encrypt(dst, src[:x.blockSize])
		src = src[x.blockSize:]
		dst = dst[x.blockSize:]
	}
}

type ecbDecrypter ecb

// NewECBDecrypter returns a BlockMode which decrypts in electronic code book
// mode, using the given Block.
func NewECBDecrypter(b cipher.Block) cipher.BlockMode {
	return (*ecbDecrypter)(newECB(b))
}
func (x *ecbDecrypter) BlockSize() int { return x.blockSize }
func (x *ecbDecrypter) CryptBlocks(dst, src []byte) {
	if len(src)%x.blockSize != 0 {
		panic("crypto/cipher: input not full blocks")
	}
	if len(dst) < len(src) {
		panic("crypto/cipher: output smaller than input")
	}
	for len(src) > 0 {
		x.b.Decrypt(dst, src[:x.blockSize])
		src = src[x.blockSize:]
		dst = dst[x.blockSize:]
	}
}

// 签名加密
func Sign(sysParam map[string]string, busParam string, method string, key string) (string, error) {
	if len(sysParam) == 0 || sysParam == nil {
		return "", errors.New("sysParam Valid")
	}
	if method == "HmacSHA256" {
		// 生成加密参数
		decodeHexKey, _ := DecodeHexUpper(key)
		busContent := EncodeAES256HexUpper(busParam, decodeHexKey)
		return signWithSHA256(sysParam, busContent, key), nil
	} else if method == "RSAWithMD5" {
		return signWithRSA(sysParam, busParam, key), nil
	} else {
		return "", errors.New("method   Valid")
	}
}

// sha256方法加密
func signWithSHA256(sysParam map[string]string, busParam string, key string) string {
	if len(busParam) > 0 && busParam != "" && len(strings.TrimSpace(busParam)) > 0 {
		sysParam["content"] = busParam
	}
	var keys []string
	for k := range sysParam {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	buf := make([]string, 200)
	buf = append(buf, key)
	for _, v := range keys {
		if !strings.EqualFold("sign", v) {
			sysVal := v + sysParam[v]
			buf = append(buf, sysVal)
		}
	}
	buf = append(buf, key)
	newString := ""
	for _, v := range buf {
		newString += fmt.Sprintf("%s", v)
	}
	newKey, _ := DecodeHexUpper(key)
	retStr := encodeHmacSHA256HexUpper(newString, newKey)
	return retStr
}

// 中介方法
func encodeHmacSHA256HexUpper(data string, key []byte) string {
	dataByte := []byte(data)
	encodeHmac := encodeHmacSHA256(dataByte, key)
	retStr := bytesToHexString(encodeHmac)
	return strings.ToUpper(retStr)
}

// rsa方式加密
func signWithRSA(sysParam map[string]string, busParam string, key string) string {
	// 暂时用不到,不做整理了
	fmt.Println(sysParam, busParam, key)
	return ""
}

// 16进制字符串转换成byte
func DecodeHexUpper(str string) ([]byte, error) {
	return hex.DecodeString(strings.ToLower(str))
}

// 中介方法
func EncodeAES256HexUpper(data string, key []byte) string {
	dataByte := []byte(data)
	newByte, _ := AesECBEncrypt(dataByte, key)
	retStr := encodeHexUpper([]byte(newByte))
	return retStr
}

// boss返回结果解密
func DecodeAES256HexUpper(data string, key []byte) string {
	newData := strings.ToLower(data)
	dataByte,_ := hex.DecodeString(newData)
	newByte, _ := AesECBDecrypt(dataByte, key)
	return string(newByte)
}

// 16进制转换字符串-结果大写
func encodeHexUpper(data []byte) string {
	str := bytesToHexString(data)
	return strings.ToUpper(str)
}

// byte转16进制字符串
func bytesToHexString(b []byte) string {
	return hex.EncodeToString(b)
}

// 16进制字符串转bytes
func hexStringToBytes(hexString string) []byte {
	newHexString := strings.ToUpper(hexString)
	length := len(hexString) / 2
	newByte := []byte(newHexString)
	retByte := make([]byte, length)
	for i := 0; i < length; i++ {
		pos := i * 2
		retByte[i] = byte(byteToByte(newByte[pos])<<4 | byteToByte(newByte[pos+1]))
	}
	return retByte
}

// byte转换
func byteToByte(b byte) int {
	byteList := []byte("0123456789ABCDEF")
	var ret int
	for k, v := range byteList {
		if string(v) == string(b) {
			ret = k
		}
	}
	return ret
}

// 获取md5加密字符串
func getMD5Str(str string) string {
	md5Data := md5.New()
	md5Data.Reset()
	md5Data.Write([]byte(str))
	retString := bytesToHexString(md5Data.Sum(nil))
	return retString
}

// Hmac-sha256加密
func encodeHmacSHA256(data, key []byte) []byte {
	h := hmac.New(sha256.New, key)
	h.Write(data)
	return h.Sum(nil)
}

// md5加密
func MD5Util(s string) string {
	hexDigits := []byte{'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'}
	byteStr := []byte(s)
	MD5 := md5.New()
	MD5.Write(byteStr)
	MD5Data := MD5.Sum([]byte(nil))
	NewByte := make([]byte, len(MD5Data)*2)
	k := 0
	for i := 0; i < len(MD5Data); i++ {
		byte0 := MD5Data[i]
		NewByte[k] = hexDigits[byte0>>4&15]
		k++
		NewByte[k] = hexDigits[byte0&15]
		k++
	}
	return string(NewByte)
}

// AES/CBC解密数据--不加填充,数据加密
func AesCBCEncrypt(source string, key []byte) (string, error) {
	// 生成16进制加密key
	newKey := hexStringToBytes(getMD5Str(string(key)))
	block, err := aes.NewCipher(newKey)
	if err != nil {
		return "", err
	}
	// 数据处理
	dataLen := len([]byte(source))
	m := dataLen % 16
	if m != 0 {
		for i := 0; i < 16-m; i++ {
			source = source + " "
		}
	}
	newByte := []byte(source)
	// 初始向量IV必须是唯一
	iv := hexStringToBytes(getMD5Str(string(key)))
	// block大小和初始向量大小一定要一致
	mode := cipher.NewCBCEncrypter(block, iv)
	encryptData := make([]byte, len(newByte))
	mode.CryptBlocks(encryptData, newByte)
	return bytesToHexString(encryptData), nil
}

// AES/CBC解密数据--不加填充,数据解密
func AesCBCDecrypt(source, key string) (string, error) {
	// 生成16进制加密key
	newKey := hexStringToBytes(getMD5Str(key))
	block, err := aes.NewCipher(newKey)
	if err != nil {
		return "", err
	}
	// 16进制转换
	decodeBytes := hexStringToBytes(source)
	iv := hexStringToBytes(getMD5Str(key))
	mode := cipher.NewCBCDecrypter(block, iv)
	retData := make([]byte, len(decodeBytes))
	mode.CryptBlocks(retData, decodeBytes)
	return string(retData), nil
}

// AES/ECB/PKCS7模式加密--签名加密方式
func AesECBEncrypt(data, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return []byte{}, err
	}
	ecb := NewECBEncryptEr(block)
	// 加PKCS7填充
	content := PKCS7Padding(data, block.BlockSize())
	encryptData := make([]byte, len(content))
	// 生成加密数据
	ecb.CryptBlocks(encryptData, content)
	return encryptData, nil
}

// AES/ECB/PKCS7模式解密--签名解密方式
func AesECBDecrypt(data, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return []byte{}, err
	}
	ecb := NewECBDecryptEr(block)
	retData := make([]byte, len(data))
	ecb.CryptBlocks(retData, data)
	// 解PKCS7填充
	retData = PKCS7UnPadding(retData)
	return retData, nil
}

// ecb加密方法
type ecb struct {
	b         cipher.Block
	blockSize int
}

func newECB(b cipher.Block) *ecb {
	return &ecb{
		b:         b,
		blockSize: b.BlockSize(),
	}
}

type ecbEncryptEr ecb

func NewECBEncryptEr(b cipher.Block) cipher.BlockMode {
	return (*ecbEncryptEr)(newECB(b))
}

func (x *ecbEncryptEr) BlockSize() int { return x.blockSize }

func (x *ecbEncryptEr) CryptBlocks(dst, src []byte) {
	if len(src)%x.blockSize != 0 {
		panic("crypto/cipher: input not full blocks")
	}
	if len(dst) < len(src) {
		panic("crypto/cipher: output smaller than input")
	}
	for len(src) > 0 {
		x.b.Encrypt(dst, src[:x.blockSize])
		src = src[x.blockSize:]
		dst = dst[x.blockSize:]
	}
}

// ecb解密方法
type ecbDecryptEr ecb

func NewECBDecryptEr(b cipher.Block) cipher.BlockMode {
	return (*ecbDecryptEr)(newECB(b))
}

func (x *ecbDecryptEr) BlockSize() int { return x.blockSize }

func (x *ecbDecryptEr) CryptBlocks(dst, src []byte) {
	if len(src)%x.blockSize != 0 {
		panic("crypto/cipher: input not full blocks")
	}
	if len(dst) < len(src) {
		panic("crypto/cipher: output smaller than input")
	}
	for len(src) > 0 {
		x.b.Decrypt(dst, src[:x.blockSize])
		src = src[x.blockSize:]
		dst = dst[x.blockSize:]
	}
}

//TODO