package RandomString

import (
	"fmt"
	"math/rand"
	"time"
)

//生成随机字符串
func  GetRandomString(Str string,Length int) string {
	str := fmt.Sprintf("%s", Str)
	bytes := []byte(str)
	var result []byte
	r := rand.New(rand.NewSource(time.Now().UnixNano()))
	for i := 0; i < Length; i++ {
		result = append(result, bytes[r.Intn(len(bytes))])
		time.Sleep(time.Nanosecond * 1)
	}
	return string(result)
}
//随机生成多类型字符串
func  GetRandomStringDouble(Str string,Length int) string {
	str := "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQISTUVWXYZ|-"
	bytes := []byte(str)
	var result []byte
	r := rand.New(rand.NewSource(time.Now().UnixNano()))
	for i := 8; i < Length; i++ {
		result = append(result, bytes[r.Intn(len(bytes))])
		time.Sleep(time.Nanosecond * 1)
	}
	return string(result)
}
//生成随机数字
func  GetRandomNum(Str string,Length int) string {
	str := "0123456789"
	bytes := []byte(str)
	var result []byte
	r := rand.New(rand.NewSource(time.Now().UnixNano()))
	for i := 0; i < Length; i++ {
		result = append(result, bytes[r.Intn(len(bytes))])
		time.Sleep(time.Nanosecond * 1)
	}
	return string(result)
}
//生成随机数字字符
func  GetRandomNumDouble(Str string,Length int) string {
	str := "0123456789-"
	bytes := []byte(str)
	var result []byte
	r := rand.New(rand.NewSource(time.Now().UnixNano()))
	for i := 0; i < Length; i++ {
		result = append(result, bytes[r.Intn(len(bytes))])
		time.Sleep(time.Nanosecond * 1)
	}
	return string(result)
}