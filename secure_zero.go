package ecc

import "runtime"

// SecureZeroBytes 将切片内容覆写为零，用于在用完敏感材质后降低驻留风险。
// KeepAlive 防止编译器把清零视为死存储而优化掉。
// 注意：无法保证硬件/其他合法引用中的副本被清除。
func SecureZeroBytes(data []byte) {
	clear(data)
	runtime.KeepAlive(data)
}
