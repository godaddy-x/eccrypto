package ecc

// SecureZeroBytes 将切片内容覆写为零，用于在用完敏感材质后降低驻留风险。
// 注意：无法保证编译器/硬件不保留副本，也不能阻止 GC 回收前其他合法引用仍可读。
func SecureZeroBytes(data []byte) {
	for i := range data {
		data[i] = 0
	}
}
