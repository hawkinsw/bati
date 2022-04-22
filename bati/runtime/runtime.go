package runtime

import "unsafe"

type BaseOffset struct {
	base uint64
}

func NewBaseOffset(base uint64) *BaseOffset {
	return &BaseOffset{base}
}

func (bfst *BaseOffset) StringOff(nameOff uint32) uint64 {
	return bfst.base + uint64(nameOff)
}

func (bfst *BaseOffset) TypeOff(typeOff uint32) uint64 {
	return bfst.base + uint64(typeOff)
}

type Name struct {
	storage *byte
}

func NewString(storage *byte) *Name {
	return &Name{storage}
}

// Stolen (and modified, slightly) from go runtime source code.
func decodeVarint(storage *byte) (int, int) {
	v := 0
	storagePtr := unsafe.Pointer(storage)
	for i := 0; ; i++ {
		x := *(*byte)(unsafe.Pointer(uintptr(storagePtr) + uintptr(i)))
		v += int(x&0x7f) << (7 * i)
		if x&0x80 == 0 {
			return i + 1, v
		}
	}
}

func (n *Name) ToString() string {
	// TODO: Support tag data!
	storagePtr := unsafe.Pointer(n.storage)
	varintSize, stringLength := decodeVarint(
		(*byte)(unsafe.Pointer(uintptr(storagePtr) + uintptr(1))),
	)
	result := make([]byte, stringLength)
	for i := 0; i < stringLength; i++ {
		result[i] = *(*byte)(unsafe.Pointer(uintptr(storagePtr) + uintptr(varintSize) + uintptr(i) + uintptr(1)))
	}
	return string(result)
}
