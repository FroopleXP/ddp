package main

func checksum(data []byte) uint16 {
	if len(data)%2 != 0 {
		data = append(data, 0x00)
	}
	var sum uint32
	for i := 0; i < len(data); i += 2 {
		sum += uint32(uint16(data[i])<<8 | uint16(data[i+1]))
	}
	return ^(uint16(sum>>16) + uint16(sum))
}
