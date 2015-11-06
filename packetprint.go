package main

import (
	"fmt"
)

func PrettyPacketSplit(b []byte, splits []int) {
	for n, i := range splits {
		splits[n] = i / 8
	}
	fmt.Println("--------------")
	//	prev := 0
	for n, bit := range b {
		if len(splits) > 0 && n == splits[0] {
			//			prev = splits[0]
			splits = splits[1:]
			fmt.Println()
		}
		fmt.Printf("%5d ", n*8)
		//split if we hit a boundary
		fmt.Printf("%08b", bit)
	}
	fmt.Println("\n--------------")
}
