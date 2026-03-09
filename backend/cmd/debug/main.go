package main

import (
	"fmt"
	"sast-backend/engine"
)

func main() {
	target := "/Users/yuy0ung/Desktop/SAST/jeesns/jeesns-web/src/main/java"
	idx := engine.NewSymbolTable()
	fmt.Println("Building index for:", target)
	err := idx.BuildIndex(target)
	if err != nil {
		fmt.Println("Error:", err)
		return
	}

	fmt.Println("ClassMap size:", len(idx.ClassMap))
	fmt.Println("MethodMap size:", len(idx.MethodMap))

	// Check UploadController
	className := "cn.jeesns.web.front.UploadController"
	methods, ok := idx.MethodMap[className]
	if !ok {
		fmt.Println("Full class name not found:", className)
		// Try simple name
		className = "UploadController"
		methods, ok = idx.MethodMap[className]
		if !ok {
			fmt.Println("Simple class name not found:", className)
			
			// List some keys
			fmt.Println("Listing first 5 keys in MethodMap:")
			i := 0
			for k := range idx.MethodMap {
				if i >= 5 { break }
				fmt.Println(k)
				i++
			}
			return
		} else {
			fmt.Println("Found by simple name:", className)
		}
	} else {
		fmt.Println("Found by full name:", className)
	}

	fmt.Println("Methods in", className, ":", len(methods))
	for m := range methods {
		fmt.Println("-", m)
	}
}
