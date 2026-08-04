// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package main

var sink int

//go:noinline
func benchmarkTarget(value int) int {
	return value + 1
}

func main() {
	sink = benchmarkTarget(1)
}
