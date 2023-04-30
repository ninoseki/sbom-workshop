package main

import (
	"fmt"

	"github.com/golang-module/carbon/v2"
)

func main() {
	fmt.Printf("Hello world at %s", carbon.Now().ToString())
}
