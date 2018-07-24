package main

import (
	"fmt"
	"os"

	octarineadapter "istio.io/istio/mixer/adapter/octarine"
)

func main() {
	addr := "7782"
	if len(os.Args) > 1 {
		addr = os.Args[1]
	}

	s, err := octarineadapter.NewOctarineAdapter(addr, "", "", "", "", "/octarine_id/gflags")
	if err != nil {
		fmt.Printf("unable to start sever: %v", err)
		os.Exit(-1)
	}

	shutdown := make(chan error, 1)
	go func() {
		s.Run(shutdown)
	}()
	_ = <-shutdown
}
