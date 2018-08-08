package main

import (
	"flag"
	"log"
	"os"

	octarineadapter "istio.io/istio/mixer/adapter/octarine"
)

// Istio has overridden glog, so we're using the built-in log library

func main() {
	port := flag.String("port", "7782", "Port of the service.")
	flag.Parse()

	s, err := octarineadapter.NewOctarineAdapter(*port, "/octarine_id/gflags")
	if err != nil {
		log.Printf("unable to start sever: %v", err)
		os.Exit(-1)
	}

	shutdown := make(chan error, 1)
	go func() {
		s.Run(shutdown)
	}()
	_ = <-shutdown
}
