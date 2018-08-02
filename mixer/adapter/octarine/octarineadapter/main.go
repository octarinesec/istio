package main

import (
	"flag"
	"os"

	"github.com/golang/glog"
	octarineadapter "istio.io/istio/mixer/adapter/octarine"
)

func main() {
	port := flag.String("port", "7782", "Port of the service.")
	flag.Parse()

	s, err := octarineadapter.NewOctarineAdapter(*port, "", "", "", "", "/octarine_id/gflags")
	if err != nil {
		glog.Errorf("unable to start sever: %v", err)
		os.Exit(-1)
	}

	shutdown := make(chan error, 1)
	go func() {
		s.Run(shutdown)
	}()
	_ = <-shutdown
}
