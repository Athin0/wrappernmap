package main

import (
	"fmt"
	"google.golang.org/grpc"
	"log"
	"net"
	"wrappernmap/pkg/NetVulnService"
	"wrappernmap/pkg/protofiles"
)

func main() {
	fmt.Println("Is's starts")
	s := grpc.NewServer()
	srv := &NetVulnService.Server{}
	protofiles.RegisterNetVulnServiceServer(s, srv)

	l, err := net.Listen("tcp", ":8080")
	if err != nil {
		log.Fatalf("Err in listen: %d", err)
		return
	}
	if err := s.Serve(l); err != nil {
		log.Fatalf("Err in serve: %d", err)
		return
	}
}
