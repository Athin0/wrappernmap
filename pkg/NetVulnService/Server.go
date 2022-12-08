package NetVulnService

import (
	"fmt"
	"github.com/Ullaakut/nmap/v2"
	"golang.org/x/net/context"
	"google.golang.org/grpc"
	"net"
	"strconv"
	"wrappernmap/pkg/logger"
	"wrappernmap/pkg/protofiles"
)

type Server struct {
	log logger.ILogger
	protofiles.UnimplementedNetVulnServiceServer
}

func InitServer(logger logger.ILogger) *Server {
	srv := &Server{}
	srv.log = logger
	return srv
}

func StartMyMicroservice(ctx context.Context, addr string, logger logger.ILogger) error {
	lis, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("cant listen on port : %w", err)
	}
	server := grpc.NewServer()
	srv := InitServer(logger)
	protofiles.RegisterNetVulnServiceServer(server, srv)
	go func() {
		err := server.Serve(lis)
		if err != nil {
			logger.Fatalf("err in Serve: %d", err)
		}
	}()
	go func() {
		<-ctx.Done()
		server.Stop()
	}()
	return nil
}

func (s *Server) CheckVuln(ctx context.Context, req *protofiles.CheckVulnRequest) (*protofiles.CheckVulnResponse, error) {
	targets := req.GetTargets() //IP addresses
	ports := req.GetTcpPort()   // only TCP ports
	resultsChan := make(chan []*protofiles.TargetResult)
	var res []*protofiles.TargetResult
	s.log.Infoln("new connection")
	go func() {
		results, err := s.GetLogic(targets, ports)
		if err != nil {
			s.log.Fatalf("Err in GetLogic: %d", err)
			resultsChan <- nil
		}
		resultsChan <- results
	}()

	select {
	case <-ctx.Done(): //cancel function execution on context done
		s.log.Infoln("request canceled")
		return nil, fmt.Errorf("request canceled")
	case res = <-resultsChan:
		if res == nil {
			return nil, fmt.Errorf("err in Get Logic")
		}
	}
	return &protofiles.CheckVulnResponse{Results: res}, nil
}

func (s *Server) ScanHosts(targets []string, ports []int32) ([]nmap.Host, error) {
	// Equivalent to
	// nmap -sV -scrips=valnures -T4 192.168.0.0/24 .
	scanner, err := nmap.NewScanner(
		nmap.WithTargets(targets...), //"localhost"
		nmap.WithScripts("vulners"),  //our script with list of vulnerable
		nmap.WithPorts(int32toSet(ports)...),
		nmap.WithServiceInfo(),
		nmap.WithTimingTemplate(nmap.TimingAggressive),
		nmap.WithVersionAll(),
		// Filter out hosts that don't have any open ports
		nmap.WithFilterHost(func(h nmap.Host) bool {
			// Filter out hosts with no open ports.
			for idx := range h.Ports {
				if h.Ports[idx].Status() == "open" {
					return true
				}
			}
			return false
		}),
		nmap.WithFilterPort(func(p nmap.Port) bool {
			// Filter out no open ports.
			return p.State.String() == "open"
		}),
	)

	if err != nil {
		s.log.Fatalf("unable to create nmap scanner: %v", err)
		return nil, err
	}

	result, _, err := scanner.Run()
	if err != nil {
		s.log.Fatalf("nmap scan failed: %v", err)
		return nil, err
	}
	return result.Hosts, nil
}

// GetLogic create list of targets
func (s *Server) GetLogic(targets []string, ports []int32) ([]*protofiles.TargetResult, error) {
	hosts, err := s.ScanHosts(targets, ports)
	if err != nil {
		s.log.Fatalf("scan hosts failed: %v", err)
		return nil, err
	}

	ans := make([]*protofiles.TargetResult, 0)
	for _, host := range hosts {
		s.log.Infof("Host %s\n", host.Addresses[0])
		targ := &protofiles.TargetResult{Target: host.Addresses[0].Addr}
		services := make([]*protofiles.Service, 0)

		for _, port := range host.Ports {
			vulns := make([]*protofiles.Vulnerability, 0)
			s.log.Infoln(port)
			for _, elem := range port.Scripts {
				for _, table := range elem.Tables {
					//table -таблица с таблицей уязвимостей
					for _, re := range table.Tables {
						vulnerability := s.GetVulner(&re)
						vulns = append(vulns, vulnerability)
					}
				}
			}
			var version string
			if len(port.Service.Product) > 0 {
				version = port.Service.Product + " " + port.Service.Version
			}
			services = append(services, &protofiles.Service{Name: port.Service.Name, Version: version, TcpPort: int32(port.ID), Vulns: vulns})
		}
		targ.Services = services
		ans = append(ans, targ)
	}

	return ans, nil
}

// GetVulner get vulnerabilities list from response tables
func (s *Server) GetVulner(re *nmap.Table) *protofiles.Vulnerability {
	var cvss = float32(0)
	var idVuln string
	for _, values := range re.Elements {
		if values.Key == "id" {
			s.log.Infoln("id:", values.Value)
			idVuln = values.Value
		}
		if values.Key == "cvss" {
			s.log.Infof("cvss:", values.Value)
			if cvssTemple, err := strconv.ParseFloat(values.Value, 32); err == nil {
				cvss = float32(cvssTemple)
			} else {
				s.log.Errorln("err in parse %d:", err)
			}
		}
	}
	return &protofiles.Vulnerability{Identifier: idVuln, CvssScore: cvss}
}

//utility function for conversion
func int32toSet(in []int32) (out []string) {
	out = make([]string, len(in))
	for i, a := range in {
		out[i] = strconv.Itoa(int(a))
	}
	return out
}
