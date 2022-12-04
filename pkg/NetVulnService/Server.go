package NetVulnService

import (
	"fmt"
	"github.com/Ullaakut/nmap/v2"
	"golang.org/x/net/context"
	"log"
	"strconv"
	"wrappernmap/pkg/protofiles"
)

type Server struct {
	protofiles.UnimplementedNetVulnServiceServer
}

func (s *Server) CheckVuln(ctx context.Context, req *protofiles.CheckVulnRequest) (*protofiles.CheckVulnResponse, error) {
	targets := req.GetTargets() //IP addresses
	ports := req.GetTcpPort()   // only TCP ports
	results, err := GetLogic(targets, ports)
	if err != nil {
		log.Printf("Err in GetLogic: %d", err)
		return nil, err
	}

	return &protofiles.CheckVulnResponse{Results: results}, nil
}

func ScanHosts(targets []string, ports []int32) ([]nmap.Host, error) {
	// Equivalent to
	// nmap -sV -scrips=valnures -T4 192.168.0.0/24 .
	scanner, err := nmap.NewScanner(
		nmap.WithTargets(targets...), //"localhost""\""+targets[0]+"\""
		nmap.WithScripts("vulners"),
		nmap.WithPorts(ConvInt32toSet(ports)...),
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
	)

	if err != nil {
		log.Fatalf("unable to create nmap scanner: %v", err)
		return nil, err
	}

	result, _, err := scanner.Run()
	if err != nil {
		log.Fatalf("nmap scan failed: %v", err)
		return nil, err
	}
	return result.Hosts, nil
}

func GetLogic(targets []string, ports []int32) ([]*protofiles.TargetResult, error) {
	hosts, err := ScanHosts(targets, ports)
	if err != nil {
		log.Fatalf("scan hosts failed: %v", err)
		return nil, err
	}

	ans := make([]*protofiles.TargetResult, 0)
	for _, host := range hosts {
		fmt.Printf("Host %s\n", host.Addresses[0])
		targ := &protofiles.TargetResult{Target: host.Addresses[0].Addr}
		services := make([]*protofiles.Service, 0)

		for _, port := range host.Ports {
			vulns := make([]*protofiles.Vulnerability, 0)
			fmt.Println(port.ID)
			for _, elem := range port.Scripts {
				for _, table := range elem.Tables {
					//table -таблица с таблицей уязвимостей
					for _, re := range table.Tables {
						vulnerability := GetVulner(&re)
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

func GetVulner(re *nmap.Table) *protofiles.Vulnerability {
	var cvss = float32(0)
	var idVuln string
	for _, values := range re.Elements {
		if values.Key == "id" {
			fmt.Println("id:", values.Value)
			idVuln = values.Value
		}
		if values.Key == "cvss" {
			fmt.Println("cvss:", values.Value)
			if cvssTample, err := strconv.ParseFloat(values.Value, 32); err == nil {
				cvss = float32(cvssTample)
			} else {
				log.Printf("err in parse %d:", err)
			}
		}
	}
	return &protofiles.Vulnerability{Identifier: idVuln, CvssScore: cvss}
}
func ConvInt32toSet(in []int32) (out []string) {
	out = make([]string, len(in))
	for i, a := range in {
		out[i] = strconv.Itoa(int(a))
	}
	return out
}
