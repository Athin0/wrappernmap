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

func GetLogic(targets []string, ports []int32) ([]*protofiles.TargetResult, error) {
	// Equivalent to
	// nmap -sV -T4 192.168.0.0/24 with a filter to remove non-RTSP ports.
	//nmap -T4 -A -v 192.168.0.0/24
	scanner, err := nmap.NewScanner(

		nmap.WithTargets(targets...), //"localhost""\""+targets[0]+"\""
		nmap.WithScripts("vulners"),
		//nmap.WithPorts(ConvInt32toSet(ports)...),
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
	}

	result, _, err := scanner.Run()
	if err != nil {
		log.Fatalf("nmap scan failed: %v", err)
	}

	ans := make([]*protofiles.TargetResult, 0)
	for _, host := range result.Hosts {
		fmt.Printf("Host %s\n", host.Addresses[0])
		targ := &protofiles.TargetResult{Target: string(host.Addresses[0].Addr)}
		services := make([]*protofiles.Service, 0)

		for _, port := range host.Ports {
			vulns := make([]*protofiles.Vulnerability, 0)
			fmt.Println(port.ID)
			for _, elem := range port.Scripts {
				fmt.Println("id: ", elem.ID) //vulners1
				fmt.Println("output: ", elem.Output)
				for _, table := range elem.Tables {
					for _, re := range table.Tables {
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
						vulns = append(vulns, &protofiles.Vulnerability{Identifier: idVuln, CvssScore: cvss})

					}
				}

				println()
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
func ConvInt32toSet(in []int32) (out []string) {
	out = make([]string, len(in))
	for i, a := range in {
		out[i] = fmt.Sprint(a)
	}
	return out
}
