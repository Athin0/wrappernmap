package wrappernmap

import (
	"context"
	"fmt"
	"github.com/sirupsen/logrus"
	"google.golang.org/grpc"
	"net/http"
	"reflect"
	"runtime"
	"testing"
	"time"
	"wrappernmap/pkg/NetVulnService"
	"wrappernmap/pkg/protofiles"
)

const (
	// какой адрес-порт слушать серверу
	listenPort string = ":8080"
	listenAddr string = "127.0.0.1:8080"
)

func wait(amout int) {
	time.Sleep(time.Duration(amout) * 10 * time.Millisecond)
}

// утилитарная функция для коннекта к серверу
func getGrpcConn(t *testing.T, port string) *grpc.ClientConn {
	grpcConn, err := grpc.Dial(
		listenPort,
		grpc.WithInsecure(),
	)
	if err != nil {
		t.Fatalf("cant connect to grpc: %v", err)
	}
	return grpcConn
}

// старт-стоп сервера
func TestServerStartStop(t *testing.T) {
	ctx, finish := context.WithCancel(context.Background())

	err := NetVulnService.StartMyMicroservice(ctx, ":8082", logrus.New())
	if err != nil {
		t.Fatalf("cant start server initial: %v", err)
	}

	wait(1)
	finish() // при вызове этой функции ваш сервер должен остановиться и освободить порт
	wait(1)

	// теперь проверим что вы освободили порт и мы можем стартовать сервер ещё раз
	ctx, finish = context.WithCancel(context.Background())

	err = NetVulnService.StartMyMicroservice(ctx, listenPort, logrus.New())
	if err != nil {
		t.Fatalf("cant start server again: %v", err)
	}

	wait(1)
	finish()
	wait(1)
}

func TestServerLeak(t *testing.T) {
	//return
	goroutinesStart := runtime.NumGoroutine()
	TestServerStartStop(t)
	goroutinesPerTwoIterations := runtime.NumGoroutine() - goroutinesStart

	goroutinesStart = runtime.NumGoroutine()
	var goroutinesStat []int
	for i := 0; i <= 25; i++ {
		TestServerStartStop(t)
		goroutinesStat = append(goroutinesStat, runtime.NumGoroutine())
	}
	goroutinesPerFiftyIterations := runtime.NumGoroutine() - goroutinesStart
	if goroutinesPerFiftyIterations > goroutinesPerTwoIterations*5 {
		t.Fatalf("looks like you have goroutines leak: %+v", goroutinesStat)
	}
}

func TestScanHosts(t *testing.T) {
	s := NetVulnService.InitServer(logrus.New())
	go http.ListenAndServe(listenPort, nil)

	sh, err := s.ScanHosts([]string{"127.0.0.1"}, []int32{8080})
	if err != nil {
		t.Fatalf("err in ScanHosts: %d", err)
	}

	if len(sh) <= 0 {
		t.Fatalf("ans len = 0")
	}
	port := sh[0].Ports[0]
	var version string
	if len(port.Service.Product) > 0 {
		version = port.Service.Product
		if len(port.Service.Version) != 0 {
			version += " " + port.Service.Version
		}
	}
	Data := protofiles.Service{Name: port.Service.Name, Version: version, TcpPort: int32(port.ID)}
	expectedData := protofiles.Service{Name: "http",
		Version: "Golang net/http server",
		TcpPort: 8080,
	}
	if !reflect.DeepEqual(Data, expectedData) {
		t.Fatalf("ans dont match\nhave %+v\nwant %+v", Data, expectedData)
	}
	return

}

func TestGetLogic(t *testing.T) {
	go func() {
		select {
		case <-time.After(300 * time.Second):
			fmt.Println("looks like you dont send anything to log stream in 300 sec")
			t.Errorf("looks like you dont send anything to log stream in 300 sec")
		}
	}()
	go http.ListenAndServe(listenPort, nil)
	s := NetVulnService.InitServer(logrus.New())
	resultsRaw, err := s.GetLogic([]string{"127.0.0.1"}, []int32{8080})
	if err != nil {
		fmt.Printf("err in CheckVuln: %d", err)
		return
	}
	if len(resultsRaw) == 0 {
		t.Fatal("result services is empty")
	}
	name := resultsRaw[0].Target
	if name != "127.0.0.1" {
		t.Fatalf("ans dont match targets\nhave %+v\nwant %+v", name, "127.0.0.1")
	}
	expectedData1 := []*protofiles.Service{{Name: "http",
		Version: "Golang net/http server ",
		TcpPort: 8080,
		Vulns:   []*protofiles.Vulnerability{}}}

	Data1 := make([]*protofiles.Service, len(resultsRaw[0].Services))
	for j, m := range resultsRaw[0].Services {
		Data1[j] = &protofiles.Service{Name: m.Name, Version: m.Version, TcpPort: m.TcpPort, Vulns: m.Vulns}
	}

	if !reflect.DeepEqual(Data1, expectedData1) {
		t.Fatalf("ans dont match\nhave %+v\nwant %+v", Data1, expectedData1)
	}
}

func TestCheckVuln(t *testing.T) {
	ctx, finish := context.WithCancel(context.Background())
	port := ":8081"
	portint32 := int32(8081)
	err := NetVulnService.StartMyMicroservice(ctx, port, logrus.New())
	if err != nil {
		t.Fatalf("cant start server initial: %d", err)
	}
	wait(1)
	defer func() {
		finish()
		wait(1)
	}()

	conn := getGrpcConn(t, port)
	defer conn.Close()

	biz := protofiles.NewNetVulnServiceClient(conn)

	wait(1)

	go func() {
		select {
		case <-ctx.Done():
			return
		case <-time.After(300 * time.Second):
			fmt.Println("looks like you dont send anything to log stream in 300 sec")
			t.Errorf("looks like you dont send anything to log stream in 300 sec")
		}
	}()

	resp, err := biz.CheckVuln(ctx, &protofiles.CheckVulnRequest{
		Targets: []string{"127.0.0.1"},
		TcpPort: []int32{portint32},
	})
	if err != nil {
		logrus.Fatalf("err in CheckVuln: %s", err.Error())
	}

	expectedData1 := []*protofiles.Service{{Name: "blackice-icecap",
		Version: "",
		TcpPort: portint32,
	}}

	resultsRaw := resp.GetResults()

	if len(resultsRaw) == 0 {
		t.Fatal("result services is empty")
	}
	name := resultsRaw[0].Target
	if name != "127.0.0.1" {
		t.Fatalf("ans dont match targets\nhave %+v\nwant %+v", name, "127.0.0.1")
	}

	Data1 := make([]*protofiles.Service, len(resultsRaw[0].Services))
	for j, m := range resultsRaw[0].Services {
		Data1[j] = &protofiles.Service{Name: m.Name, Version: m.Version, TcpPort: m.TcpPort, Vulns: m.Vulns}
	}

	if !reflect.DeepEqual(Data1, expectedData1) {
		t.Fatalf("ans dont match\nhave %+v\nwant %+v", Data1, expectedData1)
	}
}
