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
	listenAddr string = "127.0.0.1:8080"

	// кого по каким методам пускать
	ACLData string = `{
	"logger":    ["/main.Admin/Logging"],
	"stat":      ["/main.Admin/Statistics"],
	"biz_user":  ["/main.Biz/Check", "/main.Biz/Add"],
	"biz_admin": ["/main.Biz/*"]
}`
)

// чтобы не было сюрпризов когда где-то не успела преключиться горутина и не успело что-то стортовать
func wait(amout int) {
	time.Sleep(time.Duration(amout) * 10 * time.Millisecond)
}

// утилитарная функция для коннекта к серверу
func getGrpcConn(t *testing.T) *grpc.ClientConn {
	grpcConn, err := grpc.Dial(
		listenAddr,
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
	err := NetVulnService.StartMyMicroservice(ctx, listenAddr, logrus.New())
	if err != nil {
		t.Fatalf("cant start server initial: %v", err)
	}
	wait(1)
	finish() // при вызове этой функции ваш сервер должен остановиться и освободить порт
	wait(1)

	// теперь проверим что вы освободили порт и мы можем стартовать сервер ещё раз
	ctx, finish = context.WithCancel(context.Background())
	err = NetVulnService.StartMyMicroservice(ctx, listenAddr, logrus.New())
	if err != nil {
		t.Fatalf("cant start server again: %v", err)
	}
	wait(1)
	finish()
	wait(1)
}

// у вас наверняка будет что-то выполняться в отдельных горутинах
// этим тестом мы проверяем что вы останавливаете все горутины которые у вас были и нет утечек
// некоторый запас ( goroutinesPerTwoIterations*5 ) остаётся на случай рантайм горутин
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

func TestCheckVuln(t *testing.T) {
	ctx, finish := context.WithCancel(context.Background())
	err := NetVulnService.StartMyMicroservice(ctx, listenAddr, logrus.New())
	if err != nil {
		t.Fatalf("cant start server initial: %v", err)
	}
	wait(1)
	defer func() {
		finish()
		wait(1)
	}()

	conn := getGrpcConn(t)
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
		TcpPort: []int32{8080},
	})
	if err != nil {
		fmt.Printf("err in CheckVuln: %d", err)
		return
	}

	expectedData1 := []*protofiles.TargetResult{
		{Target: "127.0.0.1",
			Services: []*protofiles.Service{{Name: "http-proxy",
				Version: "",
				TcpPort: 8080,
				Vulns:   []*protofiles.Vulnerability{}}}},
	}
	resultsRaw := resp.GetResults()
	Data1 := make([]*protofiles.TargetResult, len(resultsRaw))
	for i, elem := range resultsRaw {
		servs := make([]*protofiles.Service, len(elem.Services))
		for j, m := range elem.Services {
			servs[j] = &protofiles.Service{Name: m.Name, Version: m.Version, TcpPort: m.TcpPort, Vulns: m.Vulns}
		}
		Data1[i] = &protofiles.TargetResult{Target: elem.Target,
			Services: servs,
		}
	}
	if !reflect.DeepEqual(Data1, expectedData1) {
		t.Fatalf("ans dont match\nhave %+v\nwant %+v", Data1, expectedData1)
	}

}

func TestScanHosts(t *testing.T) {
	s := NetVulnService.InitServer(logrus.New())
	go http.ListenAndServe(":8080", nil)

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

}
