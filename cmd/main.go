package main

import (
	"context"
	"fmt"
	"github.com/sirupsen/logrus"
	"github.com/spf13/viper"
	"log"
	"wrappernmap/pkg/NetVulnService"
)

func main() {
	fmt.Println("Is's starts")
	if err := initConfig(); err != nil {
		log.Fatalf("ошибка инициализации configs: %s", err.Error())
	}
	logger := InitLogger()

	port := viper.GetString("port")
	if port == "" {
		port = "8080"
	}
	port = ":" + port
	ctx := context.Background()
	err := NetVulnService.StartMyMicroservice(ctx, port, logger)
	if err != nil {
		logger.Fatalf("err in start microservice: %d", err)
	}

}
func InitLogger() *logrus.Logger {
	logger := logrus.New()

	level := viper.GetString("loglevel")
	parsedLevel, err := logrus.ParseLevel(level)
	if err != nil {

		return nil
	}
	logger.SetLevel(parsedLevel)
	return logger
}

func initConfig() error {
	viper.AddConfigPath("configs")
	viper.SetConfigName("config")
	return viper.ReadInConfig()
}
