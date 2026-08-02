package main

import "github.com/AndresGT/GoKit/logger"

func main() {

	log := logger.New(
		logger.WithColor(true),
		logger.WithLevel(logger.DebugLevel),
	)
	logger.SetDefault(log)

	log.Debug("hola")
	log.Info("info")
	log.Error("error")


	logger.Debug("hola que tal como estas")

	logger.Info("hola")
}
