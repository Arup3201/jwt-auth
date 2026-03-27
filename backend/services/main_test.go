package services

import (
	"fmt"
	"log"
	"os"
	"testing"

	"example.com/go-jwt-auth/models"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

const (
	DB_PATH = "../db/test.db"
)

func TestMain(m *testing.M) {

	db, err := gorm.Open(sqlite.Open(DB_PATH), &gorm.Config{})
	if err != nil {
		log.Fatalf("open test database: %s", err)
	}

	db.AutoMigrate(&models.User{})

	code := m.Run()

	err = os.Remove(DB_PATH)
	if err != nil {
		log.Fatalf("remove file: %s", err)
	}

	fmt.Printf("===> Database removed.\n")

	os.Exit(code)
}
