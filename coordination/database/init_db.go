package database

import (
	"context"
	"log"
	"os"
	"time"

	_ "embed"

	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
	_ "modernc.org/sqlite"
)

var ctx = context.Background()
var db *gorm.DB

func InitializeDatabase(filename string) (err error) {
	newLogger := logger.New(
		log.New(os.Stdout, "\n", log.LstdFlags), // io writer
		logger.Config{
			SlowThreshold:             time.Second,   // Slow SQL threshold
			LogLevel:                  logger.Silent, // Log level
			IgnoreRecordNotFoundError: false,         // Ignore ErrRecordNotFound error for logger
			ParameterizedQueries:      false,         // Don't include params in the SQL log
			Colorful:                  true,          // Disable color
		},
	)

	db, err = gorm.Open(sqlite.Open(filename), &gorm.Config{
		Logger: newLogger,
	})
	db.AutoMigrate(&User{}, &Device{}, &Policy{}, &Group{})
	return
}
