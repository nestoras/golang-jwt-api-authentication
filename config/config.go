package config

import (
	"fmt"
	"github.com/jinzhu/gorm"
	_ "github.com/jinzhu/gorm/dialects/mysql"
	"os"
	"encoding/json"
	"crypto/rsa"
	"io/ioutil"
	"github.com/dgrijalva/jwt-go"
)

type MysqlConfig struct {
	Host     string `json:"host"`
	Port     int    `json:"port"`
	User     string `json:"user"`
	Password string `json:"password"`
	Name     string `json:"name"`
}

type JwtConfig struct {
	PrivateKey string `json:"private"`
	PublicKey  string `json:"public"`
}

type Config struct {
	Port     int             `json:"port"`
	Env      string          `json:"env"`
	Pepper   string          `json:"pepper"`
	HMACKey  string          `json:"hmac_key"`
	Database MysqlConfig 	 `json:"database"`
	Jwt      JwtConfig   	 `json:"jwt"`
}

func LoadConfig() Config {
	f, err := os.Open(".config")
	if err != nil {
		panic(err)
	}
	var c Config
	dec := json.NewDecoder(f)
	err = dec.Decode(&c)
	if err != nil {
		panic(err)
	}
	fmt.Println("Successfully loaded .config")
	return c
}

func (c Config) IsProd() bool {
	return c.Env == "prod"
}

func LoadTestConfig() Config {
	f, err := os.Open("../.config_test")
	if err != nil {
		panic(err)
	}
	var c Config
	dec := json.NewDecoder(f)
	err = dec.Decode(&c)
	if err != nil {
		panic(err)
	}
	fmt.Println("Successfully loaded .config")
	return c
}

func (c MysqlConfig) Dialect() string {
	return "mysql"
}

func (c MysqlConfig) ConnectionInfo() string {
	if c.Password == "" {
		return fmt.Sprintf("%s@/%s?parseTime=true", c.User, c.Name)
	}
	return fmt.Sprintf("%s:%s@/%s?parseTime=true", c.User, c.Password, c.Name)
}


func GetMockDatabase(config MysqlConfig) *gorm.DB{
	testCfg := LoadTestConfig()
	testDbCfg := testCfg.Database
	dbConnect, err := gorm.Open(config.Dialect(),testDbCfg.ConnectionInfo())
	if err != nil {
		panic(err)
	}

	return dbConnect
}


func (c Config) GetPrivateKey() *rsa.PrivateKey {
	keyData, err := ioutil.ReadFile(c.Jwt.PrivateKey)
	if err != nil {
		panic(err.Error())
	}
	key, err := jwt.ParseRSAPrivateKeyFromPEM(keyData)
	if err != nil {
		panic(err.Error())
	}
	return key
}

func (c Config) GetPublicKey() *rsa.PublicKey{
	keyData, err := ioutil.ReadFile(c.Jwt.PublicKey)
	if err != nil {
		panic(err.Error())
	}
	key, err := jwt.ParseRSAPublicKeyFromPEM(keyData)
	if err != nil {
		panic(err.Error())
	}
	return key
}

