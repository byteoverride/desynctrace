package config

import (
	"strings"

	"github.com/spf13/viper"
)

type Config struct {
	Target       string `mapstructure:"target"`
	Threads      int    `mapstructure:"threads"`
	Timeout      int    `mapstructure:"timeout"`
	Verbose      bool   `mapstructure:"verbose"`
	Proxy        string `mapstructure:"proxy"`
	UserAgent    string `mapstructure:"user_agent"`
	OutputFile   string `mapstructure:"output"`
	OutputFormat string `mapstructure:"format"`
}

func LoadConfig() (*Config, error) {
	v := viper.New()

	v.SetDefault("threads", 10)
	v.SetDefault("timeout", 10)
	v.SetDefault("verbose", false)
	v.SetDefault("user_agent", "DesyncTrace/1.0")
	v.SetDefault("format", "text")

	v.SetEnvPrefix("DESYNC")
	v.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))
	v.AutomaticEnv()

	var cfg Config
	if err := v.Unmarshal(&cfg); err != nil {
		return nil, err
	}

	return &cfg, nil
}
