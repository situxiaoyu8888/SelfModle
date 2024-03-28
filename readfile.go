package ConfigModle

import (
	"fmt"
	"gopkg.in/ini.v1"
	"os"
)

func InitConfigFormIni(configFile string, mainField string, subField string) *ini.Key {
	cfg, err := ini.Load(configFile)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	return cfg.Section(mainField).Key(subField)
}
