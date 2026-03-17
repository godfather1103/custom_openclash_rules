package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"os"
	"strings"

	"gopkg.in/yaml.v3"
)

type ClashConfig struct {
	Proxies []map[string]interface{} `yaml:"proxies"`
}

func main() {
	// 1. 检查命令行参数
	if len(os.Args) < 2 {
		fmt.Println("用法: go run main.go <YAML_URL_或_本地路径>")
		fmt.Println("示例: go run main.go https://example.com/config.yaml")
		fmt.Println("示例: go run main.go ./my_config.yaml")
		return
	}

	source := os.Args[1]
	var yamlData []byte
	var err error

	// 2. 加载数据
	if strings.HasPrefix(source, "http://") || strings.HasPrefix(source, "https://") {
		yamlData, err = fetchRemote(source)
	} else {
		yamlData, err = ioutil.ReadFile(source)
	}

	if err != nil {
		log.Fatalf("错误: 无法获取数据 - %v", err)
	}

	// 3. 解析 YAML
	var config ClashConfig
	if err := yaml.Unmarshal(yamlData, &config); err != nil {
		log.Fatalf("错误: YAML 解析失败 - %v", err)
	}

	// 4. 转换节点
	var result []string
	for _, p := range config.Proxies {
		pType := strings.ToLower(fmt.Sprintf("%v", p["type"]))
		var link string

		switch pType {
		case "ss", "shadowsocks":
			link = buildSS(p)
		case "ssr":
			link = buildSSR(p)
		case "vmess":
			link = buildVmess(p)
		case "vless":
			link = buildVless(p)
		case "trojan":
			link = buildTrojan(p)
		case "hysteria2", "hy2":
			link = buildHy2(p)
		case "snell":
			link = buildSnell(p)
		}

		if link != "" {
			result = append(result, link)
		}
	}

	// 5. 输出结果
	outputFile := "proxies.txt"
	err = ioutil.WriteFile(outputFile, []byte(strings.Join(result, "\n")), 0644)
	if err != nil {
		log.Fatalf("错误: 写入文件失败 - %v", err)
	}

	fmt.Printf("\n✨ 成功! 已从 [%s] 提取 %d 个节点 -> %s\n", source, len(result), outputFile)
}

// --- 工具函数 ---

func fetchRemote(urlStr string) ([]byte, error) {
	fmt.Printf("🌐 正在下载远程配置...")
	resp, err := http.Get(urlStr)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP 状态码错误: %d", resp.StatusCode)
	}
	return ioutil.ReadAll(resp.Body)
}

// --- 协议构造逻辑 ---

func buildSS(p map[string]interface{}) string {
	auth := fmt.Sprintf("%s:%s", p["cipher"], p["password"])
	authBase64 := base64.RawURLEncoding.EncodeToString([]byte(auth))
	return fmt.Sprintf("ss://%s@%s:%v#%s", authBase64, p["server"], p["port"], url.QueryEscape(fmt.Sprintf("%v", p["name"])))
}

func buildSSR(p map[string]interface{}) string {
	mainStr := fmt.Sprintf("%s:%v:%s:%s:%s:%s",
		p["server"], p["port"], p["protocol"], p["cipher"], p["obfs"],
		base64.RawURLEncoding.EncodeToString([]byte(fmt.Sprintf("%v", p["password"]))))
	u := url.Values{}
	u.Set("remarks", base64.RawURLEncoding.EncodeToString([]byte(fmt.Sprintf("%v", p["name"]))))
	return "ssr://" + base64.RawURLEncoding.EncodeToString([]byte(mainStr+"/?"+u.Encode()))
}

func buildVmess(p map[string]interface{}) string {
	m := map[string]interface{}{
		"v": "2", "ps": p["name"], "add": p["server"], "port": p["port"],
		"id": p["uuid"], "aid": p["alterId"], "net": p["network"], "type": "none",
	}
	if p["network"] == "ws" {
		if opts, ok := p["ws-opts"].(map[string]interface{}); ok {
			m["path"] = opts["path"]
			if headers, ok := opts["headers"].(map[string]interface{}); ok {
				m["host"] = headers["host"]
			}
		}
	}
	b, _ := json.Marshal(m)
	return "vmess://" + base64.StdEncoding.EncodeToString(b)
}

func buildVless(p map[string]interface{}) string {
	u := url.Values{}
	u.Set("encryption", "none")
	u.Set("type", fmt.Sprintf("%v", p["network"]))
	if sni, ok := p["sni"]; ok {
		u.Set("sni", fmt.Sprintf("%v", sni))
	}
	return fmt.Sprintf("vless://%s@%s:%v?%s#%s", p["uuid"], p["server"], p["port"], u.Encode(), url.QueryEscape(fmt.Sprintf("%v", p["name"])))
}

func buildTrojan(p map[string]interface{}) string {
	u := url.Values{}
	if sni, ok := p["sni"]; ok {
		u.Set("sni", fmt.Sprintf("%v", sni))
	}
	return fmt.Sprintf("trojan://%s@%s:%v?%s#%s", p["password"], p["server"], p["port"], u.Encode(), url.QueryEscape(fmt.Sprintf("%v", p["name"])))
}

func buildHy2(p map[string]interface{}) string {
	u := url.Values{}
	if sni, ok := p["sni"]; ok {
		u.Set("sni", fmt.Sprintf("%v", sni))
	}
	return fmt.Sprintf("hysteria2://%s@%s:%v?%s#%s", p["password"], p["server"], p["port"], u.Encode(), url.QueryEscape(fmt.Sprintf("%v", p["name"])))
}

func buildSnell(p map[string]interface{}) string {
	u := url.Values{}
	u.Set("psk", fmt.Sprintf("%v", p["psk"]))
	if v, ok := p["version"]; ok {
		u.Set("version", fmt.Sprintf("%v", v))
	}
	return fmt.Sprintf("snell://%s:%v?%s#%s", p["server"], p["port"], u.Encode(), url.QueryEscape(fmt.Sprintf("%v", p["name"])))
}
