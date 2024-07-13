// inspired by https://github.com/tomikaa87/gree-remote
package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/andreburgaud/crypt2go/ecb"
	"github.com/mkozjak/greego/internal/config"
	"github.com/mkozjak/greego/internal/handlers"
	"github.com/mkozjak/greego/internal/manager"
)

const GENERIC_KEY = "a3K8Bx%2r8Y7#xDh"

type ScanResult struct {
	IP   string
	Port int
	ID   string
	Name string
}

type Response struct {
	T    string `json:"t,omitempty"`
	I    int    `json:"i,omitempty"`
	UID  int    `json:"uid,omitempty"`
	CID  string `json:"cid,omitempty"`
	TID  string `json:"tid,omitempty"`
	Pack string `json:"pack,omitempty"`
}

type Config struct {
	Client          string
	SocketInterface string
	ID              string
	Key             string
}

var args struct {
	Server          string
	Command         string
	Client          string
	Broadcast       string
	ID              string
	Key             string
	Verbose         bool
	SocketInterface string
	Params          []string
}

func sendData(ip string, port int, data []byte) ([]byte, error) {
	if args.Verbose {
		fmt.Printf("send_data: ip=%s, port=%d, data=%s\n", ip, port, string(data))
	}

	conn, err := net.Dial("udp", fmt.Sprintf("%s:%d", ip, port))
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	_, err = conn.Write(data)
	if err != nil {
		return nil, err
	}

	buffer := make([]byte, 1024)
	conn.SetReadDeadline(time.Now().Add(15 * time.Second))
	n, err := conn.Read(buffer)
	if err != nil {
		return nil, err
	}

	return buffer[:n], nil
}

func createRequest(tcid, packEnc string, i int) string {
	return fmt.Sprintf(`{"cid":"app","i":%d,"t":"pack","uid":0,"tcid":"%s","pack":"%s"}`, i, tcid, packEnc)
}

func createStatusRequestPack(tcid string) string {
	return fmt.Sprintf(`{"cols":["Pow","Mod","SetTem","WdSpd","Air","Blo","Health","SwhSlp","Lig","SwingLfRig","SwUpDn","Quiet","Tur","StHt","TemUn","HeatCoolType","TemRec","SvSt"],"mac":"%s","t":"status"}`, tcid)
}

func addPKCS7Padding(data []byte) []byte {
	padding := aes.BlockSize - len(data)%aes.BlockSize
	padtext := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(data, padtext...)
}

func createCipher(key []byte) (cipher.Block, error) {
	return aes.NewCipher(key)
}

func decrypt(packEncoded, key string) (string, error) {
	block, err := createCipher([]byte(key))
	if err != nil {
		return "", err
	}

	decryptor := ecb.NewECBDecrypter(block)
	packDecoded, err := base64.StdEncoding.DecodeString(packEncoded)
	if err != nil {
		return "", err
	}

	packDecrypted := make([]byte, len(packDecoded))
	decryptor.CryptBlocks(packDecrypted, packDecoded)
	packUnpadded := packDecrypted[:bytes.LastIndex(packDecrypted, []byte{'}'})+1]

	return string(packUnpadded), nil
}

func decryptGeneric(packEncoded string) (string, error) {
	return decrypt(packEncoded, GENERIC_KEY)
}

func encrypt(pack, key string) (string, error) {
	block, err := createCipher([]byte(key))
	if err != nil {
		return "", err
	}

	encryptor := ecb.NewECBEncrypter(block)
	packPadded := addPKCS7Padding([]byte(pack))
	packEncrypted := make([]byte, len(packPadded))
	encryptor.CryptBlocks(packEncrypted, packPadded)

	return base64.StdEncoding.EncodeToString(packEncrypted), nil
}

func encryptGeneric(pack string) (string, error) {
	return encrypt(pack, GENERIC_KEY)
}

func searchDevices() {
	fmt.Printf("Searching for devices using broadcast address: %s\n", args.Broadcast)

	conn, err := net.ListenPacket("udp4", ":0")
	if err != nil {
		fmt.Println("Error: ", err)
		return
	}
	defer conn.Close()

	msg := []byte(`{"t":"scan"}`)
	broadcastAddr, err := net.ResolveUDPAddr("udp4", fmt.Sprintf("%s:7000", args.Broadcast))
	if err != nil {
		fmt.Println("Error: ", err)
		return
	}
	_, err = conn.WriteTo(msg, broadcastAddr)
	if err != nil {
		fmt.Println("Error: ", err)
		return
	}

	buffer := make([]byte, 1024)
	results := []ScanResult{}

	for {
		conn.SetReadDeadline(time.Now().Add(15 * time.Second))
		n, addr, err := conn.ReadFrom(buffer)
		if err != nil {
			break
		}

		rawJson := buffer[:n]
		if args.Verbose {
			fmt.Printf("search_devices: data=%s, raw_json=%s\n", string(buffer), string(rawJson))
		}

		var resp map[string]string
		if err := json.Unmarshal(rawJson, &resp); err != nil {
			fmt.Println("Error: ", err)
			continue
		}

		pack, err := decryptGeneric(resp["pack"])
		if err != nil {
			fmt.Println("Error: ", err)
			continue
		}

		var packMap map[string]interface{}
		if err := json.Unmarshal([]byte(pack), &packMap); err != nil {
			fmt.Println("Error: ", err)
			continue
		}

		cid := "<unknown-cid>"
		if val, ok := packMap["cid"]; ok && val != "" {
			cid = val.(string)
		} else if val, ok := resp["cid"]; ok {
			cid = val
		}

		results = append(results, ScanResult{
			IP:   addr.String(),
			Port: 7000,
			ID:   cid,
			Name: packMap["name"].(string),
		})

		if args.Verbose {
			fmt.Printf("search_devices: pack=%s\n", pack)
		}
	}

	if len(results) > 0 {
		for _, r := range results {
			bindDevice(r)
		}
	}
}

func bindDevice(searchResult ScanResult) {
	fmt.Printf("Binding device: %s (%s, ID: %s)\n", searchResult.IP, searchResult.Name, searchResult.ID)

	pack := fmt.Sprintf(`{"mac":"%s","t":"bind","uid":0}`, searchResult.ID)
	packEnc, err := encryptGeneric(pack)
	if err != nil {
		fmt.Println("Error: ", err)
		return
	}

	request := createRequest(searchResult.ID, packEnc, 1)
	result, err := sendData(searchResult.IP, 7000, []byte(request))
	if err != nil {
		fmt.Println("Error: ", err)
		return
	}

	var response map[string]string
	if err := json.Unmarshal(result, &response); err != nil {
		fmt.Println("Error: ", err)
		return
	}

	if response["t"] == "pack" {
		pack := response["pack"]
		packDec, err := decryptGeneric(pack)
		if err != nil {
			fmt.Println("Error: ", err)
			return
		}

		var bindResp map[string]interface{}
		if err := json.Unmarshal([]byte(packDec), &bindResp); err != nil {
			fmt.Println("Error: ", err)
			return
		}

		if args.Verbose {
			fmt.Printf("bind_device: resp=%s\n", packDec)
		}

		if bindResp["t"].(string) == "bindok" {
			key := bindResp["key"].(string)
			fmt.Printf("Bind to %s succeeded, key = %s\n", searchResult.ID, key)
		}
	}
}

func getParam() {
	fmt.Printf("Getting parameters: %s\n", strings.Join(args.Params, ", "))

	cols := strings.Join(args.Params, `","`)
	pack := fmt.Sprintf(`{"cols":["%s"],"mac":"%s","t":"status"}`, cols, args.ID)
	packEnc, err := encrypt(pack, args.Key)
	if err != nil {
		fmt.Println("Error: ", err)
		return
	}

	request := fmt.Sprintf(`{"cid":"app","i":0,"pack":"%s","t":"pack","tcid":"%s","uid":0}`, packEnc, args.ID)
	result, err := sendData(args.Client, 7000, []byte(request))
	if err != nil {
		fmt.Println("Error: ", err)
		return
	}

	var response Response
	if err := json.Unmarshal(result, &response); err != nil {
		fmt.Println("Error: ", err)
		return
	}

	if args.Verbose {
		fmt.Printf("get_param: response=%s\n", string(result))
	}

	if response.T == "pack" {
		pack := response.Pack
		packDec, err := decrypt(pack, args.Key)
		if err != nil {
			fmt.Println("Error: ", err)
			return
		}

		var packJson map[string]interface{}
		if err := json.Unmarshal([]byte(packDec), &packJson); err != nil {
			fmt.Println("Error: ", err)
			return
		}

		if args.Verbose {
			fmt.Printf("get_param: pack=%s, json=%s\n", pack, packJson)
		}

		cols := packJson["cols"].([]interface{})
		dat := packJson["dat"].([]interface{})
		for i, col := range cols {
			fmt.Printf("%s = %s\n", col, dat[i])
		}
	}
}

func setParam() {
	kvList := [][]string{}
	for _, param := range args.Params {
		parts := strings.Split(param, "=")
		if len(parts) != 2 {
			fmt.Printf("Invalid parameter: %s\n", param)
			os.Exit(1)
		}
		kvList = append(kvList, parts)
	}

	fmt.Printf("Setting parameters: %s\n", strings.Join(args.Params, ", "))

	opts := []string{}
	ps := []string{}
	for _, kv := range kvList {
		opts = append(opts, fmt.Sprintf(`"%s"`, kv[0]))
		ps = append(ps, kv[1])
	}

	pack := fmt.Sprintf(`{"opt":[%s],"p":[%s],"t":"cmd"}`, strings.Join(opts, ","), strings.Join(ps, ","))
	packEnc, err := encrypt(pack, args.Key)
	if err != nil {
		fmt.Println("Error: ", err)
		return
	}

	request := fmt.Sprintf(`{"cid":"app","i":0,"pack":"%s","t":"pack","tcid":"%s","uid":0}`, packEnc, args.ID)
	result, err := sendData(args.Client, 7000, []byte(request))
	if err != nil {
		fmt.Println("Error: ", err)
		return
	}

	var response Response
	if err := json.Unmarshal(result, &response); err != nil {
		fmt.Println("Error: ", err)
		return
	}

	if args.Verbose {
		fmt.Printf("set_param: response=%s\n", string(result))
	}

	if response.T == "pack" {
		pack := response.Pack
		packDec, err := decrypt(pack, args.Key)
		if err != nil {
			fmt.Println("Error: ", err)
			return
		}

		var packJson map[string]interface{}
		if err := json.Unmarshal([]byte(packDec), &packJson); err != nil {
			fmt.Println("Error: ", err)
			return
		}

		if args.Verbose {
			fmt.Printf("set_param: pack=%s\n", packDec)
		}

		if int(packJson["r"].(float64)) != 200 {
			fmt.Println("Failed to set parameter")
		}
	}
}

func main() {
	c := config.New()
	m := manager.New(c)
	h := handlers.New(m)

	http.HandleFunc("/api/v1/power", func(res http.ResponseWriter, req *http.Request) {
		switch req.Method {
		case "POST":
			h.SetPower(res, req)
		default:
			http.Error(res, "", http.StatusMethodNotAllowed)
		}
	})

	http.ListenAndServe(":4242", nil)
}
