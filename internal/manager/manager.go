package manager

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"strings"
	"time"

	"github.com/andreburgaud/crypt2go/ecb"
	"github.com/mkozjak/greego/internal/config"
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

type Requester interface {
	SetParam(p []string) error
	GetParam(p []string) ([]interface{}, error)
}

type manager struct {
	cfg *config.Config
}

func New(cfg *config.Config) *manager {
	return &manager{
		cfg: cfg,
	}
}

func (m *manager) SetParam(p []string) error {
	kvList := [][]string{}
	for _, param := range p {
		parts := strings.Split(param, "=")
		if len(parts) != 2 {
			return errors.New(fmt.Sprintf("Invalid parameter: %s\n", param))
		}

		kvList = append(kvList, parts)
	}

	fmt.Printf("Setting parameters: %s\n", strings.Join(p, ", "))

	opts := []string{}
	ps := []string{}
	for _, kv := range kvList {
		opts = append(opts, fmt.Sprintf(`"%s"`, kv[0]))
		ps = append(ps, kv[1])
	}

	pack := fmt.Sprintf(`{"opt":[%s],"p":[%s],"t":"cmd"}`, strings.Join(opts, ","), strings.Join(ps, ","))
	packEnc, err := encrypt(pack, m.cfg.Client.Key)
	if err != nil {
		return err
	}

	request := fmt.Sprintf(`{"cid":"app","i":0,"pack":"%s","t":"pack","tcid":"%s","uid":0}`, packEnc, m.cfg.Client.ID)
	result, err := m.sendData(m.cfg.Client.IP, 7000, []byte(request))
	if err != nil {
		return err
	}

	var response Response
	if err := json.Unmarshal(result, &response); err != nil {
		return err
	}

	if m.cfg.App.Verbose {
		log.Printf("set_param: response=%s\n", string(result))
	}

	if response.T == "pack" {
		pack := response.Pack
		packDec, err := decrypt(pack, m.cfg.Client.Key)
		if err != nil {
			return err
		}

		var packJson map[string]interface{}
		if err := json.Unmarshal([]byte(packDec), &packJson); err != nil {
			return err
		}

		if m.cfg.App.Verbose {
			log.Printf("set_param: pack=%s\n", packDec)
		}

		if int(packJson["r"].(float64)) != 200 {
			log.Println("Failed to set parameter")
		}
	}
	return nil
}

func (m *manager) GetParam(p []string) ([]interface{}, error) {
	fmt.Printf("Getting parameters: %s\n", strings.Join(p, ", "))

	cols := strings.Join(p, `","`)
	pack := fmt.Sprintf(`{"cols":["%s"],"mac":"%s","t":"status"}`, cols, m.cfg.Client.ID)
	packEnc, err := encrypt(pack, m.cfg.Client.Key)
	if err != nil {
		return nil, err
	}

	request := fmt.Sprintf(`{"cid":"app","i":0,"pack":"%s","t":"pack","tcid":"%s","uid":0}`, packEnc, m.cfg.Client.ID)
	result, err := m.sendData(m.cfg.Client.IP, 7000, []byte(request))
	if err != nil {
		return nil, err
	}

	var response Response
	if err := json.Unmarshal(result, &response); err != nil {
		return nil, err
	}

	if m.cfg.App.Verbose {
		log.Printf("get_param: response=%s\n", string(result))
	}

	if response.T == "pack" {
		pack := response.Pack
		packDec, err := decrypt(pack, m.cfg.Client.Key)
		if err != nil {
			return nil, err
		}

		var packJson map[string]interface{}
		if err := json.Unmarshal([]byte(packDec), &packJson); err != nil {
			return nil, err
		}

		if m.cfg.App.Verbose {
			log.Printf("get_param: pack=%s, json=%s\n", pack, packJson)
		}

		cols := packJson["cols"].([]interface{})
		dat := packJson["dat"].([]interface{})

		if m.cfg.App.Verbose {
			for i, col := range cols {
				fmt.Printf("%s = %s\n", col, dat[i])
			}
		}

		return dat, nil
	}

	return nil, nil
}

func (m *manager) searchDevices() error {
	fmt.Printf("Searching for devices using broadcast address: %s\n", m.cfg.Client.Bcast)

	conn, err := net.ListenPacket("udp4", ":0")
	if err != nil {
		return err
	}
	defer conn.Close()

	msg := []byte(`{"t":"scan"}`)
	broadcastAddr, err := net.ResolveUDPAddr("udp4", fmt.Sprintf("%s:7000", m.cfg.Client.Bcast))
	if err != nil {
		return err
	}
	_, err = conn.WriteTo(msg, broadcastAddr)
	if err != nil {
		return err
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
		if m.cfg.App.Verbose {
			log.Printf("search_devices: data=%s, raw_json=%s\n", string(buffer), string(rawJson))
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

		if m.cfg.App.Verbose {
			log.Printf("search_devices: pack=%s\n", pack)
		}
	}

	if len(results) > 0 {
		for _, r := range results {
			m.bindDevice(r)
		}
	}

	return nil
}

func (m *manager) sendData(ip string, port int, data []byte) ([]byte, error) {
	if m.cfg.App.Verbose {
		log.Printf("send_data: ip=%s, port=%d, data=%s\n", ip, port, string(data))
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

func (m *manager) bindDevice(searchResult ScanResult) {
	fmt.Printf("Binding device: %s (%s, ID: %s)\n", searchResult.IP, searchResult.Name, searchResult.ID)

	pack := fmt.Sprintf(`{"mac":"%s","t":"bind","uid":0}`, searchResult.ID)
	packEnc, err := encryptGeneric(pack)
	if err != nil {
		fmt.Println("Error: ", err)
		return
	}

	request := createRequest(searchResult.ID, packEnc, 1)
	result, err := m.sendData(searchResult.IP, 7000, []byte(request))
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

		if m.cfg.App.Verbose {
			log.Printf("bind_device: resp=%s\n", packDec)
		}

		if bindResp["t"].(string) == "bindok" {
			key := bindResp["key"].(string)
			log.Printf("Bind to %s succeeded, key = %s\n", searchResult.ID, key)
		}
	}
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
