package manager

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
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
	Request(p []string) error
}

type manager struct {
	cfg *config.Config
}

func New(cfg *config.Config) *manager {
	return &manager{
		cfg: cfg,
	}
}

func (m *manager) Request(p []string) error {
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
		fmt.Printf("set_param: response=%s\n", string(result))
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
			fmt.Printf("set_param: pack=%s\n", packDec)
		}

		if int(packJson["r"].(float64)) != 200 {
			fmt.Println("Failed to set parameter")
		}
	}
	return nil
}

func (m *manager) sendData(ip string, port int, data []byte) ([]byte, error) {
	if m.cfg.App.Verbose {
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
