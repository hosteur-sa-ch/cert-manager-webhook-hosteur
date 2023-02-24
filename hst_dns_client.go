package main

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/fcjr/aia-transport-go"
)

type HstApiClient struct {
	URL string

	FK_CLIENT string
	K_KEY string
	Token string
	TokenExp string
}

func NewHstApiClient (FK_CLIENT, K_KEY, URL string) *HstApiClient {
	
	hac := &HstApiClient{
		URL: URL,
		FK_CLIENT: FK_CLIENT,
		K_KEY: K_KEY,
	}

	if !hac.getToken() {
		return nil
	}

	return hac
}

func (hac *HstApiClient) checkTokenExp() {
	tokenExp, _ := time.Parse(time.DateTime, hac.TokenExp)
	if time.Now().Unix() >= tokenExp.Unix() {
		hac.getToken()
	}
}

func (hac *HstApiClient) getToken() bool {
	
	values := map[string]string{"FK_CLIENT": hac.FK_CLIENT, "K_KEY": hac.K_KEY}

	jsonValue, _ := json.Marshal(values)

	req, err := http.NewRequest("POST", hac.URL+"/api/auth", bytes.NewBuffer(jsonValue))
	if err != nil {
		println(err.Error())
		return false
	}

	req.Header.Set("Content-Type", "application/json; charset=UTF-8")

	tr, err := aia.NewTransport()
	if err != nil {
		println(err.Error())
		return false
	}
	client := &http.Client{Transport: tr}
	resp, err := client.Do(req)
	if err != nil {
		println(err.Error())
		return false
	}

	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return false
	}

	if resp.StatusCode != 200 {
		return false
	}

	var data map[string]interface{}
	if err := json.Unmarshal(body, &data); err != nil {
		println(err.Error())
		return false
	}

	hac.Token = data["S_TOKEN"].(string)
	hac.TokenExp = data["D_TOKEN_EXPIRATION"].(string)

	return true
}

func (hac *HstApiClient) findZone(domain, name, recordType string) string {
	hac.checkTokenExp()

	req, err := http.NewRequest("GET", hac.URL+"/client/dns/domain/"+strings.TrimSuffix(domain, ".")+"/zone", nil)
	if err != nil {
		println(err.Error())
		return ""
	}

	req.Header.Set("Authorization", hac.Token)
	req.Header.Set("IDClient", hac.FK_CLIENT)

	tr, err := aia.NewTransport()
	if err != nil {
		println(err.Error())
		return ""
	}
	client := &http.Client{Transport: tr}
	resp, err := client.Do(req)
	if err != nil {
		println(err.Error())
		return ""
	}

	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		println(err.Error())
		return ""
	}

	if resp.StatusCode != 200 {
		println("Record find: "+string(body))
		return ""
	}

	var data []map[string]interface{}
	if err := json.Unmarshal(body, &data); err != nil {
		println(err.Error())
		return ""
	}

	for _, d := range data {
		dID := d["id"].(string)
		dName := d["name"].(string)
		dRecordType := d["type"].(string)
		if dName == strings.TrimSuffix(name+domain, ".") && dRecordType == recordType {
			return dID
		}
	}
	return "notFound"
}

func (hac *HstApiClient) addRecord(domain, name, content, recordType, ttl, priority string) {
	hac.checkTokenExp()

	values := map[string]string{
		"S_DOMAINE": strings.TrimSuffix(domain, "."),
		"S_NAME": strings.TrimSuffix(name, "."),
		"S_TYPE": recordType,
		"S_CONTENT": content,
		"S_TTL": ttl,
		"S_PRIORITY": priority,
	}

	jsonValue, _ := json.Marshal(values)

	req, err := http.NewRequest("POST", hac.URL+"/client/dns/domain/"+strings.TrimSuffix(domain, ".")+"/zone", bytes.NewBuffer(jsonValue))
	if err != nil {
		println(err.Error())
		return
	}

	req.Header.Set("Content-Type", "application/json; charset=UTF-8")
	req.Header.Set("Authorization", hac.Token)
	req.Header.Set("IDClient", hac.FK_CLIENT)

	tr, err := aia.NewTransport()
	if err != nil {
		println(err.Error())
		return
	}
	client := &http.Client{Transport: tr}
	resp, err := client.Do(req)
	if err != nil {
		println(err.Error())
		return
	}

	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		println(err.Error())
		return
	}

	println("Record Add: "+string(body))
}

func (hac *HstApiClient) updateRecord(domain, ID, content, recordType, ttl, priority string) {
	hac.checkTokenExp()

	values := map[string]string{
		"S_TYPE": recordType,
		"S_CONTENT": content,
		"S_TTL": ttl,
		"S_PRIORITY": priority,
	}

	jsonValue, _ := json.Marshal(values)

	req, err := http.NewRequest("PUT", hac.URL+"/client/dns/domain/"+strings.TrimSuffix(domain, ".")+"/zone/"+ID, bytes.NewBuffer(jsonValue))
	if err != nil {
		println(err.Error())
		return
	}

	req.Header.Set("Content-Type", "application/json; charset=UTF-8")
	req.Header.Set("Authorization", hac.Token)
	req.Header.Set("IDClient", hac.FK_CLIENT)

	tr, err := aia.NewTransport()
	if err != nil {
		println(err.Error())
		return
	}
	client := &http.Client{Transport: tr}
	resp, err := client.Do(req)
	if err != nil {
		println(err.Error())
		return
	}

	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		println(err.Error())
		return
	}
	println("Record Update: "+string(body))
}

func (hac *HstApiClient) deleteRecord(domain, ID string) {
	hac.checkTokenExp()

	req, err := http.NewRequest("DELETE", hac.URL+"/client/dns/domain/"+strings.TrimSuffix(domain, ".")+"/zone/"+ID, nil)
	if err != nil {
		println(err.Error())
		return
	}

	req.Header.Set("Authorization", hac.Token)
	req.Header.Set("IDClient", hac.FK_CLIENT)

	tr, err := aia.NewTransport()
	if err != nil {
		println(err.Error())
		return
	}
	client := &http.Client{Transport: tr}
	resp, err := client.Do(req)
	if err != nil {
		println(err.Error())
		return
	}

	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		println(err.Error())
		return
	}

	println("Record Delete: "+string(body))
}
