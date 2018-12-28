package moxa

import (
	"strings"
	"net"
	"os"
	"regexp"
	"strconv"
	"time"
	"crypto/md5"
	"fmt"
	"net/url"
	"net/http"
	"crypto/tls"
	"io/ioutil"
	"encoding/xml"
)

var debugmode = false

type WebProtocols string

const (
	Http WebProtocols = "http"
	Https WebProtocols = "https"
)

type MoxaData struct {
	SwitchAddr string
	Username string
	UserPass string
	Model string
	Name string
	Location string
	FirmwareVer string
	SerialNumber string
	WebProtocol WebProtocols
	AuthCookie string
}



const MOXAOIDSMAPKEYLEN = 8
var	MOXAPORTINDEXMAP = map[string][]int{
	"EDS-518A":{1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21},
	"EDS-518E":{1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21},
	"EDS-510A":{1,2,3,4,5,6,7,8,9,10,11,12,13},
	"EDS-510E":{1,2,3,4,5,6,7,8,9,10,11,12,13},
	"EDS-508A":{1,2,3,4,5,6,7,8,9,10,11},
	"EDS-505A":{1,2,3,4,5,6,7,8},
}

var	MOXAPORTNAME = map[string][]string{
	"EDS-518A":{"ethernet 1/1","ethernet 1/2","ethernet 1/3","ethernet 1/4","ethernet 1/5","ethernet 1/6","ethernet 1/7","ethernet 1/8","ethernet 1/9","ethernet 1/10","ethernet 1/11","ethernet 1/12","ethernet 1/13","ethernet 1/14","ethernet 1/15","ethernet 1/16","ethernet 1/17","ethernet 1/18","trunk 1","trunk 2","trunk 3"},
	"EDS-518E":{"ethernet 1/1","ethernet 1/2","ethernet 1/3","ethernet 1/4","ethernet 1/5","ethernet 1/6","ethernet 1/7","ethernet 1/8","ethernet 1/9","ethernet 1/10","ethernet 1/11","ethernet 1/12","ethernet 1/13","ethernet 1/14","ethernet 1/15","ethernet 1/16","ethernet 1/17","ethernet 1/18","trunk 1","trunk 2","trunk 3"},
	"EDS-510A":{"ethernet 1/1","ethernet 1/2","ethernet 1/3","ethernet 1/4","ethernet 1/5","ethernet 1/6","ethernet 1/7","ethernet 1/8","ethernet 1/9","ethernet 1/10","trunk 1","trunk 2","trunk 3"},
	"EDS-510E":{"ethernet 1/1","ethernet 1/2","ethernet 1/3","ethernet 1/4","ethernet 1/5","ethernet 1/6","ethernet 1/7","ethernet 1/8","ethernet 1/9","ethernet 1/10","trunk 1","trunk 2","trunk 3"},
	"EDS-508A":{"ethernet 1/1","ethernet 1/2","ethernet 1/3","ethernet 1/4","ethernet 1/5","ethernet 1/6","ethernet 1/7","ethernet 1/8","trunk 1","trunk 2","trunk 3"},
	"EDS-505A":{"ethernet 1/1","ethernet 1/2","ethernet 1/3","ethernet 1/4","ethernet 1/5","ethernet 1/6","trunk 1","trunk 2","trunk 3"},
}

type MacPortMI struct {
	Portindex int
	MacAddrs []string
}

type xmlddm struct {
	XMLName xml.Name `xml:"ddm"`
	SFPdata []sfpdatarecord `xml:"sfpData"`
}

type SFPDDM struct {
	Port string
	RXvalue string
	TXvalue string
}

type sfpdatarecord struct {
	Portname string `xml:"portName"`
	TXpower string `xml:"txPower"`
	RXpower string `xml:"rxPower"`
}

const movacmd = "!"
const moxapport = "4000"
const Moxaauthposturl = "/home.asp"
const MoxaDDMurl = "/xml/DDM.xml"
const maxmacpages = 32

func MoxamethotDebugmodeEnable(enable bool) (){
	debugmode = enable
}

//Input - ip or fqdn of the moxa switch
//Return: 0 if error, 1 if OK and MoxaData struct with moxa switch information
func Getmoxadata(SwitchStruct * MoxaData) (int){
	servAddr := SwitchStruct.SwitchAddr+":"+moxapport
	tcpAddr, err := net.ResolveTCPAddr("tcp", servAddr)
	if err != nil {
		println("ResolveTCPAddr failed:", err.Error())
		os.Exit(1)
	}

	conn, err := net.DialTCP("tcp", nil, tcpAddr)
	if err != nil {
		//println("Dial failed:", err.Error())
		//os.Exit(1)
		return 0
	}

	_, err = conn.Write([]byte(movacmd))
	if err != nil {
		println("Write to server failed:", err.Error())
		return 0
	}

	reply := make([]byte, 1024)

	//Read
	_, err = conn.Read(reply)
	if err != nil {
		println("Write to server failed:", err.Error())
		return 0
	}

	_, err = conn.Read(reply)
	if err != nil {
		println("Write to server failed:", err.Error())
		return 0
	}

	spst := strings.Split(string(reply),"\n")
	for _,a := range spst {

		if strings.Contains(a, "Name") {
			tind := strings.Index(a, "\t")
			nst := a[tind+1:]
			SwitchStruct.Name = nst
		}
		if strings.Contains(a, "Model") {
			tind := strings.Index(a, "\t")
			nst := a[tind+1:]
			SwitchStruct.Model = nst
		}
		if strings.Contains(a, "Location") {
			tind := strings.Index(a, "\t")
			nst := a[tind+1:]
			SwitchStruct.Location = nst
		}
		if strings.Contains(a, "Firmware Ver") {
			tind := strings.Index(a, "\t")
			nst := a[tind+2:]

			restin := regexp.MustCompile("[0-9].[0-9]")
			vnst := restin.FindString(nst)
			SwitchStruct.FirmwareVer = vnst
		}
		if strings.Contains(a, "Serial No") {
			//fmt.Println(a)
			tind := strings.Index(a, "\t")
			nst := a[tind+1:]
			SwitchStruct.SerialNumber = nst
		}
	}
	conn.Close()
	return 1
}

//
func MakeMoxaCookies(SwitchStruct * MoxaData)  (int){
	var hexhashstring string
	salt := "123"
	timestamp := strconv.FormatInt((time.Now().UnixNano()/1000000)+40000000 , 10)
	if (strings.Contains(SwitchStruct.Model,"EDS-510E")) || (strings.Contains(SwitchStruct.Model,"EDS-518E")){
		salt = "123"
		mhash := SwitchStruct.UserPass + salt
		mdhash := md5.New()
		mdhash.Write([]byte(mhash))
		bshash := mdhash.Sum(nil)

		hexhashstring = fmt.Sprintf("%x",bshash)
		SwitchStruct.AuthCookie = "User="+ SwitchStruct.Username +"; AccountName508=admin; Password508="+ hexhashstring +"; lasttime="+timestamp
		return 1
	}else{
		fver,_ := strconv.ParseFloat(SwitchStruct.FirmwareVer,32)
		if fver > 3.5 {
			sesidgen := "0000001111"
			salt = "0000001111"
			mhash := SwitchStruct.Username + SwitchStruct.UserPass + salt
			mdhash := md5.New()
			mdhash.Write([]byte(mhash))
			bshash := mdhash.Sum(nil)

			hexhashstring = fmt.Sprintf("%x",bshash)
			//fmt.Println(hexhashstring)

			SwitchStruct.AuthCookie = "sessionID="+sesidgen+"; "+"User="+SwitchStruct.Username+"; AccountName508="+SwitchStruct.Username+"; logpwd="+SwitchStruct.UserPass+";Password508="+hexhashstring+"; lasttime="+timestamp
			return 1
		}else{
			salt = "123"
			mhash := SwitchStruct.UserPass + salt
			mdhash := md5.New()
			mdhash.Write([]byte(mhash))
			bshash := mdhash.Sum(nil)

			hexhashstring = fmt.Sprintf("%x",bshash)
			//fmt.Println(hexhashstring)
			SwitchStruct.AuthCookie = "User="+SwitchStruct.Username+"; AccountName508="+SwitchStruct.Username+"; logpwd="+SwitchStruct.UserPass+";Password508="+hexhashstring+"; lasttime="+timestamp
			return 1
		}
	}
	return 0
}

func WEBGUIAuthOnMoxa(SwitchStruct * MoxaData)  (int){

	a31 := url.Values{}
	a31.Set("account",SwitchStruct.Username)
	a31.Set("password",SwitchStruct.UserPass)
	a31.Set("Loginin.x","0")
	a31.Set("Loginin.y","0")
	//debugmode := false

	tr := &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}
	client := &http.Client{Transport: tr}

	reqpr, _ := http.NewRequest("POST",string(SwitchStruct.WebProtocol)+"://"+SwitchStruct.SwitchAddr+Moxaauthposturl,strings.NewReader(a31.Encode()))
	reqpr.Header.Add("Cookie", SwitchStruct.AuthCookie)
	reqpr.Header.Add("Content-Type","application/x-www-form-urlencoded")
	resppr, errpr := client.Do(reqpr)
	if errpr != nil{
		fmt.Println(errpr)
		return 0
	}
	// Read response
	if debugmode == true{
		fmt.Println(resppr.Header)
	}

	if resppr == nil{
		fmt.Println("NoDataPr")
		return 0
	}
	datapr, errpr := ioutil.ReadAll(resppr.Body)
	if errpr != nil{
		fmt.Println(errpr)
		return 0
	}
	if debugmode == true{
		fmt.Println(string(datapr))
	}

	req, _ := http.NewRequest("GET",string(SwitchStruct.WebProtocol)+"://"+SwitchStruct.SwitchAddr+MoxaDDMurl,nil)

	// Set cookie
	req.Header.Add("Cookie", SwitchStruct.AuthCookie)
	req.Header.Add("Accept", "text/html,application/xhtml+xml,application/xml")
	req.Header.Add("User-Agent","Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:65.0) Gecko/20100101 Firefox/65.0")

	//resp, err := client.Do(req)
	respxml, err := client.Do(req)
	if err != nil{
		if debugmode == true{
			fmt.Println("DoRequest err")
		}
		fmt.Println(err)
		return 0
	}
	data, err := ioutil.ReadAll(respxml.Body)
	if err != nil{
		if debugmode == true{
			fmt.Println("Read data err")
		}
		fmt.Println(err)
		return 0
	}

	if debugmode == true {
		fmt.Println(respxml.Header)
	}

	if debugmode == true{
		fmt.Println(string(data))
	}

	// error handle
	if data != nil {
		//fmt.Printf("error = %s \n", err);
		if strings.Contains(string(data),"xml version="){
			return 1
		}
	}
	return 0

}

func GetMacAddressesOnPorts(SwitchStruct * MoxaData,portindexes []int)(int,[]MacPortMI){
	var MacPortList []MacPortMI
	MacPortList = make([]MacPortMI,0)

	for _,a := range portindexes{
		pagecount := 1
		var MacStrSt1 []string
		MacStrSt1 = make([]string,0)
		for b := 1; b < maxmacpages;b++{

			tr := &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}
			client := &http.Client{Transport: tr}

			// Declare 	HTTP Method and Url
			req, _ := http.NewRequest("GET",string(SwitchStruct.WebProtocol)+"://"+SwitchStruct.SwitchAddr+"/mac_address_table_setting.asp?mac_type="+strconv.Itoa(a+4)+"&list_page=1",nil)

			// Set cookie
			req.Header.Add("Cookie", SwitchStruct.AuthCookie)
			req.Header.Add("Accept", "text/xml")

			//resp, err := client.Do(req)
			resp, err := client.Do(req)
			if err != nil{
				if debugmode == true{
					fmt.Println(err)
				}
				return 0,nil

			}
			// Read response
			//fmt.Println(string(resp.Header))
			//fmt.Println(string(resp.Body))

			if resp == nil{
				if debugmode == true {
					fmt.Println("NoData")
				}

			}
			data, err := ioutil.ReadAll(resp.Body)
			if err != nil{
				fmt.Println(err)
				return 0,nil
			}

			if debugmode == true {
				fmt.Println(resp.Header)
			}

			if debugmode == true{
				fmt.Println(string(data))
			}

			// error handle
			if err != nil {
				//fmt.Printf("error = %s \n", err);
				return 0,nil
			}

			if b == 1{
				restpagecout := regexp.MustCompile("name=\"total_page\" value=\".+\"")
				pcountonpagestr := restpagecout.FindString(string(data))
				restpagecout = regexp.MustCompile("[0-9]+")
				pagecountstr := restpagecout.FindString(pcountonpagestr)
				pagecount,_ = strconv.Atoi(pagecountstr)
			}
			// Print response
			//fmt.Printf("Response = %s", string(data));
			rest := regexp.MustCompile("[0-9,a-f,A-F][0-9,a-f,A-F]-[0-9,a-f,A-F][0-9,a-f,A-F]-[0-9,a-f,A-F][0-9,a-f,A-F]-[0-9,a-f,A-F][0-9,a-f,A-F]-[0-9,a-f,A-F][0-9,a-f,A-F]-[0-9,a-f,A-F][0-9,a-f,A-F]")
			srt := rest.FindAllString(string(data),-1)
			for _,sd := range srt{
				//fmt.Println(sd + " | "+strconv.Itoa(a-4))
				if debugmode == true{
					fmt.Println(sd)
				}
				MacStrSt1 = append(MacStrSt1,sd)
				if debugmode == true{
					fmt.Println(MacStrSt1)
				}
			}

			if b >= pagecount{
				break
			}

		}
		MacPortList = append(MacPortList,MacPortMI{a,MacStrSt1})

	}
	return 1,MacPortList
}

func MoxaDDMinfo(SwitchStruct * MoxaData)(int,[]SFPDDM){
	tr := &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}
	client := &http.Client{Transport: tr}

	req, _ := http.NewRequest("GET",string(SwitchStruct.WebProtocol)+"://"+SwitchStruct.SwitchAddr+MoxaDDMurl,nil)

	// Set cookie
	req.Header.Add("Cookie", SwitchStruct.AuthCookie)
	req.Header.Add("Accept", "text/xml")

	//resp, err := client.Do(req)
	respxml, err := client.Do(req)
	if err != nil{
		if debugmode == true{
			fmt.Println(err)
		}
		return 0,nil
	}
	data, err := ioutil.ReadAll(respxml.Body)
	if err != nil{
		fmt.Println(err)
		return 0,nil
	}

	if debugmode == true {
		fmt.Println(respxml.Header)
	}

	if debugmode == true{
		fmt.Println(string(data))
	}

	// error handle
	if data != nil {
		//fmt.Printf("error = %s \n", err);
		if strings.Contains(string(data),"xml version="){
			var v xmlddm
			err = xml.Unmarshal(data,&v)
			if err != nil {
				os.Exit(1)
			}
			RetVal := make([]SFPDDM,0,0)
			for _,val := range v.SFPdata{
				RetVal = append(RetVal,SFPDDM{val.Portname,val.TXpower,val.RXpower})
			}
			return 1,RetVal

		}
	}
	return 0,nil
}

