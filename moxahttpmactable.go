package main

import (
	"fmt"
	"os"
	"./moxa"
	"flag"
)

func main(){
	username := flag.String("u","admin","moxa username")
	passwd := flag.String("p","moxa","moxa password")
	debugmode := flag.Int ("d",0,"for debugg set true")
	httpsmode := flag.Int("s",1,"using https")
	sfpinfo := flag.Int("f",0,"Show SFP DDM info")
	moxadata := flag.Int("m",1,"Moxa Switch data")
	switchaddress := flag.String("a","","moxa address (ip or DNS without prefix http or https")
	flag.Parse()
	mmethod := moxa.Http
	if *httpsmode == 1{
		mmethod = moxa.Https
	}

	if *debugmode == 1{
		moxa.MoxamethotDebugmodeEnable(true)
	}
	var TestMoxa = moxa.MoxaData{*switchaddress,*username,*passwd,"","","","","",mmethod,""}
	mstatus := moxa.Getmoxadata(&TestMoxa)
	if mstatus == 0 {
		os.Exit(1)
	}

	if *moxadata == 1{
		fmt.Println("Switch name: "+TestMoxa.Name)
		fmt.Println("Switch model: "+TestMoxa.Model)
		fmt.Println("Switch S/N: "+TestMoxa.SerialNumber)
		fmt.Println("Switch location: "+TestMoxa.Location)
		fmt.Println("-------------------------------------------------------")
	}

	mstatus = moxa.MakeMoxaCookies(&TestMoxa)
	if mstatus == 0 {
		os.Exit(1)
	}

	mstatus = moxa.WEBGUIAuthOnMoxa(&TestMoxa)
	if mstatus == 0{
		os.Exit(1)
	}

	pval,_ := moxa.MOXAPORTINDEXMAP[TestMoxa.Model[:moxa.MOXAOIDSMAPKEYLEN]]
	Err,MacList := moxa.GetMacAddressesOnPorts(&TestMoxa,pval)
	if Err == 0{
		os.Exit(1)
	}

	for _,elm := range MacList{
		if len(elm.MacAddrs) > 0 {
			PortName,indfind := moxa.MOXAPORTNAME[TestMoxa.Model[:moxa.MOXAOIDSMAPKEYLEN]]
			if indfind{
				fmt.Println(PortName[elm.Portindex-1])
			}else{
				fmt.Println(elm.Portindex)
			}

			for _,elminside := range elm.MacAddrs{
				fmt.Println(elminside)
			}
			fmt.Println("-------------------------------------------------------")
		}

	}
	if *sfpinfo == 1{
		fmt.Println("SFP data:")
		valid,SFPdata := moxa.MoxaDDMinfo(&TestMoxa)
		if valid == 0{
			os.Exit(1)
		}
		for _,SFPportdata := range SFPdata{
			fmt.Print(SFPportdata.Port)
			fmt.Print(" | ")
			fmt.Print(SFPportdata.RXvalue)
			fmt.Print(" | ")
			fmt.Println(SFPportdata.TXvalue)
		}
	}
}
