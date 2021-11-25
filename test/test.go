package main

import (
	"flag"
	"fmt"
	"net"
	"time"

	vrrp "github.com/trxa/VRRP-go"
)

var (
	VRID     int
	Priority int
	LocalIP  string
	RemoteIP string
)

func init() {
	flag.IntVar(&VRID, "vrid", 233, "virtual router ID")
	flag.IntVar(&Priority, "pri", 100, "router priority")
	flag.StringVar(&LocalIP, "lip", "172.19.0.1", "local IP")
	flag.StringVar(&RemoteIP, "rip", "172.19.0.2", "remote IP")
}

func main() {
	flag.Parse()
	var vr = vrrp.NewVirtualRouter(byte(VRID), net.ParseIP(LocalIP), false)
	vr.SetPeers(net.ParseIP(RemoteIP))
	vr.SetPriorityAndMasterAdvInterval(byte(Priority), time.Millisecond*800)
	vr.Enroll(vrrp.Backup2Master, func() {
		fmt.Println("backup to master")
	})
	vr.Enroll(vrrp.Master2Backup, func() {
		fmt.Println("master to backup")
	})
	vr.Enroll(vrrp.Master2Init, func() {
		fmt.Println("master to init")
	})
	vr.Enroll(vrrp.Backup2Init, func() {
		fmt.Println("backup to init")
	})
	vr.Enroll(vrrp.Init2Master, func() {
		fmt.Println("init to master")
	})
	vr.Enroll(vrrp.Init2Backup, func() {
		fmt.Println("init to backup")
	})
	go func() {
		time.Sleep(time.Minute * 5)
		vr.Stop()
	}()
	vr.StartWithEventSelector()
	fmt.Println("Done.")
}
