package vrrp

import (
	"fmt"
	"io"
	"net"
	"time"

	"github.com/trxa/VRRP-go/logger"
)

type VirtualRouter struct {
	vrID                          byte
	priority                      byte
	advertisementInterval         uint16
	advertisementIntervalOfMaster uint16
	skewTime                      uint16
	masterDownInterval            uint16
	preempt                       bool
	owner                         bool
	peers                         []net.IP
	//
	sourceIP            net.IP
	protectedIPaddrs    map[[4]byte]bool
	state               int
	iplayerInterface    ipConnection
	eventChannel        chan event
	packetQueue         chan *VRRPPacket
	advertisementTicker *time.Ticker
	masterDownTimer     *time.Timer
	transitionHandler   map[transition]func()
}

//NewVirtualRouter create a new virtual router with designated parameters
func NewVirtualRouter(vrID byte, sip net.IP, owner bool) *VirtualRouter {
	var vr = &VirtualRouter{}
	vr.vrID = vrID
	vr.owner = owner
	//default values that defined by RFC 5798
	if owner {
		vr.priority = 255
	}
	vr.state = stateInit
	vr.preempt = defaultPreempt
	vr.SetAdvInterval(defaultAdvertisementInterval)
	vr.SetPriorityAndMasterAdvInterval(defaultPriority, defaultAdvertisementInterval)

	//make
	vr.protectedIPaddrs = make(map[[4]byte]bool)
	vr.eventChannel = make(chan event, eventChannelSize)
	vr.packetQueue = make(chan *VRRPPacket, packetQueueSize)
	vr.transitionHandler = make(map[transition]func())
	vr.sourceIP = sip

	//set up IPv4 interface
	vr.iplayerInterface = newIPv4Conn(vr.sourceIP)
	logger.GLoger.Printf(logger.INFO, "virtual router %v initialized, working on %v", vrID, sip)
	return vr

}

func (r *VirtualRouter) SetPeers(peers ...net.IP) *VirtualRouter {
	r.peers = append([]net.IP(nil), peers...)
	return r
}

func (r *VirtualRouter) setPriority(priority byte) *VirtualRouter {
	if r.owner {
		return r
	}
	r.priority = priority
	return r
}

func (r *VirtualRouter) SetAdvInterval(interval time.Duration) *VirtualRouter {
	if interval < 10*time.Millisecond {
		panic("interval can not less than 10 ms")
	}
	r.advertisementInterval = uint16(interval / (10 * time.Millisecond))
	return r
}

func (r *VirtualRouter) SetPriorityAndMasterAdvInterval(priority byte, interval time.Duration) *VirtualRouter {
	r.setPriority(priority)
	if interval < 10*time.Millisecond {
		panic("interval can not be less than 10 ms")
	}
	r.setMasterAdvInterval(uint16(interval / (10 * time.Millisecond)))
	return r
}

func (r *VirtualRouter) setMasterAdvInterval(interval uint16) *VirtualRouter {
	r.advertisementIntervalOfMaster = interval
	r.skewTime = r.advertisementIntervalOfMaster - uint16(float32(r.advertisementIntervalOfMaster)*float32(r.priority)/256)
	r.masterDownInterval = 3*r.advertisementIntervalOfMaster + r.skewTime
	return r
}

func (r *VirtualRouter) SetPreemptMode(flag bool) *VirtualRouter {
	r.preempt = flag
	return r
}

func (r *VirtualRouter) AddIPvXAddr(ip net.IP) {
	var key [4]byte
	copy(key[:], ip)
	if _, ok := r.protectedIPaddrs[key]; ok {
		logger.GLoger.Printf(logger.ERROR, "VirtualRouter.AddIPvXAddr: add redundant IP addr %v", ip)
	} else {
		r.protectedIPaddrs[key] = true
	}
}

func (r *VirtualRouter) RemoveIPvXAddr(ip net.IP) {
	var key [4]byte
	copy(key[:], ip)
	if _, ok := r.protectedIPaddrs[key]; ok {
		delete(r.protectedIPaddrs, key)
		logger.GLoger.Printf(logger.INFO, "IP %v removed", ip)
	} else {
		logger.GLoger.Printf(logger.ERROR, "VirtualRouter.RemoveIPvXAddr: remove inexistent IP addr %v", ip)
	}
}

func (r *VirtualRouter) sendAdvertMessage() {
	for k := range r.protectedIPaddrs {
		logger.GLoger.Printf(logger.DEBUG, "send advert message of IP %v", net.IP(k[:]))
	}
	for _, p := range r.peers {
		var x = r.assembleVRRPPacket(p)
		if errOfWrite := r.iplayerInterface.WriteMessage(x, p); errOfWrite != nil {
			logger.GLoger.Printf(logger.ERROR, "VirtualRouter.WriteMessage: %v", errOfWrite)
		}
	}
}

//assembleVRRPPacket assemble VRRP advert packet
func (r *VirtualRouter) assembleVRRPPacket(daddr net.IP) *VRRPPacket {
	var packet VRRPPacket
	packet.SetPriority(r.priority)
	packet.SetVersion(VRRPv3)
	packet.SetVirtualRouterID(r.vrID)
	packet.SetAdvertisementInterval(r.advertisementInterval)
	packet.SetType()
	for k := range r.protectedIPaddrs {
		packet.AddIPvXAddr(net.IP(k[:]))
	}
	var pshdr PseudoHeader
	pshdr.Protocol = vrrpIPProtocolNumber
	pshdr.Daddr = daddr
	pshdr.Len = uint16(len(packet.ToBytes()))
	pshdr.Saddr = r.sourceIP
	packet.SetCheckSum(&pshdr)
	return &packet
}

//fetchVRRPPacket read VRRP packet from IP layer then push into Packet queue
func (r *VirtualRouter) fetchVRRPPacket() {
	for {
		if packet, errofFetch := r.iplayerInterface.ReadMessage(); errofFetch != nil {
			logger.GLoger.Printf(logger.INFO, "VirtualRouter.fetchVRRPPacket: %v", errofFetch)
			if errofFetch == io.EOF {
				return
			}
		} else {
			if r.vrID == packet.GetVirtualRouterID() {
				r.packetQueue <- packet
			} else {
				logger.GLoger.Printf(logger.ERROR, "VirtualRouter.fetchVRRPPacket: received a advertisement with different ID: %v", packet.GetVirtualRouterID())
			}

		}
		logger.GLoger.Printf(logger.DEBUG, "VirtualRouter.fetchVRRPPacket: received one advertisement")
	}
}

func (r *VirtualRouter) makeAdvertTicker() {
	r.advertisementTicker = time.NewTicker(time.Duration(r.advertisementInterval*10) * time.Millisecond)
}

func (r *VirtualRouter) stopAdvertTicker() {
	r.advertisementTicker.Stop()
}

func (r *VirtualRouter) makeMasterDownTimer() {
	if r.masterDownTimer == nil {
		r.masterDownTimer = time.NewTimer(time.Duration(r.masterDownInterval*10) * time.Millisecond)
	} else {
		r.resetMasterDownTimer()
	}
}

func (r *VirtualRouter) stopMasterDownTimer() {
	logger.GLoger.Printf(logger.DEBUG, "master down timer stopped")
	if !r.masterDownTimer.Stop() {
		select {
		case <-r.masterDownTimer.C:
		default:
		}
		logger.GLoger.Printf(logger.DEBUG, "master down timer expired before we stop it, drain the channel")
	}
}

func (r *VirtualRouter) resetMasterDownTimer() {
	r.stopMasterDownTimer()
	r.masterDownTimer.Reset(time.Duration(r.masterDownInterval*10) * time.Millisecond)
}

func (r *VirtualRouter) resetMasterDownTimerToSkewTime() {
	r.stopMasterDownTimer()
	r.masterDownTimer.Reset(time.Duration(r.skewTime*10) * time.Millisecond)
}

func (r *VirtualRouter) Enroll(transition2 transition, handler func()) bool {
	if _, ok := r.transitionHandler[transition2]; ok {
		logger.GLoger.Printf(logger.INFO, fmt.Sprintf("VirtualRouter.Enroll(): handler of transition [%s] overwrited", transition2))
		r.transitionHandler[transition2] = handler
		return true
	}
	logger.GLoger.Printf(logger.INFO, fmt.Sprintf("VirtualRouter.Enroll(): handler of transition [%s] enrolled", transition2))
	r.transitionHandler[transition2] = handler
	return false
}

func (r *VirtualRouter) transitionDoWork(t transition) {
	var work, ok = r.transitionHandler[t]
	if ok == false {
		//return fmt.Errorf("VirtualRouter.transitionDoWork(): handler of [%s] does not exist", t)
		return
	}
	work()
	logger.GLoger.Printf(logger.INFO, fmt.Sprintf("handler of transition [%s] called", t))
	return
}

/////////////////////////////////////////
func largerThan(ip1, ip2 net.IP) bool {
	if len(ip1) != len(ip2) {
		logger.GLoger.Printf(logger.FATAL, "largerThan: two compared IP addresses must have the same length")
	}
	for index := range ip1 {
		if ip1[index] > ip2[index] {
			return true
		} else if ip1[index] < ip2[index] {
			return false
		}
	}
	return false
}

//eventLoop VRRP event loop to handle various triggered events
func (r *VirtualRouter) eventLoop() {
	for {
		switch r.state {
		case stateInit:
			select {
			case event := <-r.eventChannel:
				switch event {
				case eventStart:
					logger.GLoger.Printf(logger.INFO, "event %v received", event)
					if r.priority == 255 || r.owner {
						logger.GLoger.Printf(logger.INFO, "enter owner mode")
						r.sendAdvertMessage()
						//set up advertisement timer
						r.makeAdvertTicker()
						logger.GLoger.Printf(logger.DEBUG, "enter stateMaster state")
						r.state = stateMaster
						r.transitionDoWork(Init2Master)
					} else {
						logger.GLoger.Printf(logger.INFO, "VR is not the owner of protected IP addresses")
						r.setMasterAdvInterval(r.advertisementInterval)
						//set up master down timer
						r.makeMasterDownTimer()
						logger.GLoger.Printf(logger.DEBUG, "enter stateBackup state")
						r.state = stateBackup
						r.transitionDoWork(Init2Backup)
					}
				}
			}
		case stateMaster:
			//check if shutdown event received
			select {
			case event := <-r.eventChannel:
				if event == eventShutdown {
					//close advert timer
					r.stopAdvertTicker()
					//send advertisement with priority 0
					var priority = r.priority
					r.setPriority(0)
					r.sendAdvertMessage()
					r.setPriority(priority)
					//transition into stateInit
					r.state = stateInit
					r.transitionDoWork(Master2Init)
					logger.GLoger.Printf(logger.INFO, "event %v received", event)
					//maybe we can break out the event loop
				}
			case <-r.advertisementTicker.C: //check if advertisement timer fired
				r.sendAdvertMessage()
			default:
				//nothing to do, just break
			}
			//process incoming advertisement
			select {
			case packet := <-r.packetQueue:
				if packet.GetPriority() == 0 {
					//I don't think we should anything here
				} else {
					if packet.GetPriority() > r.priority || (packet.GetPriority() == r.priority && largerThan(packet.Pshdr.Saddr, r.sourceIP)) {

						//cancel Advertisement timer
						r.stopAdvertTicker()
						//set up master down timer
						r.setMasterAdvInterval(packet.GetAdvertisementInterval())
						r.makeMasterDownTimer()
						r.state = stateBackup
						r.transitionDoWork(Master2Backup)
					} else {
						//just discard this one
					}
				}
			default:
				//nothing to do
			}
		case stateBackup:
			select {
			case event := <-r.eventChannel:
				if event == eventShutdown {
					//close master down timer
					r.stopMasterDownTimer()
					//transition into stateInit
					r.state = stateInit
					r.transitionDoWork(Backup2Init)
					logger.GLoger.Printf(logger.INFO, "event %s received", event)
				}
			default:
			}
			//process incoming advertisement
			select {
			case packet := <-r.packetQueue:
				if packet.GetPriority() == 0 {
					logger.GLoger.Printf(logger.INFO, "received an advertisement with priority 0, transit into stateMaster state", r.vrID)
					//Set the Master_Down_Timer to Skew_Time
					r.resetMasterDownTimerToSkewTime()
				} else {
					if r.preempt == false || packet.GetPriority() > r.priority || (packet.GetPriority() == r.priority && largerThan(packet.Pshdr.Saddr, r.sourceIP)) {
						//reset master down timer
						r.setMasterAdvInterval(packet.GetAdvertisementInterval())
						r.resetMasterDownTimer()
					} else {
						//nothing to do, just discard this one
					}
				}
			default:
				//nothing to do
			}
			select {
			//Master_Down_Timer fired
			case <-r.masterDownTimer.C:
				// Send an ADVERTISEMENT
				r.sendAdvertMessage()
				//Set the Advertisement Timer to Advertisement interval
				r.makeAdvertTicker()
				r.state = stateMaster
				r.transitionDoWork(Backup2Master)
			default:
				//nothing to do
			}
		}
	}
}

//eventSelector VRRP event selector to handle various triggered events
func (r *VirtualRouter) eventSelector() {
	for {
		switch r.state {
		case stateInit:
			select {
			case event := <-r.eventChannel:
				switch event {
				case eventStart:
					logger.GLoger.Printf(logger.INFO, "event %v received", event)
					if r.priority == 255 || r.owner {
						logger.GLoger.Printf(logger.INFO, "enter owner mode")
						r.sendAdvertMessage()
						//set up advertisement timer
						r.makeAdvertTicker()
						logger.GLoger.Printf(logger.DEBUG, "enter stateMaster state")
						r.state = stateMaster
						r.transitionDoWork(Init2Master)
					} else {
						logger.GLoger.Printf(logger.INFO, "VR is not the owner of protected IP addresses")
						r.setMasterAdvInterval(r.advertisementInterval)
						//set up master down timer
						r.makeMasterDownTimer()
						logger.GLoger.Printf(logger.DEBUG, "enter stateBackup state")
						r.state = stateBackup
						r.transitionDoWork(Init2Backup)
					}
				}
			}
		case stateMaster:
			//check if shutdown event received
			select {
			case event := <-r.eventChannel:
				if event == eventShutdown {
					//close advert timer
					r.stopAdvertTicker()
					//send advertisement with priority 0
					var priority = r.priority
					r.setPriority(0)
					r.sendAdvertMessage()
					r.setPriority(priority)
					//transition into stateInit
					r.state = stateInit
					r.transitionDoWork(Master2Init)
					logger.GLoger.Printf(logger.INFO, "event %v received", event)
					//maybe we can break out the event loop
				}
			case <-r.advertisementTicker.C: //check if advertisement timer fired
				r.sendAdvertMessage()
			case packet := <-r.packetQueue: //process incoming advertisement
				if packet.GetPriority() == 0 {
					//I don't think we should anything here
				} else {
					if packet.GetPriority() > r.priority || (packet.GetPriority() == r.priority && largerThan(packet.Pshdr.Saddr, r.sourceIP)) {
						//cancel Advertisement timer
						r.stopAdvertTicker()
						//set up master down timer
						r.setMasterAdvInterval(packet.GetAdvertisementInterval())
						r.makeMasterDownTimer()
						r.state = stateBackup
						r.transitionDoWork(Master2Backup)
					} else {
						//just discard this one
					}
				}
			}
		case stateBackup:
			select {
			case event := <-r.eventChannel:
				if event == eventShutdown {
					//close master down timer
					r.stopMasterDownTimer()
					//transition into stateInit
					r.state = stateInit
					r.transitionDoWork(Backup2Init)
					logger.GLoger.Printf(logger.INFO, "event %s received", event)
				}
			case packet := <-r.packetQueue: //process incoming advertisement
				if packet.GetPriority() == 0 {
					logger.GLoger.Printf(logger.INFO, "received an advertisement with priority 0, transit into stateMaster state", r.vrID)
					//Set the Master_Down_Timer to Skew_Time
					r.resetMasterDownTimerToSkewTime()
				} else {
					if r.preempt == false || packet.GetPriority() > r.priority || (packet.GetPriority() == r.priority && largerThan(packet.Pshdr.Saddr, r.sourceIP)) {
						//reset master down timer
						r.setMasterAdvInterval(packet.GetAdvertisementInterval())
						r.resetMasterDownTimer()
					} else {
						//nothing to do, just discard this one
					}
				}
			case <-r.masterDownTimer.C: //Master_Down_Timer fired
				// Send an ADVERTISEMENT
				r.sendAdvertMessage()
				//Set the Advertisement Timer to Advertisement interval
				r.makeAdvertTicker()
				r.state = stateMaster
				r.transitionDoWork(Backup2Master)
			}
		}
	}
}

func (vr *VirtualRouter) StartWithEventLoop() {
	go vr.fetchVRRPPacket()
	go func() {
		vr.eventChannel <- eventStart
	}()
	vr.eventLoop()
}

func (vr *VirtualRouter) StartWithEventSelector() {
	go vr.fetchVRRPPacket()
	go func() {
		vr.eventChannel <- eventStart
	}()
	vr.eventSelector()
}

func (vr *VirtualRouter) Stop() {
	vr.eventChannel <- eventShutdown
}

func (vr *VirtualRouter) Start() {
	vr.eventChannel <- eventStart
}
