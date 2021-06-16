#include "WorkerThread.h"
#include "radius.h"

WorkerThread::WorkerThread(pcpp::DpdkDevice* rxDevice, pcpp::DpdkDevice* txDevice) :
 m_RxDevice(rxDevice), m_TxDevice(txDevice), m_Stop(true), m_CoreId(MAX_NUM_OF_CORES+1)
{
}

bool WorkerThread::run(uint32_t coreId)
{
  //Register coreID for this worker
  m_CoreId =coreId;
  m_Stop = false;
  
  //initialize a  mbuf packet array of size 64
  pcpp::MBufRawPacket* mbufArr[64] = {};

  //endless loop until asking the thread to stop
  while(!m_Stop)
  {
    //receive packets from RX device
    
		pcpp::MBufRawPacket* packetArr[MAX_RECEIVE_BURST] = {};
    uint16_t numOfPackets = m_RxDevice->receivePackets(mbufArr, MAX_RECEIVE_BURST, 0);


    if (numOfPackets > 0){
      for(int i=0; i<numOfPackets; i++){
          pcpp:Packet parsedPacket(mbufArr[i]);
          Radius cRadiusInfoHolder;
          int nRet = 0;
          nRet = cRadiusInfoHolder.parseRadiusHeader(&parsedpacket);
          if(nRet<0)
            continue; // ERROR
          
          if(cRadiusInfoHolder.nRadiusCode == RADIUS_ACCOUTING_REQUEST){  
            nRet = cRadiusInfoHolder.readAttributebyBytes(parsedpacket.getLayerOfType<pcpp::RadiusLayer>());
            if(nRet<0)
              continue; // ERROR
            
            cRadiusInfoHolder.dump(); 
          }
      }
      
      //send received packet on the TX device
      m_TxDevice->sendPackets(mbufArr, numOfPackets,0);
    }
  }
  return true;
}

void WorkerThread::stop()
{
  m_Stop = true;
}

uint32_t WorkerThread::getCoreId()
{
  return m_CoreId;
}
