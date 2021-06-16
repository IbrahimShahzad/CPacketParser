#pragma once

#include "DpdkDevice.h"
#include "DpdkDeviceList.h"

#define MAX_RECEIVE_BURST 64
class WorkerThread : public pcpp::DpdkWorkerThread
{
  private:
    pcpp::DpdkDevice* m_RxDevice;
    pcpp::DpdkDevice* m_TxDevice;
    bool m_Stop;
    uint32_t m_CoreId;

  public:
    //constructor
    WorkerThread(pcpp::DpdkDevice* rxDevice, pcpp::DpdkDevice* txDevice);

    //Destructor (Does Nothing)
    
    ~WorkerThread(){
    }

    //start worker thread
    bool run(uint32_t coreId);

    //ask worker thread to stop
    void stop();

    //get worker thread core ID
    uint32_t getCoreId();
};
