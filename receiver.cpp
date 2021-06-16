#include <vector>

#include <unistd.h>
#include <sstream>
#include <iostream>
#include "SystemUtils.h"
#include "DpdkDeviceList.h"
#include "TablePrinter.h"


#include "WorkerThread.h"

#define MBUF_POOL_SIZE 16*1024-1

//Check for ports in advance
#define DEVICE_ID_1 0
#define DEVICE_ID_2 1

#define COLLECT_STATS_EVERY_SEC 2

//keep running flag 
bool bKeepRunning = true;

/**
 * @brief handles interrupt
 * 
 * @param cookie 
 */
void onApplicationInterrupted(void* cookie)
{
  bKeepRunning = false;
  std::cout << "\nShutting Down\n";
}

uint64_t u64MaxRx=0; /**< RX count */
uint64_t u64MaxTx=0; /**< TX count */

/**
 * @brief print Statistics
 * 
 * @param pRxDevice  pointer to receive device
 * @param pTxDevice  pointer to transmit device
 */
void printStats(pcpp::DpdkDevice* pRxDevice, pcpp::DpdkDevice* pTxDevice)
{
  pcpp::DpdkDevice::DpdkDeviceStats rxStats;
  pcpp::DpdkDevice::DpdkDeviceStats txStats;
  pRxDevice->getStatistics(rxStats);
  pTxDevice->getStatistics(txStats);

  std::vector<std::string> columnNames;
  columnNames.push_back(" ");
  columnNames.push_back("Total Packets");
  columnNames.push_back("Packets/sec");
  columnNames.push_back("Bytes");
  columnNames.push_back("Bits/sec");

  std::vector<int> columnLengths;
  columnLengths.push_back(10);
  columnLengths.push_back(15);
  columnLengths.push_back(15);
  columnLengths.push_back(15);
  columnLengths.push_back(15);

  pcpp::TablePrinter printer(columnNames, columnLengths);

  std::stringstream totalRx;
  totalRx << "rx" << "|" << rxStats.aggregatedRxStats.packets << "|" << rxStats.aggregatedRxStats.packetsPerSec << "|" << rxStats.aggregatedRxStats.bytes << "|" << rxStats.aggregatedRxStats.bytesPerSec*8;
  printer.printRow(totalRx.str(),'|');

  std::stringstream totalTx;
  totalTx << "tx" << "|" << txStats.aggregatedTxStats.packets << "|" << txStats.aggregatedTxStats.packetsPerSec << "|" << txStats.aggregatedTxStats.bytes << "|" << txStats.aggregatedTxStats.bytesPerSec*8;
  printer.printRow(totalTx.str(),'|');
  if(u64MaxTx < txStats.aggregatedTxStats.packetsPerSec)
  {
    u64MaxTx = txStats.aggregatedTxStats.packetsPerSec;
  }
  if (u64MaxRx < rxStats.aggregatedRxStats.packetsPerSec)
  {
    u64MaxRx = rxStats.aggregatedRxStats.packetsPerSec;
  }
  std::cout << "\nMaxTx/Sec " << u64MaxTx << std::endl;
  std::cout << "\nMaxRx/Sec " << u64MaxRx << std::endl;
}

int nNumberOfCores = 1;

/**
 * @brief main program for dpdk setup and receiving
 * 
 * @param argc 
 * @param argv 
 * @return int 
 */
int main(int argc,char* argv[])
{
  /* Register the on app close event handler */
  pcpp::ApplicationEventHandler::getInstance().onApplicationInterrupted(onApplicationInterrupted, NULL);


  /* initialize DPDK */
  pcpp::CoreMask coreMaskToUse = pcpp::getCoreMaskForAllMachineCores();
  pcpp::DpdkDeviceList::initDpdk(coreMaskToUse, MBUF_POOL_SIZE);

  /* Bind DPDK devices */
  pcpp::DpdkDevice* device1 = pcpp::DpdkDeviceList::getInstance().getDeviceByPort(DEVICE_ID_1);
  if (device1 == NULL){
    std::cout << "Cannot find device 1 with port '" << DEVICE_ID_1 << "'\n";
    return 1;
  }

  pcpp::DpdkDevice* device2 = pcpp::DpdkDeviceList::getInstance().getDeviceByPort(DEVICE_ID_2);
  if (device2 == NULL){
    std::cout << "Cannot find device 2 with port '" << DEVICE_ID_2 << "'\n";
    return 1;
  }

  /* Open DPDK devices */
  if (!device1->openMultiQueues(1,1))
  {
    std::cout << "Could'nt open device1 " << device1->getDeviceId() << " PMD " << device1->getPMDName().c_str(); 
    return 1;
  }
  
  if (!device2->openMultiQueues(1,1))
  {
    std::cout << "Could'nt open device2 " << device2->getDeviceId() << " PMD " << device2->getPMDName().c_str(); 
    return 1;
  }

  /* Create Worker Thread */
  std::vector<pcpp::DpdkWorkerThread*> workers;
  workers.push_back(new WorkerThread(device1, device2));
//  workers.push_back(new WorkerThread(device2, device1));
  
  /* Create core mask - use core 1 and 2 for the two threads */
  int workersCoreMask = 0;
  for (int i=1; i<=nNumberOfCores; i++)
  {
    //bascally create the value 0x6 (0b110) - bits that correspond to 1 and 2
    workersCoreMask = workersCoreMask | (1 << (i+1));
  }

  /* start capture in async mode */
  if(!pcpp::DpdkDeviceList::getInstance().startDpdkWorkerThreads(workersCoreMask, workers))
  {
    std::cout << "Couldn't start worker Threads\n";
    return 1;
  }

  uint64_t u64Counter = 0;
  int u64StatsCounter = 1;

  /* Keep running while True */
  while(bKeepRunning){
    //sleep for 1 second
    sleep(1);

    /* Print Sstats every COLLECT_STATS_EVERY_SEC seconds */
    if (u64Counter % COLLECT_STATS_EVERY_SEC == 0)
    {
      /* Clear screen and move to top left */
      const char clr[] = {27, '[', '2', 'J', '\0' };
      const char topLeft[] = {27, '[', '1', ';', '1', 'H', '\0' };
      std::cout << clr << topLeft ;

      std::cout << "\nStats " << u64StatsCounter++ << std::endl;
      std::cout << "========================\n";

      /* Print stats Device1 to Device2 */ 
      std::cout << "\nDevice1->Device2 stats: \n\n";
      printStats(device1,device2);

      /* Print stats Device2 to Device1 */
      std::cout << "\nDevice2->Device1 stats: \n\n";
      printStats(device2,device1);
 
    }
    u64Counter++;
  }
  
  /* Stop worker threads */
  pcpp::DpdkDeviceList::getInstance().stopDpdkWorkerThreads();
  return 0;

}
