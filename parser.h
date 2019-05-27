
//return Rad_Attribute_Details
std::char* getRadiusAttributeField(int code)
  switch(code){
    case 1: 
      return "User-Name";
    case 2: 
      return "User-Password";
    case 3: 
      return "CHAP-Password";
    case 4: 
      return "NAS-IP-Address";
    case 5: 
      return "NAS-Port";
    case 6: 
      return "Service-Type";
    case 7: 
      return "Framed-Protocol";
    case 8: 
      return "Framed-IP-Address";
    case 9: 
      return "Framed-IP-Netmask";
    case 10: 
      return "Framed-Routing";
    case 11: 
      return "Filter-Id";
    case 12: 
      return "Framed-MTU";
    case 13: 
      return "Framed-Compression";
    case 14: 
      return "Login-IP-Host";
    case 15: 
      return "Login-Service";
    case 16: 
      return "Login-TCP-Port";
    case 17: 
      return "(unassigned)";
    case 18: 
      return "Reply-Messagee";
    case 19: 
      return "Callback-Number";
    case 20: 
      return "Callback-Id";
    case 21: 
      return "(unassigned)";
    case 22: 
      return "Framed-Route";
    case 23: 
      return "Framed-IPX-Network";
    case 24: 
      return "State";
    case 25: 
      return "Class";
    case 26: 
      return "Vendor-Specific";
    case 27: 
      return "Session-Timeout";
    case 28: 
      return "Idle-Timeout";
    case 29: 
      return "Termination-Action";
    case 30: 
      return "Called-Station-Id";
    case 31: 
      return "Calling-Station-Id";
    case 32: 
      return "NAS-Identifier";
    case 33: 
      return "Proxy-State";
    case 34: 
      return "Login-LAT-Service";
    case 35: 
      return "Login-LAT-Node 3";
    case 36: 
      return "Login-LAT-Group";
    case 37: 
      return "Framed-AppleTalk-Link";
    case 38: 
      return "Framed-AppleTalk-Network";
    case 39: 
      return "Framed-AppleTalk-Zone";
    case 40: 
      return "Acct-Status-Type";
    case 41: 
      return "Acct-Delay-Time";
    case 42:
      return "Acct-Input-Octets";
    case 43:
      return "Acct-Output-Octects";
    case 44:
      return "Acct-Session-ID";
    case 45:
      return "Acct-Authentic";
    case 46: 
      return "Acct-Session-Time";
    case 47:
      return "Acct-Input-Packets";
    case 48:
      return "Acct-Output-Packets";
    case 49:
      return "Acct-Terminate-Cause";
       //1. User request
       //2. Lost carrier
       //3. Lost service
       //4. Idle timeout
       //5. Session timeout
       //6. Admin reset
       //7. Admin reboot
       //8. Port error
       //9. NAS error
       //10.  NAS request
       //11.  NAS reboot
       //12.  Port unneeded
       //13.  Port pre-empted
       //14.  Port suspended
       //15.  Service unavailable
       //16.  Callback
       //17.  User error
       //18.  Host request
    case 50:
      return "Acct-Multi-Session-ID";
    case 51:
      return "Acct-Link-Count";
    case 52:
      return "Acct-Input-Gigawords";
    case 53:
      return "Acct-Output-Gigawords";
    case 55:
      return "Event-TimeStamp";
    case 60: 
      return "CHAP-Challenge";
    case 61: 
      return "NAS-Port-Type";
    case 62: 
      return "Port-Limit";
    case 63: 
      return "Login-LAT-Port";
    default:
      return "Unknown";
  }
}

long long hexToDec(char hex[17]){
//  char hex[17];
  long long decimal, place;
  int i = 0, val, len;
  decimal = 0;
  place = 1;
  //Find the length of total number of hex digit
  len = strlen(hex);
  len--;
     
  for(i=0; hex[i]!='\0'; i++)
  {
    // Find the decimal representation of hex[i]
    if(hex[i]>='0' && hex[i]<='9'){
      val = hex[i] - 48;
    }else if(hex[i]>='a' && hex[i]<='f'){
      val = hex[i] - 97 + 10;
    }else if(hex[i]>='A' && hex[i]<='F'){
      val = hex[i] - 65 + 10;
    }
      decimal += val * pow(16, len);
      len--;
  }
//  printf("Hexadecimal number = %s\n", hex);
//  printf("Decimal number = %lld", decimal);
  
  return decimal;
}



