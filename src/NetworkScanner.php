<?php

namespace jdenoc\NetworkScanner;

class NetworkScanner {

    const OS_WINDOWS = 'windows';
    const OS_UNIX = 'unix';
    const OS_BSD = 'bsd';
    const PHYSICAL_ADDRESS_SEPARATOR_DASH = '-';
    const PHYSICAL_ADDRESS_SEPARATOR_COLON = ':';
    const PHYSICAL_ADDRESS_SEPARATOR_NA = '';
    const ARP_CMD_WINDOWS = 'arp -a';
    const ARP_CMD_UNIX = 'arp -n';
    const ARP_CMD_BSD = 'arp -a';

    /**
     * @var string
     */
    protected $system_os;

    public function __construct(){
        $this->system_os = PHP_OS;
    }

    /**
     * Checks to see if a provided physical address is on the local network
     * Will return the associated IP address on success
     * @throws \Exception
     * @param string $physical_address
     * @return string|false
     */
    public function is_physical_address_on_network($physical_address){
        if(!$this->is_valid_physical_address($physical_address)){
            return false;
        }

        $network_output = $this->arp_local_network();

        $is_available = false;
        foreach($network_output as $network_output_line){
            //Example Windows arp output:
            //  Internet Address      Physical Address      Type
            //  172.16.0.1           01-12-3b-44-53-d6     dynamic
            //  172.16.0.3           a0-4b-c2-de-93-23     dynamic

            //Example unix arp output:
            //Address                  HWtype  HWaddress           Flags Mask            Iface
            //172.16.0.3              ether   a0:4b:c2:de:93:23   C                     eth0
            //172.16.0.1              ether   01:12:3b:44:53:d6   C                     eth0

            //Example BSD apr output:
            //? (172.16.0.1) at 01:12:3b:44:53:d6 on epair0b expires in 662 seconds [ethernet]
            //? (172.16.0.3) at a0:4b:c2:de:93:23 on epair0b permanent [ethernet]

            if(
                stripos($network_output_line, $this->normalise_physical_address($physical_address, self::PHYSICAL_ADDRESS_SEPARATOR_COLON)) !== false
                || stripos($network_output_line, $this->normalise_physical_address($physical_address, self::PHYSICAL_ADDRESS_SEPARATOR_DASH)) !== false
                || stripos($network_output_line, $this->normalise_physical_address($physical_address, self::PHYSICAL_ADDRESS_SEPARATOR_NA)) !== false
            ){
                // extract IP address from line
                $ip_address_match = array();
                if(preg_match('/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/', $network_output_line, $ip_address_match) === 1){
                    $is_available = $ip_address_match[0];
                } else {
                    throw new \Exception("Mac address has been found, but there is no IP address associated with it");
                }
                break;
            }
        }

        return $is_available;
    }

    /**
     * Alias for is_physical_address_on_network()
     *
     * Checks to see if a provided physical address is on the local network
     * Will return the associated IP address on success
     * @throws \Exception
     * @param $mac_address
     * @return bool
     */
    public function is_mac_address_on_network($mac_address){
        return $this->is_physical_address_on_network($mac_address);
    }

    /**
     * @param string $physical_address
     * @return bool
     */
    public function is_valid_physical_address($physical_address){
        if (preg_match('/^([a-fA-F0-9]{2}[:|-]){5}[a-fA-F0-9]{2}$/', $physical_address) == 1){
            // 01:23:45:67:89:ab
            // 01-23-45-67-89-ab
            return true;
        } else if (preg_match('/^[a-fA-F0-9]{12}$/', $physical_address) == 1){
            // 0123456789ab
            return true;
        } else {
            return false;
        }
    }

    /**
     * Alias for is_valid_physical_address()
     * @param string $mac_address
     * @return bool
     */
    public function is_valid_mac_address($mac_address){
        return $this->is_valid_physical_address($mac_address);
    }

    /**
     * @param string $physical_address
     * @param string $new_separator
     * @return string
     */
    public function normalise_physical_address($physical_address, $new_separator){
        if(!$this->is_valid_physical_address($physical_address)){
            return '';
        }

        $physical_address = preg_replace("/[^A-Fa-f0-9 ]/", '', $physical_address);
        $split_physical_address = str_split($physical_address, 2);
        return implode($new_separator, $split_physical_address);
    }

    /**
     * Alias for normalise_physical_address()
     * @param string $mac_address
     * @param string $new_separator
     * @return string
     */
    public function normalise_mac_address($mac_address, $new_separator){
        return $this->normalise_physical_address($mac_address, $new_separator);
    }

    /**
     * @return array
     */
    protected function arp_local_network(){
        switch($this->detect_os()){
            case self::OS_WINDOWS:
                $arp_cmd = self::ARP_CMD_WINDOWS;
                break;
            case self::OS_BSD:
                $arp_cmd = self::ARP_CMD_BSD;
                break;
            case self::OS_UNIX:
            default:
                $arp_cmd = self::ARP_CMD_UNIX;
        }

        $arp_output = array();
        exec($arp_cmd, $arp_output);
        return $arp_output;
    }

    /**
     * @return string
     */
    protected function detect_os(){
        if (stripos($this->system_os, 'WIN') !== false) {
            return self::OS_WINDOWS;
        }elseif(stripos($this->system_os, 'BSD') !== false) {
            return self::OS_BSD;
        } else {
            // assume we're on a unix based system
            return self::OS_UNIX;
        }
    }

}