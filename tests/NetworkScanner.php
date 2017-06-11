<?php

namespace jdenoc\NetworkScanner\Tests;

use jdenoc\NetworkScanner\NetworkScanner as NetScan;

class NetworkScanner extends NetScan {

    private $arp_failure = false;
    private $response_component = array();

    /**
     * @param string $new_system_os
     */
    public function set_detectable_os($new_system_os){
        if(!in_array($new_system_os, array(self::OS_WINDOWS, self::OS_LINUX))){
            throw new \InvalidArgumentException("unapproved OS provided");
        }
        $this->system_os = $new_system_os;
    }

    /**
     * @param bool $fail
     */
    public function set_arp_failure($fail){
        $this->arp_failure = $fail;
    }

    /**
     * @param string $ip_address
     * @param string $physical_address
     */
    public function add_physical_address_to_response($ip_address, $physical_address){
        $this->response_component[] = array('ip'=>$ip_address, 'mac'=>$physical_address);
    }

    /**
     * Alias for add_physical_address_to_response()
     * @param string $ip_address
     * @param string $mac_address
     */
    public function add_mac_address_to_response($ip_address, $mac_address){
        $this->add_physical_address_to_response($ip_address, $mac_address);
    }

    /**
     * @return array
     */
    protected function arp_local_network(){
        if($this->detect_os() == self::OS_WINDOWS){
            $arp_output = $this->get_example_windows_arp_output();
        } else {
            $arp_output = $this->get_example_unix_arp_output();
        }

        if($this->arp_failure){
            $arp_output = $this->get_empty_arp_output();
        }
        return explode("\n", $arp_output);
    }

    /**
     * @return string
     */
    private function get_example_windows_arp_output(){
        $arp_output = '';
        $arp_output .= 'Internet Address      Physical Address      Type';
        $arp_output .= '192.168.5.1           01-12-3b-44-53-d6     dynamic';
        $arp_output .= '192.168.5.3           a0-4b-c2-de-93-23     dynamic';
        foreach($this->response_component as $response_component){
            $arp_output .= $response_component['ip'].'           '.$response_component['mac'].'    dynamic';
        }
        return $arp_output;
    }

    /**
     * @return string
     */
    private function get_example_unix_arp_output(){
        $arp_output = '';
        $arp_output .= 'Address                  HWtype  HWaddress           Flags Mask            Iface';
        $arp_output .= '192.168.5.3              ether   a0:4b:c2:de:93:23   C                     eth0';
        $arp_output .= '192.168.5.1              ether   01:12:3b:44:53:d6   C                     eth0';
        foreach($this->response_component as $response_component){
            $arp_output .= $response_component['ip'].'              ether   '.$response_component['mac'].'   C                     eth0';
        }
        return $arp_output;
    }

    /**
     * @return string
     */
    private function get_empty_arp_output(){
        return '';
    }

}