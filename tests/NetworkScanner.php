<?php

namespace jdenoc\NetworkScanner\Tests;

use jdenoc\NetworkScanner\NetworkScanner as NetScan;

class NetworkScanner extends NetScan {

    private $arp_failure = false;
    private $response_component = array();

    public function __construct(){
        parent::__construct();

        $this->add_mac_address_to_response('172.16.0.2', '01-23-45-67-89-ab');
        $this->add_mac_address_to_response('172.16.0.3', 'CD:EF:01:23:45:67');
        $this->add_mac_address_to_response('172.16.0.4', '89abcdef0123');
    }

    /**
     * @param string $new_system_os
     */
    public function set_detectable_os($new_system_os){
        if(!in_array($new_system_os, array(self::OS_WINDOWS, self::OS_UNIX, self::OS_BSD))){
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
        switch($this->detect_os()){
            case self::OS_WINDOWS:
                $arp_output = $this->get_example_windows_arp_output();
                break;
            case self::OS_BSD:
                $arp_output = $this->get_example_bsd_arp_output();
                break;
            case self::OS_UNIX:
            default:
                $arp_output = $this->get_example_unix_arp_output();
        }

        if($this->arp_failure){
            $arp_output = $this->get_empty_arp_output();
        }
        return explode(PHP_EOL, $arp_output);
    }

    /**
     * @return string
     */
    private function get_example_windows_arp_output(){
        $arp_output = 'Internet Address      Physical Address      Type'.PHP_EOL;
        foreach($this->response_component as $response_component){
            $arp_output .= $response_component['ip'].'           ';
            $arp_output .= strtolower($this->normalise_mac_address($response_component['mac'], self::PHYSICAL_ADDRESS_SEPARATOR_DASH));
            $arp_output .= '    dynamic'.PHP_EOL;
        }
        return $arp_output;
    }

    /**
     * @return string
     */
    private function get_example_unix_arp_output(){
        $arp_output = 'Address                  HWtype  HWaddress           Flags Mask            Iface'.PHP_EOL;
        foreach($this->response_component as $response_component){
            $arp_output .= $response_component['ip'].'              ether   ';
            $arp_output .= strtolower($this->normalise_mac_address($response_component['mac'], self::PHYSICAL_ADDRESS_SEPARATOR_COLON));
            $arp_output .= '   C                     eth0'.PHP_EOL;
        }
        return $arp_output;
    }

    /**
     * @return string
     */
    private function get_example_bsd_arp_output(){
        $arp_output = '';
        foreach($this->response_component as $response_component){
            $arp_output .= '? ('.$response_component['ip'].' at ';
            $arp_output .= strtolower($this->normalise_physical_address($response_component['mac'], self::PHYSICAL_ADDRESS_SEPARATOR_COLON));
            $arp_output .= ' on epair0b permanent [ethernet]'.PHP_EOL;
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