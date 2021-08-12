<?php

namespace jdenoc\NetworkScanner\Tests;

use PHPUnit_Framework_TestCase as PhpUnitTestCase;
use Faker;
use jdenoc\NetworkScanner\Tests\NetworkScanner as TNS;

class NetworkScannerTest extends PhpUnitTestCase {

    /**
     * @var Faker\Generator
     */
    private static $faker;

    public static function setUpBeforeClass(){
        self::$faker = Faker\Factory::create();
    }

    /**
     * @test
     */
    public function normalise_mac_address_to_have_colon(){
        $test_mac_address = self::$faker->macAddress;
        $faked_mac_address_separator = substr($test_mac_address, 2, 1);

        $scanner = new TNS();
        $normalised_mac_address = $scanner->normalise_mac_address($test_mac_address, TNS::PHYSICAL_ADDRESS_SEPARATOR_COLON);

        $this->assertContains(TNS::PHYSICAL_ADDRESS_SEPARATOR_COLON, $normalised_mac_address);
        $this->assertEquals(
            str_replace($faked_mac_address_separator, TNS::PHYSICAL_ADDRESS_SEPARATOR_COLON, $test_mac_address),
            $normalised_mac_address
        );
    }

    /**
     * @return array
     */
    public function providerNormalisePhysicalAddressToHave(){
        return array(
            'dash'=>[TNS::PHYSICAL_ADDRESS_SEPARATOR_DASH],
            'colon'=>[TNS::PHYSICAL_ADDRESS_SEPARATOR_COLON],
            'no-separator'=>[TNS::PHYSICAL_ADDRESS_SEPARATOR_NA]
        );
    }

    /**
     * @test
     * @dataProvider providerNormalisePhysicalAddressToHave
     *
     * @param string $new_separator
     */
    public function normalisePhysicalAddressToHave($new_separator){
        $test_mac_address = self::$faker->macAddress;
        $faked_mac_address_separator = substr($test_mac_address, 2, 1);

        $scanner = new TNS();
        $normalised_mac_address = $scanner->normalise_physical_address($test_mac_address, $new_separator);

        if($new_separator !== TNS::PHYSICAL_ADDRESS_SEPARATOR_NA){
            // only care about this assert if there is a separator
            $this->assertContains($new_separator, $normalised_mac_address);
        }
        $this->assertEquals(
            str_replace($faked_mac_address_separator, $new_separator, $test_mac_address),
            $normalised_mac_address
        );
    }

    /**
     * @test
     */
    public function normalise_invalid_mac_address(){
        $test_mac_address = self::$faker->word;

        $scanner = new TNS();
        $normalised_mac_address = $scanner->normalise_mac_address($test_mac_address, TNS::PHYSICAL_ADDRESS_SEPARATOR_COLON);

        $this->assertEmpty($normalised_mac_address);
    }

    /**
     * @test
     */
    public function mac_address_is_invalid(){
        $scanner = new TNS();
        $invalid_mac_address = self::$faker->word;
        $valid_mac = $scanner->is_valid_mac_address($invalid_mac_address);
        $this->assertFalse($valid_mac);
    }

    /**
     * @test
     * @throws \Exception
     */
    public function failed_command_for_is_mac_address_on_network(){
        $mac_address = self::$faker->macAddress;

        $scanner = new TNS();
        $scanner->set_arp_failure(true);

        $on_network = $scanner->is_mac_address_on_network($mac_address);
        $this->assertFalse($on_network);
    }

    /**
     * @return array
     */
    public function providerMacAddressOnNetworkWithSpecifiedOsCheck(){
        return array(
            'Windows'=>[TNS::OS_WINDOWS],
            'BSD'=>[TNS::OS_BSD],
            'Unix'=>[TNS::OS_UNIX]
        );
    }

    /**
     * @test
     * @dataProvider providerMacAddressOnNetworkWithSpecifiedOsCheck
     *
     * @param string $os_const
     * @throws \Exception
     */
    public function macAddressOnNetworkWithSpecifiedOsCheck($os_const){
        $mac_address = self::$faker->macAddress;
        $ip_address = self::$faker->ipv4;

        $scanner = new TNS();
        $scanner->set_detectable_os($os_const);
        $scanner->add_mac_address_to_response($ip_address, $mac_address);

        $on_network = $scanner->is_mac_address_on_network($mac_address);
        $this->assertNotFalse($on_network);
        $this->assertEquals($ip_address, $on_network);
    }

    /**
     * @return array
     */
    public function providerMacAddressNotOnNetworkWithSpecifiedOsCheck(){
        return [
            'Windows'=>[TNS::OS_WINDOWS],
            'BSD'=>[TNS::OS_BSD],
            'Unix'=>[TNS::OS_UNIX]
        ];
    }

    /**
     * @test
     * @dataProvider providerMacAddressNotOnNetworkWithSpecifiedOsCheck
     *
     * @param string $os_const
     * @throws \Exception
     */
    public function macAddressNotOnNetworkWithSpecifiedOsCheck($os_const){
        $mac_address = self::$faker->macAddress;

        $scanner = new TNS();
        $scanner->set_detectable_os($os_const);
        $scanner->add_mac_address_to_response(self::$faker->ipv4, self::$faker->macAddress);

        $on_network = $scanner->is_mac_address_on_network($mac_address);
        $this->assertFalse($on_network);
    }

}