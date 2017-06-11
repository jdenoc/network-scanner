<?php

namespace jdenoc\NetworkScanner\Tests;

use Faker;
use jdenoc\NetworkScanner\Tests\NetworkScanner as TNS;

class NetworkScannerTest extends \PHPUnit_Framework_TestCase {

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
     * @test
     */
    public function normalise_mac_address_to_have_dash(){
        $test_mac_address = self::$faker->macAddress;
        $faked_mac_address_separator = substr($test_mac_address, 2, 1);

        $scanner = new TNS();
        $normalised_mac_address = $scanner->normalise_mac_address($test_mac_address, TNS::PHYSICAL_ADDRESS_SEPARATOR_DASH);

        $this->assertContains(TNS::PHYSICAL_ADDRESS_SEPARATOR_DASH, $normalised_mac_address);
        $this->assertEquals(
            str_replace($faked_mac_address_separator, TNS::PHYSICAL_ADDRESS_SEPARATOR_DASH, $test_mac_address),
            $normalised_mac_address
        );
    }

    /**
     * @test
     */
    public function normalise_mac_address_to_have_no_separator(){
        $test_mac_address = self::$faker->macAddress;
        $faked_mac_address_separator = substr($test_mac_address, 2, 1);

        $scanner = new TNS();
        $normalised_mac_address = $scanner->normalise_mac_address($test_mac_address, TNS::PHYSICAL_ADDRESS_SEPARATOR_NA);

        $this->assertNotContains(TNS::PHYSICAL_ADDRESS_SEPARATOR_COLON, $normalised_mac_address);
        $this->assertNotContains(TNS::PHYSICAL_ADDRESS_SEPARATOR_DASH, $normalised_mac_address);
        $this->assertEquals(
            str_replace($faked_mac_address_separator, TNS::PHYSICAL_ADDRESS_SEPARATOR_NA, $test_mac_address),
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

    public function failed_command_for_is_mac_address_on_network(){
        $mac_address = self::$faker->macAddress;

        $scanner = new TNS();
        $scanner->set_arp_failure(true);

        $on_network = $scanner->is_mac_address_on_network($mac_address);
        $this->assertFalse($on_network);
    }

    public function mac_address_on_network_with_windows_os_check(){
        $mac_address = self::$faker->macAddress;
        $ip_address = self::$faker->ipv4;

        $scanner = new TNS();
        $scanner->set_detectable_os(TNS::OS_WINDOWS);
        $scanner->add_mac_address_to_response($ip_address, $mac_address);

        $on_network = $scanner->is_mac_address_on_network($mac_address);
        $this->assertNotFalse($on_network);
        $this->assertEquals($ip_address, $on_network);
    }

    public function mac_address_not_on_network_with_windows_os_check(){
        $mac_address = self::$faker->macAddress;

        $scanner = new TNS();
        $scanner->set_detectable_os(TNS::OS_WINDOWS);
        $scanner->add_mac_address_to_response(self::$faker->ipv4, self::$faker->macAddress);

        $on_network = $scanner->is_mac_address_on_network($mac_address);
        $this->assertFalse($on_network);
    }

    public function mac_address_on_network_with_linux_os_check(){
        $mac_address = self::$faker->macAddress;
        $ip_address = self::$faker->ipv4;

        $scanner = new TNS();
        $scanner->set_detectable_os(TNS::OS_LINUX);
        $scanner->add_mac_address_to_response($ip_address, $mac_address);

        $on_network = $scanner->is_mac_address_on_network($mac_address);
        $this->assertNotFalse($on_network);
        $this->assertEquals($ip_address, $on_network);
    }

    public function mac_address_not_on_network_with_linux_os_check(){
        $mac_address = self::$faker->macAddress;

        $scanner = new TNS();
        $scanner->set_detectable_os(TNS::OS_LINUX);
        $scanner->add_mac_address_to_response(self::$faker->ipv4, self::$faker->macAddress);

        $on_network = $scanner->is_mac_address_on_network($mac_address);
        $this->assertFalse($on_network);
    }

}