# Network Scanner

Library that allows you to scan a local network using `arp` and finds an IP address with a physical (mac) address

## Installation
Install the latest version with
```
composer require jdenoc/network-scanner
```

# Basic Usage
```php
<?php

use jdenoc\NetworkScanner\NetworkScanner;

$mac_address = "A1:B2:C3:D4:E5:F6";
$scanner = new NetworkScanner();
$scanner->is_physical_address_on_network($mac_address);
```