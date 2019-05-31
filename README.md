# Cifra de Hill
Implementação da Cifra de Hill em PHP

## Usage
```php
<?php
$hill = new Crypto\Hill();

$crypt = $hill->setKey([[2, 1], [-1, 4]])
    ->setMsg('CONFIRMADO')
    ->encrypt()
    ->getResult();
// print: uehjjkaqwd
    
$decrypt = $hill->setKey([[2, 1], [-1, 4]])
    ->setMsg('uehjjkaqwd')
    ->decrypt()
    ->getResult();
// print: confirmado
    
```
