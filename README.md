# ApplePayUtils
![alt text](https://travis-ci.com/hoaknoppix/ApplePayUtils.svg?branch=master)[![Language grade: Java](https://img.shields.io/lgtm/grade/java/g/hoaknoppix/ApplePayUtils.svg?logo=lgtm&logoWidth=18)](https://lgtm.com/projects/g/hoaknoppix/ApplePayUtils/context:java)[![Total alerts](https://img.shields.io/lgtm/alerts/g/hoaknoppix/ApplePayUtils.svg?logo=lgtm&logoWidth=18)](https://lgtm.com/projects/g/hoaknoppix/ApplePayUtils/alerts/)

This is the java util to decrypt apple payload data from iOS.

## Usage 

With the ephemralKeyString and the encrypted data from ios app response json, these following static methods in AppleUtils.java can be used to decrypt encrypted data as byte[], decrypted JSON String or parse as any object from decrypted JSON:

  `byte[] decryptAsBytes(String ephemeralKeyString, String privateKeyString, String certificateString, String data);`
  
  `String decryptAsString(String ephemeralKeyString, String privateKeyString, String certificateString, String data);`
  
  `T decryptAsObjectFromJSON(Class<T> clazz, String ephemeralKeyString, String privateKeyString, String certificateString, String data);`
  
See [ApplePayUtilsTest.java](https://github.com/hoaknoppix/ApplePayUtils/blob/master/src/test/java/ApplePayUtilsTest.java)

## For iOS app 
See [Apple Pay Demo](https://github.com/hoaknoppix/ApplePayDemo)
