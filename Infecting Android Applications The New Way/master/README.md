# Apk infector Archinome PoC

Program that infects APK with malicious code using DEX/Manifest patching

**Full description about What is it and How it works:**

https://www.orderofsixangles.com/en/2020/04/07/android-infection-the-new-way.html (EN)

https://www.orderofsixangles.com/ru/2020/07/04/Infecting-android-app-the-new-way.html (RU)

**Please read article berfore use it!**

Receives two args:
```
./Archinome path_to_apk output_apk_filename
```

To inject your malicious code, you should place file named payload.dex with malicious code that follow rules:

1. Class name within payload.dex - `aaaaaaaaaaaa.payload`

2. Method `public void executePayload()`

After you infect apk please sign it.

If there are problems make sure that:
   1. The original application works
   2. All file paths in PoC are correct
   3. There's nothing unusual in apkinfector.log.
   4. The name of the original Application class in the patched InjectedApp.dex is really in its place. 
   5. The target application uses its Application class. Otherwise, PoC inoperability is predictable.

If nothing helped, try to play with the `-min-api` parameter when compiling payload classes.
If nothing worked, then create an issue on github.


PoC includes files from https://github.com/avast/apkparser.

I am not a Go developer so forgive me for the quality of code
