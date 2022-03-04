# drvscanner
Scan for potentially vulnerable drivers

## Usage
By default the program will search for the following imports:
* MmMapIoSpace
* MmGetPhysicalAddress
* MmMapLockedPagesSpecifyCache
* MmBuildMdlForNonPagedPool

But this can be changed by adding a path to a txt file containing your desired imports separated by a newline when running the program. For example:
```drvscanner.exe C:\Windows\System32\Drivers target_imports.txt```.

The program will always search for IoCreateDevice regardless of whether it is passed in a custom imports.txt file or not.
