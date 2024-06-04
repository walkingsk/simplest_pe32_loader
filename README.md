# About

This demo is created according to the [Writing A PE Packer] article series from [wirediver]

I found some readers posted comments like "when running, the application gives an 'access denied' error", so I decided to try it once. That's the reason this reposity exists.

I'm NOT the original author.

# Simple MessageBox application

The `MessageBox.exe` application is written in NASM, showing a simple "Hello World" message

This app will serve as the input of our PE32 loader.

![](https://github.com/walkingsk/simplest_pe32_loader/blob/main/Preview/C_MessageBox.png)

# MessageBox loaded

Run in Visual Studio

![](https://github.com/walkingsk/simplest_pe32_loader/blob/main/Preview/0_Debug_Within_IDE.png)

Run in local CMD Prompt

![](https://github.com/walkingsk/simplest_pe32_loader/blob/main/Preview/1_Run_CMD.png)

# ALSR

ChatGPT's answer about the ASLR support on Windows

![](https://github.com/walkingsk/simplest_pe32_loader/blob/main/Preview/6_ASLR_Support.png)

Since we specify 0x00400000 in our program to load the PE32 image.

We specify another ImageBase for our loader

![](https://github.com/walkingsk/simplest_pe32_loader/blob/main/Preview/2_Specify_ImageBase.png)

System ASLR settings on Win11

![](https://github.com/walkingsk/simplest_pe32_loader/blob/main/Preview/5_System_ASLR.png)

MessageBox in the memory region of the loader

![](https://github.com/walkingsk/simplest_pe32_loader/blob/main/Preview/8_x32dbg_PE32Base.png)

This reminds you of something during unpacking

![](https://github.com/walkingsk/simplest_pe32_loader/blob/main/Preview/9_x32dbg_DumpMemoryToFile.png)

View in VMMap

![](https://github.com/walkingsk/simplest_pe32_loader/blob/main/Preview/B_VMMap_ALSR_LoaderBase.png)

# Static anaylyzer recommended

[PVS-Studio] is a wonderful static analyzer and helps improve the quality of projects


[Writing A PE Packer]: <https://wirediver.com/tutorial-writing-a-pe-packer-part-1/>
[wirediver]: <https://wirediver.com>
[PVS-Studio]: <https://pvs-studio.com/en/>
