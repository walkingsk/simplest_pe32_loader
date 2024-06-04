global WinMain
; extern _MessageBoxA@16
; extern _ExitProcess@4
extern MessageBoxA
extern ExitProcess

section code use32 class=code
WinMain:
	push	dword 0      ; UINT uType = MB_OK
	push	dword title  ; LPCSTR lpCaption
	push	dword banner ; LPCSTR lpText
	push	dword 0      ; HWND hWnd = NULL
	call	MessageBoxA

	push	dword 0      ; UINT uExitCode
	call	ExitProcess

section data use32 class=data
	banner:	db 'Hello, world!', 0
	title:	db 'Hello', 0