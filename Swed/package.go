package Swed

import (
	"encoding/binary"
	"golang.org/x/sys/windows"
	"math"
	"syscall"
	"unsafe"
)

type Swed struct {
	moduleAddress       uintptr
	processName         string
	kernel              *windows.DLL
	readProcessMemory   *windows.Proc
	writeProcessMemory  *windows.Proc
	procGetModuleHandle *windows.Proc
	windowHandle        windows.Handle
	pid                 uintptr
}

func getProcId(procName string) uint32 {
	var procId uint32
	hSnap, _ := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPPROCESS, 0)
	if hSnap != 0 {
		var procEntry windows.ProcessEntry32
		procEntry.Size = uint32(unsafe.Sizeof(procEntry))

		if err := windows.Process32First(hSnap, &procEntry); err == nil {
			for {
				if name := windows.UTF16ToString(procEntry.ExeFile[:]); name == procName {
					procId = procEntry.ProcessID
					break
				}
				if windows.Process32Next(hSnap, &procEntry) != nil {
					break
				}
			}
		}
	}
	err := windows.CloseHandle(hSnap)
	if err != nil {
		return 0
	}
	return procId
}

func getModuleBaseAddress(procId uint32, modName string) uintptr {
	var modBaseAddr uintptr
	hSnap, _ := windows.CreateToolhelp32Snapshot(syscall.TH32CS_SNAPMODULE|syscall.TH32CS_SNAPMODULE32, procId)
	if hSnap != 0 {
		var modEntry windows.ModuleEntry32
		modEntry.Size = uint32(unsafe.Sizeof(modEntry))
		if err := windows.Module32First(hSnap, &modEntry); err == nil {
			for {
				if syscall.UTF16ToString(modEntry.Module[:]) == modName {
					modBaseAddr = modEntry.ModBaseAddr
					break
				}
				if err := windows.Module32Next(hSnap, &modEntry); err != nil {
					break
				}
			}
		}
	}
	err := windows.CloseHandle(hSnap)
	if err != nil {
		return 0
	}
	return modBaseAddr
}

func (swed *Swed) initKernel() {

	swed.kernel = windows.MustLoadDLL("kernel32.dll")
	swed.readProcessMemory = swed.kernel.MustFindProc("ReadProcessMemory")
	swed.writeProcessMemory = swed.kernel.MustFindProc("WriteProcessMemory")
	swed.procGetModuleHandle = swed.kernel.MustFindProc("GetModuleHandleW")

}
func (swed *Swed) initHandle() {
	processPid := getProcId(swed.processName)
	if processPid < 0 {
		panic("Cannot find the process!")
	}
	handle, err := windows.OpenProcess(windows.PROCESS_VM_OPERATION|windows.PROCESS_VM_READ|windows.PROCESS_VM_WRITE|windows.PROCESS_QUERY_INFORMATION, false, processPid)
	if err != nil {
		panic(err)
	}

	swed.pid = uintptr(processPid)
	swed.windowHandle = handle
}
func excludeLastElement(slice []uintptr) ([]uintptr, uintptr) {
	if len(slice) <= 0 {
		return []uintptr{}, 0
	}
	last := slice[len(slice)-1]
	return slice[:len(slice)-1], last
}
func (swed *Swed) ReadString(Address uintptr, offsets ...uintptr) string {
	var data = make([]byte, 2048)
	var length uint32

	var finalAddress, value uintptr
	var valueAddresses []uintptr
	if len(offsets) > 1 {
		valueAddresses, value = excludeLastElement(offsets)
		finalAddress = swed.readPointer(swed.moduleAddress+Address, valueAddresses...)
	} else {
		if len(offsets) > 0 {
			_, _, _ = swed.readProcessMemory.Call(uintptr(swed.windowHandle),
				swed.moduleAddress+Address,
				uintptr(unsafe.Pointer(&finalAddress)),
				uintptr(len(data)),
				0)
			value = offsets[0]
		} else {
			finalAddress = swed.moduleAddress + Address
		}
	}
	ret, _, _ := swed.readProcessMemory.Call(uintptr(swed.windowHandle), finalAddress+value, uintptr(unsafe.Pointer(&data[0])), uintptr(len(data)), uintptr(unsafe.Pointer(&length)))
	if ret != 0 {
		var str string
		for _, b := range data[:length] {
			if b == 0 {
				break
			}
			str += string(b)
		}
		return str
	}
	return ""
}
func (swed *Swed) ReadInt(Address uintptr, offsets ...uintptr) int {
	var finalAddress, value uintptr
	var valueAddresses []uintptr
	if len(offsets) > 1 {
		valueAddresses, value = excludeLastElement(offsets)
		finalAddress = swed.readPointer(swed.moduleAddress+Address, valueAddresses...)
	} else {
		if len(offsets) > 0 {
			_, _, _ = swed.readProcessMemory.Call(uintptr(swed.windowHandle),
				swed.moduleAddress+Address,
				uintptr(unsafe.Pointer(&finalAddress)),
				uintptr(4),
				0)
			value = offsets[0]
		} else {
			finalAddress = swed.moduleAddress + Address
		}
	}
	var data int
	var length uint32
	ret, _, _ := swed.readProcessMemory.Call(uintptr(swed.windowHandle), finalAddress+value, uintptr(unsafe.Pointer(&data)), uintptr(4), uintptr(unsafe.Pointer(&length)))
	if ret != 0 {
		return data
	}
	return 0
}
func (swed *Swed) ReadPointer(Address uintptr, offsets ...uintptr) uintptr {
	return swed.readPointer(swed.moduleAddress+Address, offsets...)
}

func (swed *Swed) readPointer(Address uintptr, offsets ...uintptr) uintptr {

	var pointerAddress uintptr
	_, _, _ = swed.readProcessMemory.Call(uintptr(swed.windowHandle),
		Address,
		uintptr(unsafe.Pointer(&pointerAddress)),
		uintptr(4),
		0)
	finalAddress := pointerAddress
	for _, offset := range offsets {
		ret, _, _ := swed.readProcessMemory.Call(uintptr(swed.windowHandle),
			pointerAddress+offset,
			uintptr(unsafe.Pointer(&pointerAddress)),
			uintptr(4),
			0)
		if ret == 0 {
			break
		}
		finalAddress = pointerAddress
	}
	return finalAddress
}

func (swed *Swed) ReadLong(Address uintptr, offsets ...uintptr) int64 {
	var finalAddress, value uintptr
	var valueAddresses []uintptr
	if len(offsets) > 1 {
		valueAddresses, value = excludeLastElement(offsets)
		finalAddress = swed.readPointer(swed.moduleAddress+Address, valueAddresses...)
	} else {
		if len(offsets) > 0 {
			_, _, _ = swed.readProcessMemory.Call(uintptr(swed.windowHandle),
				swed.moduleAddress+Address,
				uintptr(unsafe.Pointer(&finalAddress)),
				uintptr(8),
				0)
			value = offsets[0]
		} else {
			finalAddress = swed.moduleAddress + Address
		}
	}
	var data int64
	var length uint32

	ret, _, _ := swed.readProcessMemory.Call(uintptr(swed.windowHandle), finalAddress+value, uintptr(unsafe.Pointer(&data)), uintptr(8), uintptr(unsafe.Pointer(&length)))
	if ret != 0 {
		return data
	}
	return 0
}

func (swed *Swed) ReadFloat(Address uintptr, offsets ...uintptr) float32 {
	var finalAddress, value uintptr
	var valueAddresses []uintptr
	if len(offsets) > 1 {
		valueAddresses, value = excludeLastElement(offsets)
		finalAddress = swed.readPointer(swed.moduleAddress+Address, valueAddresses...)
	} else {
		if len(offsets) > 0 {
			_, _, _ = swed.readProcessMemory.Call(uintptr(swed.windowHandle),
				swed.moduleAddress+Address,
				uintptr(unsafe.Pointer(&finalAddress)),
				uintptr(4),
				0)
			value = offsets[0]
		} else {
			finalAddress = swed.moduleAddress + Address
		}
	}
	var data float32
	var length uint32

	ret, _, _ := swed.readProcessMemory.Call(uintptr(swed.windowHandle), finalAddress+value, uintptr(unsafe.Pointer(&data)), uintptr(4), uintptr(unsafe.Pointer(&length)))
	if ret != 0 {
		return data

	}
	return 0
}

func (swed *Swed) ReadDouble(Address uintptr, offsets ...uintptr) float64 {

	var finalAddress, value uintptr
	var valueAddresses []uintptr
	if len(offsets) > 1 {
		valueAddresses, value = excludeLastElement(offsets)
		finalAddress = swed.readPointer(swed.moduleAddress+Address, valueAddresses...)
	} else {
		if len(offsets) > 0 {
			_, _, _ = swed.readProcessMemory.Call(uintptr(swed.windowHandle),
				swed.moduleAddress+Address,
				uintptr(unsafe.Pointer(&finalAddress)),
				uintptr(8),
				0)
			value = offsets[0]
		} else {
			finalAddress = swed.moduleAddress + Address
		}
	}
	var data float64
	var length uint32
	ret, _, _ := swed.readProcessMemory.Call(uintptr(swed.windowHandle), finalAddress+value, uintptr(unsafe.Pointer(&data)), uintptr(8), uintptr(unsafe.Pointer(&length)))
	if ret != 0 {
		return data
	}
	return 0
}
func (swed *Swed) ReadByte(Address uintptr, offsets ...uintptr) byte {

	var finalAddress, value uintptr
	var valueAddresses []uintptr
	if len(offsets) > 1 {
		valueAddresses, value = excludeLastElement(offsets)
		finalAddress = swed.readPointer(swed.moduleAddress+Address, valueAddresses...)
	} else {
		if len(offsets) > 0 {
			_, _, _ = swed.readProcessMemory.Call(uintptr(swed.windowHandle),
				swed.moduleAddress+Address,
				uintptr(unsafe.Pointer(&finalAddress)),
				uintptr(1),
				0)
			value = offsets[0]
		} else {
			finalAddress = swed.moduleAddress + Address
		}
	}

	var data byte
	var length uint32
	ret, _, _ := swed.readProcessMemory.Call(uintptr(swed.windowHandle), finalAddress+value, uintptr(unsafe.Pointer(&data)), uintptr(1), uintptr(unsafe.Pointer(&length)))
	if ret != 0 {
		return data
	}
	return 0
}
func (swed *Swed) ReadUint16(Address uintptr, offsets ...uintptr) uint16 {

	var finalAddress, value uintptr
	var valueAddresses []uintptr
	if len(offsets) > 1 {
		valueAddresses, value = excludeLastElement(offsets)
		finalAddress = swed.readPointer(swed.moduleAddress+Address, valueAddresses...)
	} else {
		if len(offsets) > 0 {
			_, _, _ = swed.readProcessMemory.Call(uintptr(swed.windowHandle),
				swed.moduleAddress+Address,
				uintptr(unsafe.Pointer(&finalAddress)),
				uintptr(2),
				0)
			value = offsets[0]
		} else {
			finalAddress = swed.moduleAddress + Address
		}
	}

	var data uint16
	var length uint32
	ret, _, _ := swed.readProcessMemory.Call(uintptr(swed.windowHandle), finalAddress+value, uintptr(unsafe.Pointer(&data)), uintptr(2), uintptr(unsafe.Pointer(&length)))
	if ret != 0 {
		return data
	}
	return 0
}
func (swed *Swed) ReadUint32(Address uintptr, offsets ...uintptr) uint32 {

	var finalAddress, value uintptr
	var valueAddresses []uintptr
	if len(offsets) > 1 {
		valueAddresses, value = excludeLastElement(offsets)
		finalAddress = swed.readPointer(swed.moduleAddress+Address, valueAddresses...)
	} else {
		if len(offsets) > 0 {
			_, _, _ = swed.readProcessMemory.Call(uintptr(swed.windowHandle),
				swed.moduleAddress+Address,
				uintptr(unsafe.Pointer(&finalAddress)),
				uintptr(4),
				0)
			value = offsets[0]
		} else {
			finalAddress = swed.moduleAddress + Address
		}
	}

	var data uint32
	var length uint32
	ret, _, _ := swed.readProcessMemory.Call(uintptr(swed.windowHandle), finalAddress+value, uintptr(unsafe.Pointer(&data)), uintptr(4), uintptr(unsafe.Pointer(&length)))
	if ret != 0 {
		return data
	}
	return 0
}

func (swed *Swed) WriteBytes(Address uintptr, bytes []byte, offsets ...uintptr) {
	var finalAddress, value uintptr
	var valueAddresses []uintptr
	if len(offsets) > 1 {
		valueAddresses, value = excludeLastElement(offsets)
		finalAddress = swed.readPointer(swed.moduleAddress+Address, valueAddresses...)
	} else {
		if len(offsets) > 0 {
			_, _, _ = swed.readProcessMemory.Call(uintptr(swed.windowHandle),
				swed.moduleAddress+Address,
				uintptr(unsafe.Pointer(&finalAddress)),
				uintptr(len(bytes)),
				0)
			value = offsets[0]
		} else {
			finalAddress = swed.moduleAddress + Address
		}
	}

	var length uint32
	_, _, _ = swed.writeProcessMemory.Call(uintptr(swed.windowHandle), finalAddress+value, uintptr(unsafe.Pointer(&bytes[0])), uintptr(len(bytes)), uintptr(unsafe.Pointer(&length)))
}

func (swed *Swed) ReadInt32(Address uintptr, offsets ...uintptr) int32 {
	var finalAddress, value uintptr
	var valueAddresses []uintptr
	if len(offsets) > 1 {
		valueAddresses, value = excludeLastElement(offsets)
		finalAddress = swed.readPointer(swed.moduleAddress+Address, valueAddresses...)
	} else {
		if len(offsets) > 0 {
			_, _, _ = swed.readProcessMemory.Call(uintptr(swed.windowHandle),
				swed.moduleAddress+Address,
				uintptr(unsafe.Pointer(&finalAddress)),
				uintptr(4),
				0)
			value = offsets[0]
		} else {
			finalAddress = swed.moduleAddress + Address
		}
	}
	var data int32
	var length uint32
	ret, _, _ := swed.readProcessMemory.Call(uintptr(swed.windowHandle), finalAddress+value, uintptr(unsafe.Pointer(&data)), uintptr(4), uintptr(unsafe.Pointer(&length)))
	if ret != 0 {
		return data
	}
	return 0
}
func (swed *Swed) ReadVec3(Address uintptr, offsets ...uintptr) Vec3 {
	var x, y, z float32
	if len(offsets) > 0 {
		x = swed.ReadFloat(Address, offsets...)
		offsets[len(offsets)-1] += 0x4
		y = swed.ReadFloat(Address, offsets...)
		offsets[len(offsets)-1] += 0x4
		z = swed.ReadFloat(Address, offsets...)
	} else {
		x = swed.ReadFloat(Address, offsets...)
		y = swed.ReadFloat(Address+0x4, offsets...)
		z = swed.ReadFloat(Address+0x4*2, offsets...)
	}
	return Vec3{
		X: x,
		Y: y,
		Z: z,
	}
}
func (swed *Swed) ReadVec2(Address uintptr, offsets ...uintptr) Vec2 {
	var x, y float32
	if len(offsets) > 0 {
		x = swed.ReadFloat(Address, offsets...)
		offsets[len(offsets)-1] += 0x4
		y = swed.ReadFloat(Address, offsets...)
	} else {
		x = swed.ReadFloat(Address, offsets...)
		y = swed.ReadFloat(Address+0x4, offsets...)
	}
	return Vec2{
		X: x,
		Y: y,
	}
}

func (swed *Swed) WriteVec3(Address uintptr, newValue Vec3, offsets ...uintptr) {
	if len(offsets) > 0 {
		swed.WriteFloat(Address, newValue.X, offsets...)
		offsets[len(offsets)-1] += 0x4
		swed.WriteFloat(Address, newValue.Y, offsets...)
		offsets[len(offsets)-1] += 0x4
		swed.WriteFloat(Address, newValue.Z, offsets...)
	} else {
		swed.WriteFloat(Address, newValue.X, offsets...)
		swed.WriteFloat(Address+0x4, newValue.Y, offsets...)
		swed.WriteFloat(Address+0x4*2, newValue.Z, offsets...)
	}
}
func (swed *Swed) WriteVec2(Address uintptr, newValue Vec2, offsets ...uintptr) {
	if len(offsets) > 0 {
		swed.WriteFloat(Address, newValue.X, offsets...)
		offsets[len(offsets)-1] += 0x4
		swed.WriteFloat(Address, newValue.Y, offsets...)
	} else {
		swed.WriteFloat(Address, newValue.X, offsets...)
		swed.WriteFloat(Address+0x4, newValue.Y, offsets...)
	}
}
func (swed *Swed) ReadMatrix4x4(Address uintptr, offsets ...uintptr) Matrix4x4 {
	Matrix := Matrix4x4{}
	if len(offsets) > 0 {
		Matrix.M11 = swed.ReadFloat(Address, offsets...)
		offsets[len(offsets)-1] += 0x4
		Matrix.M12 = swed.ReadFloat(Address, offsets...)
		offsets[len(offsets)-1] += 0x4
		Matrix.M13 = swed.ReadFloat(Address, offsets...)
		offsets[len(offsets)-1] += 0x4
		Matrix.M14 = swed.ReadFloat(Address, offsets...)

		offsets[len(offsets)-1] += 0x4
		Matrix.M21 = swed.ReadFloat(Address, offsets...)
		offsets[len(offsets)-1] += 0x4
		Matrix.M22 = swed.ReadFloat(Address, offsets...)
		offsets[len(offsets)-1] += 0x4
		Matrix.M23 = swed.ReadFloat(Address, offsets...)
		offsets[len(offsets)-1] += 0x4
		Matrix.M24 = swed.ReadFloat(Address, offsets...)

		offsets[len(offsets)-1] += 0x4
		Matrix.M31 = swed.ReadFloat(Address, offsets...)
		offsets[len(offsets)-1] += 0x4
		Matrix.M32 = swed.ReadFloat(Address, offsets...)
		offsets[len(offsets)-1] += 0x4
		Matrix.M33 = swed.ReadFloat(Address, offsets...)
		offsets[len(offsets)-1] += 0x4
		Matrix.M34 = swed.ReadFloat(Address, offsets...)

		offsets[len(offsets)-1] += 0x4
		Matrix.M41 = swed.ReadFloat(Address, offsets...)
		offsets[len(offsets)-1] += 0x4
		Matrix.M42 = swed.ReadFloat(Address, offsets...)
		offsets[len(offsets)-1] += 0x4
		Matrix.M43 = swed.ReadFloat(Address, offsets...)
		offsets[len(offsets)-1] += 0x4
		Matrix.M44 = swed.ReadFloat(Address, offsets...)
	} else {
		Matrix.M11 = swed.ReadFloat(Address, offsets...)
		Matrix.M12 = swed.ReadFloat(Address+0x4, offsets...)
		Matrix.M13 = swed.ReadFloat(Address+0x4*2, offsets...)
		Matrix.M14 = swed.ReadFloat(Address+0x4*3, offsets...)

		Matrix.M21 = swed.ReadFloat(Address+0x4*4, offsets...)
		Matrix.M22 = swed.ReadFloat(Address+0x4*5, offsets...)
		Matrix.M23 = swed.ReadFloat(Address+0x4*6, offsets...)
		Matrix.M24 = swed.ReadFloat(Address+0x4*7, offsets...)

		Matrix.M31 = swed.ReadFloat(Address+0x4*8, offsets...)
		Matrix.M32 = swed.ReadFloat(Address+0x4*9, offsets...)
		Matrix.M33 = swed.ReadFloat(Address+0x4*10, offsets...)
		Matrix.M34 = swed.ReadFloat(Address+0x4*11, offsets...)

		Matrix.M41 = swed.ReadFloat(Address+0x4*12, offsets...)
		Matrix.M42 = swed.ReadFloat(Address+0x4*13, offsets...)
		Matrix.M43 = swed.ReadFloat(Address+0x4*14, offsets...)
		Matrix.M44 = swed.ReadFloat(Address+0x4*15, offsets...)
	}

	return Matrix
}
func (swed *Swed) WriteMatrix4x4(Address uintptr, newValue Matrix4x4, offsets ...uintptr) {
	if len(offsets) > 0 {
		swed.WriteFloat(Address, newValue.M11, offsets...)
		offsets[len(offsets)-1] += 0x4
		swed.WriteFloat(Address, newValue.M12, offsets...)
		offsets[len(offsets)-1] += 0x4
		swed.WriteFloat(Address, newValue.M13, offsets...)
		offsets[len(offsets)-1] += 0x4
		swed.WriteFloat(Address, newValue.M14, offsets...)

		offsets[len(offsets)-1] += 0x4
		swed.WriteFloat(Address, newValue.M21, offsets...)
		offsets[len(offsets)-1] += 0x4
		swed.WriteFloat(Address, newValue.M22, offsets...)
		offsets[len(offsets)-1] += 0x4
		swed.WriteFloat(Address, newValue.M23, offsets...)
		offsets[len(offsets)-1] += 0x4
		swed.WriteFloat(Address, newValue.M24, offsets...)

		offsets[len(offsets)-1] += 0x4
		swed.WriteFloat(Address, newValue.M31, offsets...)
		offsets[len(offsets)-1] += 0x4
		swed.WriteFloat(Address, newValue.M32, offsets...)
		offsets[len(offsets)-1] += 0x4
		swed.WriteFloat(Address, newValue.M33, offsets...)
		offsets[len(offsets)-1] += 0x4
		swed.WriteFloat(Address, newValue.M34, offsets...)

		offsets[len(offsets)-1] += 0x4
		swed.WriteFloat(Address, newValue.M41, offsets...)
		offsets[len(offsets)-1] += 0x4
		swed.WriteFloat(Address, newValue.M42, offsets...)
		offsets[len(offsets)-1] += 0x4
		swed.WriteFloat(Address, newValue.M43, offsets...)
		offsets[len(offsets)-1] += 0x4
		swed.WriteFloat(Address, newValue.M44, offsets...)
	} else {
		swed.WriteFloat(Address, newValue.M11, offsets...)
		swed.WriteFloat(Address+0x4, newValue.M12, offsets...)
		swed.WriteFloat(Address+0x4*2, newValue.M13, offsets...)
		swed.WriteFloat(Address+0x4*3, newValue.M14, offsets...)

		swed.WriteFloat(Address+0x4*4, newValue.M21, offsets...)
		swed.WriteFloat(Address+0x4*5, newValue.M22, offsets...)
		swed.WriteFloat(Address+0x4*6, newValue.M23, offsets...)
		swed.WriteFloat(Address+0x4*7, newValue.M24, offsets...)

		swed.WriteFloat(Address+0x4*8, newValue.M31, offsets...)
		swed.WriteFloat(Address+0x4*9, newValue.M32, offsets...)
		swed.WriteFloat(Address+0x4*10, newValue.M33, offsets...)
		swed.WriteFloat(Address+0x4*11, newValue.M34, offsets...)

		swed.WriteFloat(Address+0x4*12, newValue.M41, offsets...)
		swed.WriteFloat(Address+0x4*13, newValue.M42, offsets...)
		swed.WriteFloat(Address+0x4*14, newValue.M43, offsets...)
		swed.WriteFloat(Address+0x4*15, newValue.M44, offsets...)
	}

}
func (swed *Swed) ReadMatrix3x3(Address uintptr, offsets ...uintptr) Matrix3x3 {
	Matrix := Matrix3x3{}
	if len(offsets) > 0 {
		Matrix.M11 = swed.ReadFloat(Address, offsets...)
		offsets[len(offsets)-1] += 0x4
		Matrix.M12 = swed.ReadFloat(Address, offsets...)
		offsets[len(offsets)-1] += 0x4
		Matrix.M13 = swed.ReadFloat(Address, offsets...)

		offsets[len(offsets)-1] += 0x4
		Matrix.M21 = swed.ReadFloat(Address, offsets...)
		offsets[len(offsets)-1] += 0x4
		Matrix.M22 = swed.ReadFloat(Address, offsets...)
		offsets[len(offsets)-1] += 0x4
		Matrix.M23 = swed.ReadFloat(Address, offsets...)

		offsets[len(offsets)-1] += 0x4
		Matrix.M31 = swed.ReadFloat(Address, offsets...)
		offsets[len(offsets)-1] += 0x4
		Matrix.M32 = swed.ReadFloat(Address, offsets...)
		offsets[len(offsets)-1] += 0x4
		Matrix.M33 = swed.ReadFloat(Address, offsets...)
	} else {
		Matrix.M11 = swed.ReadFloat(Address, offsets...)
		Matrix.M12 = swed.ReadFloat(Address+0x4, offsets...)
		Matrix.M13 = swed.ReadFloat(Address+0x4*2, offsets...)

		Matrix.M21 = swed.ReadFloat(Address+0x4*3, offsets...)
		Matrix.M22 = swed.ReadFloat(Address+0x4*4, offsets...)
		Matrix.M23 = swed.ReadFloat(Address+0x4*5, offsets...)

		Matrix.M31 = swed.ReadFloat(Address+0x4*6, offsets...)
		Matrix.M32 = swed.ReadFloat(Address+0x4*7, offsets...)
		Matrix.M33 = swed.ReadFloat(Address+0x4*8, offsets...)
	}
	return Matrix
}
func (swed *Swed) WriteMatrix3x3(Address uintptr, newValue Matrix3x3, offsets ...uintptr) {
	if len(offsets) > 0 {
		swed.WriteFloat(Address, newValue.M11, offsets...)
		offsets[len(offsets)-1] += 0x4
		swed.WriteFloat(Address, newValue.M12, offsets...)
		offsets[len(offsets)-1] += 0x4
		swed.WriteFloat(Address, newValue.M13, offsets...)

		offsets[len(offsets)-1] += 0x4
		swed.WriteFloat(Address, newValue.M21, offsets...)
		offsets[len(offsets)-1] += 0x4
		swed.WriteFloat(Address, newValue.M22, offsets...)
		offsets[len(offsets)-1] += 0x4
		swed.WriteFloat(Address, newValue.M23, offsets...)

		offsets[len(offsets)-1] += 0x4
		swed.WriteFloat(Address, newValue.M31, offsets...)
		offsets[len(offsets)-1] += 0x4
		swed.WriteFloat(Address, newValue.M32, offsets...)
		offsets[len(offsets)-1] += 0x4
		swed.WriteFloat(Address, newValue.M33, offsets...)
	} else {
		swed.WriteFloat(Address, newValue.M11, offsets...)
		swed.WriteFloat(Address+0x4, newValue.M12, offsets...)
		swed.WriteFloat(Address+0x4*2, newValue.M13, offsets...)

		swed.WriteFloat(Address+0x4*3, newValue.M21, offsets...)
		swed.WriteFloat(Address+0x4*4, newValue.M22, offsets...)
		swed.WriteFloat(Address+0x4*5, newValue.M23, offsets...)

		swed.WriteFloat(Address+0x4*6, newValue.M31, offsets...)
		swed.WriteFloat(Address+0x4*7, newValue.M32, offsets...)
		swed.WriteFloat(Address+0x4*8, newValue.M33, offsets...)
	}

}
func (swed *Swed) WriteInt32(Address uintptr, newValue int32, offsets ...uintptr) {
	var finalAddress, value uintptr
	var valueAddresses []uintptr
	if len(offsets) > 1 {
		valueAddresses, value = excludeLastElement(offsets)
		finalAddress = swed.readPointer(swed.moduleAddress+Address, valueAddresses...)
	} else {
		if len(offsets) > 0 {
			_, _, _ = swed.readProcessMemory.Call(uintptr(swed.windowHandle),
				swed.moduleAddress+Address,
				uintptr(unsafe.Pointer(&finalAddress)),
				uintptr(4),
				0)
			value = offsets[0]
		} else {
			finalAddress = swed.moduleAddress + Address
		}
	}

	var buffer = make([]byte, 4)
	binary.LittleEndian.PutUint32(buffer, uint32(newValue))

	var length uint32
	_, _, _ = swed.writeProcessMemory.Call(uintptr(swed.windowHandle), finalAddress+value, uintptr(unsafe.Pointer(&buffer[0])), uintptr(4), uintptr(unsafe.Pointer(&length)))
}

func (swed *Swed) WriteInt(Address uintptr, newValue int, offsets ...uintptr) {
	var finalAddress, value uintptr
	var valueAddresses []uintptr
	if len(offsets) > 1 {
		valueAddresses, value = excludeLastElement(offsets)
		finalAddress = swed.readPointer(swed.moduleAddress+Address, valueAddresses...)
	} else {
		if len(offsets) > 0 {
			_, _, _ = swed.readProcessMemory.Call(uintptr(swed.windowHandle),
				swed.moduleAddress+Address,
				uintptr(unsafe.Pointer(&finalAddress)),
				uintptr(4),
				0)
			value = offsets[0]
		} else {
			finalAddress = swed.moduleAddress + Address
		}
	}

	var buffer = make([]byte, 4)
	binary.LittleEndian.PutUint32(buffer, uint32(newValue))

	var length uint32
	_, _, _ = swed.writeProcessMemory.Call(uintptr(swed.windowHandle), finalAddress+value, uintptr(unsafe.Pointer(&buffer[0])), uintptr(4), uintptr(unsafe.Pointer(&length)))
}

func (swed *Swed) WriteLong(Address uintptr, newValue int64, offsets ...uintptr) {
	var finalAddress, value uintptr
	var valueAddresses []uintptr
	if len(offsets) > 1 {
		valueAddresses, value = excludeLastElement(offsets)
		finalAddress = swed.readPointer(swed.moduleAddress+Address, valueAddresses...)
	} else {
		if len(offsets) > 0 {
			_, _, _ = swed.readProcessMemory.Call(uintptr(swed.windowHandle),
				swed.moduleAddress+Address,
				uintptr(unsafe.Pointer(&finalAddress)),
				uintptr(8),
				0)
			value = offsets[0]
		} else {
			finalAddress = swed.moduleAddress + Address
		}
	}

	var buffer = make([]byte, 8)
	binary.LittleEndian.PutUint64(buffer, uint64(newValue))

	var length uint32
	_, _, _ = swed.writeProcessMemory.Call(uintptr(swed.windowHandle), finalAddress+value, uintptr(unsafe.Pointer(&buffer[0])), uintptr(8), uintptr(unsafe.Pointer(&length)))
}

func (swed *Swed) WriteFloat(Address uintptr, newValue float32, offsets ...uintptr) {
	var finalAddress, value uintptr
	var valueAddresses []uintptr
	if len(offsets) > 1 {
		valueAddresses, value = excludeLastElement(offsets)
		finalAddress = swed.readPointer(swed.moduleAddress+Address, valueAddresses...)
	} else {
		if len(offsets) > 0 {
			_, _, _ = swed.readProcessMemory.Call(uintptr(swed.windowHandle),
				swed.moduleAddress+Address,
				uintptr(unsafe.Pointer(&finalAddress)),
				uintptr(4),
				0)
			value = offsets[0]
		} else {
			finalAddress = swed.moduleAddress + Address
		}
	}

	var buffer = make([]byte, 4)
	binary.LittleEndian.PutUint32(buffer, math.Float32bits(newValue))

	var length uint32
	_, _, _ = swed.writeProcessMemory.Call(uintptr(swed.windowHandle), finalAddress+value, uintptr(unsafe.Pointer(&buffer[0])), uintptr(4), uintptr(unsafe.Pointer(&length)))
}
func (swed *Swed) WriteDouble(Address uintptr, newValue float64, offsets ...uintptr) {
	var finalAddress, value uintptr
	var valueAddresses []uintptr
	if len(offsets) > 1 {
		valueAddresses, value = excludeLastElement(offsets)
		finalAddress = swed.readPointer(swed.moduleAddress+Address, valueAddresses...)
	} else {
		if len(offsets) > 0 {
			_, _, _ = swed.readProcessMemory.Call(uintptr(swed.windowHandle),
				swed.moduleAddress+Address,
				uintptr(unsafe.Pointer(&finalAddress)),
				uintptr(8),
				0)
			value = offsets[0]
		} else {
			finalAddress = swed.moduleAddress + Address
		}
	}

	var buffer = make([]byte, 8)
	binary.LittleEndian.PutUint64(buffer, math.Float64bits(newValue))

	var length uint32
	_, _, _ = swed.writeProcessMemory.Call(uintptr(swed.windowHandle), finalAddress+value, uintptr(unsafe.Pointer(&buffer[0])), uintptr(8), uintptr(unsafe.Pointer(&length)))
}
func (swed *Swed) WriteUint32(Address uintptr, newValue uint32, offsets ...uintptr) {
	var finalAddress, value uintptr
	var valueAddresses []uintptr
	if len(offsets) > 1 {
		valueAddresses, value = excludeLastElement(offsets)
		finalAddress = swed.readPointer(swed.moduleAddress+Address, valueAddresses...)
	} else {
		if len(offsets) > 0 {
			_, _, _ = swed.readProcessMemory.Call(uintptr(swed.windowHandle),
				swed.moduleAddress+Address,
				uintptr(unsafe.Pointer(&finalAddress)),
				uintptr(4),
				0)
			value = offsets[0]
		} else {
			finalAddress = swed.moduleAddress + Address
		}
	}

	var buffer = make([]byte, 4)
	binary.LittleEndian.PutUint32(buffer, newValue)

	var length uint32
	_, _, _ = swed.writeProcessMemory.Call(uintptr(swed.windowHandle), finalAddress+value, uintptr(unsafe.Pointer(&buffer[0])), uintptr(4), uintptr(unsafe.Pointer(&length)))
}
func (swed *Swed) WriteUint16(Address uintptr, newValue uint16, offsets ...uintptr) {
	var finalAddress, value uintptr
	var valueAddresses []uintptr
	if len(offsets) > 1 {
		valueAddresses, value = excludeLastElement(offsets)
		finalAddress = swed.readPointer(swed.moduleAddress+Address, valueAddresses...)
	} else {
		if len(offsets) > 0 {
			_, _, _ = swed.readProcessMemory.Call(uintptr(swed.windowHandle),
				swed.moduleAddress+Address,
				uintptr(unsafe.Pointer(&finalAddress)),
				uintptr(2),
				0)
			value = offsets[0]
		} else {
			finalAddress = swed.moduleAddress + Address
		}
	}

	var buffer = make([]byte, 2)
	binary.LittleEndian.PutUint16(buffer, newValue)

	var length uint32
	_, _, _ = swed.writeProcessMemory.Call(uintptr(swed.windowHandle), finalAddress+value, uintptr(unsafe.Pointer(&buffer[0])), uintptr(2), uintptr(unsafe.Pointer(&length)))
}

func (swed *Swed) WriteUint64(Address uintptr, newValue uint64, offsets ...uintptr) {
	var finalAddress, value uintptr
	var valueAddresses []uintptr
	if len(offsets) > 1 {
		valueAddresses, value = excludeLastElement(offsets)
		finalAddress = swed.readPointer(swed.moduleAddress+Address, valueAddresses...)
	} else {
		if len(offsets) > 0 {
			_, _, _ = swed.readProcessMemory.Call(uintptr(swed.windowHandle),
				swed.moduleAddress+Address,
				uintptr(unsafe.Pointer(&finalAddress)),
				uintptr(8),
				0)
			value = offsets[0]
		} else {
			finalAddress = swed.moduleAddress + Address
		}
	}
	var buffer = make([]byte, 8)
	binary.LittleEndian.PutUint64(buffer, newValue)

	var length uint32
	_, _, _ = swed.writeProcessMemory.Call(uintptr(swed.windowHandle), finalAddress+value, uintptr(unsafe.Pointer(&buffer[0])), uintptr(8), uintptr(unsafe.Pointer(&length)))
}
func (swed *Swed) WriteString(Address uintptr, newValue string, offsets ...uintptr) {
	var finalAddress, value uintptr
	var valueAddresses []uintptr
	if len(offsets) > 1 {
		valueAddresses, value = excludeLastElement(offsets)
		finalAddress = swed.readPointer(swed.moduleAddress+Address, valueAddresses...)
	} else {
		if len(offsets) > 0 {
			_, _, _ = swed.readProcessMemory.Call(uintptr(swed.windowHandle),
				swed.moduleAddress+Address,
				uintptr(unsafe.Pointer(&finalAddress)),
				uintptr(4),
				0)
			value = offsets[0]
		} else {
			finalAddress = swed.moduleAddress + Address
		}
	}
	var buffer = []byte(newValue)
	var length uint32
	_, _, _ = swed.writeProcessMemory.Call(uintptr(swed.windowHandle), finalAddress+value, uintptr(unsafe.Pointer(&buffer[0])), uintptr(len(buffer)), uintptr(unsafe.Pointer(&length)))
}

func (swed *Swed) GetModuleBase(Module string) Swed {
	sw := Swed{}
	sw.kernel = swed.kernel
	sw.windowHandle = swed.windowHandle
	sw.procGetModuleHandle = swed.procGetModuleHandle
	sw.writeProcessMemory = swed.writeProcessMemory
	sw.readProcessMemory = swed.readProcessMemory
	sw.processName = swed.processName
	sw.pid = swed.pid
	sw.moduleAddress = getModuleBaseAddress(uint32(swed.pid), Module)
	return sw
}

func (swed *Swed) GetModuleAddress() uintptr {
	return swed.moduleAddress
}

func New(processName string) Swed {
	sw := Swed{}
	sw.processName = processName + ".exe"
	sw.initKernel()
	sw.initHandle()
	return sw
}

type Vec3 struct {
	X, Y, Z float32
}
type Vec2 struct {
	X, Y float32
}
type Matrix4x4 struct {
	M11, M12, M13, M14 float32
	M21, M22, M23, M24 float32
	M31, M32, M33, M34 float32
	M41, M42, M43, M44 float32
}

type Matrix3x3 struct {
	M11, M12, M13 float32
	M21, M22, M23 float32
	M31, M32, M33 float32
}

func (m *Matrix4x4) To2DCoords(Position Vec3) Vec2 {
	transformedX := m.M11*Position.X + m.M12*Position.Y + m.M13*Position.Z + m.M14
	transformedY := m.M21*Position.X + m.M22*Position.Y + m.M23*Position.Z + m.M24
	transformedW := m.M41*Position.X + m.M42*Position.Y + m.M43*Position.Z + m.M44

	if transformedW != 0 {
		transformedX /= transformedW
		transformedY /= transformedW
	}

	return Vec2{
		X: transformedX,
		Y: transformedY,
	}
}
