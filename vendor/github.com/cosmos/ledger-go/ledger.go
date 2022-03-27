/*******************************************************************************
*   (c) 2018 ZondaX GmbH
*
*  Licensed under the Apache License, Version 2.0 (the "License");
*  you may not use this file except in compliance with the License.
*  You may obtain a copy of the License at
*
*      http://www.apache.org/licenses/LICENSE-2.0
*
*  Unless required by applicable law or agreed to in writing, software
*  distributed under the License is distributed on an "AS IS" BASIS,
*  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
*  See the License for the specific language governing permissions and
*  limitations under the License.
********************************************************************************/

package ledger_go

import (
	"errors"
	"fmt"
	"sync"

	"github.com/zondax/hid"
)

const (
	VendorLedger         = 0x2c97
	UsagePageLedgerNanoS = 0xffa0
	//ProductNano     = 1
	Channel    = 0x0101
	PacketSize = 64
)

type Ledger struct {
	device      hid.Device
	readCo      sync.Once
	readChannel chan []byte
	Logging     bool
}

func NewLedger(dev *hid.Device) *Ledger {
	return &Ledger{
		device:  *dev,
		Logging: false,
	}
}

func ListDevices() {
	devices := hid.Enumerate(0, 0)

	if len(devices) == 0 {
		fmt.Printf("No devices")
	}

	for _, d := range devices {
		fmt.Printf("============ %s\n", d.Path)
		fmt.Printf("VendorID      : %x\n", d.VendorID)
		fmt.Printf("ProductID     : %x\n", d.ProductID)
		fmt.Printf("Release       : %x\n", d.Release)
		fmt.Printf("Serial        : %x\n", d.Serial)
		fmt.Printf("Manufacturer  : %s\n", d.Manufacturer)
		fmt.Printf("Product       : %s\n", d.Product)
		fmt.Printf("UsagePage     : %x\n", d.UsagePage)
		fmt.Printf("Usage         : %x\n", d.Usage)
		fmt.Printf("\n")
	}
}

func FindLedger() (*Ledger, error) {
	devices := hid.Enumerate(VendorLedger, 0)

	for _, d := range devices {
		deviceFound := d.UsagePage == UsagePageLedgerNanoS
		// Workarounds for possible empty usage pages
		deviceFound = deviceFound ||
			(d.Product == "Nano S" && d.Interface == 0) ||
			(d.Product == "Nano X" && d.Interface == 0)

		if deviceFound {
			device, err := d.Open()
			if err == nil {
				return NewLedger(device), nil
			}
		}
	}

	return nil, errors.New("no ledger connected")
}

func ErrorMessage(errorCode uint16) string {
	switch errorCode {
	// FIXME: Code and description don't match for 0x6982 and 0x6983 based on
	// apdu spec: https://www.eftlab.co.uk/index.php/site-map/knowledge-base/118-apdu-response-list

	case 0x6400:
		return "[APDU_CODE_EXECUTION_ERROR] No information given (NV-Ram not changed)"
	case 0x6700:
		return "[APDU_CODE_WRONG_LENGTH] Wrong length"
	case 0x6982:
		return "[APDU_CODE_EMPTY_BUFFER] Security condition not satisfied"
	case 0x6983:
		return "[APDU_CODE_OUTPUT_BUFFER_TOO_SMALL] Authentication method blocked"
	case 0x6984:
		return "[APDU_CODE_DATA_INVALID] Referenced data reversibly blocked (invalidated)"
	case 0x6985:
		return "[APDU_CODE_CONDITIONS_NOT_SATISFIED] Conditions of use not satisfied"
	case 0x6986:
		return "[APDU_CODE_COMMAND_NOT_ALLOWED] Command not allowed (no current EF)"
	case 0x6A80:
		return "[APDU_CODE_BAD_KEY_HANDLE] The parameters in the data field are incorrect"
	case 0x6B00:
		return "[APDU_CODE_INVALIDP1P2] Wrong parameter(s) P1-P2"
	case 0x6D00:
		return "[APDU_CODE_INS_NOT_SUPPORTED] Instruction code not supported or invalid"
	case 0x6E00:
		return "[APDU_CODE_CLA_NOT_SUPPORTED] Class not supported"
	case 0x6F00:
		return "APDU_CODE_UNKNOWN"
	case 0x6F01:
		return "APDU_CODE_SIGN_VERIFY_ERROR"
	default:
		return fmt.Sprintf("Error code: %04x", errorCode)
	}
}

func (ledger *Ledger) Close() error {
	return ledger.device.Close()
}

func (ledger *Ledger) Write(buffer []byte) (int, error) {
	totalBytes := len(buffer)
	totalWrittenBytes := 0
	for totalBytes > totalWrittenBytes {
		writtenBytes, err := ledger.device.Write(buffer)

		if ledger.Logging {
			fmt.Printf("[%3d] =) %x\n", writtenBytes, buffer[:writtenBytes])
		}

		if err != nil {
			return totalWrittenBytes, err
		}
		buffer = buffer[writtenBytes:]
		totalWrittenBytes += writtenBytes
	}
	return totalWrittenBytes, nil
}

func (ledger *Ledger) Read() <-chan []byte {
	ledger.readCo.Do(ledger.initReadChannel)
	return ledger.readChannel
}

func (ledger *Ledger) initReadChannel() {
	ledger.readChannel = make(chan []byte, 30)
	go ledger.readThread()
}

func (ledger *Ledger) readThread() {
	defer close(ledger.readChannel)

	for {
		buffer := make([]byte, PacketSize)
		readBytes, err := ledger.device.Read(buffer)

		if ledger.Logging {
			fmt.Printf("[%3d] (= %x\n", readBytes, buffer[:readBytes])
		}

		if err != nil {
			return
		}
		select {
		case ledger.readChannel <- buffer[:readBytes]:
		default:
		}
	}
}

func (ledger *Ledger) Exchange(command []byte) ([]byte, error) {
	if ledger.Logging {
		fmt.Printf("[%3d]=> %x\n", len(command), command)
	}

	if len(command) < 5 {
		return nil, fmt.Errorf("APDU commands should not be smaller than 5")
	}

	if (byte)(len(command)-5) != command[4] {
		return nil, fmt.Errorf("APDU[data length] mismatch")
	}

	serializedCommand, err := WrapCommandAPDU(Channel, command, PacketSize)
	if err != nil {
		return nil, err
	}

	// Write all the packets
	_, err = ledger.Write(serializedCommand)
	if err != nil {
		return nil, err
	}

	readChannel := ledger.Read()

	response, err := UnwrapResponseAPDU(Channel, readChannel, PacketSize)

	if len(response) < 2 {
		return nil, fmt.Errorf("len(response) < 2")
	}

	swOffset := len(response) - 2
	sw := codec.Uint16(response[swOffset:])

	if ledger.Logging {
		fmt.Printf("Response: [%3d]<= %x [%#x]\n", len(response[:swOffset]), response[:swOffset], sw)
	}
	if sw != 0x9000 {
		return response[:swOffset], errors.New(ErrorMessage(sw))
	}

	return response[:swOffset], nil
}
