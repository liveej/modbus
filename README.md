go modbus [![Build Status](https://travis-ci.org/goburrow/modbus.svg?branch=master)](https://travis-ci.org/goburrow/modbus) [![GoDoc](https://godoc.org/github.com/goburrow/modbus?status.svg)](https://godoc.org/github.com/goburrow/modbus)
=========
Fault-tolerant, fail-fast implementation of Modbus protocol in Go.

Incubating - do not use in production yet (more testing needed).

Supported functions
-------------------
Bit access:
*   Read Discrete Inputs
*   Read Coils
*   Write Single Coil
*   Write Multiple Coils

16-bit access:
*   Read Input Registers
*   Read Holding Registers
*   Write Single Register
*   Write Multiple Registers
*   Read/Write Multiple Registers
*   Mask Write Register
*   Read FIFO Queue

Supported formats
-----------------
*   TCP
*   Serial (RTU, ASCII) - Linux only

Usage
-----
Basic usage:
```go
// Modbus TCP
client := modbus.TCPClient("localhost:502")
// Read input register 9
results, err := client.ReadInputRegisters(8, 1)

// Modbus RTU/ASCII
// Default configuration is 19200, 8, 1, even
client = modbus.RTUClient("/dev/ttyS0")
results, err = client.ReadCoils(2, 1)
```

Advanced usage:
```go
// Modbus TCP
var handler modbus.TCPClientHandler
handler.Address = "localhost:502"
handler.Timeout = 10 * time.Second
handler.SlaveId = 0xFF
handler.Logger = log.New(os.Stdout, "test: ", log.LstdFlags)
// Connect manually so that multiple requests are handled in one connection session
err := handler.Connect()
defer handler.Close()

client := modbus.TCPClientWithHandler(&handler)
results, err := client.ReadDiscreteInputs(15, 2)
results, err = client.WriteMultipleRegisters(1, 2, []byte{0, 3, 0, 4})
results, err = client.WriteMultipleCoils(5, 10, []byte{4, 3})
```

```go
// Modbus RTU/ASCII
var handler modbus.RTUClientHandler
handler.Address = "/dev/ttyUSB0"
handler.BaudRate = 115200
handler.DataBits = 8
handler.Parity = "N"
handler.StopBits = 1
handler.SlaveId = 1
handler.Timeout = 5 * time.Second

err := handler.Connect()
defer handler.Close()

client := modbus.RTUClientWithHandler(&handler)
results, err := client.ReadDiscreteInputs(15, 2)
```

References
----------
-   [Modbus Specifications and Implementation Guides](http://www.modbus.org/specs.php)