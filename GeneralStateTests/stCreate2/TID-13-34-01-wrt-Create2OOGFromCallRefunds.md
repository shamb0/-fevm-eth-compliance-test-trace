
> Status

| Status | Context |
| --- | --- |
| OK | under WASM RT context |
| TODO | under native RT context |

> Test Suite

https://github.com/ethereum/tests/blob/develop/GeneralStateTests/stCreate2/Create2OOGFromCallRefunds.json#L1

> Command to execute

```
clear && \
	RUST_LOG=evm_eth_compliance=trace \
	VECTOR=test-vectors/tests/GeneralStateTests/stCreate2/Create2OOGFromCallRefunds.json \
	cargo run \
	-- \
	statetest
```

> For Review

* Execution looks OK, No "failed to create the new actor :: cannot create address with a reserved prefix" observed.

* Opcode is embedded with `Invalid` instruction. And execution hits properly with error code `pub const EVM_CONTRACT_INVALID_INSTRUCTION: ExitCode = ExitCode::new(34);`

> Opcodes

```
0000 PUSH1 0x04
0002 CALLDATALOAD
0003 DUP1
0004 EXTCODESIZE
0005 DUP1
0006 PUSH1 0x00
0008 PUSH1 0x00
000a DUP5
000b EXTCODECOPY
000c PUSH1 0x00
000e DUP2
000f PUSH1 0x00
0011 PUSH1 0x00
0013 CREATE2
0014 PUSH1 0x00
0016 DUP2
0017 EQ
0018 ISZERO
0019 PUSH1 0x1d
001b JUMPI
001c INVALID
001d JUMPDEST
001e POP
001f POP
0020 POP
```

> Execution Trace

```
2023-01-23T06:52:24.716892Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "test-vectors/tests/GeneralStateTests/stCreate2/Create2OOGFromCallRefunds.json", Total Files :: 1
2023-01-23T06:52:24.717338Z TRACE evm_eth_compliance::statetest::runner: Calling testfile => "test-vectors/tests/GeneralStateTests/stCreate2/Create2OOGFromCallRefunds.json"
2023-01-23T06:52:25.048463Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-23T06:52:25.053809Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-23T06:52:25.053838Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-23T06:52:25.054931Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-23T06:52:25.054944Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 2
2023-01-23T06:52:25.056164Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-23T06:52:25.056177Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 3
2023-01-23T06:52:25.057375Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-23T06:52:25.057390Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 4
2023-01-23T06:52:25.058508Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-23T06:52:25.058521Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 5
2023-01-23T06:52:25.059813Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-23T06:52:25.059827Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 6
2023-01-23T06:52:25.060949Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-23T06:52:25.060962Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 7
2023-01-23T06:52:25.061958Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-23T06:52:25.061974Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 8
2023-01-23T06:52:25.062929Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-23T06:52:25.062943Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 9
2023-01-23T06:52:25.064041Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-23T06:52:25.064054Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 10
2023-01-23T06:52:25.065076Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-23T06:52:25.065089Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 11
2023-01-23T06:52:25.066110Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-23T06:52:25.066124Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 12
2023-01-23T06:52:25.067083Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-23T06:52:25.067096Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 13
2023-01-23T06:52:25.068062Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-23T06:52:25.068075Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 14
2023-01-23T06:52:25.069201Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-23T06:52:25.069220Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 15
2023-01-23T06:52:25.070360Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-23T06:52:25.070376Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 16
2023-01-23T06:52:25.071400Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-23T06:52:25.071414Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 17
2023-01-23T06:52:25.072423Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-23T06:52:25.072436Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 18
2023-01-23T06:52:25.073584Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-23T06:52:25.073598Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 19
2023-01-23T06:52:25.074564Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-23T06:52:25.074578Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 20
2023-01-23T06:52:25.075566Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-23T06:52:25.075579Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 21
2023-01-23T06:52:25.076722Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-23T06:52:25.076735Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 22
2023-01-23T06:52:25.078110Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-23T06:52:25.078123Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 23
2023-01-23T06:52:25.079306Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-23T06:52:25.079319Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 24
2023-01-23T06:52:25.080338Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-23T06:52:25.080350Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 25
2023-01-23T06:52:25.081652Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-23T06:52:25.081666Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 26
2023-01-23T06:52:25.082651Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-23T06:52:25.082663Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 27
2023-01-23T06:52:25.083667Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-23T06:52:25.083680Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 28
2023-01-23T06:52:25.084904Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-23T06:52:25.084926Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 29
2023-01-23T06:52:25.086085Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-23T06:52:25.087147Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-23T06:52:25.087193Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "Create2OOGFromCallRefunds"::London::0
2023-01-23T06:52:25.087202Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stCreate2/Create2OOGFromCallRefunds.json"
2023-01-23T06:52:25.087211Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T06:52:25.087218Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [253, 66, 205, 177, 110, 4, 93, 7, 212, 45, 51, 153, 127, 42, 242, 48, 190, 214, 12, 46, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([215, 166, 242, 208, 200, 186, 79, 10, 126, 8, 221, 102, 9, 12, 200, 158, 203, 19, 78, 227]) }
2023-01-23T06:52:37.928494Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 16195678,
    events_root: None,
}
2023-01-23T06:52:37.928598Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 3
2023-01-23T06:52:37.928645Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "Create2OOGFromCallRefunds"::London::3
2023-01-23T06:52:37.928653Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stCreate2/Create2OOGFromCallRefunds.json"
2023-01-23T06:52:37.928661Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T06:52:37.928667Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [30, 100, 122, 17, 193, 139, 124, 106, 145, 126, 187, 6, 241, 147, 171, 8, 21, 0, 108, 177, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([67, 35, 255, 1, 46, 226, 200, 90, 20, 150, 237, 153, 222, 171, 201, 9, 99, 31, 101, 211]) }
2023-01-23T06:52:37.934769Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 18548813,
    events_root: None,
}
2023-01-23T06:52:37.934927Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 6
2023-01-23T06:52:37.934974Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "Create2OOGFromCallRefunds"::London::6
2023-01-23T06:52:37.934988Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stCreate2/Create2OOGFromCallRefunds.json"
2023-01-23T06:52:37.935000Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T06:52:37.935008Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [135, 212, 56, 175, 5, 79, 15, 49, 77, 194, 204, 93, 244, 62, 89, 228, 239, 185, 103, 151, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([28, 35, 125, 168, 212, 11, 234, 180, 81, 129, 48, 219, 76, 10, 52, 89, 217, 159, 194, 2]) }
2023-01-23T06:52:37.941219Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 21593472,
    events_root: None,
}
2023-01-23T06:52:37.941304Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 9
2023-01-23T06:52:37.941329Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "Create2OOGFromCallRefunds"::London::9
2023-01-23T06:52:37.941337Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stCreate2/Create2OOGFromCallRefunds.json"
2023-01-23T06:52:37.941344Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T06:52:37.941350Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [84, 17, 4, 216, 57, 38, 198, 44, 125, 64, 248, 230, 201, 244, 245, 139, 210, 52, 166, 214, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([132, 105, 76, 107, 184, 77, 78, 105, 101, 219, 134, 121, 221, 254, 217, 203, 72, 121, 220, 83]) }
2023-01-23T06:52:37.945783Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 34,
    },
    return_data: RawBytes {  },
    gas_used: 14854917,
    events_root: None,
}
2023-01-23T06:52:37.945801Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 434,
                    method: 1,
                    code: ExitCode {
                        value: 35,
                    },
                    message: "ABORT(pc=25): undefined instruction",
                },
                Frame {
                    source: 1,
                    method: 3,
                    code: ExitCode {
                        value: 35,
                    },
                    message: "constructor failed: send to f0434 method 1 aborted with code 35",
                },
                Frame {
                    source: 10,
                    method: 3,
                    code: ExitCode {
                        value: 35,
                    },
                    message: "send to f01 method 3 aborted with code 35",
                },
                Frame {
                    source: 429,
                    method: 3844450837,
                    code: ExitCode {
                        value: 34,
                    },
                    message: "ABORT(pc=28): invalid instruction",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-23T06:52:37.945887Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 1
2023-01-23T06:52:37.945911Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "Create2OOGFromCallRefunds"::London::1
2023-01-23T06:52:37.945918Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stCreate2/Create2OOGFromCallRefunds.json"
2023-01-23T06:52:37.945925Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T06:52:37.945931Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [149, 232, 134, 40, 197, 59, 92, 14, 64, 255, 109, 230, 90, 60, 248, 205, 195, 180, 119, 247, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([236, 70, 216, 243, 101, 99, 189, 62, 205, 26, 208, 253, 84, 36, 48, 143, 166, 88, 135, 41]) }
2023-01-23T06:52:37.951598Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 23065406,
    events_root: None,
}
2023-01-23T06:52:37.951664Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 2
2023-01-23T06:52:37.951688Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "Create2OOGFromCallRefunds"::London::2
2023-01-23T06:52:37.951695Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stCreate2/Create2OOGFromCallRefunds.json"
2023-01-23T06:52:37.951702Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T06:52:37.951709Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [102, 225, 204, 38, 22, 162, 115, 69, 6, 33, 200, 204, 94, 145, 216, 207, 217, 36, 148, 250, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([155, 99, 140, 31, 46, 96, 27, 93, 44, 60, 131, 66, 80, 136, 87, 209, 224, 27, 216, 212]) }
2023-01-23T06:52:37.956136Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 34,
    },
    return_data: RawBytes {  },
    gas_used: 14740875,
    events_root: None,
}
2023-01-23T06:52:37.956156Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 435,
                    method: 1,
                    code: ExitCode {
                        value: 34,
                    },
                    message: "ABORT(pc=15): invalid instruction",
                },
                Frame {
                    source: 1,
                    method: 3,
                    code: ExitCode {
                        value: 34,
                    },
                    message: "constructor failed: send to f0435 method 1 aborted with code 34",
                },
                Frame {
                    source: 10,
                    method: 3,
                    code: ExitCode {
                        value: 34,
                    },
                    message: "send to f01 method 3 aborted with code 34",
                },
                Frame {
                    source: 429,
                    method: 3844450837,
                    code: ExitCode {
                        value: 34,
                    },
                    message: "ABORT(pc=28): invalid instruction",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-23T06:52:37.956271Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 4
2023-01-23T06:52:37.956305Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "Create2OOGFromCallRefunds"::London::4
2023-01-23T06:52:37.956313Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stCreate2/Create2OOGFromCallRefunds.json"
2023-01-23T06:52:37.956320Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T06:52:37.956326Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [97, 117, 186, 153, 118, 71, 100, 37, 177, 205, 168, 225, 218, 71, 151, 104, 251, 66, 149, 66, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([188, 149, 186, 245, 1, 91, 222, 203, 63, 25, 86, 169, 35, 110, 18, 124, 122, 60, 238, 128]) }
2023-01-23T06:52:37.963390Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 25378056,
    events_root: None,
}
2023-01-23T06:52:37.963511Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 5
2023-01-23T06:52:37.963559Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "Create2OOGFromCallRefunds"::London::5
2023-01-23T06:52:37.963568Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stCreate2/Create2OOGFromCallRefunds.json"
2023-01-23T06:52:37.963575Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T06:52:37.963582Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [141, 255, 14, 68, 143, 30, 7, 142, 155, 138, 127, 207, 11, 246, 194, 145, 241, 103, 170, 239, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([20, 3, 204, 71, 166, 252, 88, 221, 29, 77, 14, 224, 191, 132, 61, 100, 47, 53, 166, 175]) }
2023-01-23T06:52:37.969534Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 34,
    },
    return_data: RawBytes {  },
    gas_used: 17603727,
    events_root: None,
}
2023-01-23T06:52:37.969565Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 436,
                    method: 1,
                    code: ExitCode {
                        value: 34,
                    },
                    message: "ABORT(pc=22): invalid instruction",
                },
                Frame {
                    source: 1,
                    method: 3,
                    code: ExitCode {
                        value: 34,
                    },
                    message: "constructor failed: send to f0436 method 1 aborted with code 34",
                },
                Frame {
                    source: 10,
                    method: 3,
                    code: ExitCode {
                        value: 34,
                    },
                    message: "send to f01 method 3 aborted with code 34",
                },
                Frame {
                    source: 429,
                    method: 3844450837,
                    code: ExitCode {
                        value: 34,
                    },
                    message: "ABORT(pc=28): invalid instruction",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-23T06:52:37.969676Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 7
2023-01-23T06:52:37.969719Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "Create2OOGFromCallRefunds"::London::7
2023-01-23T06:52:37.969727Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stCreate2/Create2OOGFromCallRefunds.json"
2023-01-23T06:52:37.969734Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T06:52:37.969741Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [162, 196, 39, 8, 0, 165, 219, 238, 164, 132, 100, 229, 242, 66, 14, 251, 23, 71, 114, 90, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([177, 189, 137, 170, 161, 168, 98, 8, 218, 14, 105, 2, 242, 92, 44, 234, 2, 122, 233, 63]) }
2023-01-23T06:52:37.977343Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 28404601,
    events_root: None,
}
2023-01-23T06:52:37.977462Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 8
2023-01-23T06:52:37.977513Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "Create2OOGFromCallRefunds"::London::8
2023-01-23T06:52:37.977523Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stCreate2/Create2OOGFromCallRefunds.json"
2023-01-23T06:52:37.977531Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T06:52:37.977537Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [77, 128, 241, 21, 14, 226, 54, 173, 250, 171, 71, 199, 13, 249, 14, 117, 124, 239, 17, 65, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([178, 221, 99, 117, 94, 25, 113, 14, 55, 217, 63, 213, 179, 235, 175, 240, 178, 120, 15, 225]) }
2023-01-23T06:52:37.983768Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 34,
    },
    return_data: RawBytes {  },
    gas_used: 20783758,
    events_root: None,
}
2023-01-23T06:52:37.983784Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 437,
                    method: 1,
                    code: ExitCode {
                        value: 34,
                    },
                    message: "ABORT(pc=25): invalid instruction",
                },
                Frame {
                    source: 1,
                    method: 3,
                    code: ExitCode {
                        value: 34,
                    },
                    message: "constructor failed: send to f0437 method 1 aborted with code 34",
                },
                Frame {
                    source: 10,
                    method: 3,
                    code: ExitCode {
                        value: 34,
                    },
                    message: "send to f01 method 3 aborted with code 34",
                },
                Frame {
                    source: 429,
                    method: 3844450837,
                    code: ExitCode {
                        value: 34,
                    },
                    message: "ABORT(pc=28): invalid instruction",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-23T06:52:37.983887Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 10
2023-01-23T06:52:37.983912Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "Create2OOGFromCallRefunds"::London::10
2023-01-23T06:52:37.983919Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stCreate2/Create2OOGFromCallRefunds.json"
2023-01-23T06:52:37.983926Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T06:52:37.983933Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [5, 102, 220, 141, 171, 200, 15, 173, 62, 217, 171, 43, 67, 9, 235, 253, 152, 137, 79, 68, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([251, 114, 94, 192, 108, 10, 201, 112, 101, 197, 5, 103, 36, 134, 180, 68, 48, 44, 184, 84]) }
2023-01-23T06:52:37.988395Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 34,
    },
    return_data: RawBytes {  },
    gas_used: 15075466,
    events_root: None,
}
2023-01-23T06:52:37.988410Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 437,
                    method: 1,
                    code: ExitCode {
                        value: 35,
                    },
                    message: "ABORT(pc=25): undefined instruction",
                },
                Frame {
                    source: 1,
                    method: 3,
                    code: ExitCode {
                        value: 35,
                    },
                    message: "constructor failed: send to f0437 method 1 aborted with code 35",
                },
                Frame {
                    source: 10,
                    method: 3,
                    code: ExitCode {
                        value: 35,
                    },
                    message: "send to f01 method 3 aborted with code 35",
                },
                Frame {
                    source: 429,
                    method: 3844450837,
                    code: ExitCode {
                        value: 34,
                    },
                    message: "ABORT(pc=28): invalid instruction",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-23T06:52:37.988493Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 11
2023-01-23T06:52:37.988517Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "Create2OOGFromCallRefunds"::London::11
2023-01-23T06:52:37.988525Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stCreate2/Create2OOGFromCallRefunds.json"
2023-01-23T06:52:37.988534Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T06:52:37.988540Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [85, 48, 92, 196, 107, 218, 241, 231, 85, 160, 90, 119, 29, 85, 207, 236, 63, 237, 239, 144, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([90, 217, 32, 146, 24, 201, 117, 10, 10, 210, 28, 70, 31, 30, 132, 56, 243, 180, 75, 35]) }
2023-01-23T06:52:37.993223Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 34,
    },
    return_data: RawBytes {  },
    gas_used: 15247967,
    events_root: None,
}
2023-01-23T06:52:37.993242Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 437,
                    method: 1,
                    code: ExitCode {
                        value: 35,
                    },
                    message: "ABORT(pc=25): undefined instruction",
                },
                Frame {
                    source: 1,
                    method: 3,
                    code: ExitCode {
                        value: 35,
                    },
                    message: "constructor failed: send to f0437 method 1 aborted with code 35",
                },
                Frame {
                    source: 10,
                    method: 3,
                    code: ExitCode {
                        value: 35,
                    },
                    message: "send to f01 method 3 aborted with code 35",
                },
                Frame {
                    source: 429,
                    method: 3844450837,
                    code: ExitCode {
                        value: 34,
                    },
                    message: "ABORT(pc=28): invalid instruction",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-23T06:52:37.993331Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 12
2023-01-23T06:52:37.993363Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "Create2OOGFromCallRefunds"::London::12
2023-01-23T06:52:37.993370Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stCreate2/Create2OOGFromCallRefunds.json"
2023-01-23T06:52:37.993377Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T06:52:37.993383Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [74, 235, 112, 75, 210, 181, 65, 52, 242, 88, 18, 137, 161, 254, 239, 34, 147, 168, 39, 34, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([128, 138, 188, 155, 213, 11, 225, 143, 246, 50, 199, 246, 94, 148, 129, 183, 56, 152, 76, 55]) }
2023-01-23T06:52:37.998999Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 17706783,
    events_root: None,
}
2023-01-23T06:52:37.999108Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 13
2023-01-23T06:52:37.999147Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "Create2OOGFromCallRefunds"::London::13
2023-01-23T06:52:37.999155Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stCreate2/Create2OOGFromCallRefunds.json"
2023-01-23T06:52:37.999162Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T06:52:37.999168Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [143, 110, 108, 116, 26, 201, 92, 26, 145, 9, 133, 14, 161, 163, 255, 199, 34, 220, 59, 248, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([55, 124, 170, 147, 221, 2, 18, 238, 216, 76, 43, 142, 118, 199, 246, 132, 57, 223, 23, 100]) }
2023-01-23T06:52:38.005693Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 24655751,
    events_root: None,
}
2023-01-23T06:52:38.005768Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 14
2023-01-23T06:52:38.005794Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "Create2OOGFromCallRefunds"::London::14
2023-01-23T06:52:38.005801Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stCreate2/Create2OOGFromCallRefunds.json"
2023-01-23T06:52:38.005808Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T06:52:38.005814Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [31, 93, 24, 123, 179, 164, 141, 187, 44, 1, 29, 10, 110, 115, 26, 200, 19, 23, 153, 173, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([171, 234, 181, 15, 37, 193, 240, 156, 211, 60, 172, 98, 156, 55, 186, 0, 159, 236, 160, 247]) }
2023-01-23T06:52:38.010815Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 34,
    },
    return_data: RawBytes {  },
    gas_used: 16289387,
    events_root: None,
}
2023-01-23T06:52:38.010831Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 439,
                    method: 1,
                    code: ExitCode {
                        value: 34,
                    },
                    message: "ABORT(pc=22): invalid instruction",
                },
                Frame {
                    source: 1,
                    method: 3,
                    code: ExitCode {
                        value: 34,
                    },
                    message: "constructor failed: send to f0439 method 1 aborted with code 34",
                },
                Frame {
                    source: 10,
                    method: 3,
                    code: ExitCode {
                        value: 34,
                    },
                    message: "send to f01 method 3 aborted with code 34",
                },
                Frame {
                    source: 429,
                    method: 3844450837,
                    code: ExitCode {
                        value: 34,
                    },
                    message: "ABORT(pc=28): invalid instruction",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-23T06:52:38.010951Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 15
2023-01-23T06:52:38.010978Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "Create2OOGFromCallRefunds"::London::15
2023-01-23T06:52:38.010985Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stCreate2/Create2OOGFromCallRefunds.json"
2023-01-23T06:52:38.010992Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T06:52:38.010998Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [153, 42, 93, 87, 222, 110, 163, 244, 17, 35, 241, 197, 18, 33, 52, 175, 66, 165, 169, 162, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([167, 18, 209, 255, 80, 109, 220, 136, 239, 83, 214, 196, 45, 184, 19, 227, 137, 201, 135, 105]) }
2023-01-23T06:52:38.017188Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 18878086,
    events_root: Some(
        Cid {
            version: V1,
            codec: 113,
            hash: Multihash {
                code: 45600,
                size: 32,
                digest: [
                    113,
                    218,
                    236,
                    99,
                    248,
                    116,
                    249,
                    119,
                    183,
                    47,
                    122,
                    8,
                    183,
                    73,
                    251,
                    203,
                    102,
                    196,
                    92,
                    253,
                    188,
                    88,
                    73,
                    95,
                    65,
                    32,
                    46,
                    156,
                    105,
                    221,
                    24,
                    75,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                ],
            },
        },
    ),
}
2023-01-23T06:52:38.017334Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 16
2023-01-23T06:52:38.017374Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "Create2OOGFromCallRefunds"::London::16
2023-01-23T06:52:38.017384Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stCreate2/Create2OOGFromCallRefunds.json"
2023-01-23T06:52:38.017391Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T06:52:38.017397Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [116, 179, 146, 145, 223, 194, 55, 192, 212, 47, 209, 84, 87, 117, 71, 120, 245, 28, 109, 232, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([143, 33, 161, 133, 93, 209, 38, 110, 16, 16, 237, 126, 30, 78, 59, 192, 15, 148, 83, 57]) }
2023-01-23T06:52:38.023931Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 24611378,
    events_root: Some(
        Cid {
            version: V1,
            codec: 113,
            hash: Multihash {
                code: 45600,
                size: 32,
                digest: [
                    113,
                    218,
                    236,
                    99,
                    248,
                    116,
                    249,
                    119,
                    183,
                    47,
                    122,
                    8,
                    183,
                    73,
                    251,
                    203,
                    102,
                    196,
                    92,
                    253,
                    188,
                    88,
                    73,
                    95,
                    65,
                    32,
                    46,
                    156,
                    105,
                    221,
                    24,
                    75,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                ],
            },
        },
    ),
}
2023-01-23T06:52:38.024056Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 17
2023-01-23T06:52:38.024079Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "Create2OOGFromCallRefunds"::London::17
2023-01-23T06:52:38.024086Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stCreate2/Create2OOGFromCallRefunds.json"
2023-01-23T06:52:38.024094Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T06:52:38.024101Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [51, 153, 199, 137, 41, 234, 184, 156, 103, 58, 137, 134, 255, 124, 169, 204, 196, 157, 180, 84, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([115, 209, 18, 63, 181, 115, 165, 219, 137, 112, 100, 108, 193, 38, 167, 163, 136, 114, 38, 238]) }
2023-01-23T06:52:38.029525Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 34,
    },
    return_data: RawBytes {  },
    gas_used: 17758577,
    events_root: None,
}
2023-01-23T06:52:38.029542Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 441,
                    method: 1,
                    code: ExitCode {
                        value: 34,
                    },
                    message: "ABORT(pc=22): invalid instruction",
                },
                Frame {
                    source: 1,
                    method: 3,
                    code: ExitCode {
                        value: 34,
                    },
                    message: "constructor failed: send to f0441 method 1 aborted with code 34",
                },
                Frame {
                    source: 10,
                    method: 3,
                    code: ExitCode {
                        value: 34,
                    },
                    message: "send to f01 method 3 aborted with code 34",
                },
                Frame {
                    source: 429,
                    method: 3844450837,
                    code: ExitCode {
                        value: 34,
                    },
                    message: "ABORT(pc=28): invalid instruction",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-23T06:52:38.029638Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 18
2023-01-23T06:52:38.029664Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "Create2OOGFromCallRefunds"::London::18
2023-01-23T06:52:38.029671Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stCreate2/Create2OOGFromCallRefunds.json"
2023-01-23T06:52:38.029678Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T06:52:38.029684Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [196, 146, 137, 46, 27, 12, 136, 54, 240, 113, 15, 144, 191, 144, 72, 0, 218, 78, 218, 141, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([164, 19, 188, 157, 123, 198, 227, 16, 99, 7, 112, 55, 126, 183, 242, 167, 190, 31, 240, 147]) }
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [179, 181, 5, 127, 144, 150, 1, 96, 232, 175, 179, 139, 57, 39, 206, 60, 231, 206, 240, 131, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([72, 66, 192, 23, 236, 195, 123, 135, 136, 153, 189, 230, 240, 174, 146, 55, 224, 60, 185, 254]) }
2023-01-23T06:52:38.039102Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 31498580,
    events_root: None,
}
2023-01-23T06:52:38.039252Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 19
2023-01-23T06:52:38.039295Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "Create2OOGFromCallRefunds"::London::19
2023-01-23T06:52:38.039303Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stCreate2/Create2OOGFromCallRefunds.json"
2023-01-23T06:52:38.039311Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T06:52:38.039317Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [249, 34, 178, 247, 1, 16, 200, 63, 142, 199, 223, 81, 43, 65, 186, 197, 98, 126, 142, 89, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([40, 113, 131, 83, 213, 98, 3, 231, 134, 49, 131, 92, 170, 242, 84, 90, 74, 151, 72, 246]) }
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [57, 132, 38, 231, 54, 128, 31, 231, 18, 223, 30, 240, 120, 163, 182, 202, 60, 111, 6, 59, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([45, 64, 152, 245, 123, 126, 128, 251, 245, 59, 92, 106, 38, 248, 46, 19, 54, 253, 5, 239]) }
2023-01-23T06:52:38.049606Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 38169477,
    events_root: None,
}
2023-01-23T06:52:38.049753Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 20
2023-01-23T06:52:38.049807Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "Create2OOGFromCallRefunds"::London::20
2023-01-23T06:52:38.049818Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stCreate2/Create2OOGFromCallRefunds.json"
2023-01-23T06:52:38.049826Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T06:52:38.049832Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [44, 167, 136, 210, 46, 33, 19, 74, 177, 144, 146, 102, 237, 59, 108, 53, 46, 42, 7, 203, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([40, 182, 218, 235, 33, 11, 225, 5, 136, 185, 130, 124, 42, 168, 16, 11, 169, 12, 214, 166]) }
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [181, 32, 104, 103, 89, 206, 211, 188, 157, 136, 152, 224, 46, 228, 22, 35, 3, 47, 244, 127, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([74, 158, 232, 176, 23, 67, 144, 90, 171, 16, 228, 107, 181, 166, 212, 111, 69, 135, 184, 75]) }
2023-01-23T06:52:38.059384Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 34,
    },
    return_data: RawBytes {  },
    gas_used: 30714509,
    events_root: None,
}
2023-01-23T06:52:38.059409Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 445,
                    method: 1,
                    code: ExitCode {
                        value: 34,
                    },
                    message: "ABORT(pc=35): invalid instruction",
                },
                Frame {
                    source: 1,
                    method: 3,
                    code: ExitCode {
                        value: 34,
                    },
                    message: "constructor failed: send to f0445 method 1 aborted with code 34",
                },
                Frame {
                    source: 10,
                    method: 3,
                    code: ExitCode {
                        value: 34,
                    },
                    message: "send to f01 method 3 aborted with code 34",
                },
                Frame {
                    source: 429,
                    method: 3844450837,
                    code: ExitCode {
                        value: 34,
                    },
                    message: "ABORT(pc=28): invalid instruction",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-23T06:52:38.059544Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 21
2023-01-23T06:52:38.059584Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "Create2OOGFromCallRefunds"::London::21
2023-01-23T06:52:38.059591Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stCreate2/Create2OOGFromCallRefunds.json"
2023-01-23T06:52:38.059599Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T06:52:38.059605Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [14, 40, 164, 87, 206, 35, 160, 22, 170, 223, 235, 193, 105, 21, 43, 194, 6, 14, 40, 155, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([120, 103, 96, 100, 116, 249, 190, 222, 117, 123, 178, 182, 219, 22, 101, 99, 7, 208, 237, 37]) }
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [71, 217, 116, 87, 5, 42, 35, 190, 142, 32, 27, 112, 61, 60, 177, 60, 37, 240, 249, 114, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([170, 231, 242, 225, 179, 169, 163, 205, 94, 242, 42, 231, 180, 207, 28, 84, 155, 73, 110, 102]) }
2023-01-23T06:52:38.068635Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 31288536,
    events_root: None,
}
2023-01-23T06:52:38.068766Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 22
2023-01-23T06:52:38.068806Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "Create2OOGFromCallRefunds"::London::22
2023-01-23T06:52:38.068814Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stCreate2/Create2OOGFromCallRefunds.json"
2023-01-23T06:52:38.068822Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T06:52:38.068828Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [221, 44, 83, 191, 202, 245, 193, 214, 152, 162, 178, 28, 9, 8, 241, 95, 127, 191, 214, 53, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([173, 101, 220, 118, 126, 227, 221, 111, 130, 239, 232, 201, 210, 70, 69, 50, 207, 38, 17, 72]) }
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [169, 157, 164, 234, 73, 3, 53, 201, 134, 213, 43, 12, 201, 227, 247, 139, 40, 106, 197, 252, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([35, 59, 216, 163, 67, 28, 202, 201, 254, 163, 77, 239, 227, 129, 106, 143, 73, 182, 194, 64]) }
2023-01-23T06:52:38.079318Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 38639152,
    events_root: None,
}
2023-01-23T06:52:38.079441Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 23
2023-01-23T06:52:38.079478Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "Create2OOGFromCallRefunds"::London::23
2023-01-23T06:52:38.079486Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stCreate2/Create2OOGFromCallRefunds.json"
2023-01-23T06:52:38.079493Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T06:52:38.079499Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [45, 85, 107, 219, 204, 55, 199, 160, 33, 135, 154, 33, 171, 226, 93, 24, 80, 212, 253, 54, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([21, 34, 247, 70, 142, 122, 19, 174, 255, 98, 183, 37, 253, 210, 62, 191, 224, 79, 199, 228]) }
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [180, 171, 138, 176, 211, 99, 118, 85, 134, 146, 94, 53, 199, 21, 227, 66, 228, 174, 60, 99, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([223, 223, 142, 153, 166, 139, 108, 56, 156, 236, 39, 109, 202, 30, 79, 221, 136, 157, 126, 212]) }
2023-01-23T06:52:38.088978Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 34,
    },
    return_data: RawBytes {  },
    gas_used: 30275053,
    events_root: None,
}
2023-01-23T06:52:38.089010Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 449,
                    method: 1,
                    code: ExitCode {
                        value: 34,
                    },
                    message: "ABORT(pc=37): invalid instruction",
                },
                Frame {
                    source: 1,
                    method: 3,
                    code: ExitCode {
                        value: 34,
                    },
                    message: "constructor failed: send to f0449 method 1 aborted with code 34",
                },
                Frame {
                    source: 10,
                    method: 3,
                    code: ExitCode {
                        value: 34,
                    },
                    message: "send to f01 method 3 aborted with code 34",
                },
                Frame {
                    source: 429,
                    method: 3844450837,
                    code: ExitCode {
                        value: 34,
                    },
                    message: "ABORT(pc=28): invalid instruction",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-23T06:52:38.089230Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-23T06:52:38.089285Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "Create2OOGFromCallRefunds"::Merge::0
2023-01-23T06:52:38.089293Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stCreate2/Create2OOGFromCallRefunds.json"
2023-01-23T06:52:38.089301Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T06:52:38.089307Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T06:52:38.092238Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 34,
    },
    return_data: RawBytes {  },
    gas_used: 6224976,
    events_root: None,
}
2023-01-23T06:52:38.092260Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 431,
                    method: 2,
                    code: ExitCode {
                        value: 18,
                    },
                    message: "can only resurrect a dead contract",
                },
                Frame {
                    source: 10,
                    method: 3,
                    code: ExitCode {
                        value: 18,
                    },
                    message: "send to f0431 method 2 aborted with code 18",
                },
                Frame {
                    source: 429,
                    method: 3844450837,
                    code: ExitCode {
                        value: 34,
                    },
                    message: "ABORT(pc=28): invalid instruction",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-23T06:52:38.092332Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 3
2023-01-23T06:52:38.092367Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "Create2OOGFromCallRefunds"::Merge::3
2023-01-23T06:52:38.092374Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stCreate2/Create2OOGFromCallRefunds.json"
2023-01-23T06:52:38.092381Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T06:52:38.092387Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T06:52:38.095274Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 34,
    },
    return_data: RawBytes {  },
    gas_used: 6229503,
    events_root: None,
}
2023-01-23T06:52:38.095296Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 432,
                    method: 2,
                    code: ExitCode {
                        value: 18,
                    },
                    message: "can only resurrect a dead contract",
                },
                Frame {
                    source: 10,
                    method: 3,
                    code: ExitCode {
                        value: 18,
                    },
                    message: "send to f0432 method 2 aborted with code 18",
                },
                Frame {
                    source: 429,
                    method: 3844450837,
                    code: ExitCode {
                        value: 34,
                    },
                    message: "ABORT(pc=28): invalid instruction",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-23T06:52:38.095365Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 6
2023-01-23T06:52:38.095398Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "Create2OOGFromCallRefunds"::Merge::6
2023-01-23T06:52:38.095405Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stCreate2/Create2OOGFromCallRefunds.json"
2023-01-23T06:52:38.095413Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T06:52:38.095419Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T06:52:38.098274Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 34,
    },
    return_data: RawBytes {  },
    gas_used: 6229854,
    events_root: None,
}
2023-01-23T06:52:38.098295Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 433,
                    method: 2,
                    code: ExitCode {
                        value: 18,
                    },
                    message: "can only resurrect a dead contract",
                },
                Frame {
                    source: 10,
                    method: 3,
                    code: ExitCode {
                        value: 18,
                    },
                    message: "send to f0433 method 2 aborted with code 18",
                },
                Frame {
                    source: 429,
                    method: 3844450837,
                    code: ExitCode {
                        value: 34,
                    },
                    message: "ABORT(pc=28): invalid instruction",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-23T06:52:38.098361Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 9
2023-01-23T06:52:38.098395Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "Create2OOGFromCallRefunds"::Merge::9
2023-01-23T06:52:38.098402Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stCreate2/Create2OOGFromCallRefunds.json"
2023-01-23T06:52:38.098409Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T06:52:38.098415Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [84, 17, 4, 216, 57, 38, 198, 44, 125, 64, 248, 230, 201, 244, 245, 139, 210, 52, 166, 214, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([96, 33, 187, 115, 222, 53, 224, 244, 47, 32, 70, 11, 226, 18, 129, 166, 126, 239, 230, 44]) }
2023-01-23T06:52:38.103563Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 34,
    },
    return_data: RawBytes {  },
    gas_used: 15017667,
    events_root: None,
}
2023-01-23T06:52:38.103590Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 449,
                    method: 1,
                    code: ExitCode {
                        value: 35,
                    },
                    message: "ABORT(pc=25): undefined instruction",
                },
                Frame {
                    source: 1,
                    method: 3,
                    code: ExitCode {
                        value: 35,
                    },
                    message: "constructor failed: send to f0449 method 1 aborted with code 35",
                },
                Frame {
                    source: 10,
                    method: 3,
                    code: ExitCode {
                        value: 35,
                    },
                    message: "send to f01 method 3 aborted with code 35",
                },
                Frame {
                    source: 429,
                    method: 3844450837,
                    code: ExitCode {
                        value: 34,
                    },
                    message: "ABORT(pc=28): invalid instruction",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-23T06:52:38.103691Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 1
2023-01-23T06:52:38.103735Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "Create2OOGFromCallRefunds"::Merge::1
2023-01-23T06:52:38.103744Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stCreate2/Create2OOGFromCallRefunds.json"
2023-01-23T06:52:38.103752Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T06:52:38.103758Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T06:52:38.106701Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 34,
    },
    return_data: RawBytes {  },
    gas_used: 6226569,
    events_root: None,
}
2023-01-23T06:52:38.106723Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 434,
                    method: 2,
                    code: ExitCode {
                        value: 18,
                    },
                    message: "can only resurrect a dead contract",
                },
                Frame {
                    source: 10,
                    method: 3,
                    code: ExitCode {
                        value: 18,
                    },
                    message: "send to f0434 method 2 aborted with code 18",
                },
                Frame {
                    source: 429,
                    method: 3844450837,
                    code: ExitCode {
                        value: 34,
                    },
                    message: "ABORT(pc=28): invalid instruction",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-23T06:52:38.106795Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 2
2023-01-23T06:52:38.106830Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "Create2OOGFromCallRefunds"::Merge::2
2023-01-23T06:52:38.106837Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stCreate2/Create2OOGFromCallRefunds.json"
2023-01-23T06:52:38.106844Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T06:52:38.106850Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [102, 225, 204, 38, 22, 162, 115, 69, 6, 33, 200, 204, 94, 145, 216, 207, 217, 36, 148, 250, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([96, 157, 121, 180, 71, 136, 28, 182, 195, 187, 216, 146, 44, 166, 42, 126, 234, 16, 198, 148]) }
2023-01-23T06:52:38.111308Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 34,
    },
    return_data: RawBytes {  },
    gas_used: 14741812,
    events_root: None,
}
2023-01-23T06:52:38.111328Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 449,
                    method: 1,
                    code: ExitCode {
                        value: 34,
                    },
                    message: "ABORT(pc=15): invalid instruction",
                },
                Frame {
                    source: 1,
                    method: 3,
                    code: ExitCode {
                        value: 34,
                    },
                    message: "constructor failed: send to f0449 method 1 aborted with code 34",
                },
                Frame {
                    source: 10,
                    method: 3,
                    code: ExitCode {
                        value: 34,
                    },
                    message: "send to f01 method 3 aborted with code 34",
                },
                Frame {
                    source: 429,
                    method: 3844450837,
                    code: ExitCode {
                        value: 34,
                    },
                    message: "ABORT(pc=28): invalid instruction",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-23T06:52:38.111411Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 4
2023-01-23T06:52:38.111439Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "Create2OOGFromCallRefunds"::Merge::4
2023-01-23T06:52:38.111447Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stCreate2/Create2OOGFromCallRefunds.json"
2023-01-23T06:52:38.111454Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T06:52:38.111460Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T06:52:38.114255Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 34,
    },
    return_data: RawBytes {  },
    gas_used: 6229580,
    events_root: None,
}
2023-01-23T06:52:38.114272Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 435,
                    method: 2,
                    code: ExitCode {
                        value: 18,
                    },
                    message: "can only resurrect a dead contract",
                },
                Frame {
                    source: 10,
                    method: 3,
                    code: ExitCode {
                        value: 18,
                    },
                    message: "send to f0435 method 2 aborted with code 18",
                },
                Frame {
                    source: 429,
                    method: 3844450837,
                    code: ExitCode {
                        value: 34,
                    },
                    message: "ABORT(pc=28): invalid instruction",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-23T06:52:38.114337Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 5
2023-01-23T06:52:38.114364Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "Create2OOGFromCallRefunds"::Merge::5
2023-01-23T06:52:38.114371Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stCreate2/Create2OOGFromCallRefunds.json"
2023-01-23T06:52:38.114378Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T06:52:38.114384Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [141, 255, 14, 68, 143, 30, 7, 142, 155, 138, 127, 207, 11, 246, 194, 145, 241, 103, 170, 239, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([57, 47, 201, 253, 31, 210, 216, 45, 82, 53, 15, 10, 140, 189, 182, 38, 139, 193, 227, 148]) }
2023-01-23T06:52:38.120721Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 34,
    },
    return_data: RawBytes {  },
    gas_used: 17777117,
    events_root: None,
}
2023-01-23T06:52:38.120750Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 449,
                    method: 1,
                    code: ExitCode {
                        value: 34,
                    },
                    message: "ABORT(pc=22): invalid instruction",
                },
                Frame {
                    source: 1,
                    method: 3,
                    code: ExitCode {
                        value: 34,
                    },
                    message: "constructor failed: send to f0449 method 1 aborted with code 34",
                },
                Frame {
                    source: 10,
                    method: 3,
                    code: ExitCode {
                        value: 34,
                    },
                    message: "send to f01 method 3 aborted with code 34",
                },
                Frame {
                    source: 429,
                    method: 3844450837,
                    code: ExitCode {
                        value: 34,
                    },
                    message: "ABORT(pc=28): invalid instruction",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-23T06:52:38.120873Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 7
2023-01-23T06:52:38.120919Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "Create2OOGFromCallRefunds"::Merge::7
2023-01-23T06:52:38.120926Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stCreate2/Create2OOGFromCallRefunds.json"
2023-01-23T06:52:38.120934Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T06:52:38.120940Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T06:52:38.123799Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 34,
    },
    return_data: RawBytes {  },
    gas_used: 6227727,
    events_root: None,
}
2023-01-23T06:52:38.123816Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 436,
                    method: 2,
                    code: ExitCode {
                        value: 18,
                    },
                    message: "can only resurrect a dead contract",
                },
                Frame {
                    source: 10,
                    method: 3,
                    code: ExitCode {
                        value: 18,
                    },
                    message: "send to f0436 method 2 aborted with code 18",
                },
                Frame {
                    source: 429,
                    method: 3844450837,
                    code: ExitCode {
                        value: 34,
                    },
                    message: "ABORT(pc=28): invalid instruction",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-23T06:52:38.123878Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 8
2023-01-23T06:52:38.123902Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "Create2OOGFromCallRefunds"::Merge::8
2023-01-23T06:52:38.123910Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stCreate2/Create2OOGFromCallRefunds.json"
2023-01-23T06:52:38.123917Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T06:52:38.123923Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [77, 128, 241, 21, 14, 226, 54, 173, 250, 171, 71, 199, 13, 249, 14, 117, 124, 239, 17, 65, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([234, 139, 137, 133, 156, 6, 41, 217, 87, 171, 216, 141, 23, 64, 208, 12, 0, 6, 118, 73]) }
2023-01-23T06:52:38.130346Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 34,
    },
    return_data: RawBytes {  },
    gas_used: 20575752,
    events_root: None,
}
2023-01-23T06:52:38.130389Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 449,
                    method: 1,
                    code: ExitCode {
                        value: 34,
                    },
                    message: "ABORT(pc=25): invalid instruction",
                },
                Frame {
                    source: 1,
                    method: 3,
                    code: ExitCode {
                        value: 34,
                    },
                    message: "constructor failed: send to f0449 method 1 aborted with code 34",
                },
                Frame {
                    source: 10,
                    method: 3,
                    code: ExitCode {
                        value: 34,
                    },
                    message: "send to f01 method 3 aborted with code 34",
                },
                Frame {
                    source: 429,
                    method: 3844450837,
                    code: ExitCode {
                        value: 34,
                    },
                    message: "ABORT(pc=28): invalid instruction",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-23T06:52:38.130587Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 10
2023-01-23T06:52:38.130649Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "Create2OOGFromCallRefunds"::Merge::10
2023-01-23T06:52:38.130662Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stCreate2/Create2OOGFromCallRefunds.json"
2023-01-23T06:52:38.130670Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T06:52:38.130676Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [5, 102, 220, 141, 171, 200, 15, 173, 62, 217, 171, 43, 67, 9, 235, 253, 152, 137, 79, 68, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([74, 138, 107, 177, 65, 173, 106, 127, 111, 235, 64, 25, 56, 77, 152, 139, 121, 241, 216, 113]) }
2023-01-23T06:52:38.135489Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 34,
    },
    return_data: RawBytes {  },
    gas_used: 14978934,
    events_root: None,
}
2023-01-23T06:52:38.135513Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 449,
                    method: 1,
                    code: ExitCode {
                        value: 35,
                    },
                    message: "ABORT(pc=25): undefined instruction",
                },
                Frame {
                    source: 1,
                    method: 3,
                    code: ExitCode {
                        value: 35,
                    },
                    message: "constructor failed: send to f0449 method 1 aborted with code 35",
                },
                Frame {
                    source: 10,
                    method: 3,
                    code: ExitCode {
                        value: 35,
                    },
                    message: "send to f01 method 3 aborted with code 35",
                },
                Frame {
                    source: 429,
                    method: 3844450837,
                    code: ExitCode {
                        value: 34,
                    },
                    message: "ABORT(pc=28): invalid instruction",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-23T06:52:38.135605Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 11
2023-01-23T06:52:38.135647Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "Create2OOGFromCallRefunds"::Merge::11
2023-01-23T06:52:38.135654Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stCreate2/Create2OOGFromCallRefunds.json"
2023-01-23T06:52:38.135661Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T06:52:38.135668Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [85, 48, 92, 196, 107, 218, 241, 231, 85, 160, 90, 119, 29, 85, 207, 236, 63, 237, 239, 144, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([126, 248, 213, 18, 73, 109, 79, 84, 218, 211, 209, 213, 172, 193, 146, 154, 144, 35, 152, 99]) }
2023-01-23T06:52:38.140030Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 34,
    },
    return_data: RawBytes {  },
    gas_used: 14795661,
    events_root: None,
}
2023-01-23T06:52:38.140046Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 449,
                    method: 1,
                    code: ExitCode {
                        value: 35,
                    },
                    message: "ABORT(pc=25): undefined instruction",
                },
                Frame {
                    source: 1,
                    method: 3,
                    code: ExitCode {
                        value: 35,
                    },
                    message: "constructor failed: send to f0449 method 1 aborted with code 35",
                },
                Frame {
                    source: 10,
                    method: 3,
                    code: ExitCode {
                        value: 35,
                    },
                    message: "send to f01 method 3 aborted with code 35",
                },
                Frame {
                    source: 429,
                    method: 3844450837,
                    code: ExitCode {
                        value: 34,
                    },
                    message: "ABORT(pc=28): invalid instruction",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-23T06:52:38.140127Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 12
2023-01-23T06:52:38.140151Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "Create2OOGFromCallRefunds"::Merge::12
2023-01-23T06:52:38.140158Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stCreate2/Create2OOGFromCallRefunds.json"
2023-01-23T06:52:38.140165Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T06:52:38.140171Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T06:52:38.142865Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 34,
    },
    return_data: RawBytes {  },
    gas_used: 6229503,
    events_root: None,
}
2023-01-23T06:52:38.142882Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 437,
                    method: 2,
                    code: ExitCode {
                        value: 18,
                    },
                    message: "can only resurrect a dead contract",
                },
                Frame {
                    source: 10,
                    method: 3,
                    code: ExitCode {
                        value: 18,
                    },
                    message: "send to f0437 method 2 aborted with code 18",
                },
                Frame {
                    source: 429,
                    method: 3844450837,
                    code: ExitCode {
                        value: 34,
                    },
                    message: "ABORT(pc=28): invalid instruction",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-23T06:52:38.142944Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 13
2023-01-23T06:52:38.142966Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "Create2OOGFromCallRefunds"::Merge::13
2023-01-23T06:52:38.142973Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stCreate2/Create2OOGFromCallRefunds.json"
2023-01-23T06:52:38.142980Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T06:52:38.142986Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T06:52:38.146044Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 34,
    },
    return_data: RawBytes {  },
    gas_used: 6229580,
    events_root: None,
}
2023-01-23T06:52:38.146065Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 438,
                    method: 2,
                    code: ExitCode {
                        value: 18,
                    },
                    message: "can only resurrect a dead contract",
                },
                Frame {
                    source: 10,
                    method: 3,
                    code: ExitCode {
                        value: 18,
                    },
                    message: "send to f0438 method 2 aborted with code 18",
                },
                Frame {
                    source: 429,
                    method: 3844450837,
                    code: ExitCode {
                        value: 34,
                    },
                    message: "ABORT(pc=28): invalid instruction",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-23T06:52:38.146157Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 14
2023-01-23T06:52:38.146190Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "Create2OOGFromCallRefunds"::Merge::14
2023-01-23T06:52:38.146197Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stCreate2/Create2OOGFromCallRefunds.json"
2023-01-23T06:52:38.146204Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T06:52:38.146211Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [31, 93, 24, 123, 179, 164, 141, 187, 44, 1, 29, 10, 110, 115, 26, 200, 19, 23, 153, 173, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([144, 116, 102, 151, 109, 193, 228, 195, 140, 185, 216, 122, 95, 12, 114, 35, 109, 70, 64, 123]) }
2023-01-23T06:52:38.151615Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 34,
    },
    return_data: RawBytes {  },
    gas_used: 16948703,
    events_root: None,
}
2023-01-23T06:52:38.151642Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 449,
                    method: 1,
                    code: ExitCode {
                        value: 34,
                    },
                    message: "ABORT(pc=22): invalid instruction",
                },
                Frame {
                    source: 1,
                    method: 3,
                    code: ExitCode {
                        value: 34,
                    },
                    message: "constructor failed: send to f0449 method 1 aborted with code 34",
                },
                Frame {
                    source: 10,
                    method: 3,
                    code: ExitCode {
                        value: 34,
                    },
                    message: "send to f01 method 3 aborted with code 34",
                },
                Frame {
                    source: 429,
                    method: 3844450837,
                    code: ExitCode {
                        value: 34,
                    },
                    message: "ABORT(pc=28): invalid instruction",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-23T06:52:38.151746Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 15
2023-01-23T06:52:38.151786Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "Create2OOGFromCallRefunds"::Merge::15
2023-01-23T06:52:38.151793Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stCreate2/Create2OOGFromCallRefunds.json"
2023-01-23T06:52:38.151800Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T06:52:38.151806Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T06:52:38.154670Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 34,
    },
    return_data: RawBytes {  },
    gas_used: 6229503,
    events_root: None,
}
2023-01-23T06:52:38.154692Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 439,
                    method: 2,
                    code: ExitCode {
                        value: 18,
                    },
                    message: "can only resurrect a dead contract",
                },
                Frame {
                    source: 10,
                    method: 3,
                    code: ExitCode {
                        value: 18,
                    },
                    message: "send to f0439 method 2 aborted with code 18",
                },
                Frame {
                    source: 429,
                    method: 3844450837,
                    code: ExitCode {
                        value: 34,
                    },
                    message: "ABORT(pc=28): invalid instruction",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-23T06:52:38.154803Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 16
2023-01-23T06:52:38.154853Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "Create2OOGFromCallRefunds"::Merge::16
2023-01-23T06:52:38.154874Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stCreate2/Create2OOGFromCallRefunds.json"
2023-01-23T06:52:38.154890Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T06:52:38.154906Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T06:52:38.157681Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 34,
    },
    return_data: RawBytes {  },
    gas_used: 6229580,
    events_root: None,
}
2023-01-23T06:52:38.157698Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 440,
                    method: 2,
                    code: ExitCode {
                        value: 18,
                    },
                    message: "can only resurrect a dead contract",
                },
                Frame {
                    source: 10,
                    method: 3,
                    code: ExitCode {
                        value: 18,
                    },
                    message: "send to f0440 method 2 aborted with code 18",
                },
                Frame {
                    source: 429,
                    method: 3844450837,
                    code: ExitCode {
                        value: 34,
                    },
                    message: "ABORT(pc=28): invalid instruction",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-23T06:52:38.157760Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 17
2023-01-23T06:52:38.157783Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "Create2OOGFromCallRefunds"::Merge::17
2023-01-23T06:52:38.157789Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stCreate2/Create2OOGFromCallRefunds.json"
2023-01-23T06:52:38.157796Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T06:52:38.157802Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [51, 153, 199, 137, 41, 234, 184, 156, 103, 58, 137, 134, 255, 124, 169, 204, 196, 157, 180, 84, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([85, 143, 18, 101, 101, 201, 146, 95, 146, 124, 254, 78, 228, 215, 122, 164, 58, 49, 178, 79]) }
2023-01-23T06:52:38.163097Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 34,
    },
    return_data: RawBytes {  },
    gas_used: 17885879,
    events_root: None,
}
2023-01-23T06:52:38.163113Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 449,
                    method: 1,
                    code: ExitCode {
                        value: 34,
                    },
                    message: "ABORT(pc=22): invalid instruction",
                },
                Frame {
                    source: 1,
                    method: 3,
                    code: ExitCode {
                        value: 34,
                    },
                    message: "constructor failed: send to f0449 method 1 aborted with code 34",
                },
                Frame {
                    source: 10,
                    method: 3,
                    code: ExitCode {
                        value: 34,
                    },
                    message: "send to f01 method 3 aborted with code 34",
                },
                Frame {
                    source: 429,
                    method: 3844450837,
                    code: ExitCode {
                        value: 34,
                    },
                    message: "ABORT(pc=28): invalid instruction",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-23T06:52:38.163206Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 18
2023-01-23T06:52:38.163229Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "Create2OOGFromCallRefunds"::Merge::18
2023-01-23T06:52:38.163236Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stCreate2/Create2OOGFromCallRefunds.json"
2023-01-23T06:52:38.163243Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T06:52:38.163248Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T06:52:38.166560Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 34,
    },
    return_data: RawBytes {  },
    gas_used: 6225341,
    events_root: None,
}
2023-01-23T06:52:38.166588Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 441,
                    method: 2,
                    code: ExitCode {
                        value: 18,
                    },
                    message: "can only resurrect a dead contract",
                },
                Frame {
                    source: 10,
                    method: 3,
                    code: ExitCode {
                        value: 18,
                    },
                    message: "send to f0441 method 2 aborted with code 18",
                },
                Frame {
                    source: 429,
                    method: 3844450837,
                    code: ExitCode {
                        value: 34,
                    },
                    message: "ABORT(pc=28): invalid instruction",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-23T06:52:38.166665Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 19
2023-01-23T06:52:38.166706Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "Create2OOGFromCallRefunds"::Merge::19
2023-01-23T06:52:38.166713Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stCreate2/Create2OOGFromCallRefunds.json"
2023-01-23T06:52:38.166721Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T06:52:38.166727Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T06:52:38.169444Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 34,
    },
    return_data: RawBytes {  },
    gas_used: 6225418,
    events_root: None,
}
2023-01-23T06:52:38.169460Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 443,
                    method: 2,
                    code: ExitCode {
                        value: 18,
                    },
                    message: "can only resurrect a dead contract",
                },
                Frame {
                    source: 10,
                    method: 3,
                    code: ExitCode {
                        value: 18,
                    },
                    message: "send to f0443 method 2 aborted with code 18",
                },
                Frame {
                    source: 429,
                    method: 3844450837,
                    code: ExitCode {
                        value: 34,
                    },
                    message: "ABORT(pc=28): invalid instruction",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-23T06:52:38.169528Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 20
2023-01-23T06:52:38.169553Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "Create2OOGFromCallRefunds"::Merge::20
2023-01-23T06:52:38.169560Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stCreate2/Create2OOGFromCallRefunds.json"
2023-01-23T06:52:38.169567Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T06:52:38.169573Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [44, 167, 136, 210, 46, 33, 19, 74, 177, 144, 146, 102, 237, 59, 108, 53, 46, 42, 7, 203, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([202, 216, 7, 119, 106, 153, 146, 153, 17, 117, 69, 127, 5, 244, 55, 40, 94, 200, 169, 244]) }
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [181, 32, 104, 103, 89, 206, 211, 188, 157, 136, 152, 224, 46, 228, 22, 35, 3, 47, 244, 127, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([140, 56, 33, 54, 218, 176, 226, 193, 90, 129, 88, 46, 163, 153, 94, 187, 147, 230, 73, 255]) }
2023-01-23T06:52:38.178233Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 34,
    },
    return_data: RawBytes {  },
    gas_used: 30665161,
    events_root: None,
}
2023-01-23T06:52:38.178253Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 449,
                    method: 1,
                    code: ExitCode {
                        value: 34,
                    },
                    message: "ABORT(pc=35): invalid instruction",
                },
                Frame {
                    source: 1,
                    method: 3,
                    code: ExitCode {
                        value: 34,
                    },
                    message: "constructor failed: send to f0449 method 1 aborted with code 34",
                },
                Frame {
                    source: 10,
                    method: 3,
                    code: ExitCode {
                        value: 34,
                    },
                    message: "send to f01 method 3 aborted with code 34",
                },
                Frame {
                    source: 429,
                    method: 3844450837,
                    code: ExitCode {
                        value: 34,
                    },
                    message: "ABORT(pc=28): invalid instruction",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-23T06:52:38.178378Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 21
2023-01-23T06:52:38.178407Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "Create2OOGFromCallRefunds"::Merge::21
2023-01-23T06:52:38.178414Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stCreate2/Create2OOGFromCallRefunds.json"
2023-01-23T06:52:38.178422Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T06:52:38.178427Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T06:52:38.181744Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 34,
    },
    return_data: RawBytes {  },
    gas_used: 6225495,
    events_root: None,
}
2023-01-23T06:52:38.181774Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 445,
                    method: 2,
                    code: ExitCode {
                        value: 18,
                    },
                    message: "can only resurrect a dead contract",
                },
                Frame {
                    source: 10,
                    method: 3,
                    code: ExitCode {
                        value: 18,
                    },
                    message: "send to f0445 method 2 aborted with code 18",
                },
                Frame {
                    source: 429,
                    method: 3844450837,
                    code: ExitCode {
                        value: 34,
                    },
                    message: "ABORT(pc=28): invalid instruction",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-23T06:52:38.181851Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 22
2023-01-23T06:52:38.181893Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "Create2OOGFromCallRefunds"::Merge::22
2023-01-23T06:52:38.181901Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stCreate2/Create2OOGFromCallRefunds.json"
2023-01-23T06:52:38.181910Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T06:52:38.181917Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T06:52:38.184663Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 34,
    },
    return_data: RawBytes {  },
    gas_used: 6225572,
    events_root: None,
}
2023-01-23T06:52:38.184679Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 447,
                    method: 2,
                    code: ExitCode {
                        value: 18,
                    },
                    message: "can only resurrect a dead contract",
                },
                Frame {
                    source: 10,
                    method: 3,
                    code: ExitCode {
                        value: 18,
                    },
                    message: "send to f0447 method 2 aborted with code 18",
                },
                Frame {
                    source: 429,
                    method: 3844450837,
                    code: ExitCode {
                        value: 34,
                    },
                    message: "ABORT(pc=28): invalid instruction",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-23T06:52:38.184741Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 23
2023-01-23T06:52:38.184764Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "Create2OOGFromCallRefunds"::Merge::23
2023-01-23T06:52:38.184770Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stCreate2/Create2OOGFromCallRefunds.json"
2023-01-23T06:52:38.184777Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T06:52:38.184783Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [45, 85, 107, 219, 204, 55, 199, 160, 33, 135, 154, 33, 171, 226, 93, 24, 80, 212, 253, 54, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([181, 8, 27, 168, 223, 145, 221, 58, 213, 216, 232, 244, 223, 5, 154, 0, 190, 59, 128, 47]) }
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [180, 171, 138, 176, 211, 99, 118, 85, 134, 146, 94, 53, 199, 21, 227, 66, 228, 174, 60, 99, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([219, 241, 99, 54, 135, 139, 195, 112, 89, 185, 78, 113, 131, 49, 207, 227, 170, 228, 180, 28]) }
2023-01-23T06:52:38.193331Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 34,
    },
    return_data: RawBytes {  },
    gas_used: 30366308,
    events_root: None,
}
2023-01-23T06:52:38.193347Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 449,
                    method: 1,
                    code: ExitCode {
                        value: 34,
                    },
                    message: "ABORT(pc=37): invalid instruction",
                },
                Frame {
                    source: 1,
                    method: 3,
                    code: ExitCode {
                        value: 34,
                    },
                    message: "constructor failed: send to f0449 method 1 aborted with code 34",
                },
                Frame {
                    source: 10,
                    method: 3,
                    code: ExitCode {
                        value: 34,
                    },
                    message: "send to f01 method 3 aborted with code 34",
                },
                Frame {
                    source: 429,
                    method: 3844450837,
                    code: ExitCode {
                        value: 34,
                    },
                    message: "ABORT(pc=28): invalid instruction",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-23T06:52:38.196225Z TRACE evm_eth_compliance::statetest::runner: TestDone => "test-vectors/tests/GeneralStateTests/stCreate2/Create2OOGFromCallRefunds.json"
2023-01-23T06:52:38.196568Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:13.145032548s
```