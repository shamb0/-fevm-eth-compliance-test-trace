
> Status

| Status | Context |
| --- | --- |
| OK | under WASM RT context |
| TODO | under native RT context |

> Test Suite

https://github.com/ethereum/tests/blob/develop/GeneralStateTests/stCreateTest/CreateOOGFromCallRefunds.json#L1

> Command to execute

```
clear && \
	RUST_LOG=evm_eth_compliance=trace \
	VECTOR=test-vectors/tests/GeneralStateTests/stCreateTest/CreateOOGFromCallRefunds.json \
	cargo run \
	-- \
	statetest
```

> For Review

* Execution looks OK, No "failed to create the new actor :: cannot create address with a reserved prefix" error observed.

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
000c DUP1
000d PUSH1 0x00
000f PUSH1 0x00
0011 CREATE
0012 PUSH1 0x00
0014 DUP2
0015 EQ
0016 ISZERO
0017 PUSH1 0x1b
0019 JUMPI
001a INVALID
001b JUMPDEST
001c POP
001d POP
001e POP
```

> Execution Trace

```
2023-01-23T08:32:50.850386Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "test-vectors/tests/GeneralStateTests/stCreateTest/CreateOOGFromCallRefunds.json", Total Files :: 1
2023-01-23T08:32:50.850841Z TRACE evm_eth_compliance::statetest::runner: Calling testfile => "test-vectors/tests/GeneralStateTests/stCreateTest/CreateOOGFromCallRefunds.json"
2023-01-23T08:32:51.192510Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-23T08:32:51.197485Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-23T08:32:51.197501Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-23T08:32:51.198609Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-23T08:32:51.198622Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 2
2023-01-23T08:32:51.199858Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-23T08:32:51.199872Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 3
2023-01-23T08:32:51.201074Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-23T08:32:51.201089Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 4
2023-01-23T08:32:51.202211Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-23T08:32:51.202224Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 5
2023-01-23T08:32:51.203526Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-23T08:32:51.203541Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 6
2023-01-23T08:32:51.204692Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-23T08:32:51.204705Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 7
2023-01-23T08:32:51.205718Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-23T08:32:51.205735Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 8
2023-01-23T08:32:51.206742Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-23T08:32:51.206755Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 9
2023-01-23T08:32:51.207867Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-23T08:32:51.207880Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 10
2023-01-23T08:32:51.208923Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-23T08:32:51.208937Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 11
2023-01-23T08:32:51.209961Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-23T08:32:51.209975Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 12
2023-01-23T08:32:51.210950Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-23T08:32:51.210964Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 13
2023-01-23T08:32:51.211968Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-23T08:32:51.211982Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 14
2023-01-23T08:32:51.213138Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-23T08:32:51.213158Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 15
2023-01-23T08:32:51.214354Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-23T08:32:51.214368Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 16
2023-01-23T08:32:51.215386Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-23T08:32:51.215399Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 17
2023-01-23T08:32:51.216432Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-23T08:32:51.216446Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 18
2023-01-23T08:32:51.217624Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-23T08:32:51.217637Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 19
2023-01-23T08:32:51.218635Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-23T08:32:51.218649Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 20
2023-01-23T08:32:51.219684Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-23T08:32:51.219698Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 21
2023-01-23T08:32:51.220886Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-23T08:32:51.220899Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 22
2023-01-23T08:32:51.222280Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-23T08:32:51.222293Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 23
2023-01-23T08:32:51.223529Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-23T08:32:51.223543Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 24
2023-01-23T08:32:51.224578Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-23T08:32:51.224591Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 25
2023-01-23T08:32:51.225899Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-23T08:32:51.225912Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 26
2023-01-23T08:32:51.226903Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-23T08:32:51.226916Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 27
2023-01-23T08:32:51.227923Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-23T08:32:51.227936Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 28
2023-01-23T08:32:51.229183Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-23T08:32:51.229205Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 29
2023-01-23T08:32:51.230382Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-23T08:32:51.231443Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-23T08:32:51.231475Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CreateOOGFromCallRefunds"::London::0
2023-01-23T08:32:51.231484Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stCreateTest/CreateOOGFromCallRefunds.json"
2023-01-23T08:32:51.231492Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T08:32:51.231499Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [69, 1, 248, 250, 30, 103, 130, 126, 191, 177, 246, 213, 81, 12, 96, 104, 113, 197, 165, 153, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([215, 166, 242, 208, 200, 186, 79, 10, 126, 8, 221, 102, 9, 12, 200, 158, 203, 19, 78, 227]) }
2023-01-23T08:33:04.538489Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 16006788,
    events_root: None,
}
2023-01-23T08:33:04.538587Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 3
2023-01-23T08:33:04.538632Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CreateOOGFromCallRefunds"::London::3
2023-01-23T08:33:04.538641Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stCreateTest/CreateOOGFromCallRefunds.json"
2023-01-23T08:33:04.538649Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T08:33:04.538655Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [195, 18, 14, 205, 155, 30, 188, 43, 35, 56, 144, 59, 65, 88, 95, 40, 233, 152, 145, 191, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([67, 35, 255, 1, 46, 226, 200, 90, 20, 150, 237, 153, 222, 171, 201, 9, 99, 31, 101, 211]) }
2023-01-23T08:33:04.544141Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 18771701,
    events_root: None,
}
2023-01-23T08:33:04.544246Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 6
2023-01-23T08:33:04.544278Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CreateOOGFromCallRefunds"::London::6
2023-01-23T08:33:04.544287Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stCreateTest/CreateOOGFromCallRefunds.json"
2023-01-23T08:33:04.544297Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T08:33:04.544303Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [249, 97, 238, 116, 65, 19, 24, 253, 137, 32, 4, 46, 185, 255, 79, 172, 202, 37, 85, 110, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([28, 35, 125, 168, 212, 11, 234, 180, 81, 129, 48, 219, 76, 10, 52, 89, 217, 159, 194, 2]) }
2023-01-23T08:33:04.550487Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 21569025,
    events_root: None,
}
2023-01-23T08:33:04.550589Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 9
2023-01-23T08:33:04.550622Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CreateOOGFromCallRefunds"::London::9
2023-01-23T08:33:04.550630Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stCreateTest/CreateOOGFromCallRefunds.json"
2023-01-23T08:33:04.550637Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T08:33:04.550643Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [154, 25, 56, 255, 192, 245, 214, 121, 177, 44, 93, 232, 48, 67, 253, 232, 225, 63, 40, 78, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([132, 105, 76, 107, 184, 77, 78, 105, 101, 219, 134, 121, 221, 254, 217, 203, 72, 121, 220, 83]) }
2023-01-23T08:33:04.555808Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 34,
    },
    return_data: RawBytes {  },
    gas_used: 15052995,
    events_root: None,
}
2023-01-23T08:33:04.555837Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
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
                    method: 2,
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
                    message: "ABORT(pc=26): invalid instruction",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-23T08:33:04.555943Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 1
2023-01-23T08:33:04.555987Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CreateOOGFromCallRefunds"::London::1
2023-01-23T08:33:04.556001Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stCreateTest/CreateOOGFromCallRefunds.json"
2023-01-23T08:33:04.556011Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T08:33:04.556018Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [154, 25, 56, 255, 192, 245, 214, 121, 177, 44, 93, 232, 48, 67, 253, 232, 225, 63, 40, 78, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([236, 70, 216, 243, 101, 99, 189, 62, 205, 26, 208, 253, 84, 36, 48, 143, 166, 88, 135, 41]) }
2023-01-23T08:33:04.561800Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 23114771,
    events_root: None,
}
2023-01-23T08:33:04.561869Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 2
2023-01-23T08:33:04.561895Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CreateOOGFromCallRefunds"::London::2
2023-01-23T08:33:04.561902Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stCreateTest/CreateOOGFromCallRefunds.json"
2023-01-23T08:33:04.561909Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T08:33:04.561915Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [178, 143, 60, 200, 18, 196, 132, 218, 140, 199, 130, 51, 47, 210, 155, 109, 169, 2, 236, 67, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([155, 99, 140, 31, 46, 96, 27, 93, 44, 60, 131, 66, 80, 136, 87, 209, 224, 27, 216, 212]) }
2023-01-23T08:33:04.566115Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 34,
    },
    return_data: RawBytes {  },
    gas_used: 14498827,
    events_root: None,
}
2023-01-23T08:33:04.566131Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
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
                    method: 2,
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
                    message: "ABORT(pc=26): invalid instruction",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-23T08:33:04.566214Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 4
2023-01-23T08:33:04.566237Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CreateOOGFromCallRefunds"::London::4
2023-01-23T08:33:04.566246Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stCreateTest/CreateOOGFromCallRefunds.json"
2023-01-23T08:33:04.566252Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T08:33:04.566258Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [178, 143, 60, 200, 18, 196, 132, 218, 140, 199, 130, 51, 47, 210, 155, 109, 169, 2, 236, 67, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([188, 149, 186, 245, 1, 91, 222, 203, 63, 25, 86, 169, 35, 110, 18, 124, 122, 60, 238, 128]) }
2023-01-23T08:33:04.572695Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 24838148,
    events_root: None,
}
2023-01-23T08:33:04.572801Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 5
2023-01-23T08:33:04.572838Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CreateOOGFromCallRefunds"::London::5
2023-01-23T08:33:04.572847Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stCreateTest/CreateOOGFromCallRefunds.json"
2023-01-23T08:33:04.572854Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T08:33:04.572860Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [148, 222, 164, 155, 113, 194, 50, 87, 36, 175, 122, 190, 240, 37, 144, 249, 103, 89, 83, 128, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([20, 3, 204, 71, 166, 252, 88, 221, 29, 77, 14, 224, 191, 132, 61, 100, 47, 53, 166, 175]) }
2023-01-23T08:33:04.578622Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 34,
    },
    return_data: RawBytes {  },
    gas_used: 17034645,
    events_root: None,
}
2023-01-23T08:33:04.578646Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
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
                    method: 2,
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
                    message: "ABORT(pc=26): invalid instruction",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-23T08:33:04.578746Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 7
2023-01-23T08:33:04.578783Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CreateOOGFromCallRefunds"::London::7
2023-01-23T08:33:04.578790Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stCreateTest/CreateOOGFromCallRefunds.json"
2023-01-23T08:33:04.578799Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T08:33:04.578805Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [148, 222, 164, 155, 113, 194, 50, 87, 36, 175, 122, 190, 240, 37, 144, 249, 103, 89, 83, 128, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([177, 189, 137, 170, 161, 168, 98, 8, 218, 14, 105, 2, 242, 92, 44, 234, 2, 122, 233, 63]) }
2023-01-23T08:33:04.585789Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 28249478,
    events_root: None,
}
2023-01-23T08:33:04.585876Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 8
2023-01-23T08:33:04.585901Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CreateOOGFromCallRefunds"::London::8
2023-01-23T08:33:04.585908Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stCreateTest/CreateOOGFromCallRefunds.json"
2023-01-23T08:33:04.585915Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T08:33:04.585921Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [180, 210, 147, 97, 152, 38, 199, 127, 107, 201, 210, 163, 102, 141, 64, 222, 83, 50, 144, 106, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([178, 221, 99, 117, 94, 25, 113, 14, 55, 217, 63, 213, 179, 235, 175, 240, 178, 120, 15, 225]) }
2023-01-23T08:33:04.592393Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 34,
    },
    return_data: RawBytes {  },
    gas_used: 20635905,
    events_root: None,
}
2023-01-23T08:33:04.592422Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
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
                    method: 2,
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
                    message: "ABORT(pc=26): invalid instruction",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-23T08:33:04.592541Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 10
2023-01-23T08:33:04.592581Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CreateOOGFromCallRefunds"::London::10
2023-01-23T08:33:04.592589Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stCreateTest/CreateOOGFromCallRefunds.json"
2023-01-23T08:33:04.592596Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T08:33:04.592602Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [180, 210, 147, 97, 152, 38, 199, 127, 107, 201, 210, 163, 102, 141, 64, 222, 83, 50, 144, 106, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([251, 114, 94, 192, 108, 10, 201, 112, 101, 197, 5, 103, 36, 134, 180, 68, 48, 44, 184, 84]) }
2023-01-23T08:33:04.596975Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 34,
    },
    return_data: RawBytes {  },
    gas_used: 14795841,
    events_root: None,
}
2023-01-23T08:33:04.596991Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
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
                    method: 2,
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
                    message: "ABORT(pc=26): invalid instruction",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-23T08:33:04.597074Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 11
2023-01-23T08:33:04.597097Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CreateOOGFromCallRefunds"::London::11
2023-01-23T08:33:04.597105Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stCreateTest/CreateOOGFromCallRefunds.json"
2023-01-23T08:33:04.597112Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T08:33:04.597118Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [180, 210, 147, 97, 152, 38, 199, 127, 107, 201, 210, 163, 102, 141, 64, 222, 83, 50, 144, 106, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([90, 217, 32, 146, 24, 201, 117, 10, 10, 210, 28, 70, 31, 30, 132, 56, 243, 180, 75, 35]) }
2023-01-23T08:33:04.601432Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 34,
    },
    return_data: RawBytes {  },
    gas_used: 15146864,
    events_root: None,
}
2023-01-23T08:33:04.601448Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
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
                    method: 2,
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
                    message: "ABORT(pc=26): invalid instruction",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-23T08:33:04.601529Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 12
2023-01-23T08:33:04.601550Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CreateOOGFromCallRefunds"::London::12
2023-01-23T08:33:04.601558Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stCreateTest/CreateOOGFromCallRefunds.json"
2023-01-23T08:33:04.601565Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T08:33:04.601571Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [180, 210, 147, 97, 152, 38, 199, 127, 107, 201, 210, 163, 102, 141, 64, 222, 83, 50, 144, 106, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([128, 138, 188, 155, 213, 11, 225, 143, 246, 50, 199, 246, 94, 148, 129, 183, 56, 152, 76, 55]) }
2023-01-23T08:33:04.606800Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 17736777,
    events_root: None,
}
2023-01-23T08:33:04.606882Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 13
2023-01-23T08:33:04.606907Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CreateOOGFromCallRefunds"::London::13
2023-01-23T08:33:04.606914Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stCreateTest/CreateOOGFromCallRefunds.json"
2023-01-23T08:33:04.606921Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T08:33:04.606927Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [87, 126, 92, 207, 117, 98, 177, 247, 234, 138, 222, 134, 77, 245, 143, 24, 141, 209, 40, 64, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([55, 124, 170, 147, 221, 2, 18, 238, 216, 76, 43, 142, 118, 199, 246, 132, 57, 223, 23, 100]) }
2023-01-23T08:33:04.613895Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 24654013,
    events_root: None,
}
2023-01-23T08:33:04.614008Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 14
2023-01-23T08:33:04.614052Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CreateOOGFromCallRefunds"::London::14
2023-01-23T08:33:04.614061Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stCreateTest/CreateOOGFromCallRefunds.json"
2023-01-23T08:33:04.614070Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T08:33:04.614077Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [197, 238, 162, 88, 198, 71, 114, 92, 152, 148, 101, 73, 255, 224, 216, 112, 84, 184, 41, 9, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([171, 234, 181, 15, 37, 193, 240, 156, 211, 60, 172, 98, 156, 55, 186, 0, 159, 236, 160, 247]) }
2023-01-23T08:33:04.619351Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 34,
    },
    return_data: RawBytes {  },
    gas_used: 17003063,
    events_root: None,
}
2023-01-23T08:33:04.619366Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
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
                    method: 2,
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
                    message: "ABORT(pc=26): invalid instruction",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-23T08:33:04.619459Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 15
2023-01-23T08:33:04.619483Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CreateOOGFromCallRefunds"::London::15
2023-01-23T08:33:04.619490Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stCreateTest/CreateOOGFromCallRefunds.json"
2023-01-23T08:33:04.619496Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T08:33:04.619503Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [197, 238, 162, 88, 198, 71, 114, 92, 152, 148, 101, 73, 255, 224, 216, 112, 84, 184, 41, 9, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([167, 18, 209, 255, 80, 109, 220, 136, 239, 83, 214, 196, 45, 184, 19, 227, 137, 201, 135, 105]) }
2023-01-23T08:33:04.625058Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 18642250,
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
2023-01-23T08:33:04.625184Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 16
2023-01-23T08:33:04.625209Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CreateOOGFromCallRefunds"::London::16
2023-01-23T08:33:04.625216Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stCreateTest/CreateOOGFromCallRefunds.json"
2023-01-23T08:33:04.625223Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T08:33:04.625229Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [173, 67, 116, 67, 158, 111, 99, 113, 162, 73, 57, 129, 24, 44, 236, 35, 12, 55, 40, 21, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([143, 33, 161, 133, 93, 209, 38, 110, 16, 16, 237, 126, 30, 78, 59, 192, 15, 148, 83, 57]) }
2023-01-23T08:33:04.632447Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 25303389,
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
2023-01-23T08:33:04.632598Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 17
2023-01-23T08:33:04.632641Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CreateOOGFromCallRefunds"::London::17
2023-01-23T08:33:04.632650Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stCreateTest/CreateOOGFromCallRefunds.json"
2023-01-23T08:33:04.632657Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T08:33:04.632663Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [225, 182, 153, 15, 212, 101, 104, 101, 160, 164, 64, 114, 40, 180, 148, 83, 72, 134, 109, 239, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([115, 209, 18, 63, 181, 115, 165, 219, 137, 112, 100, 108, 193, 38, 167, 163, 136, 114, 38, 238]) }
2023-01-23T08:33:04.637961Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 34,
    },
    return_data: RawBytes {  },
    gas_used: 17836174,
    events_root: None,
}
2023-01-23T08:33:04.637977Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
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
                    method: 2,
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
                    message: "ABORT(pc=26): invalid instruction",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-23T08:33:04.638074Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 18
2023-01-23T08:33:04.638099Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CreateOOGFromCallRefunds"::London::18
2023-01-23T08:33:04.638106Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stCreateTest/CreateOOGFromCallRefunds.json"
2023-01-23T08:33:04.638112Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T08:33:04.638119Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [225, 182, 153, 15, 212, 101, 104, 101, 160, 164, 64, 114, 40, 180, 148, 83, 72, 134, 109, 239, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([164, 19, 188, 157, 123, 198, 227, 16, 99, 7, 112, 55, 126, 183, 242, 167, 190, 31, 240, 147]) }
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [141, 41, 198, 108, 153, 250, 112, 213, 241, 8, 223, 22, 42, 197, 21, 231, 132, 77, 62, 87, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([72, 66, 192, 23, 236, 195, 123, 135, 136, 153, 189, 230, 240, 174, 146, 55, 224, 60, 185, 254]) }
2023-01-23T08:33:04.647543Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 31925871,
    events_root: None,
}
2023-01-23T08:33:04.647688Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 19
2023-01-23T08:33:04.647731Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CreateOOGFromCallRefunds"::London::19
2023-01-23T08:33:04.647740Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stCreateTest/CreateOOGFromCallRefunds.json"
2023-01-23T08:33:04.647747Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T08:33:04.647754Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [177, 117, 20, 242, 242, 48, 163, 117, 142, 88, 74, 162, 59, 57, 187, 250, 138, 166, 22, 252, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([40, 113, 131, 83, 213, 98, 3, 231, 134, 49, 131, 92, 170, 242, 84, 90, 74, 151, 72, 246]) }
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [1, 190, 14, 238, 247, 118, 116, 12, 24, 223, 91, 42, 129, 59, 198, 96, 249, 219, 139, 59, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([45, 64, 152, 245, 123, 126, 128, 251, 245, 59, 92, 106, 38, 248, 46, 19, 54, 253, 5, 239]) }
2023-01-23T08:33:04.657759Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 38764534,
    events_root: None,
}
2023-01-23T08:33:04.657868Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 20
2023-01-23T08:33:04.657894Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CreateOOGFromCallRefunds"::London::20
2023-01-23T08:33:04.657901Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stCreateTest/CreateOOGFromCallRefunds.json"
2023-01-23T08:33:04.657908Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T08:33:04.657914Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [80, 44, 200, 95, 47, 209, 235, 245, 18, 233, 148, 100, 38, 203, 57, 85, 250, 133, 149, 163, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([40, 182, 218, 235, 33, 11, 225, 5, 136, 185, 130, 124, 42, 168, 16, 11, 169, 12, 214, 166]) }
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [98, 232, 148, 157, 161, 234, 148, 184, 1, 30, 221, 112, 194, 16, 22, 236, 189, 220, 142, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([74, 158, 232, 176, 23, 67, 144, 90, 171, 16, 228, 107, 181, 166, 212, 111, 69, 135, 184, 75]) }
2023-01-23T08:33:04.667299Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 34,
    },
    return_data: RawBytes {  },
    gas_used: 31206666,
    events_root: None,
}
2023-01-23T08:33:04.667325Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
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
                    method: 2,
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
                    message: "ABORT(pc=26): invalid instruction",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-23T08:33:04.667468Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 21
2023-01-23T08:33:04.667510Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CreateOOGFromCallRefunds"::London::21
2023-01-23T08:33:04.667518Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stCreateTest/CreateOOGFromCallRefunds.json"
2023-01-23T08:33:04.667525Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T08:33:04.667531Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [80, 44, 200, 95, 47, 209, 235, 245, 18, 233, 148, 100, 38, 203, 57, 85, 250, 133, 149, 163, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([120, 103, 96, 100, 116, 249, 190, 222, 117, 123, 178, 182, 219, 22, 101, 99, 7, 208, 237, 37]) }
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [99, 233, 3, 51, 183, 42, 147, 93, 22, 167, 69, 104, 35, 182, 205, 34, 114, 167, 173, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([170, 231, 242, 225, 179, 169, 163, 205, 94, 242, 42, 231, 180, 207, 28, 84, 155, 73, 110, 102]) }
2023-01-23T08:33:04.676327Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 32056994,
    events_root: None,
}
2023-01-23T08:33:04.676433Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 22
2023-01-23T08:33:04.676457Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CreateOOGFromCallRefunds"::London::22
2023-01-23T08:33:04.676464Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stCreateTest/CreateOOGFromCallRefunds.json"
2023-01-23T08:33:04.676471Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T08:33:04.676477Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [127, 242, 204, 226, 21, 22, 111, 10, 138, 30, 175, 188, 20, 133, 94, 96, 106, 173, 190, 153, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([173, 101, 220, 118, 126, 227, 221, 111, 130, 239, 232, 201, 210, 70, 69, 50, 207, 38, 17, 72]) }
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [196, 34, 25, 18, 212, 195, 142, 179, 227, 208, 120, 63, 127, 237, 224, 224, 26, 54, 18, 47, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([35, 59, 216, 163, 67, 28, 202, 201, 254, 163, 77, 239, 227, 129, 106, 143, 73, 182, 194, 64]) }
2023-01-23T08:33:04.687356Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 38847677,
    events_root: None,
}
2023-01-23T08:33:04.687504Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 23
2023-01-23T08:33:04.687548Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CreateOOGFromCallRefunds"::London::23
2023-01-23T08:33:04.687559Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stCreateTest/CreateOOGFromCallRefunds.json"
2023-01-23T08:33:04.687566Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T08:33:04.687572Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [1, 53, 128, 57, 198, 4, 118, 136, 218, 212, 10, 116, 82, 40, 71, 80, 205, 16, 224, 195, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([21, 34, 247, 70, 142, 122, 19, 174, 255, 98, 183, 37, 253, 210, 62, 191, 224, 79, 199, 228]) }
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [178, 33, 21, 234, 209, 253, 196, 152, 209, 127, 214, 35, 178, 202, 109, 157, 70, 253, 59, 36, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([223, 223, 142, 153, 166, 139, 108, 56, 156, 236, 39, 109, 202, 30, 79, 221, 136, 157, 126, 212]) }
2023-01-23T08:33:04.696665Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 34,
    },
    return_data: RawBytes {  },
    gas_used: 30861555,
    events_root: None,
}
2023-01-23T08:33:04.696698Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
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
                    method: 2,
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
                    message: "ABORT(pc=26): invalid instruction",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-23T08:33:04.696909Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-23T08:33:04.696963Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CreateOOGFromCallRefunds"::Merge::0
2023-01-23T08:33:04.696974Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stCreateTest/CreateOOGFromCallRefunds.json"
2023-01-23T08:33:04.696984Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T08:33:04.696993Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [1, 53, 128, 57, 198, 4, 118, 136, 218, 212, 10, 116, 82, 40, 71, 80, 205, 16, 224, 195, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([121, 200, 128, 32, 100, 47, 163, 168, 222, 154, 90, 196, 49, 165, 55, 116, 4, 152, 177, 42]) }
2023-01-23T08:33:04.702085Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 16279312,
    events_root: None,
}
2023-01-23T08:33:04.702178Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 3
2023-01-23T08:33:04.702222Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CreateOOGFromCallRefunds"::Merge::3
2023-01-23T08:33:04.702230Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stCreateTest/CreateOOGFromCallRefunds.json"
2023-01-23T08:33:04.702238Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T08:33:04.702244Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [234, 69, 93, 177, 196, 151, 96, 231, 242, 160, 218, 79, 218, 118, 176, 168, 202, 155, 49, 40, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([39, 202, 0, 61, 220, 84, 98, 79, 206, 62, 176, 253, 44, 186, 245, 199, 23, 163, 253, 50]) }
2023-01-23T08:33:04.708143Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 18370322,
    events_root: None,
}
2023-01-23T08:33:04.708244Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 6
2023-01-23T08:33:04.708289Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CreateOOGFromCallRefunds"::Merge::6
2023-01-23T08:33:04.708297Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stCreateTest/CreateOOGFromCallRefunds.json"
2023-01-23T08:33:04.708305Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T08:33:04.708312Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [177, 198, 237, 248, 92, 160, 217, 199, 139, 240, 11, 152, 24, 58, 172, 212, 121, 11, 90, 78, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([192, 88, 99, 161, 23, 254, 175, 39, 213, 169, 153, 253, 197, 254, 95, 117, 145, 246, 7, 95]) }
2023-01-23T08:33:04.714292Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 21591130,
    events_root: None,
}
2023-01-23T08:33:04.714379Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 9
2023-01-23T08:33:04.714402Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CreateOOGFromCallRefunds"::Merge::9
2023-01-23T08:33:04.714409Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stCreateTest/CreateOOGFromCallRefunds.json"
2023-01-23T08:33:04.714417Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T08:33:04.714423Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [227, 96, 56, 169, 87, 190, 52, 69, 252, 216, 93, 159, 165, 58, 7, 158, 251, 200, 121, 47, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([96, 33, 187, 115, 222, 53, 224, 244, 47, 32, 70, 11, 226, 18, 129, 166, 126, 239, 230, 44]) }
2023-01-23T08:33:04.719461Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 34,
    },
    return_data: RawBytes {  },
    gas_used: 15235617,
    events_root: None,
}
2023-01-23T08:33:04.719488Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 452,
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
                    message: "constructor failed: send to f0452 method 1 aborted with code 35",
                },
                Frame {
                    source: 10,
                    method: 2,
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
                    message: "ABORT(pc=26): invalid instruction",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-23T08:33:04.719587Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 1
2023-01-23T08:33:04.719629Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CreateOOGFromCallRefunds"::Merge::1
2023-01-23T08:33:04.719637Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stCreateTest/CreateOOGFromCallRefunds.json"
2023-01-23T08:33:04.719644Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T08:33:04.719650Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [227, 96, 56, 169, 87, 190, 52, 69, 252, 216, 93, 159, 165, 58, 7, 158, 251, 200, 121, 47, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([221, 202, 25, 212, 34, 2, 50, 123, 41, 75, 186, 155, 123, 166, 127, 9, 228, 237, 116, 209]) }
2023-01-23T08:33:04.725754Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 23379267,
    events_root: None,
}
2023-01-23T08:33:04.725822Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 2
2023-01-23T08:33:04.725848Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CreateOOGFromCallRefunds"::Merge::2
2023-01-23T08:33:04.725856Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stCreateTest/CreateOOGFromCallRefunds.json"
2023-01-23T08:33:04.725863Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T08:33:04.725869Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [182, 207, 188, 99, 62, 95, 127, 176, 26, 20, 246, 1, 189, 201, 12, 136, 238, 106, 99, 51, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([96, 157, 121, 180, 71, 136, 28, 182, 195, 187, 216, 146, 44, 166, 42, 126, 234, 16, 198, 148]) }
2023-01-23T08:33:04.730166Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 34,
    },
    return_data: RawBytes {  },
    gas_used: 15130465,
    events_root: None,
}
2023-01-23T08:33:04.730181Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 453,
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
                    message: "constructor failed: send to f0453 method 1 aborted with code 34",
                },
                Frame {
                    source: 10,
                    method: 2,
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
                    message: "ABORT(pc=26): invalid instruction",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-23T08:33:04.730261Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 4
2023-01-23T08:33:04.730284Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CreateOOGFromCallRefunds"::Merge::4
2023-01-23T08:33:04.730291Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stCreateTest/CreateOOGFromCallRefunds.json"
2023-01-23T08:33:04.730298Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T08:33:04.730304Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [182, 207, 188, 99, 62, 95, 127, 176, 26, 20, 246, 1, 189, 201, 12, 136, 238, 106, 99, 51, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([125, 213, 185, 126, 102, 183, 165, 62, 81, 45, 4, 229, 242, 150, 184, 46, 206, 140, 135, 167]) }
2023-01-23T08:33:04.737313Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 25729309,
    events_root: None,
}
2023-01-23T08:33:04.737429Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 5
2023-01-23T08:33:04.737471Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CreateOOGFromCallRefunds"::Merge::5
2023-01-23T08:33:04.737479Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stCreateTest/CreateOOGFromCallRefunds.json"
2023-01-23T08:33:04.737488Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T08:33:04.737494Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [219, 82, 223, 60, 216, 188, 33, 116, 9, 120, 43, 134, 101, 24, 144, 136, 239, 15, 51, 65, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([57, 47, 201, 253, 31, 210, 216, 45, 82, 53, 15, 10, 140, 189, 182, 38, 139, 193, 227, 148]) }
2023-01-23T08:33:04.742703Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 34,
    },
    return_data: RawBytes {  },
    gas_used: 17726163,
    events_root: None,
}
2023-01-23T08:33:04.742718Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 454,
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
                    message: "constructor failed: send to f0454 method 1 aborted with code 34",
                },
                Frame {
                    source: 10,
                    method: 2,
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
                    message: "ABORT(pc=26): invalid instruction",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-23T08:33:04.742816Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 7
2023-01-23T08:33:04.742840Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CreateOOGFromCallRefunds"::Merge::7
2023-01-23T08:33:04.742847Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stCreateTest/CreateOOGFromCallRefunds.json"
2023-01-23T08:33:04.742854Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T08:33:04.742860Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [219, 82, 223, 60, 216, 188, 33, 116, 9, 120, 43, 134, 101, 24, 144, 136, 239, 15, 51, 65, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([10, 128, 19, 154, 164, 202, 88, 213, 185, 231, 230, 233, 169, 125, 32, 175, 46, 247, 104, 205]) }
2023-01-23T08:33:04.749851Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 27656219,
    events_root: None,
}
2023-01-23T08:33:04.750006Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 8
2023-01-23T08:33:04.750057Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CreateOOGFromCallRefunds"::Merge::8
2023-01-23T08:33:04.750068Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stCreateTest/CreateOOGFromCallRefunds.json"
2023-01-23T08:33:04.750075Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T08:33:04.750081Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [96, 26, 246, 137, 53, 61, 150, 5, 93, 118, 251, 59, 132, 124, 55, 162, 156, 164, 138, 231, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([234, 139, 137, 133, 156, 6, 41, 217, 87, 171, 216, 141, 23, 64, 208, 12, 0, 6, 118, 73]) }
2023-01-23T08:33:04.756537Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 34,
    },
    return_data: RawBytes {  },
    gas_used: 20286100,
    events_root: None,
}
2023-01-23T08:33:04.756574Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 455,
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
                    message: "constructor failed: send to f0455 method 1 aborted with code 34",
                },
                Frame {
                    source: 10,
                    method: 2,
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
                    message: "ABORT(pc=26): invalid instruction",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-23T08:33:04.756732Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 10
2023-01-23T08:33:04.756779Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CreateOOGFromCallRefunds"::Merge::10
2023-01-23T08:33:04.756786Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stCreateTest/CreateOOGFromCallRefunds.json"
2023-01-23T08:33:04.756794Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T08:33:04.756800Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [96, 26, 246, 137, 53, 61, 150, 5, 93, 118, 251, 59, 132, 124, 55, 162, 156, 164, 138, 231, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([74, 138, 107, 177, 65, 173, 106, 127, 111, 235, 64, 25, 56, 77, 152, 139, 121, 241, 216, 113]) }
2023-01-23T08:33:04.761337Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 34,
    },
    return_data: RawBytes {  },
    gas_used: 14977682,
    events_root: None,
}
2023-01-23T08:33:04.761361Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 455,
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
                    message: "constructor failed: send to f0455 method 1 aborted with code 35",
                },
                Frame {
                    source: 10,
                    method: 2,
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
                    message: "ABORT(pc=26): invalid instruction",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-23T08:33:04.761451Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 11
2023-01-23T08:33:04.761489Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CreateOOGFromCallRefunds"::Merge::11
2023-01-23T08:33:04.761496Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stCreateTest/CreateOOGFromCallRefunds.json"
2023-01-23T08:33:04.761503Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T08:33:04.761509Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [96, 26, 246, 137, 53, 61, 150, 5, 93, 118, 251, 59, 132, 124, 55, 162, 156, 164, 138, 231, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([126, 248, 213, 18, 73, 109, 79, 84, 218, 211, 209, 213, 172, 193, 146, 154, 144, 35, 152, 99]) }
2023-01-23T08:33:04.765885Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 34,
    },
    return_data: RawBytes {  },
    gas_used: 15025283,
    events_root: None,
}
2023-01-23T08:33:04.765901Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 455,
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
                    message: "constructor failed: send to f0455 method 1 aborted with code 35",
                },
                Frame {
                    source: 10,
                    method: 2,
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
                    message: "ABORT(pc=26): invalid instruction",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-23T08:33:04.765982Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 12
2023-01-23T08:33:04.766007Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CreateOOGFromCallRefunds"::Merge::12
2023-01-23T08:33:04.766014Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stCreateTest/CreateOOGFromCallRefunds.json"
2023-01-23T08:33:04.766021Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T08:33:04.766027Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [96, 26, 246, 137, 53, 61, 150, 5, 93, 118, 251, 59, 132, 124, 55, 162, 156, 164, 138, 231, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([167, 245, 235, 76, 86, 206, 109, 57, 189, 19, 0, 230, 242, 87, 18, 38, 208, 32, 55, 56]) }
2023-01-23T08:33:04.771565Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 18078400,
    events_root: None,
}
2023-01-23T08:33:04.771701Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 13
2023-01-23T08:33:04.771748Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CreateOOGFromCallRefunds"::Merge::13
2023-01-23T08:33:04.771756Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stCreateTest/CreateOOGFromCallRefunds.json"
2023-01-23T08:33:04.771764Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T08:33:04.771770Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [140, 233, 54, 229, 135, 116, 236, 220, 138, 83, 77, 67, 202, 188, 75, 49, 209, 188, 197, 17, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([138, 192, 102, 104, 212, 54, 151, 48, 197, 195, 196, 55, 46, 91, 125, 35, 54, 100, 85, 118]) }
2023-01-23T08:33:04.778252Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 24810053,
    events_root: None,
}
2023-01-23T08:33:04.778337Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 14
2023-01-23T08:33:04.778373Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CreateOOGFromCallRefunds"::Merge::14
2023-01-23T08:33:04.778382Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stCreateTest/CreateOOGFromCallRefunds.json"
2023-01-23T08:33:04.778389Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T08:33:04.778395Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [98, 152, 206, 36, 105, 94, 115, 222, 49, 133, 30, 27, 164, 64, 12, 124, 21, 119, 126, 28, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([144, 116, 102, 151, 109, 193, 228, 195, 140, 185, 216, 122, 95, 12, 114, 35, 109, 70, 64, 123]) }
2023-01-23T08:33:04.783605Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 34,
    },
    return_data: RawBytes {  },
    gas_used: 17454615,
    events_root: None,
}
2023-01-23T08:33:04.783620Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 457,
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
                    message: "constructor failed: send to f0457 method 1 aborted with code 34",
                },
                Frame {
                    source: 10,
                    method: 2,
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
                    message: "ABORT(pc=26): invalid instruction",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-23T08:33:04.783712Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 15
2023-01-23T08:33:04.783734Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CreateOOGFromCallRefunds"::Merge::15
2023-01-23T08:33:04.783741Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stCreateTest/CreateOOGFromCallRefunds.json"
2023-01-23T08:33:04.783748Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T08:33:04.783754Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [98, 152, 206, 36, 105, 94, 115, 222, 49, 133, 30, 27, 164, 64, 12, 124, 21, 119, 126, 28, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([75, 225, 44, 86, 78, 215, 16, 71, 27, 117, 144, 173, 253, 80, 20, 246, 7, 228, 15, 51]) }
2023-01-23T08:33:04.789957Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 18784630,
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
2023-01-23T08:33:04.790125Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 16
2023-01-23T08:33:04.790166Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CreateOOGFromCallRefunds"::Merge::16
2023-01-23T08:33:04.790175Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stCreateTest/CreateOOGFromCallRefunds.json"
2023-01-23T08:33:04.790182Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T08:33:04.790188Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [219, 71, 77, 225, 115, 73, 212, 177, 64, 246, 88, 1, 53, 217, 53, 229, 243, 40, 237, 20, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([32, 103, 245, 189, 168, 73, 149, 238, 158, 100, 244, 162, 2, 157, 240, 169, 24, 108, 156, 146]) }
2023-01-23T08:33:04.797147Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 25869319,
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
2023-01-23T08:33:04.797274Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 17
2023-01-23T08:33:04.797302Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CreateOOGFromCallRefunds"::Merge::17
2023-01-23T08:33:04.797310Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stCreateTest/CreateOOGFromCallRefunds.json"
2023-01-23T08:33:04.797317Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T08:33:04.797323Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [140, 244, 64, 245, 226, 166, 3, 182, 16, 235, 218, 159, 152, 241, 28, 232, 252, 115, 106, 23, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([85, 143, 18, 101, 101, 201, 146, 95, 146, 124, 254, 78, 228, 215, 122, 164, 58, 49, 178, 79]) }
2023-01-23T08:33:04.802883Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 34,
    },
    return_data: RawBytes {  },
    gas_used: 17947804,
    events_root: None,
}
2023-01-23T08:33:04.802919Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 459,
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
                    message: "constructor failed: send to f0459 method 1 aborted with code 34",
                },
                Frame {
                    source: 10,
                    method: 2,
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
                    message: "ABORT(pc=26): invalid instruction",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-23T08:33:04.803083Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 18
2023-01-23T08:33:04.803142Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CreateOOGFromCallRefunds"::Merge::18
2023-01-23T08:33:04.803153Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stCreateTest/CreateOOGFromCallRefunds.json"
2023-01-23T08:33:04.803164Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T08:33:04.803174Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [140, 244, 64, 245, 226, 166, 3, 182, 16, 235, 218, 159, 152, 241, 28, 232, 252, 115, 106, 23, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([67, 1, 137, 98, 70, 212, 67, 19, 201, 255, 154, 67, 250, 120, 4, 209, 79, 104, 144, 63]) }
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [226, 76, 185, 13, 123, 33, 181, 131, 183, 123, 193, 231, 187, 75, 28, 118, 7, 145, 177, 55, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([49, 38, 124, 54, 131, 54, 3, 75, 127, 190, 187, 205, 89, 114, 184, 248, 105, 6, 6, 225]) }
2023-01-23T08:33:04.812975Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 31653553,
    events_root: None,
}
2023-01-23T08:33:04.813114Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 19
2023-01-23T08:33:04.813157Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CreateOOGFromCallRefunds"::Merge::19
2023-01-23T08:33:04.813166Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stCreateTest/CreateOOGFromCallRefunds.json"
2023-01-23T08:33:04.813174Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T08:33:04.813180Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [143, 65, 157, 75, 216, 129, 119, 225, 90, 204, 103, 71, 25, 218, 254, 119, 76, 178, 233, 250, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([224, 185, 252, 233, 220, 182, 210, 59, 215, 224, 114, 129, 224, 209, 243, 213, 50, 205, 235, 229]) }
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [4, 120, 7, 108, 118, 76, 165, 20, 28, 189, 134, 82, 54, 217, 108, 189, 96, 25, 111, 106, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([191, 159, 112, 141, 232, 5, 157, 227, 71, 242, 220, 100, 76, 240, 116, 157, 77, 130, 229, 133]) }
2023-01-23T08:33:04.822889Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 37918052,
    events_root: None,
}
2023-01-23T08:33:04.823018Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 20
2023-01-23T08:33:04.823055Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CreateOOGFromCallRefunds"::Merge::20
2023-01-23T08:33:04.823063Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stCreateTest/CreateOOGFromCallRefunds.json"
2023-01-23T08:33:04.823070Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T08:33:04.823076Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [172, 48, 161, 96, 132, 86, 147, 71, 209, 164, 49, 216, 26, 86, 136, 218, 131, 148, 39, 218, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([202, 216, 7, 119, 106, 153, 146, 153, 17, 117, 69, 127, 5, 244, 55, 40, 94, 200, 169, 244]) }
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [240, 103, 244, 145, 220, 159, 72, 159, 111, 237, 207, 93, 16, 183, 10, 98, 207, 131, 50, 36, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([140, 56, 33, 54, 218, 176, 226, 193, 90, 129, 88, 46, 163, 153, 94, 187, 147, 230, 73, 255]) }
2023-01-23T08:33:04.832850Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 34,
    },
    return_data: RawBytes {  },
    gas_used: 31078998,
    events_root: None,
}
2023-01-23T08:33:04.832879Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 463,
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
                    message: "constructor failed: send to f0463 method 1 aborted with code 34",
                },
                Frame {
                    source: 10,
                    method: 2,
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
                    message: "ABORT(pc=26): invalid instruction",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-23T08:33:04.833033Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 21
2023-01-23T08:33:04.833079Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CreateOOGFromCallRefunds"::Merge::21
2023-01-23T08:33:04.833086Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stCreateTest/CreateOOGFromCallRefunds.json"
2023-01-23T08:33:04.833094Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T08:33:04.833100Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [172, 48, 161, 96, 132, 86, 147, 71, 209, 164, 49, 216, 26, 86, 136, 218, 131, 148, 39, 218, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([66, 164, 235, 226, 198, 211, 185, 232, 137, 80, 14, 181, 142, 113, 122, 170, 52, 30, 146, 127]) }
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [36, 21, 195, 35, 234, 48, 165, 178, 75, 191, 66, 196, 254, 202, 30, 117, 254, 168, 121, 19, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([25, 93, 36, 16, 33, 126, 3, 183, 90, 50, 105, 166, 149, 15, 3, 10, 170, 200, 152, 117]) }
2023-01-23T08:33:04.841964Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 31900412,
    events_root: None,
}
2023-01-23T08:33:04.842097Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 22
2023-01-23T08:33:04.842139Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CreateOOGFromCallRefunds"::Merge::22
2023-01-23T08:33:04.842147Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stCreateTest/CreateOOGFromCallRefunds.json"
2023-01-23T08:33:04.842154Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T08:33:04.842161Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [249, 131, 225, 157, 222, 63, 163, 190, 116, 239, 226, 205, 15, 197, 50, 11, 72, 25, 200, 235, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([59, 53, 249, 29, 97, 100, 74, 37, 144, 142, 18, 90, 172, 2, 157, 156, 29, 149, 16, 132]) }
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [90, 229, 223, 220, 3, 45, 110, 15, 32, 15, 31, 89, 81, 23, 6, 173, 13, 192, 85, 132, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([69, 221, 74, 20, 166, 174, 70, 159, 174, 217, 109, 198, 100, 253, 238, 242, 60, 61, 6, 176]) }
2023-01-23T08:33:04.852896Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 38882613,
    events_root: None,
}
2023-01-23T08:33:04.853029Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 23
2023-01-23T08:33:04.853071Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CreateOOGFromCallRefunds"::Merge::23
2023-01-23T08:33:04.853080Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stCreateTest/CreateOOGFromCallRefunds.json"
2023-01-23T08:33:04.853088Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T08:33:04.853094Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [148, 73, 192, 65, 146, 166, 127, 106, 243, 169, 48, 122, 124, 24, 138, 77, 123, 183, 18, 188, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([181, 8, 27, 168, 223, 145, 221, 58, 213, 216, 232, 244, 223, 5, 154, 0, 190, 59, 128, 47]) }
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [228, 118, 74, 149, 185, 165, 39, 226, 66, 202, 227, 91, 201, 189, 131, 235, 46, 37, 157, 78, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([219, 241, 99, 54, 135, 139, 195, 112, 89, 185, 78, 113, 131, 49, 207, 227, 170, 228, 180, 28]) }
2023-01-23T08:33:04.862502Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 34,
    },
    return_data: RawBytes {  },
    gas_used: 31640953,
    events_root: None,
}
2023-01-23T08:33:04.862533Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 467,
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
                    message: "constructor failed: send to f0467 method 1 aborted with code 34",
                },
                Frame {
                    source: 10,
                    method: 2,
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
                    message: "ABORT(pc=26): invalid instruction",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-23T08:33:04.865182Z TRACE evm_eth_compliance::statetest::runner: TestDone => "test-vectors/tests/GeneralStateTests/stCreateTest/CreateOOGFromCallRefunds.json"
2023-01-23T08:33:04.865589Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:13.670207368s
```