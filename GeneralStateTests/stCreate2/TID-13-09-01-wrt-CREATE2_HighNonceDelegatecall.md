> Status

| Status | Context |
| --- | --- |
| KO | under WASM RT context |
| KO | under native RT context |

KO :: USR_ASSERTION_FAILED

> Test Suite

https://github.com/ethereum/tests/blob/develop/GeneralStateTests/stCreate2/CREATE2_HighNonceDelegatecall.json#L1

> Command to execute

```
clear && \
	RUST_LOG=evm_eth_compliance=trace \
	VECTOR=test-vectors/tests/GeneralStateTests/stCreate2/CREATE2_HighNonceDelegatecall.json \
	cargo run \
	-- \
	statetest
```

> For Review

- Hit with error `pub const USR_ASSERTION_FAILED: ExitCode = ExitCode::new(24);`

```
[DEBUG] fetching parameters block: 1
2023-01-22T13:45:08.837006Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 24,
    },
    return_data: RawBytes {  },
    gas_used: 11806653,
    events_root: None,
}
2023-01-22T13:45:08.837027Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 203,
                    method: 3844450837,
                    code: ExitCode {
                        value: 24,
                    },
                    message: "panicked at 'called `Option::unwrap()` on a `None` value', actors/evm/src/interpreter/system.rs:210:22",
                },
            ],
            cause: None,
        },
    ),
)
```

> Opcodes

```
0000 PUSH1 0x04
0002 CALLDATALOAD
0003 PUSH1 0x24
0005 CALLDATALOAD
0006 PUSH1 0x44
0008 CALLDATALOAD
0009 PUSH1 0x64
000b CALLDATALOAD
000c PUSH2 0xffff
000f SLOAD
0010 JUMPDEST
0011 DUP4
0012 DUP2
0013 LT
0014 ISZERO
0015 PUSH1 0x47
0017 JUMPI
0018 PUSH5 0x60016000f3
001e PUSH1 0x00
0020 MSTORE
0021 PUSH1 0x05
0023 PUSH1 0x05
0025 PUSH1 0x20
0027 SUB
0028 PUSH1 0x00
002a CREATE
002b PUSH1 0x00
002d DUP2
002e GT
002f ISZERO
0030 PUSH1 0x3b
0032 JUMPI
0033 PUSH1 0x01
0035 DUP3
0036 ADD
0037 PUSH2 0xffff
003a SSTORE
003b JUMPDEST
003c POP
003d JUMPDEST
003e PUSH2 0xffff
0041 SLOAD
0042 SWAP1
0043 POP
0044 PUSH1 0x10
0046 JUMP
0047 JUMPDEST
0048 POP
0049 DUP1
004a PUSH1 0x00
004c MSTORE
004d PUSH1 0x00
004f DUP5
0050 EQ
0051 ISZERO
0052 PUSH1 0x65
0054 JUMPI
0055 PUSH1 0x20
0057 PUSH1 0x00
0059 PUSH1 0x20
005b PUSH1 0x00
005d DUP6
005e PUSH2 0x03e8
0061 GAS
0062 SUB
0063 DELEGATECALL
0064 POP
0065 JUMPDEST
0066 PUSH1 0x01
0068 DUP5
0069 EQ
006a ISZERO
006b PUSH1 0x80
006d JUMPI
006e PUSH1 0x20
0070 PUSH1 0x00
0072 PUSH1 0x20
0074 PUSH1 0x00
0076 PUSH1 0x00
0078 DUP7
0079 PUSH2 0x03e8
007c GAS
007d SUB
007e CALLCODE
007f POP
0080 JUMPDEST
0081 PUSH1 0x02
0083 DUP5
0084 EQ
0085 ISZERO
0086 PUSH1 0x9b
0088 JUMPI
0089 PUSH1 0x20
008b PUSH1 0x00
008d PUSH1 0x20
008f PUSH1 0x00
0091 PUSH1 0x00
0093 DUP7
0094 PUSH2 0x03e8
0097 GAS
0098 SUB
0099 CALL
009a POP
009b JUMPDEST
009c PUSH1 0x00
009e MLOAD
009f DUP1
00a0 PUSH1 0x01
00a2 SSTORE
00a3 PUSH1 0x00
00a5 DUP2
00a6 GT
00a7 ISZERO
00a8 PUSH1 0xbd
00aa JUMPI
00ab PUSH1 0x00
00ad PUSH1 0x00
00af PUSH1 0x00
00b1 PUSH1 0x00
00b3 PUSH1 0x00
00b5 DUP6
00b6 PUSH2 0x03e8
00b9 GAS
00ba SUB
00bb CALL
00bc POP
00bd JUMPDEST
00be POP
00bf POP
00c0 POP
00c1 POP
00c2 POP
```

> Execution Trace

```
2023-01-22T13:44:56.565108Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "test-vectors/tests/GeneralStateTests/stCreate2/CREATE2_HighNonceDelegatecall.json", Total Files :: 1
2023-01-22T13:44:56.565533Z TRACE evm_eth_compliance::statetest::runner: Calling testfile => "test-vectors/tests/GeneralStateTests/stCreate2/CREATE2_HighNonceDelegatecall.json"
2023-01-22T13:44:56.703627Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 255, 255, 255, 255, 255, 255, 255, 254, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([179, 152, 63, 197, 60, 234, 37, 74, 66, 53, 75, 140, 66, 70, 3, 8, 241, 171, 25, 86]) }
[DEBUG] getting cid: bafy2bzaceaii7gatq5yoovv5j5rn5hvbvdukafhmhnjm36ur627u6hyo6dame
[DEBUG] fetching parameters block: 1
2023-01-22T13:45:08.822354Z  INFO evm_eth_compliance::statetest::runner: Dummy Place Holder Contract got deployed with Actor ID [200]
2023-01-22T13:45:08.822557Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-22T13:45:08.822639Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 255, 255, 255, 255, 255, 255, 255, 255, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([157, 122, 181, 47, 53, 176, 191, 159, 121, 68, 73, 204, 112, 124, 226, 155, 100, 141, 75, 36]) }
[DEBUG] getting cid: bafy2bzacec4cfnsolavg4n5j2dv2fmv3kxxp4ti523kk2y5mk7kgbmfjo2kua
[DEBUG] fetching parameters block: 1
2023-01-22T13:45:08.825682Z  INFO evm_eth_compliance::statetest::runner: Dummy Place Holder Contract got deployed with Actor ID [201]
2023-01-22T13:45:08.825832Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-22T13:45:08.825879Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 2
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [169, 79, 83, 116, 252, 229, 237, 188, 142, 42, 134, 151, 193, 83, 49, 103, 126, 110, 191, 11, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([135, 86, 195, 226, 17, 192, 42, 192, 25, 213, 136, 254, 18, 95, 50, 68, 155, 121, 209, 130]) }
[DEBUG] getting cid: bafy2bzacea7pwnuh544tyuivy2veyn5lpl4x4aol7v5ta5aznmswhpbwdpppi
[DEBUG] fetching parameters block: 1
2023-01-22T13:45:08.828811Z  INFO evm_eth_compliance::statetest::runner: Dummy Place Holder Contract got deployed with Actor ID [202]
2023-01-22T13:45:08.828947Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-22T13:45:08.828994Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 3
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [185, 79, 83, 116, 252, 229, 237, 188, 142, 42, 134, 151, 193, 83, 49, 103, 126, 110, 191, 11, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([121, 46, 44, 168, 100, 157, 195, 57, 208, 185, 119, 244, 82, 48, 8, 55, 203, 168, 19, 62]) }
[DEBUG] getting cid: bafy2bzacedqcl3nc6z7lyot5uvqnmr2qefifohax64krp25wvlrjvnjkpwv2k
[DEBUG] fetching parameters block: 1
2023-01-22T13:45:08.831939Z  INFO evm_eth_compliance::statetest::runner: Dummy Place Holder Contract got deployed with Actor ID [203]
2023-01-22T13:45:08.832116Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-22T13:45:08.833276Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Homestead 6
2023-01-22T13:45:08.833325Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_HighNonceDelegatecall"::Homestead::6
2023-01-22T13:45:08.833334Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stCreate2/CREATE2_HighNonceDelegatecall.json"
2023-01-22T13:45:08.833342Z  INFO evm_eth_compliance::statetest::runner: TX len : 132
2023-01-22T13:45:08.833349Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [208, 97, 176, 138, 132, 235, 199, 15, 231, 151, 249, 189, 98, 244, 38, 158, 248, 39, 74, 19, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([215, 166, 242, 208, 200, 186, 79, 10, 126, 8, 221, 102, 9, 12, 200, 158, 203, 19, 78, 227]) }
[DEBUG] getting cid: bafy2bzacedef2iioq5zx33deu6ufh237wvqdt7vycaffbp5y5grxgwyyptoog
[DEBUG] fetching parameters block: 1
2023-01-22T13:45:08.837006Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 24,
    },
    return_data: RawBytes {  },
    gas_used: 11806653,
    events_root: None,
}
2023-01-22T13:45:08.837027Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 203,
                    method: 3844450837,
                    code: ExitCode {
                        value: 24,
                    },
                    message: "panicked at 'called `Option::unwrap()` on a `None` value', actors/evm/src/interpreter/system.rs:210:22",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-22T13:45:08.837084Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Homestead 7
2023-01-22T13:45:08.837114Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_HighNonceDelegatecall"::Homestead::7
2023-01-22T13:45:08.837121Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stCreate2/CREATE2_HighNonceDelegatecall.json"
2023-01-22T13:45:08.837128Z  INFO evm_eth_compliance::statetest::runner: TX len : 132
2023-01-22T13:45:08.837134Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [208, 97, 176, 138, 132, 235, 199, 15, 231, 151, 249, 189, 98, 244, 38, 158, 248, 39, 74, 19, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([67, 35, 255, 1, 46, 226, 200, 90, 20, 150, 237, 153, 222, 171, 201, 9, 99, 31, 101, 211]) }
[DEBUG] getting cid: bafy2bzacedef2iioq5zx33deu6ufh237wvqdt7vycaffbp5y5grxgwyyptoog
[DEBUG] fetching parameters block: 1
2023-01-22T13:45:08.840629Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 24,
    },
    return_data: RawBytes {  },
    gas_used: 12333819,
    events_root: None,
}
2023-01-22T13:45:08.840644Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 203,
                    method: 3844450837,
                    code: ExitCode {
                        value: 24,
                    },
                    message: "panicked at 'called `Option::unwrap()` on a `None` value', actors/evm/src/interpreter/system.rs:210:22",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-22T13:45:08.840697Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Homestead 8
2023-01-22T13:45:08.840721Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_HighNonceDelegatecall"::Homestead::8
2023-01-22T13:45:08.840728Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stCreate2/CREATE2_HighNonceDelegatecall.json"
2023-01-22T13:45:08.840735Z  INFO evm_eth_compliance::statetest::runner: TX len : 132
2023-01-22T13:45:08.840741Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [208, 97, 176, 138, 132, 235, 199, 15, 231, 151, 249, 189, 98, 244, 38, 158, 248, 39, 74, 19, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([28, 35, 125, 168, 212, 11, 234, 180, 81, 129, 48, 219, 76, 10, 52, 89, 217, 159, 194, 2]) }
[DEBUG] getting cid: bafy2bzacedef2iioq5zx33deu6ufh237wvqdt7vycaffbp5y5grxgwyyptoog
[DEBUG] fetching parameters block: 1
2023-01-22T13:45:08.844029Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 24,
    },
    return_data: RawBytes {  },
    gas_used: 11809897,
    events_root: None,
}
2023-01-22T13:45:08.844045Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 203,
                    method: 3844450837,
                    code: ExitCode {
                        value: 24,
                    },
                    message: "panicked at 'called `Option::unwrap()` on a `None` value', actors/evm/src/interpreter/system.rs:210:22",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-22T13:45:08.844097Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Homestead 9
2023-01-22T13:45:08.844120Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_HighNonceDelegatecall"::Homestead::9
2023-01-22T13:45:08.844127Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stCreate2/CREATE2_HighNonceDelegatecall.json"
2023-01-22T13:45:08.844134Z  INFO evm_eth_compliance::statetest::runner: TX len : 132
2023-01-22T13:45:08.844140Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [208, 97, 176, 138, 132, 235, 199, 15, 231, 151, 249, 189, 98, 244, 38, 158, 248, 39, 74, 19, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([132, 105, 76, 107, 184, 77, 78, 105, 101, 219, 134, 121, 221, 254, 217, 203, 72, 121, 220, 83]) }
[DEBUG] getting cid: bafy2bzacedef2iioq5zx33deu6ufh237wvqdt7vycaffbp5y5grxgwyyptoog
[DEBUG] fetching parameters block: 1
2023-01-22T13:45:08.847561Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 24,
    },
    return_data: RawBytes {  },
    gas_used: 12646965,
    events_root: None,
}
2023-01-22T13:45:08.847576Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 203,
                    method: 3844450837,
                    code: ExitCode {
                        value: 24,
                    },
                    message: "panicked at 'called `Option::unwrap()` on a `None` value', actors/evm/src/interpreter/system.rs:210:22",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-22T13:45:08.847629Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Homestead 10
2023-01-22T13:45:08.847651Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_HighNonceDelegatecall"::Homestead::10
2023-01-22T13:45:08.847658Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stCreate2/CREATE2_HighNonceDelegatecall.json"
2023-01-22T13:45:08.847665Z  INFO evm_eth_compliance::statetest::runner: TX len : 132
2023-01-22T13:45:08.847671Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [208, 97, 176, 138, 132, 235, 199, 15, 231, 151, 249, 189, 98, 244, 38, 158, 248, 39, 74, 19, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([236, 70, 216, 243, 101, 99, 189, 62, 205, 26, 208, 253, 84, 36, 48, 143, 166, 88, 135, 41]) }
[DEBUG] getting cid: bafy2bzacedef2iioq5zx33deu6ufh237wvqdt7vycaffbp5y5grxgwyyptoog
[DEBUG] fetching parameters block: 1
2023-01-22T13:45:08.850962Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 24,
    },
    return_data: RawBytes {  },
    gas_used: 11807125,
    events_root: None,
}
2023-01-22T13:45:08.850977Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 203,
                    method: 3844450837,
                    code: ExitCode {
                        value: 24,
                    },
                    message: "panicked at 'called `Option::unwrap()` on a `None` value', actors/evm/src/interpreter/system.rs:210:22",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-22T13:45:08.851028Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Homestead 11
2023-01-22T13:45:08.851056Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_HighNonceDelegatecall"::Homestead::11
2023-01-22T13:45:08.851067Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stCreate2/CREATE2_HighNonceDelegatecall.json"
2023-01-22T13:45:08.851078Z  INFO evm_eth_compliance::statetest::runner: TX len : 132
2023-01-22T13:45:08.851087Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [208, 97, 176, 138, 132, 235, 199, 15, 231, 151, 249, 189, 98, 244, 38, 158, 248, 39, 74, 19, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([155, 99, 140, 31, 46, 96, 27, 93, 44, 60, 131, 66, 80, 136, 87, 209, 224, 27, 216, 212]) }
[DEBUG] getting cid: bafy2bzacedef2iioq5zx33deu6ufh237wvqdt7vycaffbp5y5grxgwyyptoog
[DEBUG] fetching parameters block: 1
2023-01-22T13:45:08.854679Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 24,
    },
    return_data: RawBytes {  },
    gas_used: 12332709,
    events_root: None,
}
2023-01-22T13:45:08.854697Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 203,
                    method: 3844450837,
                    code: ExitCode {
                        value: 24,
                    },
                    message: "panicked at 'called `Option::unwrap()` on a `None` value', actors/evm/src/interpreter/system.rs:210:22",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-22T13:45:08.854754Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Homestead 0
2023-01-22T13:45:08.854783Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_HighNonceDelegatecall"::Homestead::0
2023-01-22T13:45:08.854790Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stCreate2/CREATE2_HighNonceDelegatecall.json"
2023-01-22T13:45:08.854797Z  INFO evm_eth_compliance::statetest::runner: TX len : 132
2023-01-22T13:45:08.854803Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [208, 97, 176, 138, 132, 235, 199, 15, 231, 151, 249, 189, 98, 244, 38, 158, 248, 39, 74, 19, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([188, 149, 186, 245, 1, 91, 222, 203, 63, 25, 86, 169, 35, 110, 18, 124, 122, 60, 238, 128]) }
[DEBUG] getting cid: bafy2bzacedef2iioq5zx33deu6ufh237wvqdt7vycaffbp5y5grxgwyyptoog
[DEBUG] fetching parameters block: 1
2023-01-22T13:45:08.858327Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 24,
    },
    return_data: RawBytes {  },
    gas_used: 12339866,
    events_root: None,
}
2023-01-22T13:45:08.858345Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 203,
                    method: 3844450837,
                    code: ExitCode {
                        value: 24,
                    },
                    message: "panicked at 'called `Option::unwrap()` on a `None` value', actors/evm/src/interpreter/system.rs:210:22",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-22T13:45:08.858401Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Homestead 1
2023-01-22T13:45:08.858425Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_HighNonceDelegatecall"::Homestead::1
2023-01-22T13:45:08.858432Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stCreate2/CREATE2_HighNonceDelegatecall.json"
2023-01-22T13:45:08.858439Z  INFO evm_eth_compliance::statetest::runner: TX len : 132
2023-01-22T13:45:08.858445Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [208, 97, 176, 138, 132, 235, 199, 15, 231, 151, 249, 189, 98, 244, 38, 158, 248, 39, 74, 19, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([20, 3, 204, 71, 166, 252, 88, 221, 29, 77, 14, 224, 191, 132, 61, 100, 47, 53, 166, 175]) }
[DEBUG] getting cid: bafy2bzacedef2iioq5zx33deu6ufh237wvqdt7vycaffbp5y5grxgwyyptoog
[DEBUG] fetching parameters block: 1
2023-01-22T13:45:08.861960Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 24,
    },
    return_data: RawBytes {  },
    gas_used: 12722827,
    events_root: None,
}
2023-01-22T13:45:08.861976Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 203,
                    method: 3844450837,
                    code: ExitCode {
                        value: 24,
                    },
                    message: "panicked at 'called `Option::unwrap()` on a `None` value', actors/evm/src/interpreter/system.rs:210:22",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-22T13:45:08.862029Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Homestead 2
2023-01-22T13:45:08.862052Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_HighNonceDelegatecall"::Homestead::2
2023-01-22T13:45:08.862059Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stCreate2/CREATE2_HighNonceDelegatecall.json"
2023-01-22T13:45:08.862066Z  INFO evm_eth_compliance::statetest::runner: TX len : 132
2023-01-22T13:45:08.862072Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [208, 97, 176, 138, 132, 235, 199, 15, 231, 151, 249, 189, 98, 244, 38, 158, 248, 39, 74, 19, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([177, 189, 137, 170, 161, 168, 98, 8, 218, 14, 105, 2, 242, 92, 44, 234, 2, 122, 233, 63]) }
[DEBUG] getting cid: bafy2bzacedef2iioq5zx33deu6ufh237wvqdt7vycaffbp5y5grxgwyyptoog
[DEBUG] fetching parameters block: 1
2023-01-22T13:45:08.865621Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 24,
    },
    return_data: RawBytes {  },
    gas_used: 12338154,
    events_root: None,
}
2023-01-22T13:45:08.865637Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 203,
                    method: 3844450837,
                    code: ExitCode {
                        value: 24,
                    },
                    message: "panicked at 'called `Option::unwrap()` on a `None` value', actors/evm/src/interpreter/system.rs:210:22",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-22T13:45:08.865692Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Homestead 3
2023-01-22T13:45:08.865717Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_HighNonceDelegatecall"::Homestead::3
2023-01-22T13:45:08.865724Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stCreate2/CREATE2_HighNonceDelegatecall.json"
2023-01-22T13:45:08.865731Z  INFO evm_eth_compliance::statetest::runner: TX len : 132
2023-01-22T13:45:08.865737Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [208, 97, 176, 138, 132, 235, 199, 15, 231, 151, 249, 189, 98, 244, 38, 158, 248, 39, 74, 19, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([178, 221, 99, 117, 94, 25, 113, 14, 55, 217, 63, 213, 179, 235, 175, 240, 178, 120, 15, 225]) }
[DEBUG] getting cid: bafy2bzacedef2iioq5zx33deu6ufh237wvqdt7vycaffbp5y5grxgwyyptoog
[DEBUG] fetching parameters block: 1
2023-01-22T13:45:08.869121Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 24,
    },
    return_data: RawBytes {  },
    gas_used: 11808681,
    events_root: None,
}
2023-01-22T13:45:08.869136Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 203,
                    method: 3844450837,
                    code: ExitCode {
                        value: 24,
                    },
                    message: "panicked at 'called `Option::unwrap()` on a `None` value', actors/evm/src/interpreter/system.rs:210:22",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-22T13:45:08.869188Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Homestead 4
2023-01-22T13:45:08.869213Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_HighNonceDelegatecall"::Homestead::4
2023-01-22T13:45:08.869220Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stCreate2/CREATE2_HighNonceDelegatecall.json"
2023-01-22T13:45:08.869227Z  INFO evm_eth_compliance::statetest::runner: TX len : 132
2023-01-22T13:45:08.869233Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [208, 97, 176, 138, 132, 235, 199, 15, 231, 151, 249, 189, 98, 244, 38, 158, 248, 39, 74, 19, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([251, 114, 94, 192, 108, 10, 201, 112, 101, 197, 5, 103, 36, 134, 180, 68, 48, 44, 184, 84]) }
[DEBUG] getting cid: bafy2bzacedef2iioq5zx33deu6ufh237wvqdt7vycaffbp5y5grxgwyyptoog
[DEBUG] fetching parameters block: 1
2023-01-22T13:45:08.872560Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 24,
    },
    return_data: RawBytes {  },
    gas_used: 11810017,
    events_root: None,
}
2023-01-22T13:45:08.872575Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 203,
                    method: 3844450837,
                    code: ExitCode {
                        value: 24,
                    },
                    message: "panicked at 'called `Option::unwrap()` on a `None` value', actors/evm/src/interpreter/system.rs:210:22",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-22T13:45:08.872627Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Homestead 5
2023-01-22T13:45:08.872651Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_HighNonceDelegatecall"::Homestead::5
2023-01-22T13:45:08.872658Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stCreate2/CREATE2_HighNonceDelegatecall.json"
2023-01-22T13:45:08.872665Z  INFO evm_eth_compliance::statetest::runner: TX len : 132
2023-01-22T13:45:08.872671Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [208, 97, 176, 138, 132, 235, 199, 15, 231, 151, 249, 189, 98, 244, 38, 158, 248, 39, 74, 19, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([90, 217, 32, 146, 24, 201, 117, 10, 10, 210, 28, 70, 31, 30, 132, 56, 243, 180, 75, 35]) }
[DEBUG] getting cid: bafy2bzacedef2iioq5zx33deu6ufh237wvqdt7vycaffbp5y5grxgwyyptoog
[DEBUG] fetching parameters block: 1
2023-01-22T13:45:08.876130Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 24,
    },
    return_data: RawBytes {  },
    gas_used: 12702512,
    events_root: None,
}
2023-01-22T13:45:08.876145Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 203,
                    method: 3844450837,
                    code: ExitCode {
                        value: 24,
                    },
                    message: "panicked at 'called `Option::unwrap()` on a `None` value', actors/evm/src/interpreter/system.rs:210:22",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-22T13:45:08.876200Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => EIP150 6
2023-01-22T13:45:08.876223Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_HighNonceDelegatecall"::EIP150::6
2023-01-22T13:45:08.876230Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stCreate2/CREATE2_HighNonceDelegatecall.json"
2023-01-22T13:45:08.876237Z  INFO evm_eth_compliance::statetest::runner: TX len : 132
2023-01-22T13:45:08.876245Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [208, 97, 176, 138, 132, 235, 199, 15, 231, 151, 249, 189, 98, 244, 38, 158, 248, 39, 74, 19, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([128, 138, 188, 155, 213, 11, 225, 143, 246, 50, 199, 246, 94, 148, 129, 183, 56, 152, 76, 55]) }
[DEBUG] getting cid: bafy2bzacedef2iioq5zx33deu6ufh237wvqdt7vycaffbp5y5grxgwyyptoog
[DEBUG] fetching parameters block: 1
2023-01-22T13:45:08.879592Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 24,
    },
    return_data: RawBytes {  },
    gas_used: 11848902,
    events_root: None,
}
2023-01-22T13:45:08.879607Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 203,
                    method: 3844450837,
                    code: ExitCode {
                        value: 24,
                    },
                    message: "panicked at 'called `Option::unwrap()` on a `None` value', actors/evm/src/interpreter/system.rs:210:22",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-22T13:45:08.879659Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => EIP150 7
2023-01-22T13:45:08.879683Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_HighNonceDelegatecall"::EIP150::7
2023-01-22T13:45:08.879690Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stCreate2/CREATE2_HighNonceDelegatecall.json"
2023-01-22T13:45:08.879697Z  INFO evm_eth_compliance::statetest::runner: TX len : 132
2023-01-22T13:45:08.879705Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [208, 97, 176, 138, 132, 235, 199, 15, 231, 151, 249, 189, 98, 244, 38, 158, 248, 39, 74, 19, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([55, 124, 170, 147, 221, 2, 18, 238, 216, 76, 43, 142, 118, 199, 246, 132, 57, 223, 23, 100]) }
[DEBUG] getting cid: bafy2bzacedef2iioq5zx33deu6ufh237wvqdt7vycaffbp5y5grxgwyyptoog
[DEBUG] fetching parameters block: 1
2023-01-22T13:45:08.883160Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 24,
    },
    return_data: RawBytes {  },
    gas_used: 12340863,
    events_root: None,
}
2023-01-22T13:45:08.883176Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 203,
                    method: 3844450837,
                    code: ExitCode {
                        value: 24,
                    },
                    message: "panicked at 'called `Option::unwrap()` on a `None` value', actors/evm/src/interpreter/system.rs:210:22",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-22T13:45:08.883228Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => EIP150 8
2023-01-22T13:45:08.883253Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_HighNonceDelegatecall"::EIP150::8
2023-01-22T13:45:08.883260Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stCreate2/CREATE2_HighNonceDelegatecall.json"
2023-01-22T13:45:08.883267Z  INFO evm_eth_compliance::statetest::runner: TX len : 132
2023-01-22T13:45:08.883273Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [208, 97, 176, 138, 132, 235, 199, 15, 231, 151, 249, 189, 98, 244, 38, 158, 248, 39, 74, 19, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([171, 234, 181, 15, 37, 193, 240, 156, 211, 60, 172, 98, 156, 55, 186, 0, 159, 236, 160, 247]) }
[DEBUG] getting cid: bafy2bzacedef2iioq5zx33deu6ufh237wvqdt7vycaffbp5y5grxgwyyptoog
[DEBUG] fetching parameters block: 1
2023-01-22T13:45:08.886586Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 24,
    },
    return_data: RawBytes {  },
    gas_used: 11806885,
    events_root: None,
}
2023-01-22T13:45:08.886602Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 203,
                    method: 3844450837,
                    code: ExitCode {
                        value: 24,
                    },
                    message: "panicked at 'called `Option::unwrap()` on a `None` value', actors/evm/src/interpreter/system.rs:210:22",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-22T13:45:08.886653Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => EIP150 9
2023-01-22T13:45:08.886676Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_HighNonceDelegatecall"::EIP150::9
2023-01-22T13:45:08.886683Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stCreate2/CREATE2_HighNonceDelegatecall.json"
2023-01-22T13:45:08.886690Z  INFO evm_eth_compliance::statetest::runner: TX len : 132
2023-01-22T13:45:08.886696Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [208, 97, 176, 138, 132, 235, 199, 15, 231, 151, 249, 189, 98, 244, 38, 158, 248, 39, 74, 19, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([167, 18, 209, 255, 80, 109, 220, 136, 239, 83, 214, 196, 45, 184, 19, 227, 137, 201, 135, 105]) }
[DEBUG] getting cid: bafy2bzacedef2iioq5zx33deu6ufh237wvqdt7vycaffbp5y5grxgwyyptoog
[DEBUG] fetching parameters block: 1
2023-01-22T13:45:08.890135Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 24,
    },
    return_data: RawBytes {  },
    gas_used: 12772372,
    events_root: None,
}
2023-01-22T13:45:08.890150Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 203,
                    method: 3844450837,
                    code: ExitCode {
                        value: 24,
                    },
                    message: "panicked at 'called `Option::unwrap()` on a `None` value', actors/evm/src/interpreter/system.rs:210:22",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-22T13:45:08.890227Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => EIP150 10
2023-01-22T13:45:08.890263Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_HighNonceDelegatecall"::EIP150::10
2023-01-22T13:45:08.890274Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stCreate2/CREATE2_HighNonceDelegatecall.json"
2023-01-22T13:45:08.890285Z  INFO evm_eth_compliance::statetest::runner: TX len : 132
2023-01-22T13:45:08.890294Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [208, 97, 176, 138, 132, 235, 199, 15, 231, 151, 249, 189, 98, 244, 38, 158, 248, 39, 74, 19, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([143, 33, 161, 133, 93, 209, 38, 110, 16, 16, 237, 126, 30, 78, 59, 192, 15, 148, 83, 57]) }
[DEBUG] getting cid: bafy2bzacedef2iioq5zx33deu6ufh237wvqdt7vycaffbp5y5grxgwyyptoog
[DEBUG] fetching parameters block: 1
2023-01-22T13:45:08.893653Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 24,
    },
    return_data: RawBytes {  },
    gas_used: 11805261,
    events_root: None,
}
2023-01-22T13:45:08.893669Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 203,
                    method: 3844450837,
                    code: ExitCode {
                        value: 24,
                    },
                    message: "panicked at 'called `Option::unwrap()` on a `None` value', actors/evm/src/interpreter/system.rs:210:22",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-22T13:45:08.893721Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => EIP150 11
2023-01-22T13:45:08.893746Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_HighNonceDelegatecall"::EIP150::11
2023-01-22T13:45:08.893753Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stCreate2/CREATE2_HighNonceDelegatecall.json"
2023-01-22T13:45:08.893760Z  INFO evm_eth_compliance::statetest::runner: TX len : 132
2023-01-22T13:45:08.893766Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [208, 97, 176, 138, 132, 235, 199, 15, 231, 151, 249, 189, 98, 244, 38, 158, 248, 39, 74, 19, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([115, 209, 18, 63, 181, 115, 165, 219, 137, 112, 100, 108, 193, 38, 167, 163, 136, 114, 38, 238]) }
[DEBUG] getting cid: bafy2bzacedef2iioq5zx33deu6ufh237wvqdt7vycaffbp5y5grxgwyyptoog
[DEBUG] fetching parameters block: 1
2023-01-22T13:45:08.897213Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 24,
    },
    return_data: RawBytes {  },
    gas_used: 12340566,
    events_root: None,
}
2023-01-22T13:45:08.897228Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 203,
                    method: 3844450837,
                    code: ExitCode {
                        value: 24,
                    },
                    message: "panicked at 'called `Option::unwrap()` on a `None` value', actors/evm/src/interpreter/system.rs:210:22",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-22T13:45:08.897282Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => EIP150 0
2023-01-22T13:45:08.897308Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_HighNonceDelegatecall"::EIP150::0
2023-01-22T13:45:08.897315Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stCreate2/CREATE2_HighNonceDelegatecall.json"
2023-01-22T13:45:08.897322Z  INFO evm_eth_compliance::statetest::runner: TX len : 132
2023-01-22T13:45:08.897329Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [208, 97, 176, 138, 132, 235, 199, 15, 231, 151, 249, 189, 98, 244, 38, 158, 248, 39, 74, 19, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([164, 19, 188, 157, 123, 198, 227, 16, 99, 7, 112, 55, 126, 183, 242, 167, 190, 31, 240, 147]) }
[DEBUG] getting cid: bafy2bzacedef2iioq5zx33deu6ufh237wvqdt7vycaffbp5y5grxgwyyptoog
[DEBUG] fetching parameters block: 1
2023-01-22T13:45:08.900669Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 24,
    },
    return_data: RawBytes {  },
    gas_used: 11807517,
    events_root: None,
}
2023-01-22T13:45:08.900689Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 203,
                    method: 3844450837,
                    code: ExitCode {
                        value: 24,
                    },
                    message: "panicked at 'called `Option::unwrap()` on a `None` value', actors/evm/src/interpreter/system.rs:210:22",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-22T13:45:08.900756Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => EIP150 1
2023-01-22T13:45:08.900781Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_HighNonceDelegatecall"::EIP150::1
2023-01-22T13:45:08.900788Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stCreate2/CREATE2_HighNonceDelegatecall.json"
2023-01-22T13:45:08.900795Z  INFO evm_eth_compliance::statetest::runner: TX len : 132
2023-01-22T13:45:08.900801Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [208, 97, 176, 138, 132, 235, 199, 15, 231, 151, 249, 189, 98, 244, 38, 158, 248, 39, 74, 19, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([40, 113, 131, 83, 213, 98, 3, 231, 134, 49, 131, 92, 170, 242, 84, 90, 74, 151, 72, 246]) }
[DEBUG] getting cid: bafy2bzacedef2iioq5zx33deu6ufh237wvqdt7vycaffbp5y5grxgwyyptoog
[DEBUG] fetching parameters block: 1
2023-01-22T13:45:08.904312Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 24,
    },
    return_data: RawBytes {  },
    gas_used: 12772640,
    events_root: None,
}
2023-01-22T13:45:08.904327Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 203,
                    method: 3844450837,
                    code: ExitCode {
                        value: 24,
                    },
                    message: "panicked at 'called `Option::unwrap()` on a `None` value', actors/evm/src/interpreter/system.rs:210:22",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-22T13:45:08.904382Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => EIP150 2
2023-01-22T13:45:08.904407Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_HighNonceDelegatecall"::EIP150::2
2023-01-22T13:45:08.904414Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stCreate2/CREATE2_HighNonceDelegatecall.json"
2023-01-22T13:45:08.904421Z  INFO evm_eth_compliance::statetest::runner: TX len : 132
2023-01-22T13:45:08.904427Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [208, 97, 176, 138, 132, 235, 199, 15, 231, 151, 249, 189, 98, 244, 38, 158, 248, 39, 74, 19, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([40, 182, 218, 235, 33, 11, 225, 5, 136, 185, 130, 124, 42, 168, 16, 11, 169, 12, 214, 166]) }
[DEBUG] getting cid: bafy2bzacedef2iioq5zx33deu6ufh237wvqdt7vycaffbp5y5grxgwyyptoog
[DEBUG] fetching parameters block: 1
2023-01-22T13:45:08.907877Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 24,
    },
    return_data: RawBytes {  },
    gas_used: 12706090,
    events_root: None,
}
2023-01-22T13:45:08.907893Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 203,
                    method: 3844450837,
                    code: ExitCode {
                        value: 24,
                    },
                    message: "panicked at 'called `Option::unwrap()` on a `None` value', actors/evm/src/interpreter/system.rs:210:22",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-22T13:45:08.907945Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => EIP150 3
2023-01-22T13:45:08.907968Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_HighNonceDelegatecall"::EIP150::3
2023-01-22T13:45:08.907975Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stCreate2/CREATE2_HighNonceDelegatecall.json"
2023-01-22T13:45:08.907982Z  INFO evm_eth_compliance::statetest::runner: TX len : 132
2023-01-22T13:45:08.907988Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [208, 97, 176, 138, 132, 235, 199, 15, 231, 151, 249, 189, 98, 244, 38, 158, 248, 39, 74, 19, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([120, 103, 96, 100, 116, 249, 190, 222, 117, 123, 178, 182, 219, 22, 101, 99, 7, 208, 237, 37]) }
[DEBUG] getting cid: bafy2bzacedef2iioq5zx33deu6ufh237wvqdt7vycaffbp5y5grxgwyyptoog
[DEBUG] fetching parameters block: 1
2023-01-22T13:45:08.911395Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 24,
    },
    return_data: RawBytes {  },
    gas_used: 12339043,
    events_root: None,
}
2023-01-22T13:45:08.911411Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 203,
                    method: 3844450837,
                    code: ExitCode {
                        value: 24,
                    },
                    message: "panicked at 'called `Option::unwrap()` on a `None` value', actors/evm/src/interpreter/system.rs:210:22",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-22T13:45:08.911471Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => EIP150 4
2023-01-22T13:45:08.911495Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_HighNonceDelegatecall"::EIP150::4
2023-01-22T13:45:08.911501Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stCreate2/CREATE2_HighNonceDelegatecall.json"
2023-01-22T13:45:08.911509Z  INFO evm_eth_compliance::statetest::runner: TX len : 132
2023-01-22T13:45:08.911515Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [208, 97, 176, 138, 132, 235, 199, 15, 231, 151, 249, 189, 98, 244, 38, 158, 248, 39, 74, 19, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([173, 101, 220, 118, 126, 227, 221, 111, 130, 239, 232, 201, 210, 70, 69, 50, 207, 38, 17, 72]) }
[DEBUG] getting cid: bafy2bzacedef2iioq5zx33deu6ufh237wvqdt7vycaffbp5y5grxgwyyptoog
[DEBUG] fetching parameters block: 1
2023-01-22T13:45:08.914921Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 24,
    },
    return_data: RawBytes {  },
    gas_used: 12343045,
    events_root: None,
}
2023-01-22T13:45:08.914937Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 203,
                    method: 3844450837,
                    code: ExitCode {
                        value: 24,
                    },
                    message: "panicked at 'called `Option::unwrap()` on a `None` value', actors/evm/src/interpreter/system.rs:210:22",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-22T13:45:08.915005Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => EIP150 5
2023-01-22T13:45:08.915039Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_HighNonceDelegatecall"::EIP150::5
2023-01-22T13:45:08.915050Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stCreate2/CREATE2_HighNonceDelegatecall.json"
2023-01-22T13:45:08.915061Z  INFO evm_eth_compliance::statetest::runner: TX len : 132
2023-01-22T13:45:08.915070Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [208, 97, 176, 138, 132, 235, 199, 15, 231, 151, 249, 189, 98, 244, 38, 158, 248, 39, 74, 19, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([21, 34, 247, 70, 142, 122, 19, 174, 255, 98, 183, 37, 253, 210, 62, 191, 224, 79, 199, 228]) }
[DEBUG] getting cid: bafy2bzacedef2iioq5zx33deu6ufh237wvqdt7vycaffbp5y5grxgwyyptoog
[DEBUG] fetching parameters block: 1
2023-01-22T13:45:08.918857Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 24,
    },
    return_data: RawBytes {  },
    gas_used: 12647722,
    events_root: None,
}
2023-01-22T13:45:08.918877Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 203,
                    method: 3844450837,
                    code: ExitCode {
                        value: 24,
                    },
                    message: "panicked at 'called `Option::unwrap()` on a `None` value', actors/evm/src/interpreter/system.rs:210:22",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-22T13:45:08.918937Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => EIP158 6
2023-01-22T13:45:08.918971Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_HighNonceDelegatecall"::EIP158::6
2023-01-22T13:45:08.918978Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stCreate2/CREATE2_HighNonceDelegatecall.json"
2023-01-22T13:45:08.918985Z  INFO evm_eth_compliance::statetest::runner: TX len : 132
2023-01-22T13:45:08.918991Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [208, 97, 176, 138, 132, 235, 199, 15, 231, 151, 249, 189, 98, 244, 38, 158, 248, 39, 74, 19, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([121, 200, 128, 32, 100, 47, 163, 168, 222, 154, 90, 196, 49, 165, 55, 116, 4, 152, 177, 42]) }
[DEBUG] getting cid: bafy2bzacedef2iioq5zx33deu6ufh237wvqdt7vycaffbp5y5grxgwyyptoog
[DEBUG] fetching parameters block: 1
2023-01-22T13:45:08.922544Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 24,
    },
    return_data: RawBytes {  },
    gas_used: 12644788,
    events_root: None,
}
2023-01-22T13:45:08.922560Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 203,
                    method: 3844450837,
                    code: ExitCode {
                        value: 24,
                    },
                    message: "panicked at 'called `Option::unwrap()` on a `None` value', actors/evm/src/interpreter/system.rs:210:22",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-22T13:45:08.922613Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => EIP158 7
2023-01-22T13:45:08.922636Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_HighNonceDelegatecall"::EIP158::7
2023-01-22T13:45:08.922643Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stCreate2/CREATE2_HighNonceDelegatecall.json"
2023-01-22T13:45:08.922651Z  INFO evm_eth_compliance::statetest::runner: TX len : 132
2023-01-22T13:45:08.922656Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [208, 97, 176, 138, 132, 235, 199, 15, 231, 151, 249, 189, 98, 244, 38, 158, 248, 39, 74, 19, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([39, 202, 0, 61, 220, 84, 98, 79, 206, 62, 176, 253, 44, 186, 245, 199, 23, 163, 253, 50]) }
[DEBUG] getting cid: bafy2bzacedef2iioq5zx33deu6ufh237wvqdt7vycaffbp5y5grxgwyyptoog
[DEBUG] fetching parameters block: 1
2023-01-22T13:45:08.926008Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 24,
    },
    return_data: RawBytes {  },
    gas_used: 11808137,
    events_root: None,
}
2023-01-22T13:45:08.926024Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 203,
                    method: 3844450837,
                    code: ExitCode {
                        value: 24,
                    },
                    message: "panicked at 'called `Option::unwrap()` on a `None` value', actors/evm/src/interpreter/system.rs:210:22",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-22T13:45:08.926076Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => EIP158 8
2023-01-22T13:45:08.926099Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_HighNonceDelegatecall"::EIP158::8
2023-01-22T13:45:08.926106Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stCreate2/CREATE2_HighNonceDelegatecall.json"
2023-01-22T13:45:08.926114Z  INFO evm_eth_compliance::statetest::runner: TX len : 132
2023-01-22T13:45:08.926120Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [208, 97, 176, 138, 132, 235, 199, 15, 231, 151, 249, 189, 98, 244, 38, 158, 248, 39, 74, 19, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([192, 88, 99, 161, 23, 254, 175, 39, 213, 169, 153, 253, 197, 254, 95, 117, 145, 246, 7, 95]) }
[DEBUG] getting cid: bafy2bzacedef2iioq5zx33deu6ufh237wvqdt7vycaffbp5y5grxgwyyptoog
[DEBUG] fetching parameters block: 1
2023-01-22T13:45:08.929536Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 24,
    },
    return_data: RawBytes {  },
    gas_used: 11810365,
    events_root: None,
}
2023-01-22T13:45:08.929552Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 203,
                    method: 3844450837,
                    code: ExitCode {
                        value: 24,
                    },
                    message: "panicked at 'called `Option::unwrap()` on a `None` value', actors/evm/src/interpreter/system.rs:210:22",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-22T13:45:08.929604Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => EIP158 9
2023-01-22T13:45:08.929627Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_HighNonceDelegatecall"::EIP158::9
2023-01-22T13:45:08.929634Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stCreate2/CREATE2_HighNonceDelegatecall.json"
2023-01-22T13:45:08.929641Z  INFO evm_eth_compliance::statetest::runner: TX len : 132
2023-01-22T13:45:08.929647Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [208, 97, 176, 138, 132, 235, 199, 15, 231, 151, 249, 189, 98, 244, 38, 158, 248, 39, 74, 19, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([96, 33, 187, 115, 222, 53, 224, 244, 47, 32, 70, 11, 226, 18, 129, 166, 126, 239, 230, 44]) }
[DEBUG] getting cid: bafy2bzacedef2iioq5zx33deu6ufh237wvqdt7vycaffbp5y5grxgwyyptoog
[DEBUG] fetching parameters block: 1
2023-01-22T13:45:08.933123Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 24,
    },
    return_data: RawBytes {  },
    gas_used: 12334266,
    events_root: None,
}
2023-01-22T13:45:08.933138Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 203,
                    method: 3844450837,
                    code: ExitCode {
                        value: 24,
                    },
                    message: "panicked at 'called `Option::unwrap()` on a `None` value', actors/evm/src/interpreter/system.rs:210:22",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-22T13:45:08.933191Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => EIP158 10
2023-01-22T13:45:08.933214Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_HighNonceDelegatecall"::EIP158::10
2023-01-22T13:45:08.933221Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stCreate2/CREATE2_HighNonceDelegatecall.json"
2023-01-22T13:45:08.933229Z  INFO evm_eth_compliance::statetest::runner: TX len : 132
2023-01-22T13:45:08.933235Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [208, 97, 176, 138, 132, 235, 199, 15, 231, 151, 249, 189, 98, 244, 38, 158, 248, 39, 74, 19, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([221, 202, 25, 212, 34, 2, 50, 123, 41, 75, 186, 155, 123, 166, 127, 9, 228, 237, 116, 209]) }
[DEBUG] getting cid: bafy2bzacedef2iioq5zx33deu6ufh237wvqdt7vycaffbp5y5grxgwyyptoog
[DEBUG] fetching parameters block: 1
2023-01-22T13:45:08.937000Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 24,
    },
    return_data: RawBytes {  },
    gas_used: 12706170,
    events_root: None,
}
2023-01-22T13:45:08.937023Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 203,
                    method: 3844450837,
                    code: ExitCode {
                        value: 24,
                    },
                    message: "panicked at 'called `Option::unwrap()` on a `None` value', actors/evm/src/interpreter/system.rs:210:22",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-22T13:45:08.937087Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => EIP158 11
2023-01-22T13:45:08.937129Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_HighNonceDelegatecall"::EIP158::11
2023-01-22T13:45:08.937137Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stCreate2/CREATE2_HighNonceDelegatecall.json"
2023-01-22T13:45:08.937144Z  INFO evm_eth_compliance::statetest::runner: TX len : 132
2023-01-22T13:45:08.937150Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [208, 97, 176, 138, 132, 235, 199, 15, 231, 151, 249, 189, 98, 244, 38, 158, 248, 39, 74, 19, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([96, 157, 121, 180, 71, 136, 28, 182, 195, 187, 216, 146, 44, 166, 42, 126, 234, 16, 198, 148]) }
[DEBUG] getting cid: bafy2bzacedef2iioq5zx33deu6ufh237wvqdt7vycaffbp5y5grxgwyyptoog
[DEBUG] fetching parameters block: 1
2023-01-22T13:45:08.940867Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 24,
    },
    return_data: RawBytes {  },
    gas_used: 12744513,
    events_root: None,
}
2023-01-22T13:45:08.940884Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 203,
                    method: 3844450837,
                    code: ExitCode {
                        value: 24,
                    },
                    message: "panicked at 'called `Option::unwrap()` on a `None` value', actors/evm/src/interpreter/system.rs:210:22",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-22T13:45:08.940950Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => EIP158 0
2023-01-22T13:45:08.940991Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_HighNonceDelegatecall"::EIP158::0
2023-01-22T13:45:08.941002Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stCreate2/CREATE2_HighNonceDelegatecall.json"
2023-01-22T13:45:08.941013Z  INFO evm_eth_compliance::statetest::runner: TX len : 132
2023-01-22T13:45:08.941023Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [208, 97, 176, 138, 132, 235, 199, 15, 231, 151, 249, 189, 98, 244, 38, 158, 248, 39, 74, 19, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([125, 213, 185, 126, 102, 183, 165, 62, 81, 45, 4, 229, 242, 150, 184, 46, 206, 140, 135, 167]) }
[DEBUG] getting cid: bafy2bzacedef2iioq5zx33deu6ufh237wvqdt7vycaffbp5y5grxgwyyptoog
[DEBUG] fetching parameters block: 1
2023-01-22T13:45:08.944839Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 24,
    },
    return_data: RawBytes {  },
    gas_used: 11807041,
    events_root: None,
}
2023-01-22T13:45:08.944861Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 203,
                    method: 3844450837,
                    code: ExitCode {
                        value: 24,
                    },
                    message: "panicked at 'called `Option::unwrap()` on a `None` value', actors/evm/src/interpreter/system.rs:210:22",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-22T13:45:08.944932Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => EIP158 1
2023-01-22T13:45:08.944970Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_HighNonceDelegatecall"::EIP158::1
2023-01-22T13:45:08.944982Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stCreate2/CREATE2_HighNonceDelegatecall.json"
2023-01-22T13:45:08.944992Z  INFO evm_eth_compliance::statetest::runner: TX len : 132
2023-01-22T13:45:08.945001Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [208, 97, 176, 138, 132, 235, 199, 15, 231, 151, 249, 189, 98, 244, 38, 158, 248, 39, 74, 19, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([57, 47, 201, 253, 31, 210, 216, 45, 82, 53, 15, 10, 140, 189, 182, 38, 139, 193, 227, 148]) }
[DEBUG] getting cid: bafy2bzacedef2iioq5zx33deu6ufh237wvqdt7vycaffbp5y5grxgwyyptoog
[DEBUG] fetching parameters block: 1
2023-01-22T13:45:08.949661Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 24,
    },
    return_data: RawBytes {  },
    gas_used: 12647566,
    events_root: None,
}
2023-01-22T13:45:08.949684Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 203,
                    method: 3844450837,
                    code: ExitCode {
                        value: 24,
                    },
                    message: "panicked at 'called `Option::unwrap()` on a `None` value', actors/evm/src/interpreter/system.rs:210:22",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-22T13:45:08.949766Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => EIP158 2
2023-01-22T13:45:08.949808Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_HighNonceDelegatecall"::EIP158::2
2023-01-22T13:45:08.949821Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stCreate2/CREATE2_HighNonceDelegatecall.json"
2023-01-22T13:45:08.949831Z  INFO evm_eth_compliance::statetest::runner: TX len : 132
2023-01-22T13:45:08.949840Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [208, 97, 176, 138, 132, 235, 199, 15, 231, 151, 249, 189, 98, 244, 38, 158, 248, 39, 74, 19, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([10, 128, 19, 154, 164, 202, 88, 213, 185, 231, 230, 233, 169, 125, 32, 175, 46, 247, 104, 205]) }
[DEBUG] getting cid: bafy2bzacedef2iioq5zx33deu6ufh237wvqdt7vycaffbp5y5grxgwyyptoog
[DEBUG] fetching parameters block: 1
2023-01-22T13:45:08.954304Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 24,
    },
    return_data: RawBytes {  },
    gas_used: 11807117,
    events_root: None,
}
2023-01-22T13:45:08.954321Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 203,
                    method: 3844450837,
                    code: ExitCode {
                        value: 24,
                    },
                    message: "panicked at 'called `Option::unwrap()` on a `None` value', actors/evm/src/interpreter/system.rs:210:22",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-22T13:45:08.954370Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => EIP158 3
2023-01-22T13:45:08.954399Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_HighNonceDelegatecall"::EIP158::3
2023-01-22T13:45:08.954406Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stCreate2/CREATE2_HighNonceDelegatecall.json"
2023-01-22T13:45:08.954413Z  INFO evm_eth_compliance::statetest::runner: TX len : 132
2023-01-22T13:45:08.954420Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [208, 97, 176, 138, 132, 235, 199, 15, 231, 151, 249, 189, 98, 244, 38, 158, 248, 39, 74, 19, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([234, 139, 137, 133, 156, 6, 41, 217, 87, 171, 216, 141, 23, 64, 208, 12, 0, 6, 118, 73]) }
[DEBUG] getting cid: bafy2bzacedef2iioq5zx33deu6ufh237wvqdt7vycaffbp5y5grxgwyyptoog
[DEBUG] fetching parameters block: 1
2023-01-22T13:45:08.958054Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 24,
    },
    return_data: RawBytes {  },
    gas_used: 11848206,
    events_root: None,
}
2023-01-22T13:45:08.958074Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 203,
                    method: 3844450837,
                    code: ExitCode {
                        value: 24,
                    },
                    message: "panicked at 'called `Option::unwrap()` on a `None` value', actors/evm/src/interpreter/system.rs:210:22",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-22T13:45:08.958126Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => EIP158 4
2023-01-22T13:45:08.958158Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_HighNonceDelegatecall"::EIP158::4
2023-01-22T13:45:08.958165Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stCreate2/CREATE2_HighNonceDelegatecall.json"
2023-01-22T13:45:08.958172Z  INFO evm_eth_compliance::statetest::runner: TX len : 132
2023-01-22T13:45:08.958178Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [208, 97, 176, 138, 132, 235, 199, 15, 231, 151, 249, 189, 98, 244, 38, 158, 248, 39, 74, 19, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([74, 138, 107, 177, 65, 173, 106, 127, 111, 235, 64, 25, 56, 77, 152, 139, 121, 241, 216, 113]) }
[DEBUG] getting cid: bafy2bzacedef2iioq5zx33deu6ufh237wvqdt7vycaffbp5y5grxgwyyptoog
[DEBUG] fetching parameters block: 1
2023-01-22T13:45:08.961894Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 24,
    },
    return_data: RawBytes {  },
    gas_used: 12744931,
    events_root: None,
}
2023-01-22T13:45:08.961915Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 203,
                    method: 3844450837,
                    code: ExitCode {
                        value: 24,
                    },
                    message: "panicked at 'called `Option::unwrap()` on a `None` value', actors/evm/src/interpreter/system.rs:210:22",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-22T13:45:08.961976Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => EIP158 5
2023-01-22T13:45:08.962012Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_HighNonceDelegatecall"::EIP158::5
2023-01-22T13:45:08.962019Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stCreate2/CREATE2_HighNonceDelegatecall.json"
2023-01-22T13:45:08.962027Z  INFO evm_eth_compliance::statetest::runner: TX len : 132
2023-01-22T13:45:08.962033Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [208, 97, 176, 138, 132, 235, 199, 15, 231, 151, 249, 189, 98, 244, 38, 158, 248, 39, 74, 19, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([126, 248, 213, 18, 73, 109, 79, 84, 218, 211, 209, 213, 172, 193, 146, 154, 144, 35, 152, 99]) }
[DEBUG] getting cid: bafy2bzacedef2iioq5zx33deu6ufh237wvqdt7vycaffbp5y5grxgwyyptoog
[DEBUG] fetching parameters block: 1
2023-01-22T13:45:08.965691Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 24,
    },
    return_data: RawBytes {  },
    gas_used: 12721062,
    events_root: None,
}
2023-01-22T13:45:08.965708Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 203,
                    method: 3844450837,
                    code: ExitCode {
                        value: 24,
                    },
                    message: "panicked at 'called `Option::unwrap()` on a `None` value', actors/evm/src/interpreter/system.rs:210:22",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-22T13:45:08.965767Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Byzantium 6
2023-01-22T13:45:08.965796Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_HighNonceDelegatecall"::Byzantium::6
2023-01-22T13:45:08.965803Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stCreate2/CREATE2_HighNonceDelegatecall.json"
2023-01-22T13:45:08.965811Z  INFO evm_eth_compliance::statetest::runner: TX len : 132
2023-01-22T13:45:08.965817Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [208, 97, 176, 138, 132, 235, 199, 15, 231, 151, 249, 189, 98, 244, 38, 158, 248, 39, 74, 19, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([167, 245, 235, 76, 86, 206, 109, 57, 189, 19, 0, 230, 242, 87, 18, 38, 208, 32, 55, 56]) }
[DEBUG] getting cid: bafy2bzacedef2iioq5zx33deu6ufh237wvqdt7vycaffbp5y5grxgwyyptoog
[DEBUG] fetching parameters block: 1
2023-01-22T13:45:08.970228Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 24,
    },
    return_data: RawBytes {  },
    gas_used: 11808601,
    events_root: None,
}
2023-01-22T13:45:08.970269Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 203,
                    method: 3844450837,
                    code: ExitCode {
                        value: 24,
                    },
                    message: "panicked at 'called `Option::unwrap()` on a `None` value', actors/evm/src/interpreter/system.rs:210:22",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-22T13:45:08.970359Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Byzantium 7
2023-01-22T13:45:08.970423Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_HighNonceDelegatecall"::Byzantium::7
2023-01-22T13:45:08.970444Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stCreate2/CREATE2_HighNonceDelegatecall.json"
2023-01-22T13:45:08.970461Z  INFO evm_eth_compliance::statetest::runner: TX len : 132
2023-01-22T13:45:08.970477Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [208, 97, 176, 138, 132, 235, 199, 15, 231, 151, 249, 189, 98, 244, 38, 158, 248, 39, 74, 19, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([138, 192, 102, 104, 212, 54, 151, 48, 197, 195, 196, 55, 46, 91, 125, 35, 54, 100, 85, 118]) }
[DEBUG] getting cid: bafy2bzacedef2iioq5zx33deu6ufh237wvqdt7vycaffbp5y5grxgwyyptoog
[DEBUG] fetching parameters block: 1
2023-01-22T13:45:08.974994Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 24,
    },
    return_data: RawBytes {  },
    gas_used: 11810285,
    events_root: None,
}
2023-01-22T13:45:08.975027Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 203,
                    method: 3844450837,
                    code: ExitCode {
                        value: 24,
                    },
                    message: "panicked at 'called `Option::unwrap()` on a `None` value', actors/evm/src/interpreter/system.rs:210:22",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-22T13:45:08.975110Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Byzantium 8
2023-01-22T13:45:08.975155Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_HighNonceDelegatecall"::Byzantium::8
2023-01-22T13:45:08.975172Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stCreate2/CREATE2_HighNonceDelegatecall.json"
2023-01-22T13:45:08.975188Z  INFO evm_eth_compliance::statetest::runner: TX len : 132
2023-01-22T13:45:08.975203Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [208, 97, 176, 138, 132, 235, 199, 15, 231, 151, 249, 189, 98, 244, 38, 158, 248, 39, 74, 19, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([144, 116, 102, 151, 109, 193, 228, 195, 140, 185, 216, 122, 95, 12, 114, 35, 109, 70, 64, 123]) }
[DEBUG] getting cid: bafy2bzacedef2iioq5zx33deu6ufh237wvqdt7vycaffbp5y5grxgwyyptoog
[DEBUG] fetching parameters block: 1
2023-01-22T13:45:08.979450Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 24,
    },
    return_data: RawBytes {  },
    gas_used: 12704917,
    events_root: None,
}
2023-01-22T13:45:08.979473Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 203,
                    method: 3844450837,
                    code: ExitCode {
                        value: 24,
                    },
                    message: "panicked at 'called `Option::unwrap()` on a `None` value', actors/evm/src/interpreter/system.rs:210:22",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-22T13:45:08.979528Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Byzantium 9
2023-01-22T13:45:08.979554Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_HighNonceDelegatecall"::Byzantium::9
2023-01-22T13:45:08.979561Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stCreate2/CREATE2_HighNonceDelegatecall.json"
2023-01-22T13:45:08.979568Z  INFO evm_eth_compliance::statetest::runner: TX len : 132
2023-01-22T13:45:08.979575Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [208, 97, 176, 138, 132, 235, 199, 15, 231, 151, 249, 189, 98, 244, 38, 158, 248, 39, 74, 19, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([75, 225, 44, 86, 78, 215, 16, 71, 27, 117, 144, 173, 253, 80, 20, 246, 7, 228, 15, 51]) }
[DEBUG] getting cid: bafy2bzacedef2iioq5zx33deu6ufh237wvqdt7vycaffbp5y5grxgwyyptoog
[DEBUG] fetching parameters block: 1
2023-01-22T13:45:08.983139Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 24,
    },
    return_data: RawBytes {  },
    gas_used: 11807825,
    events_root: None,
}
2023-01-22T13:45:08.983158Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 203,
                    method: 3844450837,
                    code: ExitCode {
                        value: 24,
                    },
                    message: "panicked at 'called `Option::unwrap()` on a `None` value', actors/evm/src/interpreter/system.rs:210:22",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-22T13:45:08.983209Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Byzantium 10
2023-01-22T13:45:08.983241Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_HighNonceDelegatecall"::Byzantium::10
2023-01-22T13:45:08.983248Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stCreate2/CREATE2_HighNonceDelegatecall.json"
2023-01-22T13:45:08.983256Z  INFO evm_eth_compliance::statetest::runner: TX len : 132
2023-01-22T13:45:08.983262Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [208, 97, 176, 138, 132, 235, 199, 15, 231, 151, 249, 189, 98, 244, 38, 158, 248, 39, 74, 19, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([32, 103, 245, 189, 168, 73, 149, 238, 158, 100, 244, 162, 2, 157, 240, 169, 24, 108, 156, 146]) }
[DEBUG] getting cid: bafy2bzacedef2iioq5zx33deu6ufh237wvqdt7vycaffbp5y5grxgwyyptoog
[DEBUG] fetching parameters block: 1
2023-01-22T13:45:08.986864Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 24,
    },
    return_data: RawBytes {  },
    gas_used: 12613887,
    events_root: None,
}
2023-01-22T13:45:08.986880Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 203,
                    method: 3844450837,
                    code: ExitCode {
                        value: 24,
                    },
                    message: "panicked at 'called `Option::unwrap()` on a `None` value', actors/evm/src/interpreter/system.rs:210:22",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-22T13:45:08.986933Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Byzantium 11
2023-01-22T13:45:08.986957Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_HighNonceDelegatecall"::Byzantium::11
2023-01-22T13:45:08.986964Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stCreate2/CREATE2_HighNonceDelegatecall.json"
2023-01-22T13:45:08.986971Z  INFO evm_eth_compliance::statetest::runner: TX len : 132
2023-01-22T13:45:08.986977Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [208, 97, 176, 138, 132, 235, 199, 15, 231, 151, 249, 189, 98, 244, 38, 158, 248, 39, 74, 19, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([85, 143, 18, 101, 101, 201, 146, 95, 146, 124, 254, 78, 228, 215, 122, 164, 58, 49, 178, 79]) }
[DEBUG] getting cid: bafy2bzacedef2iioq5zx33deu6ufh237wvqdt7vycaffbp5y5grxgwyyptoog
[DEBUG] fetching parameters block: 1
2023-01-22T13:45:08.990463Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 24,
    },
    return_data: RawBytes {  },
    gas_used: 12338645,
    events_root: None,
}
2023-01-22T13:45:08.990478Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 203,
                    method: 3844450837,
                    code: ExitCode {
                        value: 24,
                    },
                    message: "panicked at 'called `Option::unwrap()` on a `None` value', actors/evm/src/interpreter/system.rs:210:22",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-22T13:45:08.990531Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Byzantium 0
2023-01-22T13:45:08.990554Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_HighNonceDelegatecall"::Byzantium::0
2023-01-22T13:45:08.990561Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stCreate2/CREATE2_HighNonceDelegatecall.json"
2023-01-22T13:45:08.990569Z  INFO evm_eth_compliance::statetest::runner: TX len : 132
2023-01-22T13:45:08.990575Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [208, 97, 176, 138, 132, 235, 199, 15, 231, 151, 249, 189, 98, 244, 38, 158, 248, 39, 74, 19, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([67, 1, 137, 98, 70, 212, 67, 19, 201, 255, 154, 67, 250, 120, 4, 209, 79, 104, 144, 63]) }
[DEBUG] getting cid: bafy2bzacedef2iioq5zx33deu6ufh237wvqdt7vycaffbp5y5grxgwyyptoog
[DEBUG] fetching parameters block: 1
2023-01-22T13:45:08.994057Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 24,
    },
    return_data: RawBytes {  },
    gas_used: 12325399,
    events_root: None,
}
2023-01-22T13:45:08.994073Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 203,
                    method: 3844450837,
                    code: ExitCode {
                        value: 24,
                    },
                    message: "panicked at 'called `Option::unwrap()` on a `None` value', actors/evm/src/interpreter/system.rs:210:22",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-22T13:45:08.994126Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Byzantium 1
2023-01-22T13:45:08.994149Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_HighNonceDelegatecall"::Byzantium::1
2023-01-22T13:45:08.994156Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stCreate2/CREATE2_HighNonceDelegatecall.json"
2023-01-22T13:45:08.994163Z  INFO evm_eth_compliance::statetest::runner: TX len : 132
2023-01-22T13:45:08.994169Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [208, 97, 176, 138, 132, 235, 199, 15, 231, 151, 249, 189, 98, 244, 38, 158, 248, 39, 74, 19, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([224, 185, 252, 233, 220, 182, 210, 59, 215, 224, 114, 129, 224, 209, 243, 213, 50, 205, 235, 229]) }
[DEBUG] getting cid: bafy2bzacedef2iioq5zx33deu6ufh237wvqdt7vycaffbp5y5grxgwyyptoog
[DEBUG] fetching parameters block: 1
2023-01-22T13:45:08.997544Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 24,
    },
    return_data: RawBytes {  },
    gas_used: 11811029,
    events_root: None,
}
2023-01-22T13:45:08.997559Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 203,
                    method: 3844450837,
                    code: ExitCode {
                        value: 24,
                    },
                    message: "panicked at 'called `Option::unwrap()` on a `None` value', actors/evm/src/interpreter/system.rs:210:22",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-22T13:45:08.997612Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Byzantium 2
2023-01-22T13:45:08.997639Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_HighNonceDelegatecall"::Byzantium::2
2023-01-22T13:45:08.997648Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stCreate2/CREATE2_HighNonceDelegatecall.json"
2023-01-22T13:45:08.997660Z  INFO evm_eth_compliance::statetest::runner: TX len : 132
2023-01-22T13:45:08.997674Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [208, 97, 176, 138, 132, 235, 199, 15, 231, 151, 249, 189, 98, 244, 38, 158, 248, 39, 74, 19, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([202, 216, 7, 119, 106, 153, 146, 153, 17, 117, 69, 127, 5, 244, 55, 40, 94, 200, 169, 244]) }
[DEBUG] getting cid: bafy2bzacedef2iioq5zx33deu6ufh237wvqdt7vycaffbp5y5grxgwyyptoog
[DEBUG] fetching parameters block: 1
2023-01-22T13:45:09.001237Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 24,
    },
    return_data: RawBytes {  },
    gas_used: 12633618,
    events_root: None,
}
2023-01-22T13:45:09.001253Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 203,
                    method: 3844450837,
                    code: ExitCode {
                        value: 24,
                    },
                    message: "panicked at 'called `Option::unwrap()` on a `None` value', actors/evm/src/interpreter/system.rs:210:22",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-22T13:45:09.001306Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Byzantium 3
2023-01-22T13:45:09.001330Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_HighNonceDelegatecall"::Byzantium::3
2023-01-22T13:45:09.001337Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stCreate2/CREATE2_HighNonceDelegatecall.json"
2023-01-22T13:45:09.001344Z  INFO evm_eth_compliance::statetest::runner: TX len : 132
2023-01-22T13:45:09.001350Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [208, 97, 176, 138, 132, 235, 199, 15, 231, 151, 249, 189, 98, 244, 38, 158, 248, 39, 74, 19, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([66, 164, 235, 226, 198, 211, 185, 232, 137, 80, 14, 181, 142, 113, 122, 170, 52, 30, 146, 127]) }
[DEBUG] getting cid: bafy2bzacedef2iioq5zx33deu6ufh237wvqdt7vycaffbp5y5grxgwyyptoog
[DEBUG] fetching parameters block: 1
2023-01-22T13:45:09.004869Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 24,
    },
    return_data: RawBytes {  },
    gas_used: 12338850,
    events_root: None,
}
2023-01-22T13:45:09.004885Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 203,
                    method: 3844450837,
                    code: ExitCode {
                        value: 24,
                    },
                    message: "panicked at 'called `Option::unwrap()` on a `None` value', actors/evm/src/interpreter/system.rs:210:22",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-22T13:45:09.004937Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Byzantium 4
2023-01-22T13:45:09.004960Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_HighNonceDelegatecall"::Byzantium::4
2023-01-22T13:45:09.004967Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stCreate2/CREATE2_HighNonceDelegatecall.json"
2023-01-22T13:45:09.004975Z  INFO evm_eth_compliance::statetest::runner: TX len : 132
2023-01-22T13:45:09.004981Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [208, 97, 176, 138, 132, 235, 199, 15, 231, 151, 249, 189, 98, 244, 38, 158, 248, 39, 74, 19, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([59, 53, 249, 29, 97, 100, 74, 37, 144, 142, 18, 90, 172, 2, 157, 156, 29, 149, 16, 132]) }
[DEBUG] getting cid: bafy2bzacedef2iioq5zx33deu6ufh237wvqdt7vycaffbp5y5grxgwyyptoog
[DEBUG] fetching parameters block: 1
2023-01-22T13:45:09.008489Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 24,
    },
    return_data: RawBytes {  },
    gas_used: 12645953,
    events_root: None,
}
2023-01-22T13:45:09.008504Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 203,
                    method: 3844450837,
                    code: ExitCode {
                        value: 24,
                    },
                    message: "panicked at 'called `Option::unwrap()` on a `None` value', actors/evm/src/interpreter/system.rs:210:22",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-22T13:45:09.008558Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Byzantium 5
2023-01-22T13:45:09.008581Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_HighNonceDelegatecall"::Byzantium::5
2023-01-22T13:45:09.008588Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stCreate2/CREATE2_HighNonceDelegatecall.json"
2023-01-22T13:45:09.008595Z  INFO evm_eth_compliance::statetest::runner: TX len : 132
2023-01-22T13:45:09.008601Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [208, 97, 176, 138, 132, 235, 199, 15, 231, 151, 249, 189, 98, 244, 38, 158, 248, 39, 74, 19, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([181, 8, 27, 168, 223, 145, 221, 58, 213, 216, 232, 244, 223, 5, 154, 0, 190, 59, 128, 47]) }
[DEBUG] getting cid: bafy2bzacedef2iioq5zx33deu6ufh237wvqdt7vycaffbp5y5grxgwyyptoog
[DEBUG] fetching parameters block: 1
2023-01-22T13:45:09.012120Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 24,
    },
    return_data: RawBytes {  },
    gas_used: 12646425,
    events_root: None,
}
2023-01-22T13:45:09.012135Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 203,
                    method: 3844450837,
                    code: ExitCode {
                        value: 24,
                    },
                    message: "panicked at 'called `Option::unwrap()` on a `None` value', actors/evm/src/interpreter/system.rs:210:22",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-22T13:45:09.012225Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Constantinople 6
2023-01-22T13:45:09.012261Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_HighNonceDelegatecall"::Constantinople::6
2023-01-22T13:45:09.012272Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stCreate2/CREATE2_HighNonceDelegatecall.json"
2023-01-22T13:45:09.012282Z  INFO evm_eth_compliance::statetest::runner: TX len : 132
2023-01-22T13:45:09.012289Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [208, 97, 176, 138, 132, 235, 199, 15, 231, 151, 249, 189, 98, 244, 38, 158, 248, 39, 74, 19, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([234, 116, 183, 211, 19, 73, 71, 125, 114, 164, 151, 221, 52, 114, 218, 152, 238, 51, 210, 142]) }
[DEBUG] getting cid: bafy2bzacedef2iioq5zx33deu6ufh237wvqdt7vycaffbp5y5grxgwyyptoog
[DEBUG] fetching parameters block: 1
2023-01-22T13:45:09.015793Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 24,
    },
    return_data: RawBytes {  },
    gas_used: 12628684,
    events_root: None,
}
2023-01-22T13:45:09.015809Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 203,
                    method: 3844450837,
                    code: ExitCode {
                        value: 24,
                    },
                    message: "panicked at 'called `Option::unwrap()` on a `None` value', actors/evm/src/interpreter/system.rs:210:22",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-22T13:45:09.015861Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Constantinople 7
2023-01-22T13:45:09.015884Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_HighNonceDelegatecall"::Constantinople::7
2023-01-22T13:45:09.015891Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stCreate2/CREATE2_HighNonceDelegatecall.json"
2023-01-22T13:45:09.015898Z  INFO evm_eth_compliance::statetest::runner: TX len : 132
2023-01-22T13:45:09.015905Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [208, 97, 176, 138, 132, 235, 199, 15, 231, 151, 249, 189, 98, 244, 38, 158, 248, 39, 74, 19, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([3, 57, 19, 218, 51, 98, 88, 97, 53, 102, 56, 142, 234, 63, 251, 161, 22, 162, 140, 2]) }
[DEBUG] getting cid: bafy2bzacedef2iioq5zx33deu6ufh237wvqdt7vycaffbp5y5grxgwyyptoog
[DEBUG] fetching parameters block: 1
2023-01-22T13:45:09.019411Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 24,
    },
    return_data: RawBytes {  },
    gas_used: 12702856,
    events_root: None,
}
2023-01-22T13:45:09.019426Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 203,
                    method: 3844450837,
                    code: ExitCode {
                        value: 24,
                    },
                    message: "panicked at 'called `Option::unwrap()` on a `None` value', actors/evm/src/interpreter/system.rs:210:22",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-22T13:45:09.019487Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Constantinople 8
2023-01-22T13:45:09.019513Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_HighNonceDelegatecall"::Constantinople::8
2023-01-22T13:45:09.019520Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stCreate2/CREATE2_HighNonceDelegatecall.json"
2023-01-22T13:45:09.019527Z  INFO evm_eth_compliance::statetest::runner: TX len : 132
2023-01-22T13:45:09.019533Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [208, 97, 176, 138, 132, 235, 199, 15, 231, 151, 249, 189, 98, 244, 38, 158, 248, 39, 74, 19, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([63, 161, 187, 197, 65, 220, 217, 68, 174, 137, 53, 67, 149, 191, 178, 97, 158, 51, 14, 103]) }
[DEBUG] getting cid: bafy2bzacedef2iioq5zx33deu6ufh237wvqdt7vycaffbp5y5grxgwyyptoog
[DEBUG] fetching parameters block: 1
2023-01-22T13:45:09.023048Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 24,
    },
    return_data: RawBytes {  },
    gas_used: 12646041,
    events_root: None,
}
2023-01-22T13:45:09.023063Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 203,
                    method: 3844450837,
                    code: ExitCode {
                        value: 24,
                    },
                    message: "panicked at 'called `Option::unwrap()` on a `None` value', actors/evm/src/interpreter/system.rs:210:22",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-22T13:45:09.023115Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Constantinople 9
2023-01-22T13:45:09.023138Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_HighNonceDelegatecall"::Constantinople::9
2023-01-22T13:45:09.023145Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stCreate2/CREATE2_HighNonceDelegatecall.json"
2023-01-22T13:45:09.023152Z  INFO evm_eth_compliance::statetest::runner: TX len : 132
2023-01-22T13:45:09.023162Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [208, 97, 176, 138, 132, 235, 199, 15, 231, 151, 249, 189, 98, 244, 38, 158, 248, 39, 74, 19, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([218, 202, 18, 62, 227, 225, 1, 202, 186, 24, 13, 42, 91, 180, 75, 60, 236, 17, 26, 179]) }
[DEBUG] getting cid: bafy2bzacedef2iioq5zx33deu6ufh237wvqdt7vycaffbp5y5grxgwyyptoog
[DEBUG] fetching parameters block: 1
2023-01-22T13:45:09.026718Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 24,
    },
    return_data: RawBytes {  },
    gas_used: 12631833,
    events_root: None,
}
2023-01-22T13:45:09.026734Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 203,
                    method: 3844450837,
                    code: ExitCode {
                        value: 24,
                    },
                    message: "panicked at 'called `Option::unwrap()` on a `None` value', actors/evm/src/interpreter/system.rs:210:22",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-22T13:45:09.026786Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Constantinople 10
2023-01-22T13:45:09.026810Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_HighNonceDelegatecall"::Constantinople::10
2023-01-22T13:45:09.026816Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stCreate2/CREATE2_HighNonceDelegatecall.json"
2023-01-22T13:45:09.026824Z  INFO evm_eth_compliance::statetest::runner: TX len : 132
2023-01-22T13:45:09.026830Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [208, 97, 176, 138, 132, 235, 199, 15, 231, 151, 249, 189, 98, 244, 38, 158, 248, 39, 74, 19, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([42, 8, 0, 137, 245, 202, 239, 57, 123, 81, 148, 98, 201, 144, 167, 86, 38, 89, 1, 145]) }
[DEBUG] getting cid: bafy2bzacedef2iioq5zx33deu6ufh237wvqdt7vycaffbp5y5grxgwyyptoog
[DEBUG] fetching parameters block: 1
2023-01-22T13:45:09.030191Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 24,
    },
    return_data: RawBytes {  },
    gas_used: 11809553,
    events_root: None,
}
2023-01-22T13:45:09.030206Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 203,
                    method: 3844450837,
                    code: ExitCode {
                        value: 24,
                    },
                    message: "panicked at 'called `Option::unwrap()` on a `None` value', actors/evm/src/interpreter/system.rs:210:22",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-22T13:45:09.030259Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Constantinople 11
2023-01-22T13:45:09.030282Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_HighNonceDelegatecall"::Constantinople::11
2023-01-22T13:45:09.030289Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stCreate2/CREATE2_HighNonceDelegatecall.json"
2023-01-22T13:45:09.030296Z  INFO evm_eth_compliance::statetest::runner: TX len : 132
2023-01-22T13:45:09.030302Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [208, 97, 176, 138, 132, 235, 199, 15, 231, 151, 249, 189, 98, 244, 38, 158, 248, 39, 74, 19, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([104, 62, 254, 77, 166, 98, 129, 212, 171, 54, 46, 64, 123, 176, 69, 61, 126, 37, 183, 206]) }
[DEBUG] getting cid: bafy2bzacedef2iioq5zx33deu6ufh237wvqdt7vycaffbp5y5grxgwyyptoog
[DEBUG] fetching parameters block: 1
2023-01-22T13:45:09.033663Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 24,
    },
    return_data: RawBytes {  },
    gas_used: 11808369,
    events_root: None,
}
2023-01-22T13:45:09.033679Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 203,
                    method: 3844450837,
                    code: ExitCode {
                        value: 24,
                    },
                    message: "panicked at 'called `Option::unwrap()` on a `None` value', actors/evm/src/interpreter/system.rs:210:22",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-22T13:45:09.033731Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Constantinople 0
2023-01-22T13:45:09.033755Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_HighNonceDelegatecall"::Constantinople::0
2023-01-22T13:45:09.033762Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stCreate2/CREATE2_HighNonceDelegatecall.json"
2023-01-22T13:45:09.033769Z  INFO evm_eth_compliance::statetest::runner: TX len : 132
2023-01-22T13:45:09.033775Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [208, 97, 176, 138, 132, 235, 199, 15, 231, 151, 249, 189, 98, 244, 38, 158, 248, 39, 74, 19, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([120, 60, 68, 193, 57, 146, 249, 107, 202, 249, 8, 241, 235, 157, 91, 127, 14, 110, 57, 206]) }
[DEBUG] getting cid: bafy2bzacedef2iioq5zx33deu6ufh237wvqdt7vycaffbp5y5grxgwyyptoog
[DEBUG] fetching parameters block: 1
2023-01-22T13:45:09.037151Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 24,
    },
    return_data: RawBytes {  },
    gas_used: 11808605,
    events_root: None,
}
2023-01-22T13:45:09.037166Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 203,
                    method: 3844450837,
                    code: ExitCode {
                        value: 24,
                    },
                    message: "panicked at 'called `Option::unwrap()` on a `None` value', actors/evm/src/interpreter/system.rs:210:22",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-22T13:45:09.037251Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Constantinople 1
2023-01-22T13:45:09.037287Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_HighNonceDelegatecall"::Constantinople::1
2023-01-22T13:45:09.037297Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stCreate2/CREATE2_HighNonceDelegatecall.json"
2023-01-22T13:45:09.037308Z  INFO evm_eth_compliance::statetest::runner: TX len : 132
2023-01-22T13:45:09.037317Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [208, 97, 176, 138, 132, 235, 199, 15, 231, 151, 249, 189, 98, 244, 38, 158, 248, 39, 74, 19, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([147, 215, 35, 79, 72, 183, 254, 242, 194, 29, 172, 136, 14, 237, 250, 252, 242, 51, 127, 97]) }
[DEBUG] getting cid: bafy2bzacedef2iioq5zx33deu6ufh237wvqdt7vycaffbp5y5grxgwyyptoog
[DEBUG] fetching parameters block: 1
2023-01-22T13:45:09.040672Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 24,
    },
    return_data: RawBytes {  },
    gas_used: 11805885,
    events_root: None,
}
2023-01-22T13:45:09.040688Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 203,
                    method: 3844450837,
                    code: ExitCode {
                        value: 24,
                    },
                    message: "panicked at 'called `Option::unwrap()` on a `None` value', actors/evm/src/interpreter/system.rs:210:22",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-22T13:45:09.040739Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Constantinople 2
2023-01-22T13:45:09.040764Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_HighNonceDelegatecall"::Constantinople::2
2023-01-22T13:45:09.040771Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stCreate2/CREATE2_HighNonceDelegatecall.json"
2023-01-22T13:45:09.040778Z  INFO evm_eth_compliance::statetest::runner: TX len : 132
2023-01-22T13:45:09.040784Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [208, 97, 176, 138, 132, 235, 199, 15, 231, 151, 249, 189, 98, 244, 38, 158, 248, 39, 74, 19, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([242, 200, 122, 171, 63, 235, 198, 140, 32, 232, 76, 42, 197, 165, 51, 1, 171, 177, 228, 41]) }
[DEBUG] getting cid: bafy2bzacedef2iioq5zx33deu6ufh237wvqdt7vycaffbp5y5grxgwyyptoog
[DEBUG] fetching parameters block: 1
2023-01-22T13:45:09.044201Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 24,
    },
    return_data: RawBytes {  },
    gas_used: 12340863,
    events_root: None,
}
2023-01-22T13:45:09.044216Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 203,
                    method: 3844450837,
                    code: ExitCode {
                        value: 24,
                    },
                    message: "panicked at 'called `Option::unwrap()` on a `None` value', actors/evm/src/interpreter/system.rs:210:22",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-22T13:45:09.044271Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Constantinople 3
2023-01-22T13:45:09.044294Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_HighNonceDelegatecall"::Constantinople::3
2023-01-22T13:45:09.044301Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stCreate2/CREATE2_HighNonceDelegatecall.json"
2023-01-22T13:45:09.044309Z  INFO evm_eth_compliance::statetest::runner: TX len : 132
2023-01-22T13:45:09.044315Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [208, 97, 176, 138, 132, 235, 199, 15, 231, 151, 249, 189, 98, 244, 38, 158, 248, 39, 74, 19, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([62, 147, 196, 228, 19, 53, 26, 163, 227, 161, 161, 215, 158, 164, 116, 190, 53, 196, 226, 86]) }
[DEBUG] getting cid: bafy2bzacedef2iioq5zx33deu6ufh237wvqdt7vycaffbp5y5grxgwyyptoog
[DEBUG] fetching parameters block: 1
2023-01-22T13:45:09.047696Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 24,
    },
    return_data: RawBytes {  },
    gas_used: 11808837,
    events_root: None,
}
2023-01-22T13:45:09.047713Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 203,
                    method: 3844450837,
                    code: ExitCode {
                        value: 24,
                    },
                    message: "panicked at 'called `Option::unwrap()` on a `None` value', actors/evm/src/interpreter/system.rs:210:22",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-22T13:45:09.047769Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Constantinople 4
2023-01-22T13:45:09.047792Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_HighNonceDelegatecall"::Constantinople::4
2023-01-22T13:45:09.047799Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stCreate2/CREATE2_HighNonceDelegatecall.json"
2023-01-22T13:45:09.047806Z  INFO evm_eth_compliance::statetest::runner: TX len : 132
2023-01-22T13:45:09.047812Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [208, 97, 176, 138, 132, 235, 199, 15, 231, 151, 249, 189, 98, 244, 38, 158, 248, 39, 74, 19, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([245, 247, 167, 109, 171, 19, 147, 219, 109, 152, 254, 206, 145, 95, 196, 82, 59, 231, 146, 108]) }
[DEBUG] getting cid: bafy2bzacedef2iioq5zx33deu6ufh237wvqdt7vycaffbp5y5grxgwyyptoog
[DEBUG] fetching parameters block: 1
2023-01-22T13:45:09.051229Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 24,
    },
    return_data: RawBytes {  },
    gas_used: 11810909,
    events_root: None,
}
2023-01-22T13:45:09.051244Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 203,
                    method: 3844450837,
                    code: ExitCode {
                        value: 24,
                    },
                    message: "panicked at 'called `Option::unwrap()` on a `None` value', actors/evm/src/interpreter/system.rs:210:22",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-22T13:45:09.051297Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Constantinople 5
2023-01-22T13:45:09.051321Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_HighNonceDelegatecall"::Constantinople::5
2023-01-22T13:45:09.051328Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stCreate2/CREATE2_HighNonceDelegatecall.json"
2023-01-22T13:45:09.051335Z  INFO evm_eth_compliance::statetest::runner: TX len : 132
2023-01-22T13:45:09.051341Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [208, 97, 176, 138, 132, 235, 199, 15, 231, 151, 249, 189, 98, 244, 38, 158, 248, 39, 74, 19, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([7, 158, 84, 58, 120, 147, 60, 147, 138, 143, 25, 166, 137, 140, 78, 245, 163, 245, 15, 240]) }
[DEBUG] getting cid: bafy2bzacedef2iioq5zx33deu6ufh237wvqdt7vycaffbp5y5grxgwyyptoog
[DEBUG] fetching parameters block: 1
2023-01-22T13:45:09.054864Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 24,
    },
    return_data: RawBytes {  },
    gas_used: 12647962,
    events_root: None,
}
2023-01-22T13:45:09.054879Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 203,
                    method: 3844450837,
                    code: ExitCode {
                        value: 24,
                    },
                    message: "panicked at 'called `Option::unwrap()` on a `None` value', actors/evm/src/interpreter/system.rs:210:22",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-22T13:45:09.054932Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Constantinople 18
2023-01-22T13:45:09.054955Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_HighNonceDelegatecall"::Constantinople::18
2023-01-22T13:45:09.054962Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stCreate2/CREATE2_HighNonceDelegatecall.json"
2023-01-22T13:45:09.054969Z  INFO evm_eth_compliance::statetest::runner: TX len : 132
2023-01-22T13:45:09.054975Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [208, 97, 176, 138, 132, 235, 199, 15, 231, 151, 249, 189, 98, 244, 38, 158, 248, 39, 74, 19, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([101, 116, 187, 125, 159, 134, 103, 253, 71, 28, 161, 28, 224, 159, 118, 18, 173, 248, 106, 178]) }
[DEBUG] getting cid: bafy2bzacedef2iioq5zx33deu6ufh237wvqdt7vycaffbp5y5grxgwyyptoog
[DEBUG] fetching parameters block: 1
2023-01-22T13:45:09.058360Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 24,
    },
    return_data: RawBytes {  },
    gas_used: 11809769,
    events_root: None,
}
2023-01-22T13:45:09.058376Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 203,
                    method: 3844450837,
                    code: ExitCode {
                        value: 24,
                    },
                    message: "panicked at 'called `Option::unwrap()` on a `None` value', actors/evm/src/interpreter/system.rs:210:22",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-22T13:45:09.058428Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Constantinople 19
2023-01-22T13:45:09.058451Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_HighNonceDelegatecall"::Constantinople::19
2023-01-22T13:45:09.058458Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stCreate2/CREATE2_HighNonceDelegatecall.json"
2023-01-22T13:45:09.058466Z  INFO evm_eth_compliance::statetest::runner: TX len : 132
2023-01-22T13:45:09.058472Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [208, 97, 176, 138, 132, 235, 199, 15, 231, 151, 249, 189, 98, 244, 38, 158, 248, 39, 74, 19, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([155, 95, 242, 9, 90, 122, 82, 95, 203, 251, 122, 183, 134, 20, 92, 45, 133, 143, 190, 79]) }
[DEBUG] getting cid: bafy2bzacedef2iioq5zx33deu6ufh237wvqdt7vycaffbp5y5grxgwyyptoog
[DEBUG] fetching parameters block: 1
2023-01-22T13:45:09.061982Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 24,
    },
    return_data: RawBytes {  },
    gas_used: 12613107,
    events_root: None,
}
2023-01-22T13:45:09.061998Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 203,
                    method: 3844450837,
                    code: ExitCode {
                        value: 24,
                    },
                    message: "panicked at 'called `Option::unwrap()` on a `None` value', actors/evm/src/interpreter/system.rs:210:22",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-22T13:45:09.062072Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Constantinople 20
2023-01-22T13:45:09.062111Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_HighNonceDelegatecall"::Constantinople::20
2023-01-22T13:45:09.062122Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stCreate2/CREATE2_HighNonceDelegatecall.json"
2023-01-22T13:45:09.062133Z  INFO evm_eth_compliance::statetest::runner: TX len : 132
2023-01-22T13:45:09.062142Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [208, 97, 176, 138, 132, 235, 199, 15, 231, 151, 249, 189, 98, 244, 38, 158, 248, 39, 74, 19, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([54, 233, 149, 112, 243, 205, 226, 29, 96, 223, 210, 91, 9, 119, 78, 94, 236, 137, 95, 47]) }
[DEBUG] getting cid: bafy2bzacedef2iioq5zx33deu6ufh237wvqdt7vycaffbp5y5grxgwyyptoog
[DEBUG] fetching parameters block: 1
2023-01-22T13:45:09.065685Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 24,
    },
    return_data: RawBytes {  },
    gas_used: 12645348,
    events_root: None,
}
2023-01-22T13:45:09.065700Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 203,
                    method: 3844450837,
                    code: ExitCode {
                        value: 24,
                    },
                    message: "panicked at 'called `Option::unwrap()` on a `None` value', actors/evm/src/interpreter/system.rs:210:22",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-22T13:45:09.065753Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Constantinople 21
2023-01-22T13:45:09.065777Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_HighNonceDelegatecall"::Constantinople::21
2023-01-22T13:45:09.065784Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stCreate2/CREATE2_HighNonceDelegatecall.json"
2023-01-22T13:45:09.065792Z  INFO evm_eth_compliance::statetest::runner: TX len : 132
2023-01-22T13:45:09.065798Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [208, 97, 176, 138, 132, 235, 199, 15, 231, 151, 249, 189, 98, 244, 38, 158, 248, 39, 74, 19, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([238, 253, 241, 172, 208, 208, 47, 210, 127, 104, 145, 191, 55, 169, 92, 159, 79, 33, 124, 81]) }
[DEBUG] getting cid: bafy2bzacedef2iioq5zx33deu6ufh237wvqdt7vycaffbp5y5grxgwyyptoog
[DEBUG] fetching parameters block: 1
2023-01-22T13:45:09.069293Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 24,
    },
    return_data: RawBytes {  },
    gas_used: 12338781,
    events_root: None,
}
2023-01-22T13:45:09.069308Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 203,
                    method: 3844450837,
                    code: ExitCode {
                        value: 24,
                    },
                    message: "panicked at 'called `Option::unwrap()` on a `None` value', actors/evm/src/interpreter/system.rs:210:22",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-22T13:45:09.069361Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Constantinople 22
2023-01-22T13:45:09.069384Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_HighNonceDelegatecall"::Constantinople::22
2023-01-22T13:45:09.069391Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stCreate2/CREATE2_HighNonceDelegatecall.json"
2023-01-22T13:45:09.069398Z  INFO evm_eth_compliance::statetest::runner: TX len : 132
2023-01-22T13:45:09.069404Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [208, 97, 176, 138, 132, 235, 199, 15, 231, 151, 249, 189, 98, 244, 38, 158, 248, 39, 74, 19, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([172, 213, 217, 59, 199, 164, 245, 110, 126, 219, 117, 176, 255, 50, 179, 203, 237, 224, 86, 53]) }
[DEBUG] getting cid: bafy2bzacedef2iioq5zx33deu6ufh237wvqdt7vycaffbp5y5grxgwyyptoog
[DEBUG] fetching parameters block: 1
2023-01-22T13:45:09.072746Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 24,
    },
    return_data: RawBytes {  },
    gas_used: 11807905,
    events_root: None,
}
2023-01-22T13:45:09.072762Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 203,
                    method: 3844450837,
                    code: ExitCode {
                        value: 24,
                    },
                    message: "panicked at 'called `Option::unwrap()` on a `None` value', actors/evm/src/interpreter/system.rs:210:22",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-22T13:45:09.072813Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Constantinople 23
2023-01-22T13:45:09.072836Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_HighNonceDelegatecall"::Constantinople::23
2023-01-22T13:45:09.072843Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stCreate2/CREATE2_HighNonceDelegatecall.json"
2023-01-22T13:45:09.072850Z  INFO evm_eth_compliance::statetest::runner: TX len : 132
2023-01-22T13:45:09.072856Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [208, 97, 176, 138, 132, 235, 199, 15, 231, 151, 249, 189, 98, 244, 38, 158, 248, 39, 74, 19, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([233, 196, 35, 214, 167, 136, 168, 70, 9, 81, 41, 154, 152, 150, 120, 187, 161, 211, 14, 66]) }
[DEBUG] getting cid: bafy2bzacedef2iioq5zx33deu6ufh237wvqdt7vycaffbp5y5grxgwyyptoog
[DEBUG] fetching parameters block: 1
2023-01-22T13:45:09.076361Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 24,
    },
    return_data: RawBytes {  },
    gas_used: 12703555,
    events_root: None,
}
2023-01-22T13:45:09.076376Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 203,
                    method: 3844450837,
                    code: ExitCode {
                        value: 24,
                    },
                    message: "panicked at 'called `Option::unwrap()` on a `None` value', actors/evm/src/interpreter/system.rs:210:22",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-22T13:45:09.076429Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Constantinople 12
2023-01-22T13:45:09.076452Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_HighNonceDelegatecall"::Constantinople::12
2023-01-22T13:45:09.076459Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stCreate2/CREATE2_HighNonceDelegatecall.json"
2023-01-22T13:45:09.076466Z  INFO evm_eth_compliance::statetest::runner: TX len : 132
2023-01-22T13:45:09.076472Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [208, 97, 176, 138, 132, 235, 199, 15, 231, 151, 249, 189, 98, 244, 38, 158, 248, 39, 74, 19, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([160, 22, 178, 28, 123, 24, 4, 205, 147, 64, 111, 144, 122, 198, 167, 128, 46, 191, 140, 52]) }
[DEBUG] getting cid: bafy2bzacedef2iioq5zx33deu6ufh237wvqdt7vycaffbp5y5grxgwyyptoog
[DEBUG] fetching parameters block: 1
2023-01-22T13:45:09.079860Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 24,
    },
    return_data: RawBytes {  },
    gas_used: 11810173,
    events_root: None,
}
2023-01-22T13:45:09.079875Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 203,
                    method: 3844450837,
                    code: ExitCode {
                        value: 24,
                    },
                    message: "panicked at 'called `Option::unwrap()` on a `None` value', actors/evm/src/interpreter/system.rs:210:22",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-22T13:45:09.079928Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Constantinople 13
2023-01-22T13:45:09.079952Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_HighNonceDelegatecall"::Constantinople::13
2023-01-22T13:45:09.079959Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stCreate2/CREATE2_HighNonceDelegatecall.json"
2023-01-22T13:45:09.079966Z  INFO evm_eth_compliance::statetest::runner: TX len : 132
2023-01-22T13:45:09.079972Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [208, 97, 176, 138, 132, 235, 199, 15, 231, 151, 249, 189, 98, 244, 38, 158, 248, 39, 74, 19, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([6, 101, 24, 32, 72, 254, 76, 158, 23, 230, 180, 249, 6, 77, 81, 181, 195, 46, 12, 239]) }
[DEBUG] getting cid: bafy2bzacedef2iioq5zx33deu6ufh237wvqdt7vycaffbp5y5grxgwyyptoog
[DEBUG] fetching parameters block: 1
2023-01-22T13:45:09.083349Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 24,
    },
    return_data: RawBytes {  },
    gas_used: 11808525,
    events_root: None,
}
2023-01-22T13:45:09.083364Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 203,
                    method: 3844450837,
                    code: ExitCode {
                        value: 24,
                    },
                    message: "panicked at 'called `Option::unwrap()` on a `None` value', actors/evm/src/interpreter/system.rs:210:22",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-22T13:45:09.083417Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Constantinople 14
2023-01-22T13:45:09.083440Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_HighNonceDelegatecall"::Constantinople::14
2023-01-22T13:45:09.083447Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stCreate2/CREATE2_HighNonceDelegatecall.json"
2023-01-22T13:45:09.083454Z  INFO evm_eth_compliance::statetest::runner: TX len : 132
2023-01-22T13:45:09.083465Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [208, 97, 176, 138, 132, 235, 199, 15, 231, 151, 249, 189, 98, 244, 38, 158, 248, 39, 74, 19, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([210, 200, 59, 201, 171, 234, 215, 190, 204, 216, 178, 133, 65, 168, 237, 79, 59, 110, 253, 88]) }
[DEBUG] getting cid: bafy2bzacedef2iioq5zx33deu6ufh237wvqdt7vycaffbp5y5grxgwyyptoog
[DEBUG] fetching parameters block: 1
2023-01-22T13:45:09.086993Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 24,
    },
    return_data: RawBytes {  },
    gas_used: 12629594,
    events_root: None,
}
2023-01-22T13:45:09.087009Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 203,
                    method: 3844450837,
                    code: ExitCode {
                        value: 24,
                    },
                    message: "panicked at 'called `Option::unwrap()` on a `None` value', actors/evm/src/interpreter/system.rs:210:22",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-22T13:45:09.087084Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Constantinople 15
2023-01-22T13:45:09.087122Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_HighNonceDelegatecall"::Constantinople::15
2023-01-22T13:45:09.087133Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stCreate2/CREATE2_HighNonceDelegatecall.json"
2023-01-22T13:45:09.087144Z  INFO evm_eth_compliance::statetest::runner: TX len : 132
2023-01-22T13:45:09.087153Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [208, 97, 176, 138, 132, 235, 199, 15, 231, 151, 249, 189, 98, 244, 38, 158, 248, 39, 74, 19, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([152, 179, 153, 86, 207, 123, 119, 235, 95, 203, 67, 81, 180, 228, 252, 230, 238, 226, 128, 101]) }
[DEBUG] getting cid: bafy2bzacedef2iioq5zx33deu6ufh237wvqdt7vycaffbp5y5grxgwyyptoog
[DEBUG] fetching parameters block: 1
2023-01-22T13:45:09.090692Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 24,
    },
    return_data: RawBytes {  },
    gas_used: 12656887,
    events_root: None,
}
2023-01-22T13:45:09.090708Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 203,
                    method: 3844450837,
                    code: ExitCode {
                        value: 24,
                    },
                    message: "panicked at 'called `Option::unwrap()` on a `None` value', actors/evm/src/interpreter/system.rs:210:22",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-22T13:45:09.090761Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Constantinople 16
2023-01-22T13:45:09.090784Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_HighNonceDelegatecall"::Constantinople::16
2023-01-22T13:45:09.090791Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stCreate2/CREATE2_HighNonceDelegatecall.json"
2023-01-22T13:45:09.090798Z  INFO evm_eth_compliance::statetest::runner: TX len : 132
2023-01-22T13:45:09.090804Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [208, 97, 176, 138, 132, 235, 199, 15, 231, 151, 249, 189, 98, 244, 38, 158, 248, 39, 74, 19, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([138, 38, 243, 153, 218, 225, 55, 155, 27, 229, 106, 36, 160, 218, 25, 26, 79, 118, 84, 124]) }
[DEBUG] getting cid: bafy2bzacedef2iioq5zx33deu6ufh237wvqdt7vycaffbp5y5grxgwyyptoog
[DEBUG] fetching parameters block: 1
2023-01-22T13:45:09.094296Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 24,
    },
    return_data: RawBytes {  },
    gas_used: 12326479,
    events_root: None,
}
2023-01-22T13:45:09.094312Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 203,
                    method: 3844450837,
                    code: ExitCode {
                        value: 24,
                    },
                    message: "panicked at 'called `Option::unwrap()` on a `None` value', actors/evm/src/interpreter/system.rs:210:22",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-22T13:45:09.094364Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Constantinople 17
2023-01-22T13:45:09.094387Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_HighNonceDelegatecall"::Constantinople::17
2023-01-22T13:45:09.094394Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stCreate2/CREATE2_HighNonceDelegatecall.json"
2023-01-22T13:45:09.094401Z  INFO evm_eth_compliance::statetest::runner: TX len : 132
2023-01-22T13:45:09.094407Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [208, 97, 176, 138, 132, 235, 199, 15, 231, 151, 249, 189, 98, 244, 38, 158, 248, 39, 74, 19, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([36, 34, 142, 247, 128, 110, 247, 94, 198, 71, 114, 180, 208, 238, 227, 169, 93, 167, 249, 138]) }
[DEBUG] getting cid: bafy2bzacedef2iioq5zx33deu6ufh237wvqdt7vycaffbp5y5grxgwyyptoog
[DEBUG] fetching parameters block: 1
2023-01-22T13:45:09.097809Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 24,
    },
    return_data: RawBytes {  },
    gas_used: 11810753,
    events_root: None,
}
2023-01-22T13:45:09.097824Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 203,
                    method: 3844450837,
                    code: ExitCode {
                        value: 24,
                    },
                    message: "panicked at 'called `Option::unwrap()` on a `None` value', actors/evm/src/interpreter/system.rs:210:22",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-22T13:45:09.097879Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => ConstantinopleFix 6
2023-01-22T13:45:09.097904Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_HighNonceDelegatecall"::ConstantinopleFix::6
2023-01-22T13:45:09.097911Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stCreate2/CREATE2_HighNonceDelegatecall.json"
2023-01-22T13:45:09.097919Z  INFO evm_eth_compliance::statetest::runner: TX len : 132
2023-01-22T13:45:09.097925Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [208, 97, 176, 138, 132, 235, 199, 15, 231, 151, 249, 189, 98, 244, 38, 158, 248, 39, 74, 19, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([223, 135, 238, 67, 51, 204, 134, 29, 70, 229, 97, 185, 114, 169, 34, 58, 250, 236, 1, 80]) }
[DEBUG] getting cid: bafy2bzacedef2iioq5zx33deu6ufh237wvqdt7vycaffbp5y5grxgwyyptoog
[DEBUG] fetching parameters block: 1
2023-01-22T13:45:09.101479Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 24,
    },
    return_data: RawBytes {  },
    gas_used: 12338150,
    events_root: None,
}
2023-01-22T13:45:09.101494Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 203,
                    method: 3844450837,
                    code: ExitCode {
                        value: 24,
                    },
                    message: "panicked at 'called `Option::unwrap()` on a `None` value', actors/evm/src/interpreter/system.rs:210:22",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-22T13:45:09.101546Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => ConstantinopleFix 7
2023-01-22T13:45:09.101570Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_HighNonceDelegatecall"::ConstantinopleFix::7
2023-01-22T13:45:09.101577Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stCreate2/CREATE2_HighNonceDelegatecall.json"
2023-01-22T13:45:09.101584Z  INFO evm_eth_compliance::statetest::runner: TX len : 132
2023-01-22T13:45:09.101590Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [208, 97, 176, 138, 132, 235, 199, 15, 231, 151, 249, 189, 98, 244, 38, 158, 248, 39, 74, 19, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([171, 123, 201, 143, 214, 163, 34, 102, 246, 229, 97, 228, 11, 37, 109, 19, 5, 221, 226, 152]) }
[DEBUG] getting cid: bafy2bzacedef2iioq5zx33deu6ufh237wvqdt7vycaffbp5y5grxgwyyptoog
[DEBUG] fetching parameters block: 1
2023-01-22T13:45:09.105108Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 24,
    },
    return_data: RawBytes {  },
    gas_used: 12706277,
    events_root: None,
}
2023-01-22T13:45:09.105124Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 203,
                    method: 3844450837,
                    code: ExitCode {
                        value: 24,
                    },
                    message: "panicked at 'called `Option::unwrap()` on a `None` value', actors/evm/src/interpreter/system.rs:210:22",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-22T13:45:09.105177Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => ConstantinopleFix 8
2023-01-22T13:45:09.105201Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_HighNonceDelegatecall"::ConstantinopleFix::8
2023-01-22T13:45:09.105208Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stCreate2/CREATE2_HighNonceDelegatecall.json"
2023-01-22T13:45:09.105215Z  INFO evm_eth_compliance::statetest::runner: TX len : 132
2023-01-22T13:45:09.105221Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [208, 97, 176, 138, 132, 235, 199, 15, 231, 151, 249, 189, 98, 244, 38, 158, 248, 39, 74, 19, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([150, 121, 248, 15, 109, 83, 111, 178, 241, 144, 29, 41, 236, 59, 127, 169, 171, 108, 240, 235]) }
[DEBUG] getting cid: bafy2bzacedef2iioq5zx33deu6ufh237wvqdt7vycaffbp5y5grxgwyyptoog
[DEBUG] fetching parameters block: 1
2023-01-22T13:45:09.108603Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 24,
    },
    return_data: RawBytes {  },
    gas_used: 11809613,
    events_root: None,
}
2023-01-22T13:45:09.108618Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 203,
                    method: 3844450837,
                    code: ExitCode {
                        value: 24,
                    },
                    message: "panicked at 'called `Option::unwrap()` on a `None` value', actors/evm/src/interpreter/system.rs:210:22",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-22T13:45:09.108671Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => ConstantinopleFix 9
2023-01-22T13:45:09.108694Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_HighNonceDelegatecall"::ConstantinopleFix::9
2023-01-22T13:45:09.108701Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stCreate2/CREATE2_HighNonceDelegatecall.json"
2023-01-22T13:45:09.108708Z  INFO evm_eth_compliance::statetest::runner: TX len : 132
2023-01-22T13:45:09.108714Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [208, 97, 176, 138, 132, 235, 199, 15, 231, 151, 249, 189, 98, 244, 38, 158, 248, 39, 74, 19, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([216, 255, 189, 112, 116, 100, 130, 35, 19, 172, 20, 178, 52, 203, 193, 91, 93, 144, 244, 170]) }
[DEBUG] getting cid: bafy2bzacedef2iioq5zx33deu6ufh237wvqdt7vycaffbp5y5grxgwyyptoog
[DEBUG] fetching parameters block: 1
2023-01-22T13:45:09.112197Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 24,
    },
    return_data: RawBytes {  },
    gas_used: 11810309,
    events_root: None,
}
2023-01-22T13:45:09.112212Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 203,
                    method: 3844450837,
                    code: ExitCode {
                        value: 24,
                    },
                    message: "panicked at 'called `Option::unwrap()` on a `None` value', actors/evm/src/interpreter/system.rs:210:22",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-22T13:45:09.112281Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => ConstantinopleFix 10
2023-01-22T13:45:09.112320Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_HighNonceDelegatecall"::ConstantinopleFix::10
2023-01-22T13:45:09.112331Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stCreate2/CREATE2_HighNonceDelegatecall.json"
2023-01-22T13:45:09.112341Z  INFO evm_eth_compliance::statetest::runner: TX len : 132
2023-01-22T13:45:09.112350Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [208, 97, 176, 138, 132, 235, 199, 15, 231, 151, 249, 189, 98, 244, 38, 158, 248, 39, 74, 19, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([166, 79, 125, 93, 55, 208, 234, 109, 248, 252, 50, 181, 233, 25, 133, 95, 16, 4, 250, 212]) }
[DEBUG] getting cid: bafy2bzacedef2iioq5zx33deu6ufh237wvqdt7vycaffbp5y5grxgwyyptoog
[DEBUG] fetching parameters block: 1
2023-01-22T13:45:09.115920Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 24,
    },
    return_data: RawBytes {  },
    gas_used: 12771828,
    events_root: None,
}
2023-01-22T13:45:09.115935Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 203,
                    method: 3844450837,
                    code: ExitCode {
                        value: 24,
                    },
                    message: "panicked at 'called `Option::unwrap()` on a `None` value', actors/evm/src/interpreter/system.rs:210:22",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-22T13:45:09.115988Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => ConstantinopleFix 11
2023-01-22T13:45:09.116014Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_HighNonceDelegatecall"::ConstantinopleFix::11
2023-01-22T13:45:09.116021Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stCreate2/CREATE2_HighNonceDelegatecall.json"
2023-01-22T13:45:09.116028Z  INFO evm_eth_compliance::statetest::runner: TX len : 132
2023-01-22T13:45:09.116034Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [208, 97, 176, 138, 132, 235, 199, 15, 231, 151, 249, 189, 98, 244, 38, 158, 248, 39, 74, 19, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([2, 173, 127, 180, 225, 10, 235, 13, 93, 152, 13, 38, 145, 37, 45, 245, 145, 35, 49, 187]) }
[DEBUG] getting cid: bafy2bzacedef2iioq5zx33deu6ufh237wvqdt7vycaffbp5y5grxgwyyptoog
[DEBUG] fetching parameters block: 1
2023-01-22T13:45:09.119544Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 24,
    },
    return_data: RawBytes {  },
    gas_used: 12340437,
    events_root: None,
}
2023-01-22T13:45:09.119560Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 203,
                    method: 3844450837,
                    code: ExitCode {
                        value: 24,
                    },
                    message: "panicked at 'called `Option::unwrap()` on a `None` value', actors/evm/src/interpreter/system.rs:210:22",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-22T13:45:09.119612Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => ConstantinopleFix 0
2023-01-22T13:45:09.119636Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_HighNonceDelegatecall"::ConstantinopleFix::0
2023-01-22T13:45:09.119643Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stCreate2/CREATE2_HighNonceDelegatecall.json"
2023-01-22T13:45:09.119650Z  INFO evm_eth_compliance::statetest::runner: TX len : 132
2023-01-22T13:45:09.119656Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [208, 97, 176, 138, 132, 235, 199, 15, 231, 151, 249, 189, 98, 244, 38, 158, 248, 39, 74, 19, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([26, 94, 21, 132, 72, 150, 253, 219, 60, 75, 126, 210, 38, 54, 187, 181, 69, 150, 199, 238]) }
[DEBUG] getting cid: bafy2bzacedef2iioq5zx33deu6ufh237wvqdt7vycaffbp5y5grxgwyyptoog
[DEBUG] fetching parameters block: 1
2023-01-22T13:45:09.123146Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 24,
    },
    return_data: RawBytes {  },
    gas_used: 12650579,
    events_root: None,
}
2023-01-22T13:45:09.123162Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 203,
                    method: 3844450837,
                    code: ExitCode {
                        value: 24,
                    },
                    message: "panicked at 'called `Option::unwrap()` on a `None` value', actors/evm/src/interpreter/system.rs:210:22",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-22T13:45:09.123214Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => ConstantinopleFix 1
2023-01-22T13:45:09.123237Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_HighNonceDelegatecall"::ConstantinopleFix::1
2023-01-22T13:45:09.123244Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stCreate2/CREATE2_HighNonceDelegatecall.json"
2023-01-22T13:45:09.123251Z  INFO evm_eth_compliance::statetest::runner: TX len : 132
2023-01-22T13:45:09.123257Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [208, 97, 176, 138, 132, 235, 199, 15, 231, 151, 249, 189, 98, 244, 38, 158, 248, 39, 74, 19, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([175, 251, 80, 249, 105, 130, 119, 145, 133, 148, 208, 51, 71, 178, 169, 202, 39, 153, 152, 110]) }
[DEBUG] getting cid: bafy2bzacedef2iioq5zx33deu6ufh237wvqdt7vycaffbp5y5grxgwyyptoog
[DEBUG] fetching parameters block: 1
2023-01-22T13:45:09.126793Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 24,
    },
    return_data: RawBytes {  },
    gas_used: 12648384,
    events_root: None,
}
2023-01-22T13:45:09.126808Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 203,
                    method: 3844450837,
                    code: ExitCode {
                        value: 24,
                    },
                    message: "panicked at 'called `Option::unwrap()` on a `None` value', actors/evm/src/interpreter/system.rs:210:22",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-22T13:45:09.126861Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => ConstantinopleFix 2
2023-01-22T13:45:09.126884Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_HighNonceDelegatecall"::ConstantinopleFix::2
2023-01-22T13:45:09.126891Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stCreate2/CREATE2_HighNonceDelegatecall.json"
2023-01-22T13:45:09.126898Z  INFO evm_eth_compliance::statetest::runner: TX len : 132
2023-01-22T13:45:09.126904Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [208, 97, 176, 138, 132, 235, 199, 15, 231, 151, 249, 189, 98, 244, 38, 158, 248, 39, 74, 19, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([183, 147, 254, 58, 179, 36, 249, 194, 136, 77, 164, 228, 236, 185, 91, 29, 246, 206, 249, 29]) }
[DEBUG] getting cid: bafy2bzacedef2iioq5zx33deu6ufh237wvqdt7vycaffbp5y5grxgwyyptoog
[DEBUG] fetching parameters block: 1
2023-01-22T13:45:09.130296Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 24,
    },
    return_data: RawBytes {  },
    gas_used: 11806961,
    events_root: None,
}
2023-01-22T13:45:09.130312Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 203,
                    method: 3844450837,
                    code: ExitCode {
                        value: 24,
                    },
                    message: "panicked at 'called `Option::unwrap()` on a `None` value', actors/evm/src/interpreter/system.rs:210:22",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-22T13:45:09.130360Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => ConstantinopleFix 3
2023-01-22T13:45:09.130384Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_HighNonceDelegatecall"::ConstantinopleFix::3
2023-01-22T13:45:09.130391Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stCreate2/CREATE2_HighNonceDelegatecall.json"
2023-01-22T13:45:09.130398Z  INFO evm_eth_compliance::statetest::runner: TX len : 132
2023-01-22T13:45:09.130404Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [208, 97, 176, 138, 132, 235, 199, 15, 231, 151, 249, 189, 98, 244, 38, 158, 248, 39, 74, 19, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([120, 168, 127, 221, 78, 78, 205, 221, 40, 101, 104, 53, 169, 89, 117, 62, 45, 246, 126, 10]) }
[DEBUG] getting cid: bafy2bzacedef2iioq5zx33deu6ufh237wvqdt7vycaffbp5y5grxgwyyptoog
[DEBUG] fetching parameters block: 1
2023-01-22T13:45:09.133919Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 24,
    },
    return_data: RawBytes {  },
    gas_used: 12325863,
    events_root: None,
}
2023-01-22T13:45:09.133935Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 203,
                    method: 3844450837,
                    code: ExitCode {
                        value: 24,
                    },
                    message: "panicked at 'called `Option::unwrap()` on a `None` value', actors/evm/src/interpreter/system.rs:210:22",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-22T13:45:09.133988Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => ConstantinopleFix 4
2023-01-22T13:45:09.134012Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_HighNonceDelegatecall"::ConstantinopleFix::4
2023-01-22T13:45:09.134019Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stCreate2/CREATE2_HighNonceDelegatecall.json"
2023-01-22T13:45:09.134026Z  INFO evm_eth_compliance::statetest::runner: TX len : 132
2023-01-22T13:45:09.134032Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [208, 97, 176, 138, 132, 235, 199, 15, 231, 151, 249, 189, 98, 244, 38, 158, 248, 39, 74, 19, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([132, 95, 145, 17, 53, 205, 188, 252, 222, 81, 19, 14, 225, 44, 173, 102, 10, 139, 61, 204]) }
[DEBUG] getting cid: bafy2bzacedef2iioq5zx33deu6ufh237wvqdt7vycaffbp5y5grxgwyyptoog
[DEBUG] fetching parameters block: 1
2023-01-22T13:45:09.137531Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 24,
    },
    return_data: RawBytes {  },
    gas_used: 12325940,
    events_root: None,
}
2023-01-22T13:45:09.137547Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 203,
                    method: 3844450837,
                    code: ExitCode {
                        value: 24,
                    },
                    message: "panicked at 'called `Option::unwrap()` on a `None` value', actors/evm/src/interpreter/system.rs:210:22",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-22T13:45:09.137618Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => ConstantinopleFix 5
2023-01-22T13:45:09.137657Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_HighNonceDelegatecall"::ConstantinopleFix::5
2023-01-22T13:45:09.137668Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stCreate2/CREATE2_HighNonceDelegatecall.json"
2023-01-22T13:45:09.137679Z  INFO evm_eth_compliance::statetest::runner: TX len : 132
2023-01-22T13:45:09.137688Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [208, 97, 176, 138, 132, 235, 199, 15, 231, 151, 249, 189, 98, 244, 38, 158, 248, 39, 74, 19, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([5, 88, 210, 18, 26, 52, 248, 28, 151, 64, 33, 131, 197, 186, 68, 48, 182, 55, 124, 252]) }
[DEBUG] getting cid: bafy2bzacedef2iioq5zx33deu6ufh237wvqdt7vycaffbp5y5grxgwyyptoog
[DEBUG] fetching parameters block: 1
2023-01-22T13:45:09.141245Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 24,
    },
    return_data: RawBytes {  },
    gas_used: 12631833,
    events_root: None,
}
2023-01-22T13:45:09.141260Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 203,
                    method: 3844450837,
                    code: ExitCode {
                        value: 24,
                    },
                    message: "panicked at 'called `Option::unwrap()` on a `None` value', actors/evm/src/interpreter/system.rs:210:22",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-22T13:45:09.141313Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => ConstantinopleFix 18
2023-01-22T13:45:09.141337Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_HighNonceDelegatecall"::ConstantinopleFix::18
2023-01-22T13:45:09.141344Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stCreate2/CREATE2_HighNonceDelegatecall.json"
2023-01-22T13:45:09.141352Z  INFO evm_eth_compliance::statetest::runner: TX len : 132
2023-01-22T13:45:09.141358Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [208, 97, 176, 138, 132, 235, 199, 15, 231, 151, 249, 189, 98, 244, 38, 158, 248, 39, 74, 19, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([15, 247, 128, 210, 25, 115, 102, 75, 127, 51, 97, 15, 6, 109, 66, 23, 2, 119, 106, 150]) }
[DEBUG] getting cid: bafy2bzacedef2iioq5zx33deu6ufh237wvqdt7vycaffbp5y5grxgwyyptoog
[DEBUG] fetching parameters block: 1
2023-01-22T13:45:09.144884Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 24,
    },
    return_data: RawBytes {  },
    gas_used: 12703011,
    events_root: None,
}
2023-01-22T13:45:09.144899Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 203,
                    method: 3844450837,
                    code: ExitCode {
                        value: 24,
                    },
                    message: "panicked at 'called `Option::unwrap()` on a `None` value', actors/evm/src/interpreter/system.rs:210:22",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-22T13:45:09.144952Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => ConstantinopleFix 19
2023-01-22T13:45:09.144976Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_HighNonceDelegatecall"::ConstantinopleFix::19
2023-01-22T13:45:09.144983Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stCreate2/CREATE2_HighNonceDelegatecall.json"
2023-01-22T13:45:09.144990Z  INFO evm_eth_compliance::statetest::runner: TX len : 132
2023-01-22T13:45:09.144996Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [208, 97, 176, 138, 132, 235, 199, 15, 231, 151, 249, 189, 98, 244, 38, 158, 248, 39, 74, 19, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([199, 252, 73, 148, 203, 140, 110, 81, 23, 89, 7, 17, 67, 216, 186, 246, 144, 79, 37, 28]) }
[DEBUG] getting cid: bafy2bzacedef2iioq5zx33deu6ufh237wvqdt7vycaffbp5y5grxgwyyptoog
[DEBUG] fetching parameters block: 1
2023-01-22T13:45:09.148489Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 24,
    },
    return_data: RawBytes {  },
    gas_used: 12326049,
    events_root: None,
}
2023-01-22T13:45:09.148505Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 203,
                    method: 3844450837,
                    code: ExitCode {
                        value: 24,
                    },
                    message: "panicked at 'called `Option::unwrap()` on a `None` value', actors/evm/src/interpreter/system.rs:210:22",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-22T13:45:09.148558Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => ConstantinopleFix 20
2023-01-22T13:45:09.148582Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_HighNonceDelegatecall"::ConstantinopleFix::20
2023-01-22T13:45:09.148589Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stCreate2/CREATE2_HighNonceDelegatecall.json"
2023-01-22T13:45:09.148596Z  INFO evm_eth_compliance::statetest::runner: TX len : 132
2023-01-22T13:45:09.148602Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [208, 97, 176, 138, 132, 235, 199, 15, 231, 151, 249, 189, 98, 244, 38, 158, 248, 39, 74, 19, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([118, 83, 126, 208, 253, 224, 235, 219, 150, 244, 223, 154, 156, 51, 158, 143, 75, 69, 63, 136]) }
[DEBUG] getting cid: bafy2bzacedef2iioq5zx33deu6ufh237wvqdt7vycaffbp5y5grxgwyyptoog
[DEBUG] fetching parameters block: 1
2023-01-22T13:45:09.152173Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 24,
    },
    return_data: RawBytes {  },
    gas_used: 12721218,
    events_root: None,
}
2023-01-22T13:45:09.152188Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 203,
                    method: 3844450837,
                    code: ExitCode {
                        value: 24,
                    },
                    message: "panicked at 'called `Option::unwrap()` on a `None` value', actors/evm/src/interpreter/system.rs:210:22",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-22T13:45:09.152241Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => ConstantinopleFix 21
2023-01-22T13:45:09.152265Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_HighNonceDelegatecall"::ConstantinopleFix::21
2023-01-22T13:45:09.152272Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stCreate2/CREATE2_HighNonceDelegatecall.json"
2023-01-22T13:45:09.152279Z  INFO evm_eth_compliance::statetest::runner: TX len : 132
2023-01-22T13:45:09.152285Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [208, 97, 176, 138, 132, 235, 199, 15, 231, 151, 249, 189, 98, 244, 38, 158, 248, 39, 74, 19, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([166, 190, 176, 88, 26, 69, 172, 111, 50, 159, 85, 218, 194, 71, 246, 209, 144, 181, 175, 145]) }
[DEBUG] getting cid: bafy2bzacedef2iioq5zx33deu6ufh237wvqdt7vycaffbp5y5grxgwyyptoog
[DEBUG] fetching parameters block: 1
2023-01-22T13:45:09.155803Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 24,
    },
    return_data: RawBytes {  },
    gas_used: 12703787,
    events_root: None,
}
2023-01-22T13:45:09.155818Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 203,
                    method: 3844450837,
                    code: ExitCode {
                        value: 24,
                    },
                    message: "panicked at 'called `Option::unwrap()` on a `None` value', actors/evm/src/interpreter/system.rs:210:22",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-22T13:45:09.155872Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => ConstantinopleFix 22
2023-01-22T13:45:09.155896Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_HighNonceDelegatecall"::ConstantinopleFix::22
2023-01-22T13:45:09.155903Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stCreate2/CREATE2_HighNonceDelegatecall.json"
2023-01-22T13:45:09.155911Z  INFO evm_eth_compliance::statetest::runner: TX len : 132
2023-01-22T13:45:09.155917Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [208, 97, 176, 138, 132, 235, 199, 15, 231, 151, 249, 189, 98, 244, 38, 158, 248, 39, 74, 19, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([36, 157, 234, 94, 37, 166, 2, 133, 61, 174, 211, 48, 33, 142, 84, 86, 31, 155, 191, 251]) }
[DEBUG] getting cid: bafy2bzacedef2iioq5zx33deu6ufh237wvqdt7vycaffbp5y5grxgwyyptoog
[DEBUG] fetching parameters block: 1
2023-01-22T13:45:09.159447Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 24,
    },
    return_data: RawBytes {  },
    gas_used: 12646109,
    events_root: None,
}
2023-01-22T13:45:09.159468Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 203,
                    method: 3844450837,
                    code: ExitCode {
                        value: 24,
                    },
                    message: "panicked at 'called `Option::unwrap()` on a `None` value', actors/evm/src/interpreter/system.rs:210:22",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-22T13:45:09.159521Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => ConstantinopleFix 23
2023-01-22T13:45:09.159545Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_HighNonceDelegatecall"::ConstantinopleFix::23
2023-01-22T13:45:09.159552Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stCreate2/CREATE2_HighNonceDelegatecall.json"
2023-01-22T13:45:09.159559Z  INFO evm_eth_compliance::statetest::runner: TX len : 132
2023-01-22T13:45:09.159566Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [208, 97, 176, 138, 132, 235, 199, 15, 231, 151, 249, 189, 98, 244, 38, 158, 248, 39, 74, 19, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([168, 221, 180, 246, 133, 219, 169, 147, 169, 53, 222, 23, 131, 225, 185, 196, 200, 150, 125, 157]) }
[DEBUG] getting cid: bafy2bzacedef2iioq5zx33deu6ufh237wvqdt7vycaffbp5y5grxgwyyptoog
[DEBUG] fetching parameters block: 1
2023-01-22T13:45:09.162943Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 24,
    },
    return_data: RawBytes {  },
    gas_used: 11849526,
    events_root: None,
}
2023-01-22T13:45:09.162959Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 203,
                    method: 3844450837,
                    code: ExitCode {
                        value: 24,
                    },
                    message: "panicked at 'called `Option::unwrap()` on a `None` value', actors/evm/src/interpreter/system.rs:210:22",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-22T13:45:09.163017Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => ConstantinopleFix 12
2023-01-22T13:45:09.163052Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_HighNonceDelegatecall"::ConstantinopleFix::12
2023-01-22T13:45:09.163063Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stCreate2/CREATE2_HighNonceDelegatecall.json"
2023-01-22T13:45:09.163074Z  INFO evm_eth_compliance::statetest::runner: TX len : 132
2023-01-22T13:45:09.163083Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [208, 97, 176, 138, 132, 235, 199, 15, 231, 151, 249, 189, 98, 244, 38, 158, 248, 39, 74, 19, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([225, 238, 158, 198, 199, 137, 8, 97, 185, 67, 160, 127, 119, 163, 164, 92, 239, 8, 248, 230]) }
[DEBUG] getting cid: bafy2bzacedef2iioq5zx33deu6ufh237wvqdt7vycaffbp5y5grxgwyyptoog
[DEBUG] fetching parameters block: 1
2023-01-22T13:45:09.166638Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 24,
    },
    return_data: RawBytes {  },
    gas_used: 12704700,
    events_root: None,
}
2023-01-22T13:45:09.166653Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 203,
                    method: 3844450837,
                    code: ExitCode {
                        value: 24,
                    },
                    message: "panicked at 'called `Option::unwrap()` on a `None` value', actors/evm/src/interpreter/system.rs:210:22",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-22T13:45:09.166706Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => ConstantinopleFix 13
2023-01-22T13:45:09.166730Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_HighNonceDelegatecall"::ConstantinopleFix::13
2023-01-22T13:45:09.166737Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stCreate2/CREATE2_HighNonceDelegatecall.json"
2023-01-22T13:45:09.166744Z  INFO evm_eth_compliance::statetest::runner: TX len : 132
2023-01-22T13:45:09.166750Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [208, 97, 176, 138, 132, 235, 199, 15, 231, 151, 249, 189, 98, 244, 38, 158, 248, 39, 74, 19, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([40, 80, 7, 100, 179, 140, 229, 153, 27, 223, 230, 101, 202, 1, 70, 47, 242, 104, 48, 7]) }
[DEBUG] getting cid: bafy2bzacedef2iioq5zx33deu6ufh237wvqdt7vycaffbp5y5grxgwyyptoog
[DEBUG] fetching parameters block: 1
2023-01-22T13:45:09.170251Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 24,
    },
    return_data: RawBytes {  },
    gas_used: 12646113,
    events_root: None,
}
2023-01-22T13:45:09.170267Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 203,
                    method: 3844450837,
                    code: ExitCode {
                        value: 24,
                    },
                    message: "panicked at 'called `Option::unwrap()` on a `None` value', actors/evm/src/interpreter/system.rs:210:22",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-22T13:45:09.170320Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => ConstantinopleFix 14
2023-01-22T13:45:09.170343Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_HighNonceDelegatecall"::ConstantinopleFix::14
2023-01-22T13:45:09.170350Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stCreate2/CREATE2_HighNonceDelegatecall.json"
2023-01-22T13:45:09.170357Z  INFO evm_eth_compliance::statetest::runner: TX len : 132
2023-01-22T13:45:09.170363Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [208, 97, 176, 138, 132, 235, 199, 15, 231, 151, 249, 189, 98, 244, 38, 158, 248, 39, 74, 19, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([117, 80, 21, 32, 38, 68, 114, 59, 236, 156, 92, 19, 239, 125, 17, 220, 1, 54, 208, 204]) }
[DEBUG] getting cid: bafy2bzacedef2iioq5zx33deu6ufh237wvqdt7vycaffbp5y5grxgwyyptoog
[DEBUG] fetching parameters block: 1
2023-01-22T13:45:09.173879Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 24,
    },
    return_data: RawBytes {  },
    gas_used: 12647338,
    events_root: None,
}
2023-01-22T13:45:09.173894Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 203,
                    method: 3844450837,
                    code: ExitCode {
                        value: 24,
                    },
                    message: "panicked at 'called `Option::unwrap()` on a `None` value', actors/evm/src/interpreter/system.rs:210:22",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-22T13:45:09.173947Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => ConstantinopleFix 15
2023-01-22T13:45:09.173971Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_HighNonceDelegatecall"::ConstantinopleFix::15
2023-01-22T13:45:09.173978Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stCreate2/CREATE2_HighNonceDelegatecall.json"
2023-01-22T13:45:09.173985Z  INFO evm_eth_compliance::statetest::runner: TX len : 132
2023-01-22T13:45:09.173991Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [208, 97, 176, 138, 132, 235, 199, 15, 231, 151, 249, 189, 98, 244, 38, 158, 248, 39, 74, 19, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([31, 100, 222, 111, 3, 64, 116, 117, 72, 255, 201, 98, 104, 128, 244, 234, 58, 79, 189, 62]) }
[DEBUG] getting cid: bafy2bzacedef2iioq5zx33deu6ufh237wvqdt7vycaffbp5y5grxgwyyptoog
[DEBUG] fetching parameters block: 1
2023-01-22T13:45:09.177540Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 24,
    },
    return_data: RawBytes {  },
    gas_used: 12703895,
    events_root: None,
}
2023-01-22T13:45:09.177556Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 203,
                    method: 3844450837,
                    code: ExitCode {
                        value: 24,
                    },
                    message: "panicked at 'called `Option::unwrap()` on a `None` value', actors/evm/src/interpreter/system.rs:210:22",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-22T13:45:09.177608Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => ConstantinopleFix 16
2023-01-22T13:45:09.177632Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_HighNonceDelegatecall"::ConstantinopleFix::16
2023-01-22T13:45:09.177639Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stCreate2/CREATE2_HighNonceDelegatecall.json"
2023-01-22T13:45:09.177646Z  INFO evm_eth_compliance::statetest::runner: TX len : 132
2023-01-22T13:45:09.177652Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [208, 97, 176, 138, 132, 235, 199, 15, 231, 151, 249, 189, 98, 244, 38, 158, 248, 39, 74, 19, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([96, 221, 7, 113, 89, 247, 138, 119, 225, 55, 135, 221, 132, 165, 82, 22, 202, 208, 233, 91]) }
[DEBUG] getting cid: bafy2bzacedef2iioq5zx33deu6ufh237wvqdt7vycaffbp5y5grxgwyyptoog
[DEBUG] fetching parameters block: 1
2023-01-22T13:45:09.181154Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 24,
    },
    return_data: RawBytes {  },
    gas_used: 12338462,
    events_root: None,
}
2023-01-22T13:45:09.181170Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 203,
                    method: 3844450837,
                    code: ExitCode {
                        value: 24,
                    },
                    message: "panicked at 'called `Option::unwrap()` on a `None` value', actors/evm/src/interpreter/system.rs:210:22",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-22T13:45:09.181224Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => ConstantinopleFix 17
2023-01-22T13:45:09.181248Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_HighNonceDelegatecall"::ConstantinopleFix::17
2023-01-22T13:45:09.181255Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stCreate2/CREATE2_HighNonceDelegatecall.json"
2023-01-22T13:45:09.181263Z  INFO evm_eth_compliance::statetest::runner: TX len : 132
2023-01-22T13:45:09.181273Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [208, 97, 176, 138, 132, 235, 199, 15, 231, 151, 249, 189, 98, 244, 38, 158, 248, 39, 74, 19, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([155, 48, 90, 18, 221, 116, 7, 27, 31, 161, 14, 26, 47, 29, 244, 108, 165, 178, 172, 107]) }
[DEBUG] getting cid: bafy2bzacedef2iioq5zx33deu6ufh237wvqdt7vycaffbp5y5grxgwyyptoog
[DEBUG] fetching parameters block: 1
2023-01-22T13:45:09.184780Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 24,
    },
    return_data: RawBytes {  },
    gas_used: 12340437,
    events_root: None,
}
2023-01-22T13:45:09.184796Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 203,
                    method: 3844450837,
                    code: ExitCode {
                        value: 24,
                    },
                    message: "panicked at 'called `Option::unwrap()` on a `None` value', actors/evm/src/interpreter/system.rs:210:22",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-22T13:45:09.184851Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 6
2023-01-22T13:45:09.184875Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_HighNonceDelegatecall"::Istanbul::6
2023-01-22T13:45:09.184882Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stCreate2/CREATE2_HighNonceDelegatecall.json"
2023-01-22T13:45:09.184890Z  INFO evm_eth_compliance::statetest::runner: TX len : 132
2023-01-22T13:45:09.184896Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [208, 97, 176, 138, 132, 235, 199, 15, 231, 151, 249, 189, 98, 244, 38, 158, 248, 39, 74, 19, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([119, 4, 145, 93, 73, 93, 109, 235, 174, 220, 80, 34, 135, 115, 159, 83, 251, 51, 62, 194]) }
[DEBUG] getting cid: bafy2bzacedef2iioq5zx33deu6ufh237wvqdt7vycaffbp5y5grxgwyyptoog
[DEBUG] fetching parameters block: 1
2023-01-22T13:45:09.188263Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 24,
    },
    return_data: RawBytes {  },
    gas_used: 11810053,
    events_root: None,
}
2023-01-22T13:45:09.188278Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 203,
                    method: 3844450837,
                    code: ExitCode {
                        value: 24,
                    },
                    message: "panicked at 'called `Option::unwrap()` on a `None` value', actors/evm/src/interpreter/system.rs:210:22",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-22T13:45:09.188345Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 7
2023-01-22T13:45:09.188383Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_HighNonceDelegatecall"::Istanbul::7
2023-01-22T13:45:09.188394Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stCreate2/CREATE2_HighNonceDelegatecall.json"
2023-01-22T13:45:09.188405Z  INFO evm_eth_compliance::statetest::runner: TX len : 132
2023-01-22T13:45:09.188414Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [208, 97, 176, 138, 132, 235, 199, 15, 231, 151, 249, 189, 98, 244, 38, 158, 248, 39, 74, 19, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([88, 135, 6, 16, 62, 111, 126, 121, 88, 155, 35, 12, 237, 236, 216, 103, 21, 167, 148, 17]) }
[DEBUG] getting cid: bafy2bzacedef2iioq5zx33deu6ufh237wvqdt7vycaffbp5y5grxgwyyptoog
[DEBUG] fetching parameters block: 1
2023-01-22T13:45:09.191936Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 24,
    },
    return_data: RawBytes {  },
    gas_used: 12688997,
    events_root: None,
}
2023-01-22T13:45:09.191952Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 203,
                    method: 3844450837,
                    code: ExitCode {
                        value: 24,
                    },
                    message: "panicked at 'called `Option::unwrap()` on a `None` value', actors/evm/src/interpreter/system.rs:210:22",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-22T13:45:09.192004Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 8
2023-01-22T13:45:09.192028Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_HighNonceDelegatecall"::Istanbul::8
2023-01-22T13:45:09.192035Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stCreate2/CREATE2_HighNonceDelegatecall.json"
2023-01-22T13:45:09.192042Z  INFO evm_eth_compliance::statetest::runner: TX len : 132
2023-01-22T13:45:09.192048Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [208, 97, 176, 138, 132, 235, 199, 15, 231, 151, 249, 189, 98, 244, 38, 158, 248, 39, 74, 19, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([42, 76, 99, 23, 230, 105, 11, 148, 115, 193, 49, 201, 172, 238, 44, 177, 35, 167, 102, 62]) }
[DEBUG] getting cid: bafy2bzacedef2iioq5zx33deu6ufh237wvqdt7vycaffbp5y5grxgwyyptoog
[DEBUG] fetching parameters block: 1
2023-01-22T13:45:09.195549Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 24,
    },
    return_data: RawBytes {  },
    gas_used: 12646341,
    events_root: None,
}
2023-01-22T13:45:09.195565Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 203,
                    method: 3844450837,
                    code: ExitCode {
                        value: 24,
                    },
                    message: "panicked at 'called `Option::unwrap()` on a `None` value', actors/evm/src/interpreter/system.rs:210:22",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-22T13:45:09.195618Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 9
2023-01-22T13:45:09.195642Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_HighNonceDelegatecall"::Istanbul::9
2023-01-22T13:45:09.195649Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stCreate2/CREATE2_HighNonceDelegatecall.json"
2023-01-22T13:45:09.195656Z  INFO evm_eth_compliance::statetest::runner: TX len : 132
2023-01-22T13:45:09.195662Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [208, 97, 176, 138, 132, 235, 199, 15, 231, 151, 249, 189, 98, 244, 38, 158, 248, 39, 74, 19, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([119, 145, 84, 64, 213, 27, 134, 173, 52, 245, 118, 171, 99, 148, 112, 180, 105, 70, 113, 93]) }
[DEBUG] getting cid: bafy2bzacedef2iioq5zx33deu6ufh237wvqdt7vycaffbp5y5grxgwyyptoog
[DEBUG] fetching parameters block: 1
2023-01-22T13:45:09.199205Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 24,
    },
    return_data: RawBytes {  },
    gas_used: 12826213,
    events_root: None,
}
2023-01-22T13:45:09.199221Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 203,
                    method: 3844450837,
                    code: ExitCode {
                        value: 24,
                    },
                    message: "panicked at 'called `Option::unwrap()` on a `None` value', actors/evm/src/interpreter/system.rs:210:22",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-22T13:45:09.199275Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 10
2023-01-22T13:45:09.199298Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_HighNonceDelegatecall"::Istanbul::10
2023-01-22T13:45:09.199305Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stCreate2/CREATE2_HighNonceDelegatecall.json"
2023-01-22T13:45:09.199312Z  INFO evm_eth_compliance::statetest::runner: TX len : 132
2023-01-22T13:45:09.199318Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [208, 97, 176, 138, 132, 235, 199, 15, 231, 151, 249, 189, 98, 244, 38, 158, 248, 39, 74, 19, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([29, 140, 230, 138, 107, 84, 150, 22, 173, 23, 154, 28, 236, 246, 46, 198, 72, 180, 189, 9]) }
[DEBUG] getting cid: bafy2bzacedef2iioq5zx33deu6ufh237wvqdt7vycaffbp5y5grxgwyyptoog
[DEBUG] fetching parameters block: 1
2023-01-22T13:45:09.202739Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 24,
    },
    return_data: RawBytes {  },
    gas_used: 11809069,
    events_root: None,
}
2023-01-22T13:45:09.202754Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 203,
                    method: 3844450837,
                    code: ExitCode {
                        value: 24,
                    },
                    message: "panicked at 'called `Option::unwrap()` on a `None` value', actors/evm/src/interpreter/system.rs:210:22",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-22T13:45:09.202806Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 11
2023-01-22T13:45:09.202829Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_HighNonceDelegatecall"::Istanbul::11
2023-01-22T13:45:09.202836Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stCreate2/CREATE2_HighNonceDelegatecall.json"
2023-01-22T13:45:09.202843Z  INFO evm_eth_compliance::statetest::runner: TX len : 132
2023-01-22T13:45:09.202849Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [208, 97, 176, 138, 132, 235, 199, 15, 231, 151, 249, 189, 98, 244, 38, 158, 248, 39, 74, 19, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([18, 27, 2, 121, 157, 192, 163, 52, 201, 162, 159, 21, 26, 224, 61, 97, 216, 253, 235, 163]) }
[DEBUG] getting cid: bafy2bzacedef2iioq5zx33deu6ufh237wvqdt7vycaffbp5y5grxgwyyptoog
[DEBUG] fetching parameters block: 1
2023-01-22T13:45:09.206242Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 24,
    },
    return_data: RawBytes {  },
    gas_used: 11810209,
    events_root: None,
}
2023-01-22T13:45:09.206258Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 203,
                    method: 3844450837,
                    code: ExitCode {
                        value: 24,
                    },
                    message: "panicked at 'called `Option::unwrap()` on a `None` value', actors/evm/src/interpreter/system.rs:210:22",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-22T13:45:09.206308Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-22T13:45:09.206331Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_HighNonceDelegatecall"::Istanbul::0
2023-01-22T13:45:09.206338Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stCreate2/CREATE2_HighNonceDelegatecall.json"
2023-01-22T13:45:09.206345Z  INFO evm_eth_compliance::statetest::runner: TX len : 132
2023-01-22T13:45:09.206351Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [208, 97, 176, 138, 132, 235, 199, 15, 231, 151, 249, 189, 98, 244, 38, 158, 248, 39, 74, 19, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([251, 148, 47, 146, 203, 69, 25, 195, 112, 159, 197, 4, 200, 234, 86, 36, 129, 72, 237, 154]) }
[DEBUG] getting cid: bafy2bzacedef2iioq5zx33deu6ufh237wvqdt7vycaffbp5y5grxgwyyptoog
[DEBUG] fetching parameters block: 1
2023-01-22T13:45:09.209887Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 24,
    },
    return_data: RawBytes {  },
    gas_used: 12706121,
    events_root: None,
}
2023-01-22T13:45:09.209902Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 203,
                    method: 3844450837,
                    code: ExitCode {
                        value: 24,
                    },
                    message: "panicked at 'called `Option::unwrap()` on a `None` value', actors/evm/src/interpreter/system.rs:210:22",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-22T13:45:09.209956Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 1
2023-01-22T13:45:09.209980Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_HighNonceDelegatecall"::Istanbul::1
2023-01-22T13:45:09.209987Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stCreate2/CREATE2_HighNonceDelegatecall.json"
2023-01-22T13:45:09.209995Z  INFO evm_eth_compliance::statetest::runner: TX len : 132
2023-01-22T13:45:09.210001Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [208, 97, 176, 138, 132, 235, 199, 15, 231, 151, 249, 189, 98, 244, 38, 158, 248, 39, 74, 19, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([0, 139, 20, 138, 169, 250, 202, 38, 0, 219, 54, 113, 39, 208, 211, 109, 45, 57, 7, 29]) }
[DEBUG] getting cid: bafy2bzacedef2iioq5zx33deu6ufh237wvqdt7vycaffbp5y5grxgwyyptoog
[DEBUG] fetching parameters block: 1
2023-01-22T13:45:09.213558Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 24,
    },
    return_data: RawBytes {  },
    gas_used: 12338145,
    events_root: None,
}
2023-01-22T13:45:09.213574Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 203,
                    method: 3844450837,
                    code: ExitCode {
                        value: 24,
                    },
                    message: "panicked at 'called `Option::unwrap()` on a `None` value', actors/evm/src/interpreter/system.rs:210:22",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-22T13:45:09.213629Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 2
2023-01-22T13:45:09.213655Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_HighNonceDelegatecall"::Istanbul::2
2023-01-22T13:45:09.213662Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stCreate2/CREATE2_HighNonceDelegatecall.json"
2023-01-22T13:45:09.213669Z  INFO evm_eth_compliance::statetest::runner: TX len : 132
2023-01-22T13:45:09.213685Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [208, 97, 176, 138, 132, 235, 199, 15, 231, 151, 249, 189, 98, 244, 38, 158, 248, 39, 74, 19, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([131, 21, 199, 119, 4, 1, 184, 120, 124, 242, 219, 243, 79, 251, 176, 103, 61, 174, 128, 243]) }
[DEBUG] getting cid: bafy2bzacedef2iioq5zx33deu6ufh237wvqdt7vycaffbp5y5grxgwyyptoog
[DEBUG] fetching parameters block: 1
2023-01-22T13:45:09.217357Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 24,
    },
    return_data: RawBytes {  },
    gas_used: 12686857,
    events_root: None,
}
2023-01-22T13:45:09.217375Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 203,
                    method: 3844450837,
                    code: ExitCode {
                        value: 24,
                    },
                    message: "panicked at 'called `Option::unwrap()` on a `None` value', actors/evm/src/interpreter/system.rs:210:22",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-22T13:45:09.217430Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 3
2023-01-22T13:45:09.217460Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_HighNonceDelegatecall"::Istanbul::3
2023-01-22T13:45:09.217467Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stCreate2/CREATE2_HighNonceDelegatecall.json"
2023-01-22T13:45:09.217474Z  INFO evm_eth_compliance::statetest::runner: TX len : 132
2023-01-22T13:45:09.217480Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [208, 97, 176, 138, 132, 235, 199, 15, 231, 151, 249, 189, 98, 244, 38, 158, 248, 39, 74, 19, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([100, 203, 6, 94, 91, 68, 100, 181, 149, 221, 44, 86, 222, 158, 169, 227, 218, 136, 249, 75]) }
[DEBUG] getting cid: bafy2bzacedef2iioq5zx33deu6ufh237wvqdt7vycaffbp5y5grxgwyyptoog
[DEBUG] fetching parameters block: 1
2023-01-22T13:45:09.220991Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 24,
    },
    return_data: RawBytes {  },
    gas_used: 12706079,
    events_root: None,
}
2023-01-22T13:45:09.221006Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 203,
                    method: 3844450837,
                    code: ExitCode {
                        value: 24,
                    },
                    message: "panicked at 'called `Option::unwrap()` on a `None` value', actors/evm/src/interpreter/system.rs:210:22",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-22T13:45:09.221059Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 4
2023-01-22T13:45:09.221082Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_HighNonceDelegatecall"::Istanbul::4
2023-01-22T13:45:09.221089Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stCreate2/CREATE2_HighNonceDelegatecall.json"
2023-01-22T13:45:09.221096Z  INFO evm_eth_compliance::statetest::runner: TX len : 132
2023-01-22T13:45:09.221102Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [208, 97, 176, 138, 132, 235, 199, 15, 231, 151, 249, 189, 98, 244, 38, 158, 248, 39, 74, 19, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([26, 240, 28, 195, 132, 99, 78, 96, 33, 68, 142, 205, 74, 246, 255, 91, 152, 252, 192, 155]) }
[DEBUG] getting cid: bafy2bzacedef2iioq5zx33deu6ufh237wvqdt7vycaffbp5y5grxgwyyptoog
[DEBUG] fetching parameters block: 1
2023-01-22T13:45:09.224574Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 24,
    },
    return_data: RawBytes {  },
    gas_used: 12326281,
    events_root: None,
}
2023-01-22T13:45:09.224589Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 203,
                    method: 3844450837,
                    code: ExitCode {
                        value: 24,
                    },
                    message: "panicked at 'called `Option::unwrap()` on a `None` value', actors/evm/src/interpreter/system.rs:210:22",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-22T13:45:09.224644Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 5
2023-01-22T13:45:09.224667Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_HighNonceDelegatecall"::Istanbul::5
2023-01-22T13:45:09.224674Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stCreate2/CREATE2_HighNonceDelegatecall.json"
2023-01-22T13:45:09.224681Z  INFO evm_eth_compliance::statetest::runner: TX len : 132
2023-01-22T13:45:09.224687Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [208, 97, 176, 138, 132, 235, 199, 15, 231, 151, 249, 189, 98, 244, 38, 158, 248, 39, 74, 19, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([80, 121, 104, 125, 93, 227, 237, 85, 56, 27, 105, 5, 43, 95, 74, 142, 141, 225, 238, 47]) }
[DEBUG] getting cid: bafy2bzacedef2iioq5zx33deu6ufh237wvqdt7vycaffbp5y5grxgwyyptoog
[DEBUG] fetching parameters block: 1
2023-01-22T13:45:09.228180Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 24,
    },
    return_data: RawBytes {  },
    gas_used: 12685277,
    events_root: None,
}
2023-01-22T13:45:09.228195Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 203,
                    method: 3844450837,
                    code: ExitCode {
                        value: 24,
                    },
                    message: "panicked at 'called `Option::unwrap()` on a `None` value', actors/evm/src/interpreter/system.rs:210:22",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-22T13:45:09.228271Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 18
2023-01-22T13:45:09.228304Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_HighNonceDelegatecall"::Istanbul::18
2023-01-22T13:45:09.228315Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stCreate2/CREATE2_HighNonceDelegatecall.json"
2023-01-22T13:45:09.228326Z  INFO evm_eth_compliance::statetest::runner: TX len : 132
2023-01-22T13:45:09.228335Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [208, 97, 176, 138, 132, 235, 199, 15, 231, 151, 249, 189, 98, 244, 38, 158, 248, 39, 74, 19, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([95, 70, 69, 70, 176, 49, 182, 243, 189, 49, 50, 205, 114, 117, 90, 14, 54, 147, 219, 141]) }
[DEBUG] getting cid: bafy2bzacedef2iioq5zx33deu6ufh237wvqdt7vycaffbp5y5grxgwyyptoog
[DEBUG] fetching parameters block: 1
2023-01-22T13:45:09.231889Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 24,
    },
    return_data: RawBytes {  },
    gas_used: 12705746,
    events_root: None,
}
2023-01-22T13:45:09.231906Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 203,
                    method: 3844450837,
                    code: ExitCode {
                        value: 24,
                    },
                    message: "panicked at 'called `Option::unwrap()` on a `None` value', actors/evm/src/interpreter/system.rs:210:22",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-22T13:45:09.231959Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 19
2023-01-22T13:45:09.231984Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_HighNonceDelegatecall"::Istanbul::19
2023-01-22T13:45:09.231991Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stCreate2/CREATE2_HighNonceDelegatecall.json"
2023-01-22T13:45:09.231998Z  INFO evm_eth_compliance::statetest::runner: TX len : 132
2023-01-22T13:45:09.232004Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [208, 97, 176, 138, 132, 235, 199, 15, 231, 151, 249, 189, 98, 244, 38, 158, 248, 39, 74, 19, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([2, 29, 119, 133, 104, 132, 91, 37, 255, 242, 99, 245, 110, 126, 96, 115, 141, 115, 78, 231]) }
[DEBUG] getting cid: bafy2bzacedef2iioq5zx33deu6ufh237wvqdt7vycaffbp5y5grxgwyyptoog
[DEBUG] fetching parameters block: 1
2023-01-22T13:45:09.235533Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 24,
    },
    return_data: RawBytes {  },
    gas_used: 12744519,
    events_root: None,
}
2023-01-22T13:45:09.235548Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 203,
                    method: 3844450837,
                    code: ExitCode {
                        value: 24,
                    },
                    message: "panicked at 'called `Option::unwrap()` on a `None` value', actors/evm/src/interpreter/system.rs:210:22",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-22T13:45:09.235602Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 20
2023-01-22T13:45:09.235626Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_HighNonceDelegatecall"::Istanbul::20
2023-01-22T13:45:09.235633Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stCreate2/CREATE2_HighNonceDelegatecall.json"
2023-01-22T13:45:09.235640Z  INFO evm_eth_compliance::statetest::runner: TX len : 132
2023-01-22T13:45:09.235646Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [208, 97, 176, 138, 132, 235, 199, 15, 231, 151, 249, 189, 98, 244, 38, 158, 248, 39, 74, 19, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([166, 111, 150, 7, 151, 203, 163, 23, 193, 47, 73, 19, 21, 71, 28, 22, 47, 225, 171, 163]) }
[DEBUG] getting cid: bafy2bzacedef2iioq5zx33deu6ufh237wvqdt7vycaffbp5y5grxgwyyptoog
[DEBUG] fetching parameters block: 1
2023-01-22T13:45:09.239121Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 24,
    },
    return_data: RawBytes {  },
    gas_used: 12338081,
    events_root: None,
}
2023-01-22T13:45:09.239136Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 203,
                    method: 3844450837,
                    code: ExitCode {
                        value: 24,
                    },
                    message: "panicked at 'called `Option::unwrap()` on a `None` value', actors/evm/src/interpreter/system.rs:210:22",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-22T13:45:09.239189Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 21
2023-01-22T13:45:09.239212Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_HighNonceDelegatecall"::Istanbul::21
2023-01-22T13:45:09.239219Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stCreate2/CREATE2_HighNonceDelegatecall.json"
2023-01-22T13:45:09.239226Z  INFO evm_eth_compliance::statetest::runner: TX len : 132
2023-01-22T13:45:09.239232Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [208, 97, 176, 138, 132, 235, 199, 15, 231, 151, 249, 189, 98, 244, 38, 158, 248, 39, 74, 19, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([227, 33, 40, 41, 106, 100, 194, 98, 93, 91, 102, 65, 34, 228, 239, 113, 118, 110, 188, 163]) }
[DEBUG] getting cid: bafy2bzacedef2iioq5zx33deu6ufh237wvqdt7vycaffbp5y5grxgwyyptoog
[DEBUG] fetching parameters block: 1
2023-01-22T13:45:09.242773Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 24,
    },
    return_data: RawBytes {  },
    gas_used: 12648069,
    events_root: None,
}
2023-01-22T13:45:09.242788Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 203,
                    method: 3844450837,
                    code: ExitCode {
                        value: 24,
                    },
                    message: "panicked at 'called `Option::unwrap()` on a `None` value', actors/evm/src/interpreter/system.rs:210:22",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-22T13:45:09.242841Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 22
2023-01-22T13:45:09.242864Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_HighNonceDelegatecall"::Istanbul::22
2023-01-22T13:45:09.242871Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stCreate2/CREATE2_HighNonceDelegatecall.json"
2023-01-22T13:45:09.242878Z  INFO evm_eth_compliance::statetest::runner: TX len : 132
2023-01-22T13:45:09.242884Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [208, 97, 176, 138, 132, 235, 199, 15, 231, 151, 249, 189, 98, 244, 38, 158, 248, 39, 74, 19, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([238, 67, 40, 127, 153, 170, 231, 31, 27, 189, 74, 95, 145, 13, 91, 152, 106, 149, 37, 30]) }
[DEBUG] getting cid: bafy2bzacedef2iioq5zx33deu6ufh237wvqdt7vycaffbp5y5grxgwyyptoog
[DEBUG] fetching parameters block: 1
2023-01-22T13:45:09.246409Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 24,
    },
    return_data: RawBytes {  },
    gas_used: 12703163,
    events_root: None,
}
2023-01-22T13:45:09.246424Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 203,
                    method: 3844450837,
                    code: ExitCode {
                        value: 24,
                    },
                    message: "panicked at 'called `Option::unwrap()` on a `None` value', actors/evm/src/interpreter/system.rs:210:22",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-22T13:45:09.246476Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 23
2023-01-22T13:45:09.246500Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_HighNonceDelegatecall"::Istanbul::23
2023-01-22T13:45:09.246507Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stCreate2/CREATE2_HighNonceDelegatecall.json"
2023-01-22T13:45:09.246514Z  INFO evm_eth_compliance::statetest::runner: TX len : 132
2023-01-22T13:45:09.246520Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [208, 97, 176, 138, 132, 235, 199, 15, 231, 151, 249, 189, 98, 244, 38, 158, 248, 39, 74, 19, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([21, 40, 14, 38, 252, 118, 66, 103, 98, 150, 252, 118, 196, 220, 120, 14, 191, 136, 175, 22]) }
[DEBUG] getting cid: bafy2bzacedef2iioq5zx33deu6ufh237wvqdt7vycaffbp5y5grxgwyyptoog
[DEBUG] fetching parameters block: 1
2023-01-22T13:45:09.249999Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 24,
    },
    return_data: RawBytes {  },
    gas_used: 12334229,
    events_root: None,
}
2023-01-22T13:45:09.250014Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 203,
                    method: 3844450837,
                    code: ExitCode {
                        value: 24,
                    },
                    message: "panicked at 'called `Option::unwrap()` on a `None` value', actors/evm/src/interpreter/system.rs:210:22",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-22T13:45:09.250067Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 12
2023-01-22T13:45:09.250093Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_HighNonceDelegatecall"::Istanbul::12
2023-01-22T13:45:09.250101Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stCreate2/CREATE2_HighNonceDelegatecall.json"
2023-01-22T13:45:09.250109Z  INFO evm_eth_compliance::statetest::runner: TX len : 132
2023-01-22T13:45:09.250116Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [208, 97, 176, 138, 132, 235, 199, 15, 231, 151, 249, 189, 98, 244, 38, 158, 248, 39, 74, 19, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([23, 195, 35, 199, 237, 215, 9, 133, 138, 169, 41, 41, 21, 140, 61, 47, 131, 109, 202, 227]) }
[DEBUG] getting cid: bafy2bzacedef2iioq5zx33deu6ufh237wvqdt7vycaffbp5y5grxgwyyptoog
[DEBUG] fetching parameters block: 1
2023-01-22T13:45:09.253622Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 24,
    },
    return_data: RawBytes {  },
    gas_used: 12689053,
    events_root: None,
}
2023-01-22T13:45:09.253638Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 203,
                    method: 3844450837,
                    code: ExitCode {
                        value: 24,
                    },
                    message: "panicked at 'called `Option::unwrap()` on a `None` value', actors/evm/src/interpreter/system.rs:210:22",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-22T13:45:09.253721Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 13
2023-01-22T13:45:09.253758Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_HighNonceDelegatecall"::Istanbul::13
2023-01-22T13:45:09.253768Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stCreate2/CREATE2_HighNonceDelegatecall.json"
2023-01-22T13:45:09.253779Z  INFO evm_eth_compliance::statetest::runner: TX len : 132
2023-01-22T13:45:09.253788Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [208, 97, 176, 138, 132, 235, 199, 15, 231, 151, 249, 189, 98, 244, 38, 158, 248, 39, 74, 19, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([246, 154, 244, 177, 203, 194, 213, 20, 114, 118, 61, 213, 14, 253, 29, 3, 171, 95, 81, 165]) }
[DEBUG] getting cid: bafy2bzacedef2iioq5zx33deu6ufh237wvqdt7vycaffbp5y5grxgwyyptoog
[DEBUG] fetching parameters block: 1
2023-01-22T13:45:09.257279Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 24,
    },
    return_data: RawBytes {  },
    gas_used: 11808605,
    events_root: None,
}
2023-01-22T13:45:09.257300Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 203,
                    method: 3844450837,
                    code: ExitCode {
                        value: 24,
                    },
                    message: "panicked at 'called `Option::unwrap()` on a `None` value', actors/evm/src/interpreter/system.rs:210:22",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-22T13:45:09.257363Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 14
2023-01-22T13:45:09.257397Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_HighNonceDelegatecall"::Istanbul::14
2023-01-22T13:45:09.257404Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stCreate2/CREATE2_HighNonceDelegatecall.json"
2023-01-22T13:45:09.257412Z  INFO evm_eth_compliance::statetest::runner: TX len : 132
2023-01-22T13:45:09.257418Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [208, 97, 176, 138, 132, 235, 199, 15, 231, 151, 249, 189, 98, 244, 38, 158, 248, 39, 74, 19, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([125, 142, 180, 67, 30, 195, 115, 147, 46, 53, 0, 167, 68, 199, 138, 215, 197, 146, 77, 23]) }
[DEBUG] getting cid: bafy2bzacedef2iioq5zx33deu6ufh237wvqdt7vycaffbp5y5grxgwyyptoog
[DEBUG] fetching parameters block: 1
2023-01-22T13:45:09.260833Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 24,
    },
    return_data: RawBytes {  },
    gas_used: 11809069,
    events_root: None,
}
2023-01-22T13:45:09.260848Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 203,
                    method: 3844450837,
                    code: ExitCode {
                        value: 24,
                    },
                    message: "panicked at 'called `Option::unwrap()` on a `None` value', actors/evm/src/interpreter/system.rs:210:22",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-22T13:45:09.260901Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 15
2023-01-22T13:45:09.260926Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_HighNonceDelegatecall"::Istanbul::15
2023-01-22T13:45:09.260933Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stCreate2/CREATE2_HighNonceDelegatecall.json"
2023-01-22T13:45:09.260940Z  INFO evm_eth_compliance::statetest::runner: TX len : 132
2023-01-22T13:45:09.260946Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [208, 97, 176, 138, 132, 235, 199, 15, 231, 151, 249, 189, 98, 244, 38, 158, 248, 39, 74, 19, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([177, 249, 71, 16, 94, 5, 7, 223, 202, 108, 158, 33, 121, 14, 250, 246, 50, 245, 3, 253]) }
[DEBUG] getting cid: bafy2bzacedef2iioq5zx33deu6ufh237wvqdt7vycaffbp5y5grxgwyyptoog
[DEBUG] fetching parameters block: 1
2023-01-22T13:45:09.264490Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 24,
    },
    return_data: RawBytes {  },
    gas_used: 12720325,
    events_root: None,
}
2023-01-22T13:45:09.264507Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 203,
                    method: 3844450837,
                    code: ExitCode {
                        value: 24,
                    },
                    message: "panicked at 'called `Option::unwrap()` on a `None` value', actors/evm/src/interpreter/system.rs:210:22",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-22T13:45:09.264564Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 16
2023-01-22T13:45:09.264594Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_HighNonceDelegatecall"::Istanbul::16
2023-01-22T13:45:09.264601Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stCreate2/CREATE2_HighNonceDelegatecall.json"
2023-01-22T13:45:09.264608Z  INFO evm_eth_compliance::statetest::runner: TX len : 132
2023-01-22T13:45:09.264614Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [208, 97, 176, 138, 132, 235, 199, 15, 231, 151, 249, 189, 98, 244, 38, 158, 248, 39, 74, 19, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([2, 180, 255, 222, 75, 104, 55, 64, 26, 55, 66, 244, 63, 138, 191, 90, 119, 72, 198, 78]) }
[DEBUG] getting cid: bafy2bzacedef2iioq5zx33deu6ufh237wvqdt7vycaffbp5y5grxgwyyptoog
[DEBUG] fetching parameters block: 1
2023-01-22T13:45:09.268166Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 24,
    },
    return_data: RawBytes {  },
    gas_used: 12687581,
    events_root: None,
}
2023-01-22T13:45:09.268182Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 203,
                    method: 3844450837,
                    code: ExitCode {
                        value: 24,
                    },
                    message: "panicked at 'called `Option::unwrap()` on a `None` value', actors/evm/src/interpreter/system.rs:210:22",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-22T13:45:09.268236Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 17
2023-01-22T13:45:09.268263Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_HighNonceDelegatecall"::Istanbul::17
2023-01-22T13:45:09.268270Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stCreate2/CREATE2_HighNonceDelegatecall.json"
2023-01-22T13:45:09.268277Z  INFO evm_eth_compliance::statetest::runner: TX len : 132
2023-01-22T13:45:09.268283Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [208, 97, 176, 138, 132, 235, 199, 15, 231, 151, 249, 189, 98, 244, 38, 158, 248, 39, 74, 19, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([149, 187, 226, 191, 13, 68, 76, 32, 90, 2, 76, 3, 240, 217, 5, 67, 149, 177, 111, 250]) }
[DEBUG] getting cid: bafy2bzacedef2iioq5zx33deu6ufh237wvqdt7vycaffbp5y5grxgwyyptoog
[DEBUG] fetching parameters block: 1
2023-01-22T13:45:09.271825Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 24,
    },
    return_data: RawBytes {  },
    gas_used: 12325556,
    events_root: None,
}
2023-01-22T13:45:09.271843Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 203,
                    method: 3844450837,
                    code: ExitCode {
                        value: 24,
                    },
                    message: "panicked at 'called `Option::unwrap()` on a `None` value', actors/evm/src/interpreter/system.rs:210:22",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-22T13:45:09.271904Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 6
2023-01-22T13:45:09.271934Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_HighNonceDelegatecall"::Berlin::6
2023-01-22T13:45:09.271941Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stCreate2/CREATE2_HighNonceDelegatecall.json"
2023-01-22T13:45:09.271948Z  INFO evm_eth_compliance::statetest::runner: TX len : 132
2023-01-22T13:45:09.271954Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [208, 97, 176, 138, 132, 235, 199, 15, 231, 151, 249, 189, 98, 244, 38, 158, 248, 39, 74, 19, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([135, 155, 16, 115, 107, 83, 219, 96, 57, 81, 173, 154, 223, 235, 119, 252, 35, 123, 158, 8]) }
[DEBUG] getting cid: bafy2bzacedef2iioq5zx33deu6ufh237wvqdt7vycaffbp5y5grxgwyyptoog
[DEBUG] fetching parameters block: 1
2023-01-22T13:45:09.275346Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 24,
    },
    return_data: RawBytes {  },
    gas_used: 11809225,
    events_root: None,
}
2023-01-22T13:45:09.275362Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 203,
                    method: 3844450837,
                    code: ExitCode {
                        value: 24,
                    },
                    message: "panicked at 'called `Option::unwrap()` on a `None` value', actors/evm/src/interpreter/system.rs:210:22",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-22T13:45:09.275414Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 7
2023-01-22T13:45:09.275439Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_HighNonceDelegatecall"::Berlin::7
2023-01-22T13:45:09.275446Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stCreate2/CREATE2_HighNonceDelegatecall.json"
2023-01-22T13:45:09.275453Z  INFO evm_eth_compliance::statetest::runner: TX len : 132
2023-01-22T13:45:09.275467Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [208, 97, 176, 138, 132, 235, 199, 15, 231, 151, 249, 189, 98, 244, 38, 158, 248, 39, 74, 19, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([132, 180, 189, 234, 113, 120, 190, 163, 101, 172, 135, 223, 102, 86, 69, 171, 195, 191, 48, 248]) }
[DEBUG] getting cid: bafy2bzacedef2iioq5zx33deu6ufh237wvqdt7vycaffbp5y5grxgwyyptoog
[DEBUG] fetching parameters block: 1
2023-01-22T13:45:09.279022Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 24,
    },
    return_data: RawBytes {  },
    gas_used: 12688929,
    events_root: None,
}
2023-01-22T13:45:09.279038Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 203,
                    method: 3844450837,
                    code: ExitCode {
                        value: 24,
                    },
                    message: "panicked at 'called `Option::unwrap()` on a `None` value', actors/evm/src/interpreter/system.rs:210:22",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-22T13:45:09.279110Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 8
2023-01-22T13:45:09.279152Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_HighNonceDelegatecall"::Berlin::8
2023-01-22T13:45:09.279164Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stCreate2/CREATE2_HighNonceDelegatecall.json"
2023-01-22T13:45:09.279174Z  INFO evm_eth_compliance::statetest::runner: TX len : 132
2023-01-22T13:45:09.279183Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [208, 97, 176, 138, 132, 235, 199, 15, 231, 151, 249, 189, 98, 244, 38, 158, 248, 39, 74, 19, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([6, 122, 253, 222, 35, 73, 130, 165, 2, 129, 148, 135, 157, 66, 77, 31, 233, 24, 38, 118]) }
[DEBUG] getting cid: bafy2bzacedef2iioq5zx33deu6ufh237wvqdt7vycaffbp5y5grxgwyyptoog
[DEBUG] fetching parameters block: 1
2023-01-22T13:45:09.282773Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 24,
    },
    return_data: RawBytes {  },
    gas_used: 12647491,
    events_root: None,
}
2023-01-22T13:45:09.282789Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 203,
                    method: 3844450837,
                    code: ExitCode {
                        value: 24,
                    },
                    message: "panicked at 'called `Option::unwrap()` on a `None` value', actors/evm/src/interpreter/system.rs:210:22",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-22T13:45:09.282843Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 9
2023-01-22T13:45:09.282868Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_HighNonceDelegatecall"::Berlin::9
2023-01-22T13:45:09.282875Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stCreate2/CREATE2_HighNonceDelegatecall.json"
2023-01-22T13:45:09.282882Z  INFO evm_eth_compliance::statetest::runner: TX len : 132
2023-01-22T13:45:09.282888Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [208, 97, 176, 138, 132, 235, 199, 15, 231, 151, 249, 189, 98, 244, 38, 158, 248, 39, 74, 19, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([77, 179, 37, 229, 81, 207, 123, 87, 60, 115, 156, 105, 136, 92, 146, 11, 86, 211, 213, 140]) }
[DEBUG] getting cid: bafy2bzacedef2iioq5zx33deu6ufh237wvqdt7vycaffbp5y5grxgwyyptoog
[DEBUG] fetching parameters block: 1
2023-01-22T13:45:09.286375Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 24,
    },
    return_data: RawBytes {  },
    gas_used: 12338489,
    events_root: None,
}
2023-01-22T13:45:09.286391Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 203,
                    method: 3844450837,
                    code: ExitCode {
                        value: 24,
                    },
                    message: "panicked at 'called `Option::unwrap()` on a `None` value', actors/evm/src/interpreter/system.rs:210:22",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-22T13:45:09.286443Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 10
2023-01-22T13:45:09.286466Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_HighNonceDelegatecall"::Berlin::10
2023-01-22T13:45:09.286473Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stCreate2/CREATE2_HighNonceDelegatecall.json"
2023-01-22T13:45:09.286480Z  INFO evm_eth_compliance::statetest::runner: TX len : 132
2023-01-22T13:45:09.286486Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [208, 97, 176, 138, 132, 235, 199, 15, 231, 151, 249, 189, 98, 244, 38, 158, 248, 39, 74, 19, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([159, 89, 244, 97, 216, 246, 171, 160, 194, 159, 249, 175, 143, 250, 196, 14, 37, 21, 116, 148]) }
[DEBUG] getting cid: bafy2bzacedef2iioq5zx33deu6ufh237wvqdt7vycaffbp5y5grxgwyyptoog
[DEBUG] fetching parameters block: 1
2023-01-22T13:45:09.289830Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 24,
    },
    return_data: RawBytes {  },
    gas_used: 11849058,
    events_root: None,
}
2023-01-22T13:45:09.289845Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 203,
                    method: 3844450837,
                    code: ExitCode {
                        value: 24,
                    },
                    message: "panicked at 'called `Option::unwrap()` on a `None` value', actors/evm/src/interpreter/system.rs:210:22",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-22T13:45:09.289896Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 11
2023-01-22T13:45:09.289919Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_HighNonceDelegatecall"::Berlin::11
2023-01-22T13:45:09.289925Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stCreate2/CREATE2_HighNonceDelegatecall.json"
2023-01-22T13:45:09.289932Z  INFO evm_eth_compliance::statetest::runner: TX len : 132
2023-01-22T13:45:09.289938Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [208, 97, 176, 138, 132, 235, 199, 15, 231, 151, 249, 189, 98, 244, 38, 158, 248, 39, 74, 19, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([81, 80, 28, 154, 255, 53, 201, 25, 240, 13, 78, 24, 7, 243, 215, 88, 230, 75, 209, 72]) }
[DEBUG] getting cid: bafy2bzacedef2iioq5zx33deu6ufh237wvqdt7vycaffbp5y5grxgwyyptoog
[DEBUG] fetching parameters block: 1
2023-01-22T13:45:09.293466Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 24,
    },
    return_data: RawBytes {  },
    gas_used: 12647140,
    events_root: None,
}
2023-01-22T13:45:09.293481Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 203,
                    method: 3844450837,
                    code: ExitCode {
                        value: 24,
                    },
                    message: "panicked at 'called `Option::unwrap()` on a `None` value', actors/evm/src/interpreter/system.rs:210:22",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-22T13:45:09.293534Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-22T13:45:09.293557Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_HighNonceDelegatecall"::Berlin::0
2023-01-22T13:45:09.293564Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stCreate2/CREATE2_HighNonceDelegatecall.json"
2023-01-22T13:45:09.293571Z  INFO evm_eth_compliance::statetest::runner: TX len : 132
2023-01-22T13:45:09.293577Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [208, 97, 176, 138, 132, 235, 199, 15, 231, 151, 249, 189, 98, 244, 38, 158, 248, 39, 74, 19, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([156, 171, 158, 121, 236, 77, 77, 104, 97, 93, 182, 60, 124, 79, 216, 70, 25, 4, 156, 250]) }
[DEBUG] getting cid: bafy2bzacedef2iioq5zx33deu6ufh237wvqdt7vycaffbp5y5grxgwyyptoog
[DEBUG] fetching parameters block: 1
2023-01-22T13:45:09.297088Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 24,
    },
    return_data: RawBytes {  },
    gas_used: 12325696,
    events_root: None,
}
2023-01-22T13:45:09.297103Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 203,
                    method: 3844450837,
                    code: ExitCode {
                        value: 24,
                    },
                    message: "panicked at 'called `Option::unwrap()` on a `None` value', actors/evm/src/interpreter/system.rs:210:22",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-22T13:45:09.297157Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 1
2023-01-22T13:45:09.297181Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_HighNonceDelegatecall"::Berlin::1
2023-01-22T13:45:09.297188Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stCreate2/CREATE2_HighNonceDelegatecall.json"
2023-01-22T13:45:09.297195Z  INFO evm_eth_compliance::statetest::runner: TX len : 132
2023-01-22T13:45:09.297201Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [208, 97, 176, 138, 132, 235, 199, 15, 231, 151, 249, 189, 98, 244, 38, 158, 248, 39, 74, 19, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([41, 144, 215, 158, 252, 240, 131, 109, 15, 144, 3, 221, 34, 42, 228, 35, 224, 218, 9, 210]) }
[DEBUG] getting cid: bafy2bzacedef2iioq5zx33deu6ufh237wvqdt7vycaffbp5y5grxgwyyptoog
[DEBUG] fetching parameters block: 1
2023-01-22T13:45:09.300711Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 24,
    },
    return_data: RawBytes {  },
    gas_used: 12629130,
    events_root: None,
}
2023-01-22T13:45:09.300726Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 203,
                    method: 3844450837,
                    code: ExitCode {
                        value: 24,
                    },
                    message: "panicked at 'called `Option::unwrap()` on a `None` value', actors/evm/src/interpreter/system.rs:210:22",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-22T13:45:09.300779Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 2
2023-01-22T13:45:09.300802Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_HighNonceDelegatecall"::Berlin::2
2023-01-22T13:45:09.300809Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stCreate2/CREATE2_HighNonceDelegatecall.json"
2023-01-22T13:45:09.300816Z  INFO evm_eth_compliance::statetest::runner: TX len : 132
2023-01-22T13:45:09.300822Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [208, 97, 176, 138, 132, 235, 199, 15, 231, 151, 249, 189, 98, 244, 38, 158, 248, 39, 74, 19, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([54, 140, 199, 165, 133, 117, 18, 215, 66, 153, 234, 211, 197, 77, 137, 96, 114, 167, 13, 75]) }
[DEBUG] getting cid: bafy2bzacedef2iioq5zx33deu6ufh237wvqdt7vycaffbp5y5grxgwyyptoog
[DEBUG] fetching parameters block: 1
2023-01-22T13:45:09.304309Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 24,
    },
    return_data: RawBytes {  },
    gas_used: 12632533,
    events_root: None,
}
2023-01-22T13:45:09.304325Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 203,
                    method: 3844450837,
                    code: ExitCode {
                        value: 24,
                    },
                    message: "panicked at 'called `Option::unwrap()` on a `None` value', actors/evm/src/interpreter/system.rs:210:22",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-22T13:45:09.304392Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 3
2023-01-22T13:45:09.304426Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_HighNonceDelegatecall"::Berlin::3
2023-01-22T13:45:09.304437Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stCreate2/CREATE2_HighNonceDelegatecall.json"
2023-01-22T13:45:09.304447Z  INFO evm_eth_compliance::statetest::runner: TX len : 132
2023-01-22T13:45:09.304457Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [208, 97, 176, 138, 132, 235, 199, 15, 231, 151, 249, 189, 98, 244, 38, 158, 248, 39, 74, 19, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([239, 165, 144, 40, 183, 72, 233, 8, 233, 179, 217, 27, 205, 204, 157, 197, 219, 127, 14, 35]) }
[DEBUG] getting cid: bafy2bzacedef2iioq5zx33deu6ufh237wvqdt7vycaffbp5y5grxgwyyptoog
[DEBUG] fetching parameters block: 1
2023-01-22T13:45:09.307827Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 24,
    },
    return_data: RawBytes {  },
    gas_used: 11806885,
    events_root: None,
}
2023-01-22T13:45:09.307843Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 203,
                    method: 3844450837,
                    code: ExitCode {
                        value: 24,
                    },
                    message: "panicked at 'called `Option::unwrap()` on a `None` value', actors/evm/src/interpreter/system.rs:210:22",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-22T13:45:09.307894Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 4
2023-01-22T13:45:09.307917Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_HighNonceDelegatecall"::Berlin::4
2023-01-22T13:45:09.307924Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stCreate2/CREATE2_HighNonceDelegatecall.json"
2023-01-22T13:45:09.307931Z  INFO evm_eth_compliance::statetest::runner: TX len : 132
2023-01-22T13:45:09.307937Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [208, 97, 176, 138, 132, 235, 199, 15, 231, 151, 249, 189, 98, 244, 38, 158, 248, 39, 74, 19, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([145, 39, 57, 40, 244, 97, 114, 211, 157, 178, 230, 42, 204, 136, 110, 218, 94, 3, 133, 15]) }
[DEBUG] getting cid: bafy2bzacedef2iioq5zx33deu6ufh237wvqdt7vycaffbp5y5grxgwyyptoog
[DEBUG] fetching parameters block: 1
2023-01-22T13:45:09.311445Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 24,
    },
    return_data: RawBytes {  },
    gas_used: 12628099,
    events_root: None,
}
2023-01-22T13:45:09.311465Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 203,
                    method: 3844450837,
                    code: ExitCode {
                        value: 24,
                    },
                    message: "panicked at 'called `Option::unwrap()` on a `None` value', actors/evm/src/interpreter/system.rs:210:22",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-22T13:45:09.311519Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 5
2023-01-22T13:45:09.311542Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_HighNonceDelegatecall"::Berlin::5
2023-01-22T13:45:09.311549Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stCreate2/CREATE2_HighNonceDelegatecall.json"
2023-01-22T13:45:09.311556Z  INFO evm_eth_compliance::statetest::runner: TX len : 132
2023-01-22T13:45:09.311562Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [208, 97, 176, 138, 132, 235, 199, 15, 231, 151, 249, 189, 98, 244, 38, 158, 248, 39, 74, 19, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([43, 121, 247, 50, 237, 37, 132, 48, 70, 152, 225, 148, 95, 26, 219, 87, 32, 242, 98, 90]) }
[DEBUG] getting cid: bafy2bzacedef2iioq5zx33deu6ufh237wvqdt7vycaffbp5y5grxgwyyptoog
[DEBUG] fetching parameters block: 1
2023-01-22T13:45:09.314994Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 24,
    },
    return_data: RawBytes {  },
    gas_used: 12615213,
    events_root: None,
}
2023-01-22T13:45:09.315009Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 203,
                    method: 3844450837,
                    code: ExitCode {
                        value: 24,
                    },
                    message: "panicked at 'called `Option::unwrap()` on a `None` value', actors/evm/src/interpreter/system.rs:210:22",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-22T13:45:09.315063Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 18
2023-01-22T13:45:09.315088Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_HighNonceDelegatecall"::Berlin::18
2023-01-22T13:45:09.315095Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stCreate2/CREATE2_HighNonceDelegatecall.json"
2023-01-22T13:45:09.315102Z  INFO evm_eth_compliance::statetest::runner: TX len : 132
2023-01-22T13:45:09.315108Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [208, 97, 176, 138, 132, 235, 199, 15, 231, 151, 249, 189, 98, 244, 38, 158, 248, 39, 74, 19, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([184, 255, 181, 20, 221, 252, 201, 27, 63, 8, 16, 146, 19, 110, 18, 158, 84, 214, 49, 125]) }
[DEBUG] getting cid: bafy2bzacedef2iioq5zx33deu6ufh237wvqdt7vycaffbp5y5grxgwyyptoog
[DEBUG] fetching parameters block: 1
2023-01-22T13:45:09.318492Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 24,
    },
    return_data: RawBytes {  },
    gas_used: 11805497,
    events_root: None,
}
2023-01-22T13:45:09.318508Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 203,
                    method: 3844450837,
                    code: ExitCode {
                        value: 24,
                    },
                    message: "panicked at 'called `Option::unwrap()` on a `None` value', actors/evm/src/interpreter/system.rs:210:22",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-22T13:45:09.318559Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 19
2023-01-22T13:45:09.318582Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_HighNonceDelegatecall"::Berlin::19
2023-01-22T13:45:09.318589Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stCreate2/CREATE2_HighNonceDelegatecall.json"
2023-01-22T13:45:09.318596Z  INFO evm_eth_compliance::statetest::runner: TX len : 132
2023-01-22T13:45:09.318602Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [208, 97, 176, 138, 132, 235, 199, 15, 231, 151, 249, 189, 98, 244, 38, 158, 248, 39, 74, 19, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([5, 105, 242, 156, 75, 161, 251, 173, 228, 244, 156, 55, 159, 15, 30, 21, 129, 208, 49, 115]) }
[DEBUG] getting cid: bafy2bzacedef2iioq5zx33deu6ufh237wvqdt7vycaffbp5y5grxgwyyptoog
[DEBUG] fetching parameters block: 1
2023-01-22T13:45:09.322106Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 24,
    },
    return_data: RawBytes {  },
    gas_used: 12656343,
    events_root: None,
}
2023-01-22T13:45:09.322122Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 203,
                    method: 3844450837,
                    code: ExitCode {
                        value: 24,
                    },
                    message: "panicked at 'called `Option::unwrap()` on a `None` value', actors/evm/src/interpreter/system.rs:210:22",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-22T13:45:09.322174Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 20
2023-01-22T13:45:09.322198Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_HighNonceDelegatecall"::Berlin::20
2023-01-22T13:45:09.322205Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stCreate2/CREATE2_HighNonceDelegatecall.json"
2023-01-22T13:45:09.322212Z  INFO evm_eth_compliance::statetest::runner: TX len : 132
2023-01-22T13:45:09.322218Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [208, 97, 176, 138, 132, 235, 199, 15, 231, 151, 249, 189, 98, 244, 38, 158, 248, 39, 74, 19, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([132, 183, 224, 215, 231, 71, 205, 164, 221, 233, 232, 111, 213, 234, 70, 82, 92, 231, 191, 172]) }
[DEBUG] getting cid: bafy2bzacedef2iioq5zx33deu6ufh237wvqdt7vycaffbp5y5grxgwyyptoog
[DEBUG] fetching parameters block: 1
2023-01-22T13:45:09.325729Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 24,
    },
    return_data: RawBytes {  },
    gas_used: 12706623,
    events_root: None,
}
2023-01-22T13:45:09.325745Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 203,
                    method: 3844450837,
                    code: ExitCode {
                        value: 24,
                    },
                    message: "panicked at 'called `Option::unwrap()` on a `None` value', actors/evm/src/interpreter/system.rs:210:22",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-22T13:45:09.325796Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 21
2023-01-22T13:45:09.325827Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_HighNonceDelegatecall"::Berlin::21
2023-01-22T13:45:09.325840Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stCreate2/CREATE2_HighNonceDelegatecall.json"
2023-01-22T13:45:09.325847Z  INFO evm_eth_compliance::statetest::runner: TX len : 132
2023-01-22T13:45:09.325853Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [208, 97, 176, 138, 132, 235, 199, 15, 231, 151, 249, 189, 98, 244, 38, 158, 248, 39, 74, 19, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([165, 61, 106, 15, 46, 11, 223, 246, 4, 93, 31, 89, 52, 0, 67, 121, 23, 247, 59, 138]) }
[DEBUG] getting cid: bafy2bzacedef2iioq5zx33deu6ufh237wvqdt7vycaffbp5y5grxgwyyptoog
[DEBUG] fetching parameters block: 1
2023-01-22T13:45:09.329325Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 24,
    },
    return_data: RawBytes {  },
    gas_used: 12333490,
    events_root: None,
}
2023-01-22T13:45:09.329340Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 203,
                    method: 3844450837,
                    code: ExitCode {
                        value: 24,
                    },
                    message: "panicked at 'called `Option::unwrap()` on a `None` value', actors/evm/src/interpreter/system.rs:210:22",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-22T13:45:09.329394Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 22
2023-01-22T13:45:09.329426Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_HighNonceDelegatecall"::Berlin::22
2023-01-22T13:45:09.329443Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stCreate2/CREATE2_HighNonceDelegatecall.json"
2023-01-22T13:45:09.329453Z  INFO evm_eth_compliance::statetest::runner: TX len : 132
2023-01-22T13:45:09.329463Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [208, 97, 176, 138, 132, 235, 199, 15, 231, 151, 249, 189, 98, 244, 38, 158, 248, 39, 74, 19, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([166, 33, 73, 89, 43, 117, 95, 36, 123, 177, 163, 118, 200, 201, 50, 148, 185, 37, 107, 154]) }
[DEBUG] getting cid: bafy2bzacedef2iioq5zx33deu6ufh237wvqdt7vycaffbp5y5grxgwyyptoog
[DEBUG] fetching parameters block: 1
2023-01-22T13:45:09.332996Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 24,
    },
    return_data: RawBytes {  },
    gas_used: 12629126,
    events_root: None,
}
2023-01-22T13:45:09.333012Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 203,
                    method: 3844450837,
                    code: ExitCode {
                        value: 24,
                    },
                    message: "panicked at 'called `Option::unwrap()` on a `None` value', actors/evm/src/interpreter/system.rs:210:22",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-22T13:45:09.333065Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 23
2023-01-22T13:45:09.333089Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_HighNonceDelegatecall"::Berlin::23
2023-01-22T13:45:09.333096Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stCreate2/CREATE2_HighNonceDelegatecall.json"
2023-01-22T13:45:09.333103Z  INFO evm_eth_compliance::statetest::runner: TX len : 132
2023-01-22T13:45:09.333109Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [208, 97, 176, 138, 132, 235, 199, 15, 231, 151, 249, 189, 98, 244, 38, 158, 248, 39, 74, 19, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([148, 193, 25, 127, 138, 190, 135, 142, 9, 94, 134, 72, 116, 183, 208, 145, 89, 123, 125, 176]) }
[DEBUG] getting cid: bafy2bzacedef2iioq5zx33deu6ufh237wvqdt7vycaffbp5y5grxgwyyptoog
[DEBUG] fetching parameters block: 1
2023-01-22T13:45:09.337332Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 24,
    },
    return_data: RawBytes {  },
    gas_used: 12706624,
    events_root: None,
}
2023-01-22T13:45:09.337358Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 203,
                    method: 3844450837,
                    code: ExitCode {
                        value: 24,
                    },
                    message: "panicked at 'called `Option::unwrap()` on a `None` value', actors/evm/src/interpreter/system.rs:210:22",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-22T13:45:09.337439Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 12
2023-01-22T13:45:09.337481Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_HighNonceDelegatecall"::Berlin::12
2023-01-22T13:45:09.337489Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stCreate2/CREATE2_HighNonceDelegatecall.json"
2023-01-22T13:45:09.337497Z  INFO evm_eth_compliance::statetest::runner: TX len : 132
2023-01-22T13:45:09.337504Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [208, 97, 176, 138, 132, 235, 199, 15, 231, 151, 249, 189, 98, 244, 38, 158, 248, 39, 74, 19, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([123, 226, 50, 52, 222, 73, 76, 23, 47, 7, 197, 161, 190, 22, 190, 175, 154, 153, 133, 213]) }
[DEBUG] getting cid: bafy2bzacedef2iioq5zx33deu6ufh237wvqdt7vycaffbp5y5grxgwyyptoog
[DEBUG] fetching parameters block: 1
2023-01-22T13:45:09.341286Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 24,
    },
    return_data: RawBytes {  },
    gas_used: 12326320,
    events_root: None,
}
2023-01-22T13:45:09.341301Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 203,
                    method: 3844450837,
                    code: ExitCode {
                        value: 24,
                    },
                    message: "panicked at 'called `Option::unwrap()` on a `None` value', actors/evm/src/interpreter/system.rs:210:22",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-22T13:45:09.341357Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 13
2023-01-22T13:45:09.341384Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_HighNonceDelegatecall"::Berlin::13
2023-01-22T13:45:09.341392Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stCreate2/CREATE2_HighNonceDelegatecall.json"
2023-01-22T13:45:09.341399Z  INFO evm_eth_compliance::statetest::runner: TX len : 132
2023-01-22T13:45:09.341406Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [208, 97, 176, 138, 132, 235, 199, 15, 231, 151, 249, 189, 98, 244, 38, 158, 248, 39, 74, 19, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([206, 5, 126, 171, 226, 44, 99, 187, 109, 146, 70, 233, 204, 42, 34, 178, 199, 101, 125, 42]) }
[DEBUG] getting cid: bafy2bzacedef2iioq5zx33deu6ufh237wvqdt7vycaffbp5y5grxgwyyptoog
[DEBUG] fetching parameters block: 1
2023-01-22T13:45:09.345011Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 24,
    },
    return_data: RawBytes {  },
    gas_used: 12340905,
    events_root: None,
}
2023-01-22T13:45:09.345027Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 203,
                    method: 3844450837,
                    code: ExitCode {
                        value: 24,
                    },
                    message: "panicked at 'called `Option::unwrap()` on a `None` value', actors/evm/src/interpreter/system.rs:210:22",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-22T13:45:09.345083Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 14
2023-01-22T13:45:09.345107Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_HighNonceDelegatecall"::Berlin::14
2023-01-22T13:45:09.345115Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stCreate2/CREATE2_HighNonceDelegatecall.json"
2023-01-22T13:45:09.345122Z  INFO evm_eth_compliance::statetest::runner: TX len : 132
2023-01-22T13:45:09.345129Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [208, 97, 176, 138, 132, 235, 199, 15, 231, 151, 249, 189, 98, 244, 38, 158, 248, 39, 74, 19, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([229, 134, 218, 28, 173, 120, 102, 217, 86, 17, 87, 148, 11, 132, 141, 172, 158, 89, 43, 245]) }
[DEBUG] getting cid: bafy2bzacedef2iioq5zx33deu6ufh237wvqdt7vycaffbp5y5grxgwyyptoog
[DEBUG] fetching parameters block: 1
2023-01-22T13:45:09.348796Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 24,
    },
    return_data: RawBytes {  },
    gas_used: 12646197,
    events_root: None,
}
2023-01-22T13:45:09.348812Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 203,
                    method: 3844450837,
                    code: ExitCode {
                        value: 24,
                    },
                    message: "panicked at 'called `Option::unwrap()` on a `None` value', actors/evm/src/interpreter/system.rs:210:22",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-22T13:45:09.348868Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 15
2023-01-22T13:45:09.348895Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_HighNonceDelegatecall"::Berlin::15
2023-01-22T13:45:09.348903Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stCreate2/CREATE2_HighNonceDelegatecall.json"
2023-01-22T13:45:09.348911Z  INFO evm_eth_compliance::statetest::runner: TX len : 132
2023-01-22T13:45:09.348917Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [208, 97, 176, 138, 132, 235, 199, 15, 231, 151, 249, 189, 98, 244, 38, 158, 248, 39, 74, 19, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([223, 202, 140, 233, 184, 139, 245, 92, 60, 253, 237, 185, 78, 222, 238, 205, 254, 61, 116, 112]) }
[DEBUG] getting cid: bafy2bzacedef2iioq5zx33deu6ufh237wvqdt7vycaffbp5y5grxgwyyptoog
[DEBUG] fetching parameters block: 1
2023-01-22T13:45:09.352836Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 24,
    },
    return_data: RawBytes {  },
    gas_used: 12706856,
    events_root: None,
}
2023-01-22T13:45:09.352868Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 203,
                    method: 3844450837,
                    code: ExitCode {
                        value: 24,
                    },
                    message: "panicked at 'called `Option::unwrap()` on a `None` value', actors/evm/src/interpreter/system.rs:210:22",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-22T13:45:09.352966Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 16
2023-01-22T13:45:09.353023Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_HighNonceDelegatecall"::Berlin::16
2023-01-22T13:45:09.353037Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stCreate2/CREATE2_HighNonceDelegatecall.json"
2023-01-22T13:45:09.353049Z  INFO evm_eth_compliance::statetest::runner: TX len : 132
2023-01-22T13:45:09.353059Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [208, 97, 176, 138, 132, 235, 199, 15, 231, 151, 249, 189, 98, 244, 38, 158, 248, 39, 74, 19, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([27, 47, 20, 62, 115, 89, 64, 100, 228, 180, 154, 197, 75, 89, 74, 3, 65, 136, 122, 18]) }
[DEBUG] getting cid: bafy2bzacedef2iioq5zx33deu6ufh237wvqdt7vycaffbp5y5grxgwyyptoog
[DEBUG] fetching parameters block: 1
2023-01-22T13:45:09.357309Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 24,
    },
    return_data: RawBytes {  },
    gas_used: 12645797,
    events_root: None,
}
2023-01-22T13:45:09.357336Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 203,
                    method: 3844450837,
                    code: ExitCode {
                        value: 24,
                    },
                    message: "panicked at 'called `Option::unwrap()` on a `None` value', actors/evm/src/interpreter/system.rs:210:22",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-22T13:45:09.357402Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 17
2023-01-22T13:45:09.357444Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_HighNonceDelegatecall"::Berlin::17
2023-01-22T13:45:09.357452Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stCreate2/CREATE2_HighNonceDelegatecall.json"
2023-01-22T13:45:09.357460Z  INFO evm_eth_compliance::statetest::runner: TX len : 132
2023-01-22T13:45:09.357466Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [208, 97, 176, 138, 132, 235, 199, 15, 231, 151, 249, 189, 98, 244, 38, 158, 248, 39, 74, 19, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([149, 71, 225, 67, 173, 140, 14, 147, 102, 27, 208, 141, 97, 205, 181, 63, 253, 204, 193, 100]) }
[DEBUG] getting cid: bafy2bzacedef2iioq5zx33deu6ufh237wvqdt7vycaffbp5y5grxgwyyptoog
[DEBUG] fetching parameters block: 1
2023-01-22T13:45:09.361377Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 24,
    },
    return_data: RawBytes {  },
    gas_used: 12703787,
    events_root: None,
}
2023-01-22T13:45:09.361399Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 203,
                    method: 3844450837,
                    code: ExitCode {
                        value: 24,
                    },
                    message: "panicked at 'called `Option::unwrap()` on a `None` value', actors/evm/src/interpreter/system.rs:210:22",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-22T13:45:09.361464Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 6
2023-01-22T13:45:09.361505Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_HighNonceDelegatecall"::London::6
2023-01-22T13:45:09.361512Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stCreate2/CREATE2_HighNonceDelegatecall.json"
2023-01-22T13:45:09.361520Z  INFO evm_eth_compliance::statetest::runner: TX len : 132
2023-01-22T13:45:09.361526Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [208, 97, 176, 138, 132, 235, 199, 15, 231, 151, 249, 189, 98, 244, 38, 158, 248, 39, 74, 19, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([137, 145, 54, 83, 246, 51, 78, 58, 91, 216, 106, 48, 128, 183, 231, 127, 217, 76, 111, 78]) }
[DEBUG] getting cid: bafy2bzacedef2iioq5zx33deu6ufh237wvqdt7vycaffbp5y5grxgwyyptoog
[DEBUG] fetching parameters block: 1
2023-01-22T13:45:09.365989Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 24,
    },
    return_data: RawBytes {  },
    gas_used: 12702980,
    events_root: None,
}
2023-01-22T13:45:09.366016Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 203,
                    method: 3844450837,
                    code: ExitCode {
                        value: 24,
                    },
                    message: "panicked at 'called `Option::unwrap()` on a `None` value', actors/evm/src/interpreter/system.rs:210:22",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-22T13:45:09.366089Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 7
2023-01-22T13:45:09.366133Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_HighNonceDelegatecall"::London::7
2023-01-22T13:45:09.366141Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stCreate2/CREATE2_HighNonceDelegatecall.json"
2023-01-22T13:45:09.366148Z  INFO evm_eth_compliance::statetest::runner: TX len : 132
2023-01-22T13:45:09.366155Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [208, 97, 176, 138, 132, 235, 199, 15, 231, 151, 249, 189, 98, 244, 38, 158, 248, 39, 74, 19, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([159, 71, 60, 185, 123, 210, 99, 236, 135, 165, 57, 125, 84, 113, 104, 125, 111, 150, 82, 231]) }
[DEBUG] getting cid: bafy2bzacedef2iioq5zx33deu6ufh237wvqdt7vycaffbp5y5grxgwyyptoog
[DEBUG] fetching parameters block: 1
2023-01-22T13:45:09.369979Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 24,
    },
    return_data: RawBytes {  },
    gas_used: 12706370,
    events_root: None,
}
2023-01-22T13:45:09.369995Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 203,
                    method: 3844450837,
                    code: ExitCode {
                        value: 24,
                    },
                    message: "panicked at 'called `Option::unwrap()` on a `None` value', actors/evm/src/interpreter/system.rs:210:22",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-22T13:45:09.370050Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 8
2023-01-22T13:45:09.370076Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_HighNonceDelegatecall"::London::8
2023-01-22T13:45:09.370083Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stCreate2/CREATE2_HighNonceDelegatecall.json"
2023-01-22T13:45:09.370091Z  INFO evm_eth_compliance::statetest::runner: TX len : 132
2023-01-22T13:45:09.370097Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [208, 97, 176, 138, 132, 235, 199, 15, 231, 151, 249, 189, 98, 244, 38, 158, 248, 39, 74, 19, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([9, 224, 232, 168, 153, 181, 62, 58, 189, 119, 63, 170, 224, 170, 186, 134, 128, 166, 153, 2]) }
[DEBUG] getting cid: bafy2bzacedef2iioq5zx33deu6ufh237wvqdt7vycaffbp5y5grxgwyyptoog
[DEBUG] fetching parameters block: 1
2023-01-22T13:45:09.373648Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 24,
    },
    return_data: RawBytes {  },
    gas_used: 11848906,
    events_root: None,
}
2023-01-22T13:45:09.373664Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 203,
                    method: 3844450837,
                    code: ExitCode {
                        value: 24,
                    },
                    message: "panicked at 'called `Option::unwrap()` on a `None` value', actors/evm/src/interpreter/system.rs:210:22",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-22T13:45:09.373718Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 9
2023-01-22T13:45:09.373743Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_HighNonceDelegatecall"::London::9
2023-01-22T13:45:09.373750Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stCreate2/CREATE2_HighNonceDelegatecall.json"
2023-01-22T13:45:09.373758Z  INFO evm_eth_compliance::statetest::runner: TX len : 132
2023-01-22T13:45:09.373764Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [208, 97, 176, 138, 132, 235, 199, 15, 231, 151, 249, 189, 98, 244, 38, 158, 248, 39, 74, 19, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([72, 105, 66, 48, 74, 19, 182, 9, 127, 234, 99, 15, 143, 107, 125, 55, 183, 169, 1, 75]) }
[DEBUG] getting cid: bafy2bzacedef2iioq5zx33deu6ufh237wvqdt7vycaffbp5y5grxgwyyptoog
[DEBUG] fetching parameters block: 1
2023-01-22T13:45:09.377354Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 24,
    },
    return_data: RawBytes {  },
    gas_used: 12332713,
    events_root: None,
}
2023-01-22T13:45:09.377369Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 203,
                    method: 3844450837,
                    code: ExitCode {
                        value: 24,
                    },
                    message: "panicked at 'called `Option::unwrap()` on a `None` value', actors/evm/src/interpreter/system.rs:210:22",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-22T13:45:09.377432Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 10
2023-01-22T13:45:09.377456Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_HighNonceDelegatecall"::London::10
2023-01-22T13:45:09.377464Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stCreate2/CREATE2_HighNonceDelegatecall.json"
2023-01-22T13:45:09.377471Z  INFO evm_eth_compliance::statetest::runner: TX len : 132
2023-01-22T13:45:09.377478Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [208, 97, 176, 138, 132, 235, 199, 15, 231, 151, 249, 189, 98, 244, 38, 158, 248, 39, 74, 19, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([173, 13, 34, 169, 194, 222, 156, 216, 136, 151, 149, 175, 128, 183, 62, 242, 162, 66, 247, 154]) }
[DEBUG] getting cid: bafy2bzacedef2iioq5zx33deu6ufh237wvqdt7vycaffbp5y5grxgwyyptoog
[DEBUG] fetching parameters block: 1
2023-01-22T13:45:09.381058Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 24,
    },
    return_data: RawBytes {  },
    gas_used: 12339006,
    events_root: None,
}
2023-01-22T13:45:09.381076Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 203,
                    method: 3844450837,
                    code: ExitCode {
                        value: 24,
                    },
                    message: "panicked at 'called `Option::unwrap()` on a `None` value', actors/evm/src/interpreter/system.rs:210:22",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-22T13:45:09.381131Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 11
2023-01-22T13:45:09.381155Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_HighNonceDelegatecall"::London::11
2023-01-22T13:45:09.381162Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stCreate2/CREATE2_HighNonceDelegatecall.json"
2023-01-22T13:45:09.381169Z  INFO evm_eth_compliance::statetest::runner: TX len : 132
2023-01-22T13:45:09.381175Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [208, 97, 176, 138, 132, 235, 199, 15, 231, 151, 249, 189, 98, 244, 38, 158, 248, 39, 74, 19, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([131, 115, 166, 173, 188, 201, 114, 218, 180, 15, 32, 132, 97, 59, 168, 72, 199, 135, 26, 237]) }
[DEBUG] getting cid: bafy2bzacedef2iioq5zx33deu6ufh237wvqdt7vycaffbp5y5grxgwyyptoog
[DEBUG] fetching parameters block: 1
2023-01-22T13:45:09.385063Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 24,
    },
    return_data: RawBytes {  },
    gas_used: 11808837,
    events_root: None,
}
2023-01-22T13:45:09.385079Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 203,
                    method: 3844450837,
                    code: ExitCode {
                        value: 24,
                    },
                    message: "panicked at 'called `Option::unwrap()` on a `None` value', actors/evm/src/interpreter/system.rs:210:22",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-22T13:45:09.385137Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-22T13:45:09.385165Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_HighNonceDelegatecall"::London::0
2023-01-22T13:45:09.385173Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stCreate2/CREATE2_HighNonceDelegatecall.json"
2023-01-22T13:45:09.385180Z  INFO evm_eth_compliance::statetest::runner: TX len : 132
2023-01-22T13:45:09.385186Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [208, 97, 176, 138, 132, 235, 199, 15, 231, 151, 249, 189, 98, 244, 38, 158, 248, 39, 74, 19, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([18, 39, 234, 47, 187, 115, 16, 236, 114, 133, 188, 67, 197, 218, 58, 244, 8, 111, 45, 93]) }
[DEBUG] getting cid: bafy2bzacedef2iioq5zx33deu6ufh237wvqdt7vycaffbp5y5grxgwyyptoog
[DEBUG] fetching parameters block: 1
2023-01-22T13:45:09.389010Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 24,
    },
    return_data: RawBytes {  },
    gas_used: 12647608,
    events_root: None,
}
2023-01-22T13:45:09.389025Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 203,
                    method: 3844450837,
                    code: ExitCode {
                        value: 24,
                    },
                    message: "panicked at 'called `Option::unwrap()` on a `None` value', actors/evm/src/interpreter/system.rs:210:22",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-22T13:45:09.389081Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 1
2023-01-22T13:45:09.389107Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_HighNonceDelegatecall"::London::1
2023-01-22T13:45:09.389114Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stCreate2/CREATE2_HighNonceDelegatecall.json"
2023-01-22T13:45:09.389122Z  INFO evm_eth_compliance::statetest::runner: TX len : 132
2023-01-22T13:45:09.389128Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [208, 97, 176, 138, 132, 235, 199, 15, 231, 151, 249, 189, 98, 244, 38, 158, 248, 39, 74, 19, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([196, 252, 58, 192, 43, 102, 19, 227, 208, 48, 84, 217, 49, 54, 72, 20, 86, 249, 108, 199]) }
[DEBUG] getting cid: bafy2bzacedef2iioq5zx33deu6ufh237wvqdt7vycaffbp5y5grxgwyyptoog
[DEBUG] fetching parameters block: 1
2023-01-22T13:45:09.393429Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 24,
    },
    return_data: RawBytes {  },
    gas_used: 12326167,
    events_root: None,
}
2023-01-22T13:45:09.393456Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 203,
                    method: 3844450837,
                    code: ExitCode {
                        value: 24,
                    },
                    message: "panicked at 'called `Option::unwrap()` on a `None` value', actors/evm/src/interpreter/system.rs:210:22",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-22T13:45:09.393529Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 2
2023-01-22T13:45:09.393574Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_HighNonceDelegatecall"::London::2
2023-01-22T13:45:09.393582Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stCreate2/CREATE2_HighNonceDelegatecall.json"
2023-01-22T13:45:09.393590Z  INFO evm_eth_compliance::statetest::runner: TX len : 132
2023-01-22T13:45:09.393596Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [208, 97, 176, 138, 132, 235, 199, 15, 231, 151, 249, 189, 98, 244, 38, 158, 248, 39, 74, 19, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([104, 100, 146, 14, 168, 38, 124, 198, 79, 189, 132, 64, 2, 229, 247, 115, 204, 163, 78, 56]) }
[DEBUG] getting cid: bafy2bzacedef2iioq5zx33deu6ufh237wvqdt7vycaffbp5y5grxgwyyptoog
[DEBUG] fetching parameters block: 1
2023-01-22T13:45:09.397884Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 24,
    },
    return_data: RawBytes {  },
    gas_used: 12644327,
    events_root: None,
}
2023-01-22T13:45:09.397911Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 203,
                    method: 3844450837,
                    code: ExitCode {
                        value: 24,
                    },
                    message: "panicked at 'called `Option::unwrap()` on a `None` value', actors/evm/src/interpreter/system.rs:210:22",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-22T13:45:09.397982Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 3
2023-01-22T13:45:09.398025Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_HighNonceDelegatecall"::London::3
2023-01-22T13:45:09.398034Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stCreate2/CREATE2_HighNonceDelegatecall.json"
2023-01-22T13:45:09.398042Z  INFO evm_eth_compliance::statetest::runner: TX len : 132
2023-01-22T13:45:09.398048Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [208, 97, 176, 138, 132, 235, 199, 15, 231, 151, 249, 189, 98, 244, 38, 158, 248, 39, 74, 19, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([248, 236, 36, 139, 209, 50, 63, 77, 176, 13, 235, 83, 117, 214, 72, 106, 36, 231, 224, 83]) }
[DEBUG] getting cid: bafy2bzacedef2iioq5zx33deu6ufh237wvqdt7vycaffbp5y5grxgwyyptoog
[DEBUG] fetching parameters block: 1
2023-01-22T13:45:09.401944Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 24,
    },
    return_data: RawBytes {  },
    gas_used: 12645885,
    events_root: None,
}
2023-01-22T13:45:09.401968Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 203,
                    method: 3844450837,
                    code: ExitCode {
                        value: 24,
                    },
                    message: "panicked at 'called `Option::unwrap()` on a `None` value', actors/evm/src/interpreter/system.rs:210:22",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-22T13:45:09.402031Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 4
2023-01-22T13:45:09.402072Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_HighNonceDelegatecall"::London::4
2023-01-22T13:45:09.402082Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stCreate2/CREATE2_HighNonceDelegatecall.json"
2023-01-22T13:45:09.402090Z  INFO evm_eth_compliance::statetest::runner: TX len : 132
2023-01-22T13:45:09.402097Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [208, 97, 176, 138, 132, 235, 199, 15, 231, 151, 249, 189, 98, 244, 38, 158, 248, 39, 74, 19, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([36, 188, 161, 83, 225, 149, 170, 173, 187, 199, 21, 89, 135, 233, 104, 124, 133, 104, 36, 47]) }
[DEBUG] getting cid: bafy2bzacedef2iioq5zx33deu6ufh237wvqdt7vycaffbp5y5grxgwyyptoog
[DEBUG] fetching parameters block: 1
2023-01-22T13:45:09.406289Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 24,
    },
    return_data: RawBytes {  },
    gas_used: 12629396,
    events_root: None,
}
2023-01-22T13:45:09.406306Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 203,
                    method: 3844450837,
                    code: ExitCode {
                        value: 24,
                    },
                    message: "panicked at 'called `Option::unwrap()` on a `None` value', actors/evm/src/interpreter/system.rs:210:22",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-22T13:45:09.406363Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 5
2023-01-22T13:45:09.406396Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_HighNonceDelegatecall"::London::5
2023-01-22T13:45:09.406403Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stCreate2/CREATE2_HighNonceDelegatecall.json"
2023-01-22T13:45:09.406411Z  INFO evm_eth_compliance::statetest::runner: TX len : 132
2023-01-22T13:45:09.406417Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [208, 97, 176, 138, 132, 235, 199, 15, 231, 151, 249, 189, 98, 244, 38, 158, 248, 39, 74, 19, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([66, 65, 152, 213, 159, 82, 223, 248, 171, 98, 8, 190, 84, 85, 124, 203, 165, 140, 121, 165]) }
[DEBUG] getting cid: bafy2bzacedef2iioq5zx33deu6ufh237wvqdt7vycaffbp5y5grxgwyyptoog
[DEBUG] fetching parameters block: 1
2023-01-22T13:45:09.409990Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 24,
    },
    return_data: RawBytes {  },
    gas_used: 12704051,
    events_root: None,
}
2023-01-22T13:45:09.410007Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 203,
                    method: 3844450837,
                    code: ExitCode {
                        value: 24,
                    },
                    message: "panicked at 'called `Option::unwrap()` on a `None` value', actors/evm/src/interpreter/system.rs:210:22",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-22T13:45:09.410060Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 18
2023-01-22T13:45:09.410084Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_HighNonceDelegatecall"::London::18
2023-01-22T13:45:09.410091Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stCreate2/CREATE2_HighNonceDelegatecall.json"
2023-01-22T13:45:09.410098Z  INFO evm_eth_compliance::statetest::runner: TX len : 132
2023-01-22T13:45:09.410104Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [208, 97, 176, 138, 132, 235, 199, 15, 231, 151, 249, 189, 98, 244, 38, 158, 248, 39, 74, 19, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([245, 222, 198, 130, 175, 92, 183, 6, 115, 219, 17, 82, 10, 189, 100, 94, 176, 56, 53, 204]) }
[DEBUG] getting cid: bafy2bzacedef2iioq5zx33deu6ufh237wvqdt7vycaffbp5y5grxgwyyptoog
[DEBUG] fetching parameters block: 1
2023-01-22T13:45:09.413651Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 24,
    },
    return_data: RawBytes {  },
    gas_used: 12647806,
    events_root: None,
}
2023-01-22T13:45:09.413669Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 203,
                    method: 3844450837,
                    code: ExitCode {
                        value: 24,
                    },
                    message: "panicked at 'called `Option::unwrap()` on a `None` value', actors/evm/src/interpreter/system.rs:210:22",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-22T13:45:09.413721Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 19
2023-01-22T13:45:09.413747Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_HighNonceDelegatecall"::London::19
2023-01-22T13:45:09.413758Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stCreate2/CREATE2_HighNonceDelegatecall.json"
2023-01-22T13:45:09.413768Z  INFO evm_eth_compliance::statetest::runner: TX len : 132
2023-01-22T13:45:09.413777Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [208, 97, 176, 138, 132, 235, 199, 15, 231, 151, 249, 189, 98, 244, 38, 158, 248, 39, 74, 19, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([47, 143, 208, 29, 244, 71, 123, 233, 135, 174, 142, 22, 199, 133, 150, 66, 191, 126, 245, 105]) }
[DEBUG] getting cid: bafy2bzacedef2iioq5zx33deu6ufh237wvqdt7vycaffbp5y5grxgwyyptoog
[DEBUG] fetching parameters block: 1
2023-01-22T13:45:09.417349Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 24,
    },
    return_data: RawBytes {  },
    gas_used: 12648190,
    events_root: None,
}
2023-01-22T13:45:09.417365Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 203,
                    method: 3844450837,
                    code: ExitCode {
                        value: 24,
                    },
                    message: "panicked at 'called `Option::unwrap()` on a `None` value', actors/evm/src/interpreter/system.rs:210:22",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-22T13:45:09.417421Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 20
2023-01-22T13:45:09.417446Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_HighNonceDelegatecall"::London::20
2023-01-22T13:45:09.417453Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stCreate2/CREATE2_HighNonceDelegatecall.json"
2023-01-22T13:45:09.417460Z  INFO evm_eth_compliance::statetest::runner: TX len : 132
2023-01-22T13:45:09.417466Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [208, 97, 176, 138, 132, 235, 199, 15, 231, 151, 249, 189, 98, 244, 38, 158, 248, 39, 74, 19, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([9, 240, 5, 238, 205, 144, 121, 190, 117, 244, 171, 119, 221, 242, 93, 166, 187, 11, 249, 159]) }
[DEBUG] getting cid: bafy2bzacedef2iioq5zx33deu6ufh237wvqdt7vycaffbp5y5grxgwyyptoog
[DEBUG] fetching parameters block: 1
2023-01-22T13:45:09.421327Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 24,
    },
    return_data: RawBytes {  },
    gas_used: 12704921,
    events_root: None,
}
2023-01-22T13:45:09.421350Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 203,
                    method: 3844450837,
                    code: ExitCode {
                        value: 24,
                    },
                    message: "panicked at 'called `Option::unwrap()` on a `None` value', actors/evm/src/interpreter/system.rs:210:22",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-22T13:45:09.421435Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 21
2023-01-22T13:45:09.421483Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_HighNonceDelegatecall"::London::21
2023-01-22T13:45:09.421496Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stCreate2/CREATE2_HighNonceDelegatecall.json"
2023-01-22T13:45:09.421507Z  INFO evm_eth_compliance::statetest::runner: TX len : 132
2023-01-22T13:45:09.421517Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [208, 97, 176, 138, 132, 235, 199, 15, 231, 151, 249, 189, 98, 244, 38, 158, 248, 39, 74, 19, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([127, 22, 74, 146, 31, 240, 94, 4, 5, 0, 168, 124, 152, 159, 106, 186, 166, 245, 96, 1]) }
[DEBUG] getting cid: bafy2bzacedef2iioq5zx33deu6ufh237wvqdt7vycaffbp5y5grxgwyyptoog
[DEBUG] fetching parameters block: 1
2023-01-22T13:45:09.425564Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 24,
    },
    return_data: RawBytes {  },
    gas_used: 12333962,
    events_root: None,
}
2023-01-22T13:45:09.425583Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 203,
                    method: 3844450837,
                    code: ExitCode {
                        value: 24,
                    },
                    message: "panicked at 'called `Option::unwrap()` on a `None` value', actors/evm/src/interpreter/system.rs:210:22",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-22T13:45:09.425641Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 22
2023-01-22T13:45:09.425675Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_HighNonceDelegatecall"::London::22
2023-01-22T13:45:09.425683Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stCreate2/CREATE2_HighNonceDelegatecall.json"
2023-01-22T13:45:09.425691Z  INFO evm_eth_compliance::statetest::runner: TX len : 132
2023-01-22T13:45:09.425697Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [208, 97, 176, 138, 132, 235, 199, 15, 231, 151, 249, 189, 98, 244, 38, 158, 248, 39, 74, 19, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([73, 61, 140, 212, 105, 148, 249, 14, 52, 230, 238, 162, 150, 154, 9, 21, 65, 159, 123, 114]) }
[DEBUG] getting cid: bafy2bzacedef2iioq5zx33deu6ufh237wvqdt7vycaffbp5y5grxgwyyptoog
[DEBUG] fetching parameters block: 1
2023-01-22T13:45:09.429324Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 24,
    },
    return_data: RawBytes {  },
    gas_used: 12646791,
    events_root: None,
}
2023-01-22T13:45:09.429340Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 203,
                    method: 3844450837,
                    code: ExitCode {
                        value: 24,
                    },
                    message: "panicked at 'called `Option::unwrap()` on a `None` value', actors/evm/src/interpreter/system.rs:210:22",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-22T13:45:09.429399Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 23
2023-01-22T13:45:09.429433Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_HighNonceDelegatecall"::London::23
2023-01-22T13:45:09.429445Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stCreate2/CREATE2_HighNonceDelegatecall.json"
2023-01-22T13:45:09.429455Z  INFO evm_eth_compliance::statetest::runner: TX len : 132
2023-01-22T13:45:09.429478Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [208, 97, 176, 138, 132, 235, 199, 15, 231, 151, 249, 189, 98, 244, 38, 158, 248, 39, 74, 19, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([139, 5, 231, 32, 229, 212, 4, 215, 238, 97, 99, 197, 170, 49, 135, 202, 113, 170, 126, 42]) }
[DEBUG] getting cid: bafy2bzacedef2iioq5zx33deu6ufh237wvqdt7vycaffbp5y5grxgwyyptoog
[DEBUG] fetching parameters block: 1
2023-01-22T13:45:09.433600Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 24,
    },
    return_data: RawBytes {  },
    gas_used: 12646501,
    events_root: None,
}
2023-01-22T13:45:09.433620Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 203,
                    method: 3844450837,
                    code: ExitCode {
                        value: 24,
                    },
                    message: "panicked at 'called `Option::unwrap()` on a `None` value', actors/evm/src/interpreter/system.rs:210:22",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-22T13:45:09.433677Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 12
2023-01-22T13:45:09.433709Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_HighNonceDelegatecall"::London::12
2023-01-22T13:45:09.433716Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stCreate2/CREATE2_HighNonceDelegatecall.json"
2023-01-22T13:45:09.433723Z  INFO evm_eth_compliance::statetest::runner: TX len : 132
2023-01-22T13:45:09.433729Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [208, 97, 176, 138, 132, 235, 199, 15, 231, 151, 249, 189, 98, 244, 38, 158, 248, 39, 74, 19, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([116, 63, 104, 161, 128, 157, 77, 211, 34, 225, 247, 206, 99, 136, 227, 1, 169, 47, 205, 63]) }
[DEBUG] getting cid: bafy2bzacedef2iioq5zx33deu6ufh237wvqdt7vycaffbp5y5grxgwyyptoog
[DEBUG] fetching parameters block: 1
2023-01-22T13:45:09.437169Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 24,
    },
    return_data: RawBytes {  },
    gas_used: 11807361,
    events_root: None,
}
2023-01-22T13:45:09.437184Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 203,
                    method: 3844450837,
                    code: ExitCode {
                        value: 24,
                    },
                    message: "panicked at 'called `Option::unwrap()` on a `None` value', actors/evm/src/interpreter/system.rs:210:22",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-22T13:45:09.437232Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 13
2023-01-22T13:45:09.437256Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_HighNonceDelegatecall"::London::13
2023-01-22T13:45:09.437262Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stCreate2/CREATE2_HighNonceDelegatecall.json"
2023-01-22T13:45:09.437269Z  INFO evm_eth_compliance::statetest::runner: TX len : 132
2023-01-22T13:45:09.437276Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [208, 97, 176, 138, 132, 235, 199, 15, 231, 151, 249, 189, 98, 244, 38, 158, 248, 39, 74, 19, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([24, 23, 0, 25, 83, 60, 59, 147, 214, 85, 44, 223, 55, 32, 220, 231, 144, 240, 221, 9]) }
[DEBUG] getting cid: bafy2bzacedef2iioq5zx33deu6ufh237wvqdt7vycaffbp5y5grxgwyyptoog
[DEBUG] fetching parameters block: 1
2023-01-22T13:45:09.440958Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 24,
    },
    return_data: RawBytes {  },
    gas_used: 12643405,
    events_root: None,
}
2023-01-22T13:45:09.440974Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 203,
                    method: 3844450837,
                    code: ExitCode {
                        value: 24,
                    },
                    message: "panicked at 'called `Option::unwrap()` on a `None` value', actors/evm/src/interpreter/system.rs:210:22",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-22T13:45:09.441034Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 14
2023-01-22T13:45:09.441070Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_HighNonceDelegatecall"::London::14
2023-01-22T13:45:09.441079Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stCreate2/CREATE2_HighNonceDelegatecall.json"
2023-01-22T13:45:09.441086Z  INFO evm_eth_compliance::statetest::runner: TX len : 132
2023-01-22T13:45:09.441092Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [208, 97, 176, 138, 132, 235, 199, 15, 231, 151, 249, 189, 98, 244, 38, 158, 248, 39, 74, 19, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([218, 18, 189, 93, 37, 195, 61, 200, 121, 174, 177, 80, 117, 158, 115, 198, 236, 94, 150, 60]) }
[DEBUG] getting cid: bafy2bzacedef2iioq5zx33deu6ufh237wvqdt7vycaffbp5y5grxgwyyptoog
[DEBUG] fetching parameters block: 1
2023-01-22T13:45:09.445038Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 24,
    },
    return_data: RawBytes {  },
    gas_used: 12720906,
    events_root: None,
}
2023-01-22T13:45:09.445058Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 203,
                    method: 3844450837,
                    code: ExitCode {
                        value: 24,
                    },
                    message: "panicked at 'called `Option::unwrap()` on a `None` value', actors/evm/src/interpreter/system.rs:210:22",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-22T13:45:09.445117Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 15
2023-01-22T13:45:09.445151Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_HighNonceDelegatecall"::London::15
2023-01-22T13:45:09.445158Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stCreate2/CREATE2_HighNonceDelegatecall.json"
2023-01-22T13:45:09.445166Z  INFO evm_eth_compliance::statetest::runner: TX len : 132
2023-01-22T13:45:09.445173Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [208, 97, 176, 138, 132, 235, 199, 15, 231, 151, 249, 189, 98, 244, 38, 158, 248, 39, 74, 19, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([185, 91, 157, 88, 96, 101, 55, 73, 90, 229, 142, 243, 119, 115, 114, 183, 43, 146, 80, 225]) }
[DEBUG] getting cid: bafy2bzacedef2iioq5zx33deu6ufh237wvqdt7vycaffbp5y5grxgwyyptoog
[DEBUG] fetching parameters block: 1
2023-01-22T13:45:09.448727Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 24,
    },
    return_data: RawBytes {  },
    gas_used: 12325863,
    events_root: None,
}
2023-01-22T13:45:09.448742Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 203,
                    method: 3844450837,
                    code: ExitCode {
                        value: 24,
                    },
                    message: "panicked at 'called `Option::unwrap()` on a `None` value', actors/evm/src/interpreter/system.rs:210:22",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-22T13:45:09.448796Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 16
2023-01-22T13:45:09.448821Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_HighNonceDelegatecall"::London::16
2023-01-22T13:45:09.448829Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stCreate2/CREATE2_HighNonceDelegatecall.json"
2023-01-22T13:45:09.448836Z  INFO evm_eth_compliance::statetest::runner: TX len : 132
2023-01-22T13:45:09.448841Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [208, 97, 176, 138, 132, 235, 199, 15, 231, 151, 249, 189, 98, 244, 38, 158, 248, 39, 74, 19, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([56, 243, 246, 92, 115, 19, 198, 26, 238, 116, 138, 85, 63, 113, 173, 50, 124, 171, 198, 175]) }
[DEBUG] getting cid: bafy2bzacedef2iioq5zx33deu6ufh237wvqdt7vycaffbp5y5grxgwyyptoog
[DEBUG] fetching parameters block: 1
2023-01-22T13:45:09.452409Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 24,
    },
    return_data: RawBytes {  },
    gas_used: 12646653,
    events_root: None,
}
2023-01-22T13:45:09.452426Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 203,
                    method: 3844450837,
                    code: ExitCode {
                        value: 24,
                    },
                    message: "panicked at 'called `Option::unwrap()` on a `None` value', actors/evm/src/interpreter/system.rs:210:22",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-22T13:45:09.452479Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 17
2023-01-22T13:45:09.452503Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_HighNonceDelegatecall"::London::17
2023-01-22T13:45:09.452510Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stCreate2/CREATE2_HighNonceDelegatecall.json"
2023-01-22T13:45:09.452517Z  INFO evm_eth_compliance::statetest::runner: TX len : 132
2023-01-22T13:45:09.452523Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [208, 97, 176, 138, 132, 235, 199, 15, 231, 151, 249, 189, 98, 244, 38, 158, 248, 39, 74, 19, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([73, 186, 110, 150, 243, 78, 194, 219, 28, 109, 164, 54, 87, 70, 183, 24, 19, 38, 68, 186]) }
[DEBUG] getting cid: bafy2bzacedef2iioq5zx33deu6ufh237wvqdt7vycaffbp5y5grxgwyyptoog
[DEBUG] fetching parameters block: 1
2023-01-22T13:45:09.456882Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 24,
    },
    return_data: RawBytes {  },
    gas_used: 12644354,
    events_root: None,
}
2023-01-22T13:45:09.456906Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 203,
                    method: 3844450837,
                    code: ExitCode {
                        value: 24,
                    },
                    message: "panicked at 'called `Option::unwrap()` on a `None` value', actors/evm/src/interpreter/system.rs:210:22",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-22T13:45:09.456974Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 6
2023-01-22T13:45:09.457016Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_HighNonceDelegatecall"::Merge::6
2023-01-22T13:45:09.457023Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stCreate2/CREATE2_HighNonceDelegatecall.json"
2023-01-22T13:45:09.457031Z  INFO evm_eth_compliance::statetest::runner: TX len : 132
2023-01-22T13:45:09.457037Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [208, 97, 176, 138, 132, 235, 199, 15, 231, 151, 249, 189, 98, 244, 38, 158, 248, 39, 74, 19, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([233, 107, 20, 12, 37, 155, 50, 137, 233, 240, 196, 99, 127, 179, 80, 190, 4, 194, 225, 237]) }
[DEBUG] getting cid: bafy2bzacedef2iioq5zx33deu6ufh237wvqdt7vycaffbp5y5grxgwyyptoog
[DEBUG] fetching parameters block: 1
2023-01-22T13:45:09.460686Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 24,
    },
    return_data: RawBytes {  },
    gas_used: 12629206,
    events_root: None,
}
2023-01-22T13:45:09.460701Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 203,
                    method: 3844450837,
                    code: ExitCode {
                        value: 24,
                    },
                    message: "panicked at 'called `Option::unwrap()` on a `None` value', actors/evm/src/interpreter/system.rs:210:22",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-22T13:45:09.460756Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 7
2023-01-22T13:45:09.460781Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_HighNonceDelegatecall"::Merge::7
2023-01-22T13:45:09.460789Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stCreate2/CREATE2_HighNonceDelegatecall.json"
2023-01-22T13:45:09.460796Z  INFO evm_eth_compliance::statetest::runner: TX len : 132
2023-01-22T13:45:09.460802Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [208, 97, 176, 138, 132, 235, 199, 15, 231, 151, 249, 189, 98, 244, 38, 158, 248, 39, 74, 19, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([28, 26, 191, 187, 28, 234, 77, 252, 28, 24, 75, 240, 211, 118, 185, 19, 78, 149, 70, 245]) }
[DEBUG] getting cid: bafy2bzacedef2iioq5zx33deu6ufh237wvqdt7vycaffbp5y5grxgwyyptoog
[DEBUG] fetching parameters block: 1
2023-01-22T13:45:09.464742Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 24,
    },
    return_data: RawBytes {  },
    gas_used: 12647570,
    events_root: None,
}
2023-01-22T13:45:09.464758Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 203,
                    method: 3844450837,
                    code: ExitCode {
                        value: 24,
                    },
                    message: "panicked at 'called `Option::unwrap()` on a `None` value', actors/evm/src/interpreter/system.rs:210:22",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-22T13:45:09.464815Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 8
2023-01-22T13:45:09.464843Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_HighNonceDelegatecall"::Merge::8
2023-01-22T13:45:09.464851Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stCreate2/CREATE2_HighNonceDelegatecall.json"
2023-01-22T13:45:09.464857Z  INFO evm_eth_compliance::statetest::runner: TX len : 132
2023-01-22T13:45:09.464864Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [208, 97, 176, 138, 132, 235, 199, 15, 231, 151, 249, 189, 98, 244, 38, 158, 248, 39, 74, 19, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([201, 38, 38, 22, 62, 219, 150, 135, 177, 241, 59, 153, 34, 29, 22, 107, 242, 108, 195, 135]) }
[DEBUG] getting cid: bafy2bzacedef2iioq5zx33deu6ufh237wvqdt7vycaffbp5y5grxgwyyptoog
[DEBUG] fetching parameters block: 1
2023-01-22T13:45:09.468645Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 24,
    },
    return_data: RawBytes {  },
    gas_used: 11809145,
    events_root: None,
}
2023-01-22T13:45:09.468668Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 203,
                    method: 3844450837,
                    code: ExitCode {
                        value: 24,
                    },
                    message: "panicked at 'called `Option::unwrap()` on a `None` value', actors/evm/src/interpreter/system.rs:210:22",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-22T13:45:09.468727Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 9
2023-01-22T13:45:09.468763Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_HighNonceDelegatecall"::Merge::9
2023-01-22T13:45:09.468771Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stCreate2/CREATE2_HighNonceDelegatecall.json"
2023-01-22T13:45:09.468778Z  INFO evm_eth_compliance::statetest::runner: TX len : 132
2023-01-22T13:45:09.468785Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [208, 97, 176, 138, 132, 235, 199, 15, 231, 151, 249, 189, 98, 244, 38, 158, 248, 39, 74, 19, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([145, 33, 89, 45, 120, 162, 235, 138, 158, 220, 105, 187, 248, 227, 88, 59, 111, 227, 175, 120]) }
[DEBUG] getting cid: bafy2bzacedef2iioq5zx33deu6ufh237wvqdt7vycaffbp5y5grxgwyyptoog
[DEBUG] fetching parameters block: 1
2023-01-22T13:45:09.472359Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 24,
    },
    return_data: RawBytes {  },
    gas_used: 12338937,
    events_root: None,
}
2023-01-22T13:45:09.472375Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 203,
                    method: 3844450837,
                    code: ExitCode {
                        value: 24,
                    },
                    message: "panicked at 'called `Option::unwrap()` on a `None` value', actors/evm/src/interpreter/system.rs:210:22",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-22T13:45:09.472429Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 10
2023-01-22T13:45:09.472455Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_HighNonceDelegatecall"::Merge::10
2023-01-22T13:45:09.472462Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stCreate2/CREATE2_HighNonceDelegatecall.json"
2023-01-22T13:45:09.472469Z  INFO evm_eth_compliance::statetest::runner: TX len : 132
2023-01-22T13:45:09.472475Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [208, 97, 176, 138, 132, 235, 199, 15, 231, 151, 249, 189, 98, 244, 38, 158, 248, 39, 74, 19, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([92, 78, 32, 183, 20, 116, 160, 24, 93, 13, 74, 60, 71, 47, 68, 214, 9, 69, 33, 242]) }
[DEBUG] getting cid: bafy2bzacedef2iioq5zx33deu6ufh237wvqdt7vycaffbp5y5grxgwyyptoog
[DEBUG] fetching parameters block: 1
2023-01-22T13:45:09.476057Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 24,
    },
    return_data: RawBytes {  },
    gas_used: 12646631,
    events_root: None,
}
2023-01-22T13:45:09.476073Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 203,
                    method: 3844450837,
                    code: ExitCode {
                        value: 24,
                    },
                    message: "panicked at 'called `Option::unwrap()` on a `None` value', actors/evm/src/interpreter/system.rs:210:22",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-22T13:45:09.476127Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 11
2023-01-22T13:45:09.476150Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_HighNonceDelegatecall"::Merge::11
2023-01-22T13:45:09.476159Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stCreate2/CREATE2_HighNonceDelegatecall.json"
2023-01-22T13:45:09.476166Z  INFO evm_eth_compliance::statetest::runner: TX len : 132
2023-01-22T13:45:09.476172Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [208, 97, 176, 138, 132, 235, 199, 15, 231, 151, 249, 189, 98, 244, 38, 158, 248, 39, 74, 19, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([29, 170, 11, 152, 113, 250, 63, 241, 164, 232, 205, 177, 191, 59, 170, 2, 166, 154, 6, 141]) }
[DEBUG] getting cid: bafy2bzacedef2iioq5zx33deu6ufh237wvqdt7vycaffbp5y5grxgwyyptoog
[DEBUG] fetching parameters block: 1
2023-01-22T13:45:09.479622Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 24,
    },
    return_data: RawBytes {  },
    gas_used: 11806809,
    events_root: None,
}
2023-01-22T13:45:09.479638Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 203,
                    method: 3844450837,
                    code: ExitCode {
                        value: 24,
                    },
                    message: "panicked at 'called `Option::unwrap()` on a `None` value', actors/evm/src/interpreter/system.rs:210:22",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-22T13:45:09.479690Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-22T13:45:09.479715Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_HighNonceDelegatecall"::Merge::0
2023-01-22T13:45:09.479722Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stCreate2/CREATE2_HighNonceDelegatecall.json"
2023-01-22T13:45:09.479729Z  INFO evm_eth_compliance::statetest::runner: TX len : 132
2023-01-22T13:45:09.479735Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [208, 97, 176, 138, 132, 235, 199, 15, 231, 151, 249, 189, 98, 244, 38, 158, 248, 39, 74, 19, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([224, 127, 142, 26, 16, 56, 223, 204, 58, 154, 158, 13, 80, 107, 194, 252, 198, 89, 188, 114]) }
[DEBUG] getting cid: bafy2bzacedef2iioq5zx33deu6ufh237wvqdt7vycaffbp5y5grxgwyyptoog
[DEBUG] fetching parameters block: 1
2023-01-22T13:45:09.484027Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 24,
    },
    return_data: RawBytes {  },
    gas_used: 12340098,
    events_root: None,
}
2023-01-22T13:45:09.484054Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 203,
                    method: 3844450837,
                    code: ExitCode {
                        value: 24,
                    },
                    message: "panicked at 'called `Option::unwrap()` on a `None` value', actors/evm/src/interpreter/system.rs:210:22",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-22T13:45:09.484122Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 1
2023-01-22T13:45:09.484165Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_HighNonceDelegatecall"::Merge::1
2023-01-22T13:45:09.484173Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stCreate2/CREATE2_HighNonceDelegatecall.json"
2023-01-22T13:45:09.484180Z  INFO evm_eth_compliance::statetest::runner: TX len : 132
2023-01-22T13:45:09.484186Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [208, 97, 176, 138, 132, 235, 199, 15, 231, 151, 249, 189, 98, 244, 38, 158, 248, 39, 74, 19, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([83, 242, 32, 232, 142, 92, 253, 105, 158, 39, 47, 205, 245, 242, 166, 27, 224, 56, 84, 129]) }
[DEBUG] getting cid: bafy2bzacedef2iioq5zx33deu6ufh237wvqdt7vycaffbp5y5grxgwyyptoog
[DEBUG] fetching parameters block: 1
2023-01-22T13:45:09.487922Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 24,
    },
    return_data: RawBytes {  },
    gas_used: 12704449,
    events_root: None,
}
2023-01-22T13:45:09.487940Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 203,
                    method: 3844450837,
                    code: ExitCode {
                        value: 24,
                    },
                    message: "panicked at 'called `Option::unwrap()` on a `None` value', actors/evm/src/interpreter/system.rs:210:22",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-22T13:45:09.487994Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 2
2023-01-22T13:45:09.488023Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_HighNonceDelegatecall"::Merge::2
2023-01-22T13:45:09.488030Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stCreate2/CREATE2_HighNonceDelegatecall.json"
2023-01-22T13:45:09.488037Z  INFO evm_eth_compliance::statetest::runner: TX len : 132
2023-01-22T13:45:09.488043Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [208, 97, 176, 138, 132, 235, 199, 15, 231, 151, 249, 189, 98, 244, 38, 158, 248, 39, 74, 19, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([32, 12, 253, 213, 163, 63, 29, 115, 178, 187, 161, 163, 212, 193, 125, 27, 3, 62, 7, 249]) }
[DEBUG] getting cid: bafy2bzacedef2iioq5zx33deu6ufh237wvqdt7vycaffbp5y5grxgwyyptoog
[DEBUG] fetching parameters block: 1
2023-01-22T13:45:09.491662Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 24,
    },
    return_data: RawBytes {  },
    gas_used: 12703480,
    events_root: None,
}
2023-01-22T13:45:09.491678Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 203,
                    method: 3844450837,
                    code: ExitCode {
                        value: 24,
                    },
                    message: "panicked at 'called `Option::unwrap()` on a `None` value', actors/evm/src/interpreter/system.rs:210:22",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-22T13:45:09.491732Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 3
2023-01-22T13:45:09.491757Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_HighNonceDelegatecall"::Merge::3
2023-01-22T13:45:09.491763Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stCreate2/CREATE2_HighNonceDelegatecall.json"
2023-01-22T13:45:09.491771Z  INFO evm_eth_compliance::statetest::runner: TX len : 132
2023-01-22T13:45:09.491777Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [208, 97, 176, 138, 132, 235, 199, 15, 231, 151, 249, 189, 98, 244, 38, 158, 248, 39, 74, 19, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([10, 31, 101, 35, 215, 26, 74, 181, 210, 246, 179, 103, 102, 200, 253, 136, 135, 201, 30, 222]) }
[DEBUG] getting cid: bafy2bzacedef2iioq5zx33deu6ufh237wvqdt7vycaffbp5y5grxgwyyptoog
[DEBUG] fetching parameters block: 1
2023-01-22T13:45:09.495264Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 24,
    },
    return_data: RawBytes {  },
    gas_used: 11810597,
    events_root: None,
}
2023-01-22T13:45:09.495285Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 203,
                    method: 3844450837,
                    code: ExitCode {
                        value: 24,
                    },
                    message: "panicked at 'called `Option::unwrap()` on a `None` value', actors/evm/src/interpreter/system.rs:210:22",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-22T13:45:09.495363Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 4
2023-01-22T13:45:09.495399Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_HighNonceDelegatecall"::Merge::4
2023-01-22T13:45:09.495410Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stCreate2/CREATE2_HighNonceDelegatecall.json"
2023-01-22T13:45:09.495420Z  INFO evm_eth_compliance::statetest::runner: TX len : 132
2023-01-22T13:45:09.495428Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [208, 97, 176, 138, 132, 235, 199, 15, 231, 151, 249, 189, 98, 244, 38, 158, 248, 39, 74, 19, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([111, 101, 131, 235, 47, 251, 193, 19, 227, 95, 161, 71, 165, 135, 114, 55, 251, 221, 137, 48]) }
[DEBUG] getting cid: bafy2bzacedef2iioq5zx33deu6ufh237wvqdt7vycaffbp5y5grxgwyyptoog
[DEBUG] fetching parameters block: 1
2023-01-22T13:45:09.499472Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 24,
    },
    return_data: RawBytes {  },
    gas_used: 12323079,
    events_root: None,
}
2023-01-22T13:45:09.499498Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 203,
                    method: 3844450837,
                    code: ExitCode {
                        value: 24,
                    },
                    message: "panicked at 'called `Option::unwrap()` on a `None` value', actors/evm/src/interpreter/system.rs:210:22",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-22T13:45:09.499584Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 5
2023-01-22T13:45:09.499628Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_HighNonceDelegatecall"::Merge::5
2023-01-22T13:45:09.499636Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stCreate2/CREATE2_HighNonceDelegatecall.json"
2023-01-22T13:45:09.499643Z  INFO evm_eth_compliance::statetest::runner: TX len : 132
2023-01-22T13:45:09.499649Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [208, 97, 176, 138, 132, 235, 199, 15, 231, 151, 249, 189, 98, 244, 38, 158, 248, 39, 74, 19, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([32, 102, 203, 126, 45, 108, 207, 145, 210, 218, 252, 249, 122, 133, 241, 60, 219, 42, 234, 109]) }
[DEBUG] getting cid: bafy2bzacedef2iioq5zx33deu6ufh237wvqdt7vycaffbp5y5grxgwyyptoog
[DEBUG] fetching parameters block: 1
2023-01-22T13:45:09.503352Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 24,
    },
    return_data: RawBytes {  },
    gas_used: 12773652,
    events_root: None,
}
2023-01-22T13:45:09.503367Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 203,
                    method: 3844450837,
                    code: ExitCode {
                        value: 24,
                    },
                    message: "panicked at 'called `Option::unwrap()` on a `None` value', actors/evm/src/interpreter/system.rs:210:22",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-22T13:45:09.503421Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 18
2023-01-22T13:45:09.503446Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_HighNonceDelegatecall"::Merge::18
2023-01-22T13:45:09.503454Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stCreate2/CREATE2_HighNonceDelegatecall.json"
2023-01-22T13:45:09.503465Z  INFO evm_eth_compliance::statetest::runner: TX len : 132
2023-01-22T13:45:09.503471Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [208, 97, 176, 138, 132, 235, 199, 15, 231, 151, 249, 189, 98, 244, 38, 158, 248, 39, 74, 19, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([196, 98, 194, 59, 213, 64, 206, 31, 14, 190, 130, 228, 239, 109, 211, 237, 18, 175, 83, 144]) }
[DEBUG] getting cid: bafy2bzacedef2iioq5zx33deu6ufh237wvqdt7vycaffbp5y5grxgwyyptoog
[DEBUG] fetching parameters block: 1
2023-01-22T13:45:09.506856Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 24,
    },
    return_data: RawBytes {  },
    gas_used: 11810249,
    events_root: None,
}
2023-01-22T13:45:09.506871Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 203,
                    method: 3844450837,
                    code: ExitCode {
                        value: 24,
                    },
                    message: "panicked at 'called `Option::unwrap()` on a `None` value', actors/evm/src/interpreter/system.rs:210:22",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-22T13:45:09.506923Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 19
2023-01-22T13:45:09.506946Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_HighNonceDelegatecall"::Merge::19
2023-01-22T13:45:09.506953Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stCreate2/CREATE2_HighNonceDelegatecall.json"
2023-01-22T13:45:09.506960Z  INFO evm_eth_compliance::statetest::runner: TX len : 132
2023-01-22T13:45:09.506966Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [208, 97, 176, 138, 132, 235, 199, 15, 231, 151, 249, 189, 98, 244, 38, 158, 248, 39, 74, 19, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([71, 70, 230, 190, 48, 241, 157, 172, 217, 73, 0, 165, 128, 235, 16, 135, 37, 189, 190, 113]) }
[DEBUG] getting cid: bafy2bzacedef2iioq5zx33deu6ufh237wvqdt7vycaffbp5y5grxgwyyptoog
[DEBUG] fetching parameters block: 1
2023-01-22T13:45:09.510576Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 24,
    },
    return_data: RawBytes {  },
    gas_used: 12826262,
    events_root: None,
}
2023-01-22T13:45:09.510593Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 203,
                    method: 3844450837,
                    code: ExitCode {
                        value: 24,
                    },
                    message: "panicked at 'called `Option::unwrap()` on a `None` value', actors/evm/src/interpreter/system.rs:210:22",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-22T13:45:09.510645Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 20
2023-01-22T13:45:09.510668Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_HighNonceDelegatecall"::Merge::20
2023-01-22T13:45:09.510675Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stCreate2/CREATE2_HighNonceDelegatecall.json"
2023-01-22T13:45:09.510682Z  INFO evm_eth_compliance::statetest::runner: TX len : 132
2023-01-22T13:45:09.510688Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [208, 97, 176, 138, 132, 235, 199, 15, 231, 151, 249, 189, 98, 244, 38, 158, 248, 39, 74, 19, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([29, 74, 4, 136, 2, 197, 156, 124, 105, 58, 48, 79, 205, 124, 25, 157, 119, 224, 166, 125]) }
[DEBUG] getting cid: bafy2bzacedef2iioq5zx33deu6ufh237wvqdt7vycaffbp5y5grxgwyyptoog
[DEBUG] fetching parameters block: 1
2023-01-22T13:45:09.514090Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 24,
    },
    return_data: RawBytes {  },
    gas_used: 11848438,
    events_root: None,
}
2023-01-22T13:45:09.514105Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 203,
                    method: 3844450837,
                    code: ExitCode {
                        value: 24,
                    },
                    message: "panicked at 'called `Option::unwrap()` on a `None` value', actors/evm/src/interpreter/system.rs:210:22",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-22T13:45:09.514158Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 21
2023-01-22T13:45:09.514182Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_HighNonceDelegatecall"::Merge::21
2023-01-22T13:45:09.514189Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stCreate2/CREATE2_HighNonceDelegatecall.json"
2023-01-22T13:45:09.514197Z  INFO evm_eth_compliance::statetest::runner: TX len : 132
2023-01-22T13:45:09.514202Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [208, 97, 176, 138, 132, 235, 199, 15, 231, 151, 249, 189, 98, 244, 38, 158, 248, 39, 74, 19, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([195, 245, 116, 142, 151, 66, 202, 110, 58, 159, 70, 222, 65, 77, 234, 43, 213, 48, 253, 205]) }
[DEBUG] getting cid: bafy2bzacedef2iioq5zx33deu6ufh237wvqdt7vycaffbp5y5grxgwyyptoog
[DEBUG] fetching parameters block: 1
2023-01-22T13:45:09.518418Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 24,
    },
    return_data: RawBytes {  },
    gas_used: 12334385,
    events_root: None,
}
2023-01-22T13:45:09.518443Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 203,
                    method: 3844450837,
                    code: ExitCode {
                        value: 24,
                    },
                    message: "panicked at 'called `Option::unwrap()` on a `None` value', actors/evm/src/interpreter/system.rs:210:22",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-22T13:45:09.518520Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 22
2023-01-22T13:45:09.518562Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_HighNonceDelegatecall"::Merge::22
2023-01-22T13:45:09.518569Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stCreate2/CREATE2_HighNonceDelegatecall.json"
2023-01-22T13:45:09.518577Z  INFO evm_eth_compliance::statetest::runner: TX len : 132
2023-01-22T13:45:09.518583Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [208, 97, 176, 138, 132, 235, 199, 15, 231, 151, 249, 189, 98, 244, 38, 158, 248, 39, 74, 19, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([204, 53, 98, 209, 229, 200, 215, 107, 227, 119, 179, 25, 140, 108, 161, 147, 169, 11, 20, 115]) }
[DEBUG] getting cid: bafy2bzacedef2iioq5zx33deu6ufh237wvqdt7vycaffbp5y5grxgwyyptoog
[DEBUG] fetching parameters block: 1
2023-01-22T13:45:09.522219Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 24,
    },
    return_data: RawBytes {  },
    gas_used: 11808993,
    events_root: None,
}
2023-01-22T13:45:09.522235Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 203,
                    method: 3844450837,
                    code: ExitCode {
                        value: 24,
                    },
                    message: "panicked at 'called `Option::unwrap()` on a `None` value', actors/evm/src/interpreter/system.rs:210:22",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-22T13:45:09.522288Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 23
2023-01-22T13:45:09.522315Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_HighNonceDelegatecall"::Merge::23
2023-01-22T13:45:09.522322Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stCreate2/CREATE2_HighNonceDelegatecall.json"
2023-01-22T13:45:09.522329Z  INFO evm_eth_compliance::statetest::runner: TX len : 132
2023-01-22T13:45:09.522334Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [208, 97, 176, 138, 132, 235, 199, 15, 231, 151, 249, 189, 98, 244, 38, 158, 248, 39, 74, 19, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([40, 178, 254, 193, 140, 79, 21, 80, 164, 98, 191, 21, 73, 18, 4, 43, 202, 172, 1, 184]) }
[DEBUG] getting cid: bafy2bzacedef2iioq5zx33deu6ufh237wvqdt7vycaffbp5y5grxgwyyptoog
[DEBUG] fetching parameters block: 1
2023-01-22T13:45:09.525873Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 24,
    },
    return_data: RawBytes {  },
    gas_used: 12337934,
    events_root: None,
}
2023-01-22T13:45:09.525888Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 203,
                    method: 3844450837,
                    code: ExitCode {
                        value: 24,
                    },
                    message: "panicked at 'called `Option::unwrap()` on a `None` value', actors/evm/src/interpreter/system.rs:210:22",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-22T13:45:09.525943Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 12
2023-01-22T13:45:09.525967Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_HighNonceDelegatecall"::Merge::12
2023-01-22T13:45:09.525975Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stCreate2/CREATE2_HighNonceDelegatecall.json"
2023-01-22T13:45:09.525982Z  INFO evm_eth_compliance::statetest::runner: TX len : 132
2023-01-22T13:45:09.525987Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [208, 97, 176, 138, 132, 235, 199, 15, 231, 151, 249, 189, 98, 244, 38, 158, 248, 39, 74, 19, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([188, 234, 201, 49, 114, 108, 161, 6, 193, 42, 108, 44, 66, 95, 77, 32, 42, 210, 209, 216]) }
[DEBUG] getting cid: bafy2bzacedef2iioq5zx33deu6ufh237wvqdt7vycaffbp5y5grxgwyyptoog
[DEBUG] fetching parameters block: 1
2023-01-22T13:45:09.529521Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 24,
    },
    return_data: RawBytes {  },
    gas_used: 12338150,
    events_root: None,
}
2023-01-22T13:45:09.529536Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 203,
                    method: 3844450837,
                    code: ExitCode {
                        value: 24,
                    },
                    message: "panicked at 'called `Option::unwrap()` on a `None` value', actors/evm/src/interpreter/system.rs:210:22",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-22T13:45:09.529590Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 13
2023-01-22T13:45:09.529613Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_HighNonceDelegatecall"::Merge::13
2023-01-22T13:45:09.529620Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stCreate2/CREATE2_HighNonceDelegatecall.json"
2023-01-22T13:45:09.529627Z  INFO evm_eth_compliance::statetest::runner: TX len : 132
2023-01-22T13:45:09.529634Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [208, 97, 176, 138, 132, 235, 199, 15, 231, 151, 249, 189, 98, 244, 38, 158, 248, 39, 74, 19, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([126, 43, 88, 164, 145, 22, 42, 161, 83, 26, 206, 54, 162, 199, 187, 115, 68, 241, 84, 138]) }
[DEBUG] getting cid: bafy2bzacedef2iioq5zx33deu6ufh237wvqdt7vycaffbp5y5grxgwyyptoog
[DEBUG] fetching parameters block: 1
2023-01-22T13:45:09.533768Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 24,
    },
    return_data: RawBytes {  },
    gas_used: 12333177,
    events_root: None,
}
2023-01-22T13:45:09.533793Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 203,
                    method: 3844450837,
                    code: ExitCode {
                        value: 24,
                    },
                    message: "panicked at 'called `Option::unwrap()` on a `None` value', actors/evm/src/interpreter/system.rs:210:22",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-22T13:45:09.533866Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 14
2023-01-22T13:45:09.533907Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_HighNonceDelegatecall"::Merge::14
2023-01-22T13:45:09.533914Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stCreate2/CREATE2_HighNonceDelegatecall.json"
2023-01-22T13:45:09.533921Z  INFO evm_eth_compliance::statetest::runner: TX len : 132
2023-01-22T13:45:09.533928Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [208, 97, 176, 138, 132, 235, 199, 15, 231, 151, 249, 189, 98, 244, 38, 158, 248, 39, 74, 19, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([147, 253, 123, 90, 174, 188, 203, 171, 110, 84, 239, 160, 222, 55, 66, 212, 224, 160, 168, 137]) }
[DEBUG] getting cid: bafy2bzacedef2iioq5zx33deu6ufh237wvqdt7vycaffbp5y5grxgwyyptoog
[DEBUG] fetching parameters block: 1
2023-01-22T13:45:09.537669Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 24,
    },
    return_data: RawBytes {  },
    gas_used: 12654563,
    events_root: None,
}
2023-01-22T13:45:09.537685Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 203,
                    method: 3844450837,
                    code: ExitCode {
                        value: 24,
                    },
                    message: "panicked at 'called `Option::unwrap()` on a `None` value', actors/evm/src/interpreter/system.rs:210:22",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-22T13:45:09.537743Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 15
2023-01-22T13:45:09.537769Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_HighNonceDelegatecall"::Merge::15
2023-01-22T13:45:09.537776Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stCreate2/CREATE2_HighNonceDelegatecall.json"
2023-01-22T13:45:09.537783Z  INFO evm_eth_compliance::statetest::runner: TX len : 132
2023-01-22T13:45:09.537790Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [208, 97, 176, 138, 132, 235, 199, 15, 231, 151, 249, 189, 98, 244, 38, 158, 248, 39, 74, 19, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([251, 38, 65, 156, 132, 234, 224, 205, 126, 248, 103, 225, 8, 124, 250, 208, 120, 32, 32, 107]) }
[DEBUG] getting cid: bafy2bzacedef2iioq5zx33deu6ufh237wvqdt7vycaffbp5y5grxgwyyptoog
[DEBUG] fetching parameters block: 1
2023-01-22T13:45:09.541316Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 24,
    },
    return_data: RawBytes {  },
    gas_used: 12706450,
    events_root: None,
}
2023-01-22T13:45:09.541332Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 203,
                    method: 3844450837,
                    code: ExitCode {
                        value: 24,
                    },
                    message: "panicked at 'called `Option::unwrap()` on a `None` value', actors/evm/src/interpreter/system.rs:210:22",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-22T13:45:09.541385Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 16
2023-01-22T13:45:09.541409Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_HighNonceDelegatecall"::Merge::16
2023-01-22T13:45:09.541417Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stCreate2/CREATE2_HighNonceDelegatecall.json"
2023-01-22T13:45:09.541424Z  INFO evm_eth_compliance::statetest::runner: TX len : 132
2023-01-22T13:45:09.541430Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [208, 97, 176, 138, 132, 235, 199, 15, 231, 151, 249, 189, 98, 244, 38, 158, 248, 39, 74, 19, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([49, 148, 229, 172, 111, 229, 44, 147, 138, 118, 204, 113, 64, 57, 137, 98, 223, 38, 83, 174]) }
[DEBUG] getting cid: bafy2bzacedef2iioq5zx33deu6ufh237wvqdt7vycaffbp5y5grxgwyyptoog
[DEBUG] fetching parameters block: 1
2023-01-22T13:45:09.544864Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 24,
    },
    return_data: RawBytes {  },
    gas_used: 11807437,
    events_root: None,
}
2023-01-22T13:45:09.544879Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 203,
                    method: 3844450837,
                    code: ExitCode {
                        value: 24,
                    },
                    message: "panicked at 'called `Option::unwrap()` on a `None` value', actors/evm/src/interpreter/system.rs:210:22",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-22T13:45:09.544933Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 17
2023-01-22T13:45:09.544958Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_HighNonceDelegatecall"::Merge::17
2023-01-22T13:45:09.544965Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stCreate2/CREATE2_HighNonceDelegatecall.json"
2023-01-22T13:45:09.544972Z  INFO evm_eth_compliance::statetest::runner: TX len : 132
2023-01-22T13:45:09.544977Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [208, 97, 176, 138, 132, 235, 199, 15, 231, 151, 249, 189, 98, 244, 38, 158, 248, 39, 74, 19, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([187, 249, 92, 28, 16, 244, 165, 219, 119, 35, 12, 202, 251, 251, 48, 189, 74, 117, 48, 202]) }
[DEBUG] getting cid: bafy2bzacedef2iioq5zx33deu6ufh237wvqdt7vycaffbp5y5grxgwyyptoog
[DEBUG] fetching parameters block: 1
2023-01-22T13:45:09.549086Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 24,
    },
    return_data: RawBytes {  },
    gas_used: 11806649,
    events_root: None,
}
2023-01-22T13:45:09.549111Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 203,
                    method: 3844450837,
                    code: ExitCode {
                        value: 24,
                    },
                    message: "panicked at 'called `Option::unwrap()` on a `None` value', actors/evm/src/interpreter/system.rs:210:22",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-22T13:45:09.551757Z TRACE evm_eth_compliance::statetest::runner: TestDone => "test-vectors/tests/GeneralStateTests/stCreate2/CREATE2_HighNonceDelegatecall.json"
2023-01-22T13:45:09.552021Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:12.845581919s
```