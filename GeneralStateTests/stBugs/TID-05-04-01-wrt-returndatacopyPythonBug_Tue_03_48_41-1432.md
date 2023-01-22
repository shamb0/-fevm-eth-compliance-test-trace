> Status

| Status | Context |
| --- | --- |
| KO | under WASM RT context |
| OK | under native RT context |

KO :: InvalidMemoryAccess Need Investigation

> Test Suite

https://github.com/ethereum/tests/blob/develop/GeneralStateTests/stBugs/returndatacopyPythonBug_Tue_03_48_41-1432.json#L1

> Command to execute

```
clear && \
	RUST_LOG=evm_eth_compliance=trace \
	VECTOR=test-vectors/tests/GeneralStateTests/stBugs/returndatacopyPythonBug_Tue_03_48_41-1432.json \
	cargo run \
	-- \
	statetest
```

> For Review

InvalidMemoryAccess Need Investigation

```
2023-01-20T15:17:22.909576Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 202,
                    method: 3844450837,
                    code: ExitCode {
                        value: 33,
                    },
                    message: "contract reverted",
                },
                Frame {
                    source: 203,
                    method: 3844450837,
                    code: ExitCode {
                        value: 23,
                    },
                    message: "EVM execution error: StaticModeViolation",
                },
                Frame {
                    source: 204,
                    method: 3844450837,
                    code: ExitCode {
                        value: 23,
                    },
                    message: "EVM execution error: InvalidMemoryAccess",
                },
            ],
            cause: None,
        },
    ),
)
```

> Execution Trace

```
2023-01-20T15:17:10.589021Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "test-vectors/tests/GeneralStateTests/stBugs/returndatacopyPythonBug_Tue_03_48_41-1432.json", Total Files :: 1
2023-01-20T15:17:10.589460Z TRACE evm_eth_compliance::statetest::runner: Calling testfile => "test-vectors/tests/GeneralStateTests/stBugs/returndatacopyPythonBug_Tue_03_48_41-1432.json"
2023-01-20T15:17:10.711791Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [169, 79, 83, 116, 252, 229, 237, 188, 142, 42, 134, 151, 193, 83, 49, 103, 126, 110, 191, 11, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([179, 152, 63, 197, 60, 234, 37, 74, 66, 53, 75, 140, 66, 70, 3, 8, 241, 171, 25, 86]) }
[DEBUG] getting cid: bafy2bzaceaii7gatq5yoovv5j5rn5hvbvdukafhmhnjm36ur627u6hyo6dame
[DEBUG] fetching parameters block: 1
2023-01-20T15:17:22.809890Z  INFO evm_eth_compliance::statetest::runner: Dummy Place Holder Contract got deployed with Actor ID [200]
2023-01-20T15:17:22.810070Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-20T15:17:22.810148Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [185, 79, 83, 116, 252, 229, 237, 188, 142, 42, 134, 151, 193, 83, 49, 103, 126, 110, 191, 11, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([157, 122, 181, 47, 53, 176, 191, 159, 121, 68, 73, 204, 112, 124, 226, 155, 100, 141, 75, 36]) }
[DEBUG] getting cid: bafy2bzacecsquj7xh4vk2t3fxpfxek3wh4jdtmd7u5en66azvnwf7l4u47cl6
[DEBUG] fetching parameters block: 1
2023-01-20T15:17:22.813208Z  INFO evm_eth_compliance::statetest::runner: Dummy Place Holder Contract got deployed with Actor ID [201]
2023-01-20T15:17:22.813375Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-20T15:17:22.813420Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 2
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [201, 79, 83, 116, 252, 229, 237, 188, 142, 42, 134, 151, 193, 83, 49, 103, 126, 110, 191, 11, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([135, 86, 195, 226, 17, 192, 42, 192, 25, 213, 136, 254, 18, 95, 50, 68, 155, 121, 209, 130]) }
[DEBUG] getting cid: bafy2bzacec3meeo3jdxvlj7nv2juuin2lr32lkq4c6qs3zi2vijclcdc3pef2
[DEBUG] fetching parameters block: 1
2023-01-20T15:17:22.816528Z  INFO evm_eth_compliance::statetest::runner: Dummy Place Holder Contract got deployed with Actor ID [202]
2023-01-20T15:17:22.816742Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-20T15:17:22.816788Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 3
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [217, 79, 83, 116, 252, 229, 237, 188, 142, 42, 134, 151, 193, 83, 49, 103, 126, 110, 191, 11, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([121, 46, 44, 168, 100, 157, 195, 57, 208, 185, 119, 244, 82, 48, 8, 55, 203, 168, 19, 62]) }
[DEBUG] getting cid: bafy2bzaceajgvxqhinbqkp5iinprlfg25zfxyy2lrha7bjrb5kk4s6bepdqpy
[DEBUG] fetching parameters block: 1
2023-01-20T15:17:22.819736Z  INFO evm_eth_compliance::statetest::runner: Dummy Place Holder Contract got deployed with Actor ID [203]
2023-01-20T15:17:22.820343Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-20T15:17:22.820398Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 4
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([102, 145, 95, 210, 114, 99, 97, 196, 103, 113, 159, 135, 176, 147, 142, 56, 188, 98, 191, 170]) }
[DEBUG] getting cid: bafy2bzacebenfhvtlwzrp6we5eqfwjvzpoauosi4r7n3dqriz5kuqhuzjvdjm
[DEBUG] fetching parameters block: 1
2023-01-20T15:17:22.823443Z  INFO evm_eth_compliance::statetest::runner: Dummy Place Holder Contract got deployed with Actor ID [204]
2023-01-20T15:17:22.823788Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-20T15:17:22.824951Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-20T15:17:22.825005Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "returndatacopyPythonBug_Tue_03_48_41-1432"::Istanbul::0
2023-01-20T15:17:22.825014Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBugs/returndatacopyPythonBug_Tue_03_48_41-1432.json"
2023-01-20T15:17:22.825022Z  INFO evm_eth_compliance::statetest::runner: TX len : 676
2023-01-20T15:17:22.825029Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [177, 192, 211, 114, 55, 161, 246, 189, 98, 2, 174, 212, 181, 167, 41, 13, 252, 218, 101, 145, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([215, 166, 242, 208, 200, 186, 79, 10, 126, 8, 221, 102, 9, 12, 200, 158, 203, 19, 78, 227]) }
[DEBUG] getting cid: bafy2bzacecbjqavjsk7sldka6o422kwpabv3drcqjnyrpteq2hgrc45266s7a
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
2023-01-20T15:17:22.830156Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 23,
    },
    return_data: RawBytes {  },
    gas_used: 15702288,
    events_root: None,
}
2023-01-20T15:17:22.830176Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 202,
                    method: 3844450837,
                    code: ExitCode {
                        value: 33,
                    },
                    message: "contract reverted",
                },
                Frame {
                    source: 203,
                    method: 3844450837,
                    code: ExitCode {
                        value: 23,
                    },
                    message: "EVM execution error: StaticModeViolation",
                },
                Frame {
                    source: 204,
                    method: 3844450837,
                    code: ExitCode {
                        value: 23,
                    },
                    message: "EVM execution error: InvalidMemoryAccess",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-20T15:17:22.830260Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-20T15:17:22.830289Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "returndatacopyPythonBug_Tue_03_48_41-1432"::Istanbul::0
2023-01-20T15:17:22.830296Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBugs/returndatacopyPythonBug_Tue_03_48_41-1432.json"
2023-01-20T15:17:22.830303Z  INFO evm_eth_compliance::statetest::runner: TX len : 676
2023-01-20T15:17:22.830309Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [177, 192, 211, 114, 55, 161, 246, 189, 98, 2, 174, 212, 181, 167, 41, 13, 252, 218, 101, 145, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([67, 35, 255, 1, 46, 226, 200, 90, 20, 150, 237, 153, 222, 171, 201, 9, 99, 31, 101, 211]) }
[DEBUG] getting cid: bafy2bzacecbjqavjsk7sldka6o422kwpabv3drcqjnyrpteq2hgrc45266s7a
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
2023-01-20T15:17:22.835423Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 23,
    },
    return_data: RawBytes {  },
    gas_used: 16227618,
    events_root: None,
}
2023-01-20T15:17:22.835439Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 202,
                    method: 3844450837,
                    code: ExitCode {
                        value: 33,
                    },
                    message: "contract reverted",
                },
                Frame {
                    source: 203,
                    method: 3844450837,
                    code: ExitCode {
                        value: 23,
                    },
                    message: "EVM execution error: StaticModeViolation",
                },
                Frame {
                    source: 204,
                    method: 3844450837,
                    code: ExitCode {
                        value: 23,
                    },
                    message: "EVM execution error: InvalidMemoryAccess",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-20T15:17:22.835522Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-20T15:17:22.835551Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "returndatacopyPythonBug_Tue_03_48_41-1432"::Istanbul::0
2023-01-20T15:17:22.835558Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBugs/returndatacopyPythonBug_Tue_03_48_41-1432.json"
2023-01-20T15:17:22.835565Z  INFO evm_eth_compliance::statetest::runner: TX len : 676
2023-01-20T15:17:22.835571Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [177, 192, 211, 114, 55, 161, 246, 189, 98, 2, 174, 212, 181, 167, 41, 13, 252, 218, 101, 145, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([28, 35, 125, 168, 212, 11, 234, 180, 81, 129, 48, 219, 76, 10, 52, 89, 217, 159, 194, 2]) }
[DEBUG] getting cid: bafy2bzacecbjqavjsk7sldka6o422kwpabv3drcqjnyrpteq2hgrc45266s7a
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
2023-01-20T15:17:22.840758Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 23,
    },
    return_data: RawBytes {  },
    gas_used: 16225220,
    events_root: None,
}
2023-01-20T15:17:22.840777Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 202,
                    method: 3844450837,
                    code: ExitCode {
                        value: 33,
                    },
                    message: "contract reverted",
                },
                Frame {
                    source: 203,
                    method: 3844450837,
                    code: ExitCode {
                        value: 23,
                    },
                    message: "EVM execution error: StaticModeViolation",
                },
                Frame {
                    source: 204,
                    method: 3844450837,
                    code: ExitCode {
                        value: 23,
                    },
                    message: "EVM execution error: InvalidMemoryAccess",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-20T15:17:22.840861Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-20T15:17:22.840897Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "returndatacopyPythonBug_Tue_03_48_41-1432"::Istanbul::0
2023-01-20T15:17:22.840904Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBugs/returndatacopyPythonBug_Tue_03_48_41-1432.json"
2023-01-20T15:17:22.840911Z  INFO evm_eth_compliance::statetest::runner: TX len : 676
2023-01-20T15:17:22.840917Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [177, 192, 211, 114, 55, 161, 246, 189, 98, 2, 174, 212, 181, 167, 41, 13, 252, 218, 101, 145, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([132, 105, 76, 107, 184, 77, 78, 105, 101, 219, 134, 121, 221, 254, 217, 203, 72, 121, 220, 83]) }
[DEBUG] getting cid: bafy2bzacecbjqavjsk7sldka6o422kwpabv3drcqjnyrpteq2hgrc45266s7a
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
2023-01-20T15:17:22.846069Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 23,
    },
    return_data: RawBytes {  },
    gas_used: 16564608,
    events_root: None,
}
2023-01-20T15:17:22.846085Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 202,
                    method: 3844450837,
                    code: ExitCode {
                        value: 33,
                    },
                    message: "contract reverted",
                },
                Frame {
                    source: 203,
                    method: 3844450837,
                    code: ExitCode {
                        value: 23,
                    },
                    message: "EVM execution error: StaticModeViolation",
                },
                Frame {
                    source: 204,
                    method: 3844450837,
                    code: ExitCode {
                        value: 23,
                    },
                    message: "EVM execution error: InvalidMemoryAccess",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-20T15:17:22.846170Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-20T15:17:22.846199Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "returndatacopyPythonBug_Tue_03_48_41-1432"::Berlin::0
2023-01-20T15:17:22.846206Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBugs/returndatacopyPythonBug_Tue_03_48_41-1432.json"
2023-01-20T15:17:22.846213Z  INFO evm_eth_compliance::statetest::runner: TX len : 676
2023-01-20T15:17:22.846219Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [177, 192, 211, 114, 55, 161, 246, 189, 98, 2, 174, 212, 181, 167, 41, 13, 252, 218, 101, 145, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([236, 70, 216, 243, 101, 99, 189, 62, 205, 26, 208, 253, 84, 36, 48, 143, 166, 88, 135, 41]) }
[DEBUG] getting cid: bafy2bzacecbjqavjsk7sldka6o422kwpabv3drcqjnyrpteq2hgrc45266s7a
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
2023-01-20T15:17:22.851232Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 23,
    },
    return_data: RawBytes {  },
    gas_used: 15701512,
    events_root: None,
}
2023-01-20T15:17:22.851247Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 202,
                    method: 3844450837,
                    code: ExitCode {
                        value: 33,
                    },
                    message: "contract reverted",
                },
                Frame {
                    source: 203,
                    method: 3844450837,
                    code: ExitCode {
                        value: 23,
                    },
                    message: "EVM execution error: StaticModeViolation",
                },
                Frame {
                    source: 204,
                    method: 3844450837,
                    code: ExitCode {
                        value: 23,
                    },
                    message: "EVM execution error: InvalidMemoryAccess",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-20T15:17:22.851326Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-20T15:17:22.851355Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "returndatacopyPythonBug_Tue_03_48_41-1432"::Berlin::0
2023-01-20T15:17:22.851362Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBugs/returndatacopyPythonBug_Tue_03_48_41-1432.json"
2023-01-20T15:17:22.851370Z  INFO evm_eth_compliance::statetest::runner: TX len : 676
2023-01-20T15:17:22.851376Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [177, 192, 211, 114, 55, 161, 246, 189, 98, 2, 174, 212, 181, 167, 41, 13, 252, 218, 101, 145, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([155, 99, 140, 31, 46, 96, 27, 93, 44, 60, 131, 66, 80, 136, 87, 209, 224, 27, 216, 212]) }
[DEBUG] getting cid: bafy2bzacecbjqavjsk7sldka6o422kwpabv3drcqjnyrpteq2hgrc45266s7a
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
2023-01-20T15:17:22.856520Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 23,
    },
    return_data: RawBytes {  },
    gas_used: 16216764,
    events_root: None,
}
2023-01-20T15:17:22.856537Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 202,
                    method: 3844450837,
                    code: ExitCode {
                        value: 33,
                    },
                    message: "contract reverted",
                },
                Frame {
                    source: 203,
                    method: 3844450837,
                    code: ExitCode {
                        value: 23,
                    },
                    message: "EVM execution error: StaticModeViolation",
                },
                Frame {
                    source: 204,
                    method: 3844450837,
                    code: ExitCode {
                        value: 23,
                    },
                    message: "EVM execution error: InvalidMemoryAccess",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-20T15:17:22.856622Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-20T15:17:22.856655Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "returndatacopyPythonBug_Tue_03_48_41-1432"::Berlin::0
2023-01-20T15:17:22.856662Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBugs/returndatacopyPythonBug_Tue_03_48_41-1432.json"
2023-01-20T15:17:22.856669Z  INFO evm_eth_compliance::statetest::runner: TX len : 676
2023-01-20T15:17:22.856675Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [177, 192, 211, 114, 55, 161, 246, 189, 98, 2, 174, 212, 181, 167, 41, 13, 252, 218, 101, 145, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([188, 149, 186, 245, 1, 91, 222, 203, 63, 25, 86, 169, 35, 110, 18, 124, 122, 60, 238, 128]) }
[DEBUG] getting cid: bafy2bzacecbjqavjsk7sldka6o422kwpabv3drcqjnyrpteq2hgrc45266s7a
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
2023-01-20T15:17:22.861868Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 23,
    },
    return_data: RawBytes {  },
    gas_used: 16224057,
    events_root: None,
}
2023-01-20T15:17:22.861883Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 202,
                    method: 3844450837,
                    code: ExitCode {
                        value: 33,
                    },
                    message: "contract reverted",
                },
                Frame {
                    source: 203,
                    method: 3844450837,
                    code: ExitCode {
                        value: 23,
                    },
                    message: "EVM execution error: StaticModeViolation",
                },
                Frame {
                    source: 204,
                    method: 3844450837,
                    code: ExitCode {
                        value: 23,
                    },
                    message: "EVM execution error: InvalidMemoryAccess",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-20T15:17:22.861965Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-20T15:17:22.861994Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "returndatacopyPythonBug_Tue_03_48_41-1432"::Berlin::0
2023-01-20T15:17:22.862001Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBugs/returndatacopyPythonBug_Tue_03_48_41-1432.json"
2023-01-20T15:17:22.862008Z  INFO evm_eth_compliance::statetest::runner: TX len : 676
2023-01-20T15:17:22.862014Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [177, 192, 211, 114, 55, 161, 246, 189, 98, 2, 174, 212, 181, 167, 41, 13, 252, 218, 101, 145, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([20, 3, 204, 71, 166, 252, 88, 221, 29, 77, 14, 224, 191, 132, 61, 100, 47, 53, 166, 175]) }
[DEBUG] getting cid: bafy2bzacecbjqavjsk7sldka6o422kwpabv3drcqjnyrpteq2hgrc45266s7a
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
2023-01-20T15:17:22.867159Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 23,
    },
    return_data: RawBytes {  },
    gas_used: 16634194,
    events_root: None,
}
2023-01-20T15:17:22.867174Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 202,
                    method: 3844450837,
                    code: ExitCode {
                        value: 33,
                    },
                    message: "contract reverted",
                },
                Frame {
                    source: 203,
                    method: 3844450837,
                    code: ExitCode {
                        value: 23,
                    },
                    message: "EVM execution error: StaticModeViolation",
                },
                Frame {
                    source: 204,
                    method: 3844450837,
                    code: ExitCode {
                        value: 23,
                    },
                    message: "EVM execution error: InvalidMemoryAccess",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-20T15:17:22.867257Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-20T15:17:22.867287Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "returndatacopyPythonBug_Tue_03_48_41-1432"::London::0
2023-01-20T15:17:22.867294Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBugs/returndatacopyPythonBug_Tue_03_48_41-1432.json"
2023-01-20T15:17:22.867301Z  INFO evm_eth_compliance::statetest::runner: TX len : 676
2023-01-20T15:17:22.867307Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [177, 192, 211, 114, 55, 161, 246, 189, 98, 2, 174, 212, 181, 167, 41, 13, 252, 218, 101, 145, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([177, 189, 137, 170, 161, 168, 98, 8, 218, 14, 105, 2, 242, 92, 44, 234, 2, 122, 233, 63]) }
[DEBUG] getting cid: bafy2bzacecbjqavjsk7sldka6o422kwpabv3drcqjnyrpteq2hgrc45266s7a
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
2023-01-20T15:17:22.872336Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 23,
    },
    return_data: RawBytes {  },
    gas_used: 15701440,
    events_root: None,
}
2023-01-20T15:17:22.872351Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 202,
                    method: 3844450837,
                    code: ExitCode {
                        value: 33,
                    },
                    message: "contract reverted",
                },
                Frame {
                    source: 203,
                    method: 3844450837,
                    code: ExitCode {
                        value: 23,
                    },
                    message: "EVM execution error: StaticModeViolation",
                },
                Frame {
                    source: 204,
                    method: 3844450837,
                    code: ExitCode {
                        value: 23,
                    },
                    message: "EVM execution error: InvalidMemoryAccess",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-20T15:17:22.872433Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-20T15:17:22.872462Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "returndatacopyPythonBug_Tue_03_48_41-1432"::London::0
2023-01-20T15:17:22.872469Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBugs/returndatacopyPythonBug_Tue_03_48_41-1432.json"
2023-01-20T15:17:22.872476Z  INFO evm_eth_compliance::statetest::runner: TX len : 676
2023-01-20T15:17:22.872482Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [177, 192, 211, 114, 55, 161, 246, 189, 98, 2, 174, 212, 181, 167, 41, 13, 252, 218, 101, 145, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([178, 221, 99, 117, 94, 25, 113, 14, 55, 217, 63, 213, 179, 235, 175, 240, 178, 120, 15, 225]) }
[DEBUG] getting cid: bafy2bzacecbjqavjsk7sldka6o422kwpabv3drcqjnyrpteq2hgrc45266s7a
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
2023-01-20T15:17:22.877623Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 23,
    },
    return_data: RawBytes {  },
    gas_used: 15701848,
    events_root: None,
}
2023-01-20T15:17:22.877642Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 202,
                    method: 3844450837,
                    code: ExitCode {
                        value: 33,
                    },
                    message: "contract reverted",
                },
                Frame {
                    source: 203,
                    method: 3844450837,
                    code: ExitCode {
                        value: 23,
                    },
                    message: "EVM execution error: StaticModeViolation",
                },
                Frame {
                    source: 204,
                    method: 3844450837,
                    code: ExitCode {
                        value: 23,
                    },
                    message: "EVM execution error: InvalidMemoryAccess",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-20T15:17:22.877724Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-20T15:17:22.877761Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "returndatacopyPythonBug_Tue_03_48_41-1432"::London::0
2023-01-20T15:17:22.877768Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBugs/returndatacopyPythonBug_Tue_03_48_41-1432.json"
2023-01-20T15:17:22.877776Z  INFO evm_eth_compliance::statetest::runner: TX len : 676
2023-01-20T15:17:22.877782Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [177, 192, 211, 114, 55, 161, 246, 189, 98, 2, 174, 212, 181, 167, 41, 13, 252, 218, 101, 145, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([251, 114, 94, 192, 108, 10, 201, 112, 101, 197, 5, 103, 36, 134, 180, 68, 48, 44, 184, 84]) }
[DEBUG] getting cid: bafy2bzacecbjqavjsk7sldka6o422kwpabv3drcqjnyrpteq2hgrc45266s7a
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
2023-01-20T15:17:22.882814Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 23,
    },
    return_data: RawBytes {  },
    gas_used: 15706816,
    events_root: None,
}
2023-01-20T15:17:22.882829Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 202,
                    method: 3844450837,
                    code: ExitCode {
                        value: 33,
                    },
                    message: "contract reverted",
                },
                Frame {
                    source: 203,
                    method: 3844450837,
                    code: ExitCode {
                        value: 23,
                    },
                    message: "EVM execution error: StaticModeViolation",
                },
                Frame {
                    source: 204,
                    method: 3844450837,
                    code: ExitCode {
                        value: 23,
                    },
                    message: "EVM execution error: InvalidMemoryAccess",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-20T15:17:22.882910Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-20T15:17:22.882938Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "returndatacopyPythonBug_Tue_03_48_41-1432"::London::0
2023-01-20T15:17:22.882945Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBugs/returndatacopyPythonBug_Tue_03_48_41-1432.json"
2023-01-20T15:17:22.882952Z  INFO evm_eth_compliance::statetest::runner: TX len : 676
2023-01-20T15:17:22.882958Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [177, 192, 211, 114, 55, 161, 246, 189, 98, 2, 174, 212, 181, 167, 41, 13, 252, 218, 101, 145, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([90, 217, 32, 146, 24, 201, 117, 10, 10, 210, 28, 70, 31, 30, 132, 56, 243, 180, 75, 35]) }
[DEBUG] getting cid: bafy2bzacecbjqavjsk7sldka6o422kwpabv3drcqjnyrpteq2hgrc45266s7a
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
2023-01-20T15:17:22.888127Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 23,
    },
    return_data: RawBytes {  },
    gas_used: 16624427,
    events_root: None,
}
2023-01-20T15:17:22.888143Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 202,
                    method: 3844450837,
                    code: ExitCode {
                        value: 33,
                    },
                    message: "contract reverted",
                },
                Frame {
                    source: 203,
                    method: 3844450837,
                    code: ExitCode {
                        value: 23,
                    },
                    message: "EVM execution error: StaticModeViolation",
                },
                Frame {
                    source: 204,
                    method: 3844450837,
                    code: ExitCode {
                        value: 23,
                    },
                    message: "EVM execution error: InvalidMemoryAccess",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-20T15:17:22.888226Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-20T15:17:22.888255Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "returndatacopyPythonBug_Tue_03_48_41-1432"::Merge::0
2023-01-20T15:17:22.888262Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBugs/returndatacopyPythonBug_Tue_03_48_41-1432.json"
2023-01-20T15:17:22.888270Z  INFO evm_eth_compliance::statetest::runner: TX len : 676
2023-01-20T15:17:22.888276Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [177, 192, 211, 114, 55, 161, 246, 189, 98, 2, 174, 212, 181, 167, 41, 13, 252, 218, 101, 145, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([128, 138, 188, 155, 213, 11, 225, 143, 246, 50, 199, 246, 94, 148, 129, 183, 56, 152, 76, 55]) }
[DEBUG] getting cid: bafy2bzacecbjqavjsk7sldka6o422kwpabv3drcqjnyrpteq2hgrc45266s7a
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
2023-01-20T15:17:22.893428Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 23,
    },
    return_data: RawBytes {  },
    gas_used: 15769164,
    events_root: None,
}
2023-01-20T15:17:22.893449Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 202,
                    method: 3844450837,
                    code: ExitCode {
                        value: 33,
                    },
                    message: "contract reverted",
                },
                Frame {
                    source: 203,
                    method: 3844450837,
                    code: ExitCode {
                        value: 23,
                    },
                    message: "EVM execution error: StaticModeViolation",
                },
                Frame {
                    source: 204,
                    method: 3844450837,
                    code: ExitCode {
                        value: 23,
                    },
                    message: "EVM execution error: InvalidMemoryAccess",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-20T15:17:22.893538Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-20T15:17:22.893577Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "returndatacopyPythonBug_Tue_03_48_41-1432"::Merge::0
2023-01-20T15:17:22.893584Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBugs/returndatacopyPythonBug_Tue_03_48_41-1432.json"
2023-01-20T15:17:22.893592Z  INFO evm_eth_compliance::statetest::runner: TX len : 676
2023-01-20T15:17:22.893598Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [177, 192, 211, 114, 55, 161, 246, 189, 98, 2, 174, 212, 181, 167, 41, 13, 252, 218, 101, 145, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([55, 124, 170, 147, 221, 2, 18, 238, 216, 76, 43, 142, 118, 199, 246, 132, 57, 223, 23, 100]) }
[DEBUG] getting cid: bafy2bzacecbjqavjsk7sldka6o422kwpabv3drcqjnyrpteq2hgrc45266s7a
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
2023-01-20T15:17:22.898832Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 23,
    },
    return_data: RawBytes {  },
    gas_used: 16227982,
    events_root: None,
}
2023-01-20T15:17:22.898850Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 202,
                    method: 3844450837,
                    code: ExitCode {
                        value: 33,
                    },
                    message: "contract reverted",
                },
                Frame {
                    source: 203,
                    method: 3844450837,
                    code: ExitCode {
                        value: 23,
                    },
                    message: "EVM execution error: StaticModeViolation",
                },
                Frame {
                    source: 204,
                    method: 3844450837,
                    code: ExitCode {
                        value: 23,
                    },
                    message: "EVM execution error: InvalidMemoryAccess",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-20T15:17:22.898935Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-20T15:17:22.898970Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "returndatacopyPythonBug_Tue_03_48_41-1432"::Merge::0
2023-01-20T15:17:22.898977Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBugs/returndatacopyPythonBug_Tue_03_48_41-1432.json"
2023-01-20T15:17:22.898984Z  INFO evm_eth_compliance::statetest::runner: TX len : 676
2023-01-20T15:17:22.898990Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [177, 192, 211, 114, 55, 161, 246, 189, 98, 2, 174, 212, 181, 167, 41, 13, 252, 218, 101, 145, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([171, 234, 181, 15, 37, 193, 240, 156, 211, 60, 172, 98, 156, 55, 186, 0, 159, 236, 160, 247]) }
[DEBUG] getting cid: bafy2bzacecbjqavjsk7sldka6o422kwpabv3drcqjnyrpteq2hgrc45266s7a
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
2023-01-20T15:17:22.904089Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 23,
    },
    return_data: RawBytes {  },
    gas_used: 15702520,
    events_root: None,
}
2023-01-20T15:17:22.904106Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 202,
                    method: 3844450837,
                    code: ExitCode {
                        value: 33,
                    },
                    message: "contract reverted",
                },
                Frame {
                    source: 203,
                    method: 3844450837,
                    code: ExitCode {
                        value: 23,
                    },
                    message: "EVM execution error: StaticModeViolation",
                },
                Frame {
                    source: 204,
                    method: 3844450837,
                    code: ExitCode {
                        value: 23,
                    },
                    message: "EVM execution error: InvalidMemoryAccess",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-20T15:17:22.904190Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-20T15:17:22.904233Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "returndatacopyPythonBug_Tue_03_48_41-1432"::Merge::0
2023-01-20T15:17:22.904244Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBugs/returndatacopyPythonBug_Tue_03_48_41-1432.json"
2023-01-20T15:17:22.904255Z  INFO evm_eth_compliance::statetest::runner: TX len : 676
2023-01-20T15:17:22.904264Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [177, 192, 211, 114, 55, 161, 246, 189, 98, 2, 174, 212, 181, 167, 41, 13, 252, 218, 101, 145, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([167, 18, 209, 255, 80, 109, 220, 136, 239, 83, 214, 196, 45, 184, 19, 227, 137, 201, 135, 105]) }
[DEBUG] getting cid: bafy2bzacecbjqavjsk7sldka6o422kwpabv3drcqjnyrpteq2hgrc45266s7a
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
2023-01-20T15:17:22.909555Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 23,
    },
    return_data: RawBytes {  },
    gas_used: 16622489,
    events_root: None,
}
2023-01-20T15:17:22.909576Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 202,
                    method: 3844450837,
                    code: ExitCode {
                        value: 33,
                    },
                    message: "contract reverted",
                },
                Frame {
                    source: 203,
                    method: 3844450837,
                    code: ExitCode {
                        value: 23,
                    },
                    message: "EVM execution error: StaticModeViolation",
                },
                Frame {
                    source: 204,
                    method: 3844450837,
                    code: ExitCode {
                        value: 23,
                    },
                    message: "EVM execution error: InvalidMemoryAccess",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-20T15:17:22.912071Z TRACE evm_eth_compliance::statetest::runner: TestDone => "test-vectors/tests/GeneralStateTests/stBugs/returndatacopyPythonBug_Tue_03_48_41-1432.json"
2023-01-20T15:17:22.912341Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:12.197906978s
```
