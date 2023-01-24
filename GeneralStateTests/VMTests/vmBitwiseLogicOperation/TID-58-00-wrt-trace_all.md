> Status

| Status | Context |
| --- | --- |
| OK | under WASM RT context |
| TODO | under native RT context |

> Test Suite

https://github.com/ethereum/tests/blob/develop/GeneralStateTests/VMTests/vmBitwiseLogicOperation

> For Review

* Execution looks OK. No error observed

> Command to execute

```
clear && \
	RUST_LOG=evm_eth_compliance=trace \
	VECTOR=test-vectors/tests/GeneralStateTests/VMTests/vmBitwiseLogicOperation \
	cargo run --release \
	-- \
	statetest
```

> Execution Trace

```
2023-01-23T15:58:18.010153Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "test-vectors/tests/GeneralStateTests/VMTests/vmBitwiseLogicOperation", Total Files :: 11
2023-01-23T15:58:18.010405Z TRACE evm_eth_compliance::statetest::runner: Calling testfile => "test-vectors/tests/GeneralStateTests/VMTests/vmBitwiseLogicOperation/and.json"
2023-01-23T15:58:18.040504Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-23T15:58:18.040700Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-23T15:58:18.040705Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-23T15:58:18.040761Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-23T15:58:18.040763Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 2
2023-01-23T15:58:18.040823Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-23T15:58:18.040826Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 3
2023-01-23T15:58:18.040882Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-23T15:58:18.040884Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 4
2023-01-23T15:58:18.040932Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-23T15:58:18.040934Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 5
2023-01-23T15:58:18.040999Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-23T15:58:18.041002Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 6
2023-01-23T15:58:18.041057Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-23T15:58:18.041132Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-23T15:58:18.041136Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "and"::Istanbul::0
2023-01-23T15:58:18.041139Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmBitwiseLogicOperation/and.json"
2023-01-23T15:58:18.041142Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:58:18.041143Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:58:18.403547Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3954202,
    events_root: None,
}
2023-01-23T15:58:18.403569Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 2
2023-01-23T15:58:18.403575Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "and"::Istanbul::2
2023-01-23T15:58:18.403578Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmBitwiseLogicOperation/and.json"
2023-01-23T15:58:18.403581Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:58:18.403582Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:58:18.403774Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3954202,
    events_root: None,
}
2023-01-23T15:58:18.403784Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 3
2023-01-23T15:58:18.403786Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "and"::Istanbul::3
2023-01-23T15:58:18.403788Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmBitwiseLogicOperation/and.json"
2023-01-23T15:58:18.403791Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:58:18.403792Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:58:18.403977Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 4000836,
    events_root: None,
}
2023-01-23T15:58:18.403986Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 4
2023-01-23T15:58:18.403988Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "and"::Istanbul::4
2023-01-23T15:58:18.403990Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmBitwiseLogicOperation/and.json"
2023-01-23T15:58:18.403993Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:58:18.403994Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:58:18.404176Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 4000836,
    events_root: None,
}
2023-01-23T15:58:18.404185Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 1
2023-01-23T15:58:18.404187Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "and"::Istanbul::1
2023-01-23T15:58:18.404189Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmBitwiseLogicOperation/and.json"
2023-01-23T15:58:18.404192Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:58:18.404193Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:58:18.404361Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3029411,
    events_root: None,
}
2023-01-23T15:58:18.404370Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-23T15:58:18.404372Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "and"::Berlin::0
2023-01-23T15:58:18.404374Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmBitwiseLogicOperation/and.json"
2023-01-23T15:58:18.404377Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:58:18.404378Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:58:18.404553Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3058615,
    events_root: None,
}
2023-01-23T15:58:18.404562Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 2
2023-01-23T15:58:18.404564Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "and"::Berlin::2
2023-01-23T15:58:18.404566Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmBitwiseLogicOperation/and.json"
2023-01-23T15:58:18.404568Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:58:18.404570Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:58:18.404737Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3058615,
    events_root: None,
}
2023-01-23T15:58:18.404746Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 3
2023-01-23T15:58:18.404748Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "and"::Berlin::3
2023-01-23T15:58:18.404750Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmBitwiseLogicOperation/and.json"
2023-01-23T15:58:18.404752Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:58:18.404753Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:58:18.404923Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3062101,
    events_root: None,
}
2023-01-23T15:58:18.404931Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 4
2023-01-23T15:58:18.404934Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "and"::Berlin::4
2023-01-23T15:58:18.404936Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmBitwiseLogicOperation/and.json"
2023-01-23T15:58:18.404938Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:58:18.404940Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:58:18.405108Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3062101,
    events_root: None,
}
2023-01-23T15:58:18.405116Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 1
2023-01-23T15:58:18.405119Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "and"::Berlin::1
2023-01-23T15:58:18.405121Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmBitwiseLogicOperation/and.json"
2023-01-23T15:58:18.405123Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:58:18.405124Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:58:18.405289Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3029411,
    events_root: None,
}
2023-01-23T15:58:18.405297Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-23T15:58:18.405300Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "and"::London::0
2023-01-23T15:58:18.405302Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmBitwiseLogicOperation/and.json"
2023-01-23T15:58:18.405304Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:58:18.405306Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:58:18.405477Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3058615,
    events_root: None,
}
2023-01-23T15:58:18.405485Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 2
2023-01-23T15:58:18.405487Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "and"::London::2
2023-01-23T15:58:18.405489Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmBitwiseLogicOperation/and.json"
2023-01-23T15:58:18.405492Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:58:18.405493Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:58:18.405666Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3058615,
    events_root: None,
}
2023-01-23T15:58:18.405675Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 3
2023-01-23T15:58:18.405677Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "and"::London::3
2023-01-23T15:58:18.405679Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmBitwiseLogicOperation/and.json"
2023-01-23T15:58:18.405682Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:58:18.405683Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:58:18.405851Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3062101,
    events_root: None,
}
2023-01-23T15:58:18.405859Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 4
2023-01-23T15:58:18.405861Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "and"::London::4
2023-01-23T15:58:18.405863Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmBitwiseLogicOperation/and.json"
2023-01-23T15:58:18.405866Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:58:18.405867Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:58:18.406034Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3062101,
    events_root: None,
}
2023-01-23T15:58:18.406042Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 1
2023-01-23T15:58:18.406045Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "and"::London::1
2023-01-23T15:58:18.406047Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmBitwiseLogicOperation/and.json"
2023-01-23T15:58:18.406049Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:58:18.406051Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:58:18.406214Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3029411,
    events_root: None,
}
2023-01-23T15:58:18.406222Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-23T15:58:18.406225Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "and"::Merge::0
2023-01-23T15:58:18.406226Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmBitwiseLogicOperation/and.json"
2023-01-23T15:58:18.406229Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:58:18.406230Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:58:18.406397Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3058615,
    events_root: None,
}
2023-01-23T15:58:18.406405Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 2
2023-01-23T15:58:18.406407Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "and"::Merge::2
2023-01-23T15:58:18.406409Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmBitwiseLogicOperation/and.json"
2023-01-23T15:58:18.406412Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:58:18.406413Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:58:18.406579Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3058615,
    events_root: None,
}
2023-01-23T15:58:18.406588Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 3
2023-01-23T15:58:18.406590Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "and"::Merge::3
2023-01-23T15:58:18.406592Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmBitwiseLogicOperation/and.json"
2023-01-23T15:58:18.406595Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:58:18.406596Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:58:18.406763Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3062101,
    events_root: None,
}
2023-01-23T15:58:18.406772Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 4
2023-01-23T15:58:18.406774Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "and"::Merge::4
2023-01-23T15:58:18.406776Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmBitwiseLogicOperation/and.json"
2023-01-23T15:58:18.406779Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:58:18.406780Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:58:18.406946Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3062101,
    events_root: None,
}
2023-01-23T15:58:18.406955Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 1
2023-01-23T15:58:18.406957Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "and"::Merge::1
2023-01-23T15:58:18.406959Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmBitwiseLogicOperation/and.json"
2023-01-23T15:58:18.406961Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:58:18.406963Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:58:18.407126Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3029411,
    events_root: None,
}
2023-01-23T15:58:18.408561Z TRACE evm_eth_compliance::statetest::runner: TestDone => "test-vectors/tests/GeneralStateTests/VMTests/vmBitwiseLogicOperation/and.json"
2023-01-23T15:58:18.408589Z TRACE evm_eth_compliance::statetest::runner: Calling testfile => "test-vectors/tests/GeneralStateTests/VMTests/vmBitwiseLogicOperation/byte.json"
2023-01-23T15:58:18.433945Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-23T15:58:18.434046Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-23T15:58:18.434049Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-23T15:58:18.434099Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-23T15:58:18.434101Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 2
2023-01-23T15:58:18.434157Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-23T15:58:18.434159Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 3
2023-01-23T15:58:18.434209Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-23T15:58:18.434211Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 4
2023-01-23T15:58:18.434256Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-23T15:58:18.434258Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 5
2023-01-23T15:58:18.434317Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-23T15:58:18.434319Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 6
2023-01-23T15:58:18.434372Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-23T15:58:18.434374Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 7
2023-01-23T15:58:18.434416Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-23T15:58:18.434418Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 8
2023-01-23T15:58:18.434459Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-23T15:58:18.434460Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 9
2023-01-23T15:58:18.434510Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-23T15:58:18.434512Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 10
2023-01-23T15:58:18.434558Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-23T15:58:18.434560Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 11
2023-01-23T15:58:18.434605Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-23T15:58:18.434607Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 12
2023-01-23T15:58:18.434648Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-23T15:58:18.434650Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 13
2023-01-23T15:58:18.434692Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-23T15:58:18.434762Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-23T15:58:18.434767Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "byte"::Istanbul::0
2023-01-23T15:58:18.434769Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmBitwiseLogicOperation/byte.json"
2023-01-23T15:58:18.434772Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:58:18.434774Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:58:18.784054Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3948560,
    events_root: None,
}
2023-01-23T15:58:18.784078Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 1
2023-01-23T15:58:18.784084Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "byte"::Istanbul::1
2023-01-23T15:58:18.784086Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmBitwiseLogicOperation/byte.json"
2023-01-23T15:58:18.784089Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:58:18.784091Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:58:18.784294Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3948560,
    events_root: None,
}
2023-01-23T15:58:18.784303Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 2
2023-01-23T15:58:18.784305Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "byte"::Istanbul::2
2023-01-23T15:58:18.784308Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmBitwiseLogicOperation/byte.json"
2023-01-23T15:58:18.784310Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:58:18.784312Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:58:18.784494Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3948560,
    events_root: None,
}
2023-01-23T15:58:18.784502Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 3
2023-01-23T15:58:18.784505Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "byte"::Istanbul::3
2023-01-23T15:58:18.784507Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmBitwiseLogicOperation/byte.json"
2023-01-23T15:58:18.784510Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:58:18.784511Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:58:18.784691Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3948560,
    events_root: None,
}
2023-01-23T15:58:18.784700Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 4
2023-01-23T15:58:18.784702Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "byte"::Istanbul::4
2023-01-23T15:58:18.784704Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmBitwiseLogicOperation/byte.json"
2023-01-23T15:58:18.784707Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:58:18.784709Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:58:18.784889Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3948560,
    events_root: None,
}
2023-01-23T15:58:18.784897Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 5
2023-01-23T15:58:18.784900Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "byte"::Istanbul::5
2023-01-23T15:58:18.784902Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmBitwiseLogicOperation/byte.json"
2023-01-23T15:58:18.784904Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:58:18.784906Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:58:18.785085Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3948560,
    events_root: None,
}
2023-01-23T15:58:18.785094Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 6
2023-01-23T15:58:18.785096Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "byte"::Istanbul::6
2023-01-23T15:58:18.785098Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmBitwiseLogicOperation/byte.json"
2023-01-23T15:58:18.785101Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:58:18.785102Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:58:18.785283Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3948560,
    events_root: None,
}
2023-01-23T15:58:18.785291Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 7
2023-01-23T15:58:18.785294Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "byte"::Istanbul::7
2023-01-23T15:58:18.785295Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmBitwiseLogicOperation/byte.json"
2023-01-23T15:58:18.785298Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:58:18.785299Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:58:18.785478Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3948560,
    events_root: None,
}
2023-01-23T15:58:18.785487Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 8
2023-01-23T15:58:18.785489Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "byte"::Istanbul::8
2023-01-23T15:58:18.785491Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmBitwiseLogicOperation/byte.json"
2023-01-23T15:58:18.785494Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:58:18.785496Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:58:18.785666Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3023769,
    events_root: None,
}
2023-01-23T15:58:18.785674Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 9
2023-01-23T15:58:18.785677Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "byte"::Istanbul::9
2023-01-23T15:58:18.785679Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmBitwiseLogicOperation/byte.json"
2023-01-23T15:58:18.785681Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:58:18.785683Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:58:18.785847Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3024753,
    events_root: None,
}
2023-01-23T15:58:18.785855Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 10
2023-01-23T15:58:18.785858Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "byte"::Istanbul::10
2023-01-23T15:58:18.785859Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmBitwiseLogicOperation/byte.json"
2023-01-23T15:58:18.785862Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:58:18.785863Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:58:18.786041Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3949479,
    events_root: None,
}
2023-01-23T15:58:18.786050Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 11
2023-01-23T15:58:18.786052Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "byte"::Istanbul::11
2023-01-23T15:58:18.786054Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmBitwiseLogicOperation/byte.json"
2023-01-23T15:58:18.786057Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:58:18.786058Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:58:18.786525Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 14888317,
    events_root: None,
}
2023-01-23T15:58:18.786537Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-23T15:58:18.786539Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "byte"::Berlin::0
2023-01-23T15:58:18.786541Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmBitwiseLogicOperation/byte.json"
2023-01-23T15:58:18.786544Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:58:18.786545Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:58:18.786722Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3053338,
    events_root: None,
}
2023-01-23T15:58:18.786730Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 1
2023-01-23T15:58:18.786733Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "byte"::Berlin::1
2023-01-23T15:58:18.786735Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmBitwiseLogicOperation/byte.json"
2023-01-23T15:58:18.786737Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:58:18.786739Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:58:18.786905Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3053338,
    events_root: None,
}
2023-01-23T15:58:18.786913Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 2
2023-01-23T15:58:18.786916Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "byte"::Berlin::2
2023-01-23T15:58:18.786918Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmBitwiseLogicOperation/byte.json"
2023-01-23T15:58:18.786920Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:58:18.786922Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:58:18.787087Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3053338,
    events_root: None,
}
2023-01-23T15:58:18.787096Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 3
2023-01-23T15:58:18.787098Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "byte"::Berlin::3
2023-01-23T15:58:18.787100Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmBitwiseLogicOperation/byte.json"
2023-01-23T15:58:18.787103Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:58:18.787104Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:58:18.787269Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3053338,
    events_root: None,
}
2023-01-23T15:58:18.787278Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 4
2023-01-23T15:58:18.787280Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "byte"::Berlin::4
2023-01-23T15:58:18.787282Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmBitwiseLogicOperation/byte.json"
2023-01-23T15:58:18.787284Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:58:18.787286Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:58:18.787450Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3053338,
    events_root: None,
}
2023-01-23T15:58:18.787459Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 5
2023-01-23T15:58:18.787461Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "byte"::Berlin::5
2023-01-23T15:58:18.787463Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmBitwiseLogicOperation/byte.json"
2023-01-23T15:58:18.787465Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:58:18.787467Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:58:18.787632Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3053338,
    events_root: None,
}
2023-01-23T15:58:18.787640Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 6
2023-01-23T15:58:18.787642Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "byte"::Berlin::6
2023-01-23T15:58:18.787644Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmBitwiseLogicOperation/byte.json"
2023-01-23T15:58:18.787647Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:58:18.787648Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:58:18.787812Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3053338,
    events_root: None,
}
2023-01-23T15:58:18.787821Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 7
2023-01-23T15:58:18.787823Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "byte"::Berlin::7
2023-01-23T15:58:18.787825Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmBitwiseLogicOperation/byte.json"
2023-01-23T15:58:18.787828Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:58:18.787829Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:58:18.787993Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3053338,
    events_root: None,
}
2023-01-23T15:58:18.788001Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 8
2023-01-23T15:58:18.788004Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "byte"::Berlin::8
2023-01-23T15:58:18.788006Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmBitwiseLogicOperation/byte.json"
2023-01-23T15:58:18.788009Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:58:18.788010Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:58:18.788172Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3023769,
    events_root: None,
}
2023-01-23T15:58:18.788180Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 9
2023-01-23T15:58:18.788183Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "byte"::Berlin::9
2023-01-23T15:58:18.788185Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmBitwiseLogicOperation/byte.json"
2023-01-23T15:58:18.788187Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:58:18.788189Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:58:18.788350Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3024753,
    events_root: None,
}
2023-01-23T15:58:18.788358Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 10
2023-01-23T15:58:18.788361Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "byte"::Berlin::10
2023-01-23T15:58:18.788363Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmBitwiseLogicOperation/byte.json"
2023-01-23T15:58:18.788365Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:58:18.788367Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:58:18.788532Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3052589,
    events_root: None,
}
2023-01-23T15:58:18.788541Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 11
2023-01-23T15:58:18.788543Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "byte"::Berlin::11
2023-01-23T15:58:18.788546Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmBitwiseLogicOperation/byte.json"
2023-01-23T15:58:18.788548Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:58:18.788549Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:58:18.789002Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 10738155,
    events_root: None,
}
2023-01-23T15:58:18.789013Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-23T15:58:18.789016Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "byte"::London::0
2023-01-23T15:58:18.789018Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmBitwiseLogicOperation/byte.json"
2023-01-23T15:58:18.789020Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:58:18.789022Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:58:18.789192Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3053338,
    events_root: None,
}
2023-01-23T15:58:18.789200Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 1
2023-01-23T15:58:18.789203Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "byte"::London::1
2023-01-23T15:58:18.789205Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmBitwiseLogicOperation/byte.json"
2023-01-23T15:58:18.789207Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:58:18.789209Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:58:18.789374Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3053338,
    events_root: None,
}
2023-01-23T15:58:18.789382Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 2
2023-01-23T15:58:18.789384Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "byte"::London::2
2023-01-23T15:58:18.789386Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmBitwiseLogicOperation/byte.json"
2023-01-23T15:58:18.789389Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:58:18.789390Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:58:18.789555Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3053338,
    events_root: None,
}
2023-01-23T15:58:18.789563Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 3
2023-01-23T15:58:18.789566Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "byte"::London::3
2023-01-23T15:58:18.789568Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmBitwiseLogicOperation/byte.json"
2023-01-23T15:58:18.789570Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:58:18.789572Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:58:18.789742Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3053338,
    events_root: None,
}
2023-01-23T15:58:18.789751Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 4
2023-01-23T15:58:18.789753Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "byte"::London::4
2023-01-23T15:58:18.789755Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmBitwiseLogicOperation/byte.json"
2023-01-23T15:58:18.789758Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:58:18.789759Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:58:18.789924Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3053338,
    events_root: None,
}
2023-01-23T15:58:18.789932Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 5
2023-01-23T15:58:18.789934Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "byte"::London::5
2023-01-23T15:58:18.789936Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmBitwiseLogicOperation/byte.json"
2023-01-23T15:58:18.789939Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:58:18.789940Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:58:18.790104Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3053338,
    events_root: None,
}
2023-01-23T15:58:18.790113Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 6
2023-01-23T15:58:18.790115Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "byte"::London::6
2023-01-23T15:58:18.790117Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmBitwiseLogicOperation/byte.json"
2023-01-23T15:58:18.790120Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:58:18.790121Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:58:18.790287Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3053338,
    events_root: None,
}
2023-01-23T15:58:18.790295Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 7
2023-01-23T15:58:18.790297Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "byte"::London::7
2023-01-23T15:58:18.790299Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmBitwiseLogicOperation/byte.json"
2023-01-23T15:58:18.790302Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:58:18.790303Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:58:18.790468Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3053338,
    events_root: None,
}
2023-01-23T15:58:18.790476Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 8
2023-01-23T15:58:18.790478Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "byte"::London::8
2023-01-23T15:58:18.790480Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmBitwiseLogicOperation/byte.json"
2023-01-23T15:58:18.790483Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:58:18.790484Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:58:18.790646Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3023769,
    events_root: None,
}
2023-01-23T15:58:18.790654Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 9
2023-01-23T15:58:18.790656Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "byte"::London::9
2023-01-23T15:58:18.790658Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmBitwiseLogicOperation/byte.json"
2023-01-23T15:58:18.790661Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:58:18.790662Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:58:18.790824Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3024753,
    events_root: None,
}
2023-01-23T15:58:18.790832Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 10
2023-01-23T15:58:18.790835Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "byte"::London::10
2023-01-23T15:58:18.790837Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmBitwiseLogicOperation/byte.json"
2023-01-23T15:58:18.790839Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:58:18.790840Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:58:18.791006Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3052589,
    events_root: None,
}
2023-01-23T15:58:18.791014Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 11
2023-01-23T15:58:18.791017Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "byte"::London::11
2023-01-23T15:58:18.791019Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmBitwiseLogicOperation/byte.json"
2023-01-23T15:58:18.791022Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:58:18.791023Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:58:18.791475Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 10738155,
    events_root: None,
}
2023-01-23T15:58:18.791486Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-23T15:58:18.791488Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "byte"::Merge::0
2023-01-23T15:58:18.791490Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmBitwiseLogicOperation/byte.json"
2023-01-23T15:58:18.791493Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:58:18.791494Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:58:18.791665Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3053338,
    events_root: None,
}
2023-01-23T15:58:18.791673Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 1
2023-01-23T15:58:18.791676Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "byte"::Merge::1
2023-01-23T15:58:18.791678Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmBitwiseLogicOperation/byte.json"
2023-01-23T15:58:18.791680Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:58:18.791682Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:58:18.791848Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3053338,
    events_root: None,
}
2023-01-23T15:58:18.791856Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 2
2023-01-23T15:58:18.791859Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "byte"::Merge::2
2023-01-23T15:58:18.791861Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmBitwiseLogicOperation/byte.json"
2023-01-23T15:58:18.791863Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:58:18.791864Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:58:18.792058Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3053338,
    events_root: None,
}
2023-01-23T15:58:18.792067Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 3
2023-01-23T15:58:18.792069Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "byte"::Merge::3
2023-01-23T15:58:18.792071Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmBitwiseLogicOperation/byte.json"
2023-01-23T15:58:18.792074Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:58:18.792075Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:58:18.792242Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3053338,
    events_root: None,
}
2023-01-23T15:58:18.792250Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 4
2023-01-23T15:58:18.792252Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "byte"::Merge::4
2023-01-23T15:58:18.792254Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmBitwiseLogicOperation/byte.json"
2023-01-23T15:58:18.792257Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:58:18.792258Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:58:18.792423Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3053338,
    events_root: None,
}
2023-01-23T15:58:18.792431Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 5
2023-01-23T15:58:18.792434Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "byte"::Merge::5
2023-01-23T15:58:18.792436Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmBitwiseLogicOperation/byte.json"
2023-01-23T15:58:18.792438Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:58:18.792440Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:58:18.792604Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3053338,
    events_root: None,
}
2023-01-23T15:58:18.792612Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 6
2023-01-23T15:58:18.792615Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "byte"::Merge::6
2023-01-23T15:58:18.792617Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmBitwiseLogicOperation/byte.json"
2023-01-23T15:58:18.792619Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:58:18.792620Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:58:18.792785Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3053338,
    events_root: None,
}
2023-01-23T15:58:18.792793Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 7
2023-01-23T15:58:18.792796Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "byte"::Merge::7
2023-01-23T15:58:18.792798Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmBitwiseLogicOperation/byte.json"
2023-01-23T15:58:18.792800Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:58:18.792801Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:58:18.792966Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3053338,
    events_root: None,
}
2023-01-23T15:58:18.792974Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 8
2023-01-23T15:58:18.792976Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "byte"::Merge::8
2023-01-23T15:58:18.792978Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmBitwiseLogicOperation/byte.json"
2023-01-23T15:58:18.792981Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:58:18.792982Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:58:18.793144Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3023769,
    events_root: None,
}
2023-01-23T15:58:18.793152Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 9
2023-01-23T15:58:18.793155Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "byte"::Merge::9
2023-01-23T15:58:18.793157Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmBitwiseLogicOperation/byte.json"
2023-01-23T15:58:18.793159Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:58:18.793161Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:58:18.793321Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3024753,
    events_root: None,
}
2023-01-23T15:58:18.793329Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 10
2023-01-23T15:58:18.793331Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "byte"::Merge::10
2023-01-23T15:58:18.793333Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmBitwiseLogicOperation/byte.json"
2023-01-23T15:58:18.793336Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:58:18.793337Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:58:18.793502Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3052589,
    events_root: None,
}
2023-01-23T15:58:18.793510Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 11
2023-01-23T15:58:18.793513Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "byte"::Merge::11
2023-01-23T15:58:18.793515Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmBitwiseLogicOperation/byte.json"
2023-01-23T15:58:18.793517Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:58:18.793518Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:58:18.793975Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 10738155,
    events_root: None,
}
2023-01-23T15:58:18.795318Z TRACE evm_eth_compliance::statetest::runner: TestDone => "test-vectors/tests/GeneralStateTests/VMTests/vmBitwiseLogicOperation/byte.json"
2023-01-23T15:58:18.795349Z TRACE evm_eth_compliance::statetest::runner: Calling testfile => "test-vectors/tests/GeneralStateTests/VMTests/vmBitwiseLogicOperation/eq.json"
2023-01-23T15:58:18.819676Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-23T15:58:18.819773Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-23T15:58:18.819776Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-23T15:58:18.819827Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-23T15:58:18.819829Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 2
2023-01-23T15:58:18.819883Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-23T15:58:18.819885Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 3
2023-01-23T15:58:18.819938Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-23T15:58:18.819940Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 4
2023-01-23T15:58:18.819990Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-23T15:58:18.820059Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-23T15:58:18.820064Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "eq"::Istanbul::0
2023-01-23T15:58:18.820066Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmBitwiseLogicOperation/eq.json"
2023-01-23T15:58:18.820070Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:58:18.820071Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:58:19.159396Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3033429,
    events_root: None,
}
2023-01-23T15:58:19.159418Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 1
2023-01-23T15:58:19.159424Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "eq"::Istanbul::1
2023-01-23T15:58:19.159427Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmBitwiseLogicOperation/eq.json"
2023-01-23T15:58:19.159430Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:58:19.159431Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:58:19.159633Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3957490,
    events_root: None,
}
2023-01-23T15:58:19.159642Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 2
2023-01-23T15:58:19.159645Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "eq"::Istanbul::2
2023-01-23T15:58:19.159647Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmBitwiseLogicOperation/eq.json"
2023-01-23T15:58:19.159649Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:58:19.159651Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:58:19.159839Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3960179,
    events_root: None,
}
2023-01-23T15:58:19.159848Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-23T15:58:19.159851Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "eq"::Berlin::0
2023-01-23T15:58:19.159853Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmBitwiseLogicOperation/eq.json"
2023-01-23T15:58:19.159855Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:58:19.159857Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:58:19.160024Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3033429,
    events_root: None,
}
2023-01-23T15:58:19.160032Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 1
2023-01-23T15:58:19.160035Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "eq"::Berlin::1
2023-01-23T15:58:19.160037Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmBitwiseLogicOperation/eq.json"
2023-01-23T15:58:19.160039Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:58:19.160041Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:58:19.160210Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3061903,
    events_root: None,
}
2023-01-23T15:58:19.160219Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 2
2023-01-23T15:58:19.160221Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "eq"::Berlin::2
2023-01-23T15:58:19.160223Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmBitwiseLogicOperation/eq.json"
2023-01-23T15:58:19.160225Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:58:19.160227Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:58:19.160394Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3064956,
    events_root: None,
}
2023-01-23T15:58:19.160403Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-23T15:58:19.160405Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "eq"::London::0
2023-01-23T15:58:19.160407Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmBitwiseLogicOperation/eq.json"
2023-01-23T15:58:19.160409Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:58:19.160411Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:58:19.160650Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3033429,
    events_root: None,
}
2023-01-23T15:58:19.160662Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 1
2023-01-23T15:58:19.160665Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "eq"::London::1
2023-01-23T15:58:19.160668Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmBitwiseLogicOperation/eq.json"
2023-01-23T15:58:19.160672Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:58:19.160674Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:58:19.160859Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3061903,
    events_root: None,
}
2023-01-23T15:58:19.160867Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 2
2023-01-23T15:58:19.160870Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "eq"::London::2
2023-01-23T15:58:19.160872Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmBitwiseLogicOperation/eq.json"
2023-01-23T15:58:19.160875Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:58:19.160876Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:58:19.161046Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3064956,
    events_root: None,
}
2023-01-23T15:58:19.161055Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-23T15:58:19.161057Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "eq"::Merge::0
2023-01-23T15:58:19.161059Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmBitwiseLogicOperation/eq.json"
2023-01-23T15:58:19.161062Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:58:19.161063Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:58:19.161232Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3033429,
    events_root: None,
}
2023-01-23T15:58:19.161240Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 1
2023-01-23T15:58:19.161243Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "eq"::Merge::1
2023-01-23T15:58:19.161245Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmBitwiseLogicOperation/eq.json"
2023-01-23T15:58:19.161247Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:58:19.161249Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:58:19.161420Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3061903,
    events_root: None,
}
2023-01-23T15:58:19.161428Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 2
2023-01-23T15:58:19.161431Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "eq"::Merge::2
2023-01-23T15:58:19.161433Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmBitwiseLogicOperation/eq.json"
2023-01-23T15:58:19.161435Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:58:19.161436Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:58:19.161607Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3064956,
    events_root: None,
}
2023-01-23T15:58:19.162759Z TRACE evm_eth_compliance::statetest::runner: TestDone => "test-vectors/tests/GeneralStateTests/VMTests/vmBitwiseLogicOperation/eq.json"
2023-01-23T15:58:19.162786Z TRACE evm_eth_compliance::statetest::runner: Calling testfile => "test-vectors/tests/GeneralStateTests/VMTests/vmBitwiseLogicOperation/gt.json"
2023-01-23T15:58:19.187302Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-23T15:58:19.187402Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-23T15:58:19.187404Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-23T15:58:19.187456Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-23T15:58:19.187458Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 2
2023-01-23T15:58:19.187513Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-23T15:58:19.187515Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 3
2023-01-23T15:58:19.187565Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-23T15:58:19.187567Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 4
2023-01-23T15:58:19.187616Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-23T15:58:19.187618Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 5
2023-01-23T15:58:19.187681Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-23T15:58:19.187750Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-23T15:58:19.187754Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "gt"::Istanbul::0
2023-01-23T15:58:19.187757Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmBitwiseLogicOperation/gt.json"
2023-01-23T15:58:19.187760Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:58:19.187762Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:58:19.543240Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3955993,
    events_root: None,
}
2023-01-23T15:58:19.543261Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 1
2023-01-23T15:58:19.543267Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "gt"::Istanbul::1
2023-01-23T15:58:19.543269Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmBitwiseLogicOperation/gt.json"
2023-01-23T15:58:19.543272Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:58:19.543274Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:58:19.543481Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3031202,
    events_root: None,
}
2023-01-23T15:58:19.543492Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 2
2023-01-23T15:58:19.543495Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "gt"::Istanbul::2
2023-01-23T15:58:19.543497Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmBitwiseLogicOperation/gt.json"
2023-01-23T15:58:19.543499Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:58:19.543501Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:58:19.543694Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3955396,
    events_root: None,
}
2023-01-23T15:58:19.543703Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 3
2023-01-23T15:58:19.543705Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "gt"::Istanbul::3
2023-01-23T15:58:19.543707Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmBitwiseLogicOperation/gt.json"
2023-01-23T15:58:19.543709Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:58:19.543711Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:58:19.543905Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3030605,
    events_root: None,
}
2023-01-23T15:58:19.543914Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-23T15:58:19.543917Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "gt"::Berlin::0
2023-01-23T15:58:19.543919Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmBitwiseLogicOperation/gt.json"
2023-01-23T15:58:19.543922Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:58:19.543923Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:58:19.544104Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3060407,
    events_root: None,
}
2023-01-23T15:58:19.544114Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 1
2023-01-23T15:58:19.544117Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "gt"::Berlin::1
2023-01-23T15:58:19.544118Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmBitwiseLogicOperation/gt.json"
2023-01-23T15:58:19.544121Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:58:19.544122Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:58:19.544296Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3031202,
    events_root: None,
}
2023-01-23T15:58:19.544305Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 2
2023-01-23T15:58:19.544307Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "gt"::Berlin::2
2023-01-23T15:58:19.544309Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmBitwiseLogicOperation/gt.json"
2023-01-23T15:58:19.544312Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:58:19.544313Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:58:19.544492Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3060174,
    events_root: None,
}
2023-01-23T15:58:19.544502Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 3
2023-01-23T15:58:19.544505Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "gt"::Berlin::3
2023-01-23T15:58:19.544507Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmBitwiseLogicOperation/gt.json"
2023-01-23T15:58:19.544510Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:58:19.544511Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:58:19.544684Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3030605,
    events_root: None,
}
2023-01-23T15:58:19.544692Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-23T15:58:19.544695Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "gt"::London::0
2023-01-23T15:58:19.544697Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmBitwiseLogicOperation/gt.json"
2023-01-23T15:58:19.544699Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:58:19.544701Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:58:19.544877Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3060407,
    events_root: None,
}
2023-01-23T15:58:19.544886Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 1
2023-01-23T15:58:19.544888Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "gt"::London::1
2023-01-23T15:58:19.544891Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmBitwiseLogicOperation/gt.json"
2023-01-23T15:58:19.544894Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:58:19.544895Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:58:19.545086Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3031202,
    events_root: None,
}
2023-01-23T15:58:19.545095Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 2
2023-01-23T15:58:19.545098Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "gt"::London::2
2023-01-23T15:58:19.545099Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmBitwiseLogicOperation/gt.json"
2023-01-23T15:58:19.545102Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:58:19.545103Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:58:19.545280Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3060174,
    events_root: None,
}
2023-01-23T15:58:19.545289Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 3
2023-01-23T15:58:19.545291Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "gt"::London::3
2023-01-23T15:58:19.545293Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmBitwiseLogicOperation/gt.json"
2023-01-23T15:58:19.545296Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:58:19.545297Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:58:19.545469Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3030605,
    events_root: None,
}
2023-01-23T15:58:19.545478Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-23T15:58:19.545481Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "gt"::Merge::0
2023-01-23T15:58:19.545483Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmBitwiseLogicOperation/gt.json"
2023-01-23T15:58:19.545486Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:58:19.545488Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:58:19.545676Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3060407,
    events_root: None,
}
2023-01-23T15:58:19.545686Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 1
2023-01-23T15:58:19.545690Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "gt"::Merge::1
2023-01-23T15:58:19.545692Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmBitwiseLogicOperation/gt.json"
2023-01-23T15:58:19.545696Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:58:19.545697Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:58:19.545885Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3031202,
    events_root: None,
}
2023-01-23T15:58:19.545894Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 2
2023-01-23T15:58:19.545896Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "gt"::Merge::2
2023-01-23T15:58:19.545898Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmBitwiseLogicOperation/gt.json"
2023-01-23T15:58:19.545901Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:58:19.545902Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:58:19.546078Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3060174,
    events_root: None,
}
2023-01-23T15:58:19.546087Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 3
2023-01-23T15:58:19.546089Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "gt"::Merge::3
2023-01-23T15:58:19.546091Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmBitwiseLogicOperation/gt.json"
2023-01-23T15:58:19.546093Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:58:19.546095Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:58:19.546265Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3030605,
    events_root: None,
}
2023-01-23T15:58:19.547430Z TRACE evm_eth_compliance::statetest::runner: TestDone => "test-vectors/tests/GeneralStateTests/VMTests/vmBitwiseLogicOperation/gt.json"
2023-01-23T15:58:19.547454Z TRACE evm_eth_compliance::statetest::runner: Calling testfile => "test-vectors/tests/GeneralStateTests/VMTests/vmBitwiseLogicOperation/iszero.json"
2023-01-23T15:58:19.572746Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-23T15:58:19.572848Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-23T15:58:19.572852Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-23T15:58:19.572904Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-23T15:58:19.572906Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 2
2023-01-23T15:58:19.572962Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-23T15:58:19.572964Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 3
2023-01-23T15:58:19.573017Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-23T15:58:19.573019Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 4
2023-01-23T15:58:19.573085Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-23T15:58:19.573196Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-23T15:58:19.573203Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "iszero"::Istanbul::0
2023-01-23T15:58:19.573207Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmBitwiseLogicOperation/iszero.json"
2023-01-23T15:58:19.573211Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:58:19.573213Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:58:19.914796Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3029889,
    events_root: None,
}
2023-01-23T15:58:19.914826Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 1
2023-01-23T15:58:19.914832Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "iszero"::Istanbul::1
2023-01-23T15:58:19.914835Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmBitwiseLogicOperation/iszero.json"
2023-01-23T15:58:19.914838Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:58:19.914840Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:58:19.915057Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3953329,
    events_root: None,
}
2023-01-23T15:58:19.915067Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 2
2023-01-23T15:58:19.915070Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "iszero"::Istanbul::2
2023-01-23T15:58:19.915073Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmBitwiseLogicOperation/iszero.json"
2023-01-23T15:58:19.915075Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:58:19.915077Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:58:19.915253Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3030349,
    events_root: None,
}
2023-01-23T15:58:19.915262Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-23T15:58:19.915265Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "iszero"::Berlin::0
2023-01-23T15:58:19.915267Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmBitwiseLogicOperation/iszero.json"
2023-01-23T15:58:19.915269Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:58:19.915271Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:58:19.915443Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3029889,
    events_root: None,
}
2023-01-23T15:58:19.915452Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 1
2023-01-23T15:58:19.915455Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "iszero"::Berlin::1
2023-01-23T15:58:19.915457Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmBitwiseLogicOperation/iszero.json"
2023-01-23T15:58:19.915460Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:58:19.915461Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:58:19.915640Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3057743,
    events_root: None,
}
2023-01-23T15:58:19.915649Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 2
2023-01-23T15:58:19.915651Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "iszero"::Berlin::2
2023-01-23T15:58:19.915653Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmBitwiseLogicOperation/iszero.json"
2023-01-23T15:58:19.915655Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:58:19.915657Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:58:19.915829Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3030349,
    events_root: None,
}
2023-01-23T15:58:19.915838Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-23T15:58:19.915840Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "iszero"::London::0
2023-01-23T15:58:19.915842Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmBitwiseLogicOperation/iszero.json"
2023-01-23T15:58:19.915845Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:58:19.915846Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:58:19.916016Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3029889,
    events_root: None,
}
2023-01-23T15:58:19.916025Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 1
2023-01-23T15:58:19.916028Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "iszero"::London::1
2023-01-23T15:58:19.916030Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmBitwiseLogicOperation/iszero.json"
2023-01-23T15:58:19.916032Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:58:19.916034Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:58:19.916207Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3057743,
    events_root: None,
}
2023-01-23T15:58:19.916217Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 2
2023-01-23T15:58:19.916219Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "iszero"::London::2
2023-01-23T15:58:19.916221Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmBitwiseLogicOperation/iszero.json"
2023-01-23T15:58:19.916223Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:58:19.916225Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:58:19.916449Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3030349,
    events_root: None,
}
2023-01-23T15:58:19.916461Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-23T15:58:19.916464Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "iszero"::Merge::0
2023-01-23T15:58:19.916467Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmBitwiseLogicOperation/iszero.json"
2023-01-23T15:58:19.916470Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:58:19.916472Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:58:19.916650Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3029889,
    events_root: None,
}
2023-01-23T15:58:19.916658Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 1
2023-01-23T15:58:19.916661Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "iszero"::Merge::1
2023-01-23T15:58:19.916663Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmBitwiseLogicOperation/iszero.json"
2023-01-23T15:58:19.916665Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:58:19.916667Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:58:19.916840Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3057743,
    events_root: None,
}
2023-01-23T15:58:19.916849Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 2
2023-01-23T15:58:19.916852Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "iszero"::Merge::2
2023-01-23T15:58:19.916854Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmBitwiseLogicOperation/iszero.json"
2023-01-23T15:58:19.916856Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:58:19.916858Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:58:19.917027Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3030349,
    events_root: None,
}
2023-01-23T15:58:19.918330Z TRACE evm_eth_compliance::statetest::runner: TestDone => "test-vectors/tests/GeneralStateTests/VMTests/vmBitwiseLogicOperation/iszero.json"
2023-01-23T15:58:19.918359Z TRACE evm_eth_compliance::statetest::runner: Calling testfile => "test-vectors/tests/GeneralStateTests/VMTests/vmBitwiseLogicOperation/lt.json"
2023-01-23T15:58:19.943691Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-23T15:58:19.943798Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-23T15:58:19.943802Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-23T15:58:19.943854Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-23T15:58:19.943856Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 2
2023-01-23T15:58:19.943913Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-23T15:58:19.943915Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 3
2023-01-23T15:58:19.943967Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-23T15:58:19.943969Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 4
2023-01-23T15:58:19.944020Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-23T15:58:19.944022Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 5
2023-01-23T15:58:19.944087Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-23T15:58:19.944159Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-23T15:58:19.944163Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "lt"::Istanbul::0
2023-01-23T15:58:19.944166Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmBitwiseLogicOperation/lt.json"
2023-01-23T15:58:19.944169Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:58:19.944170Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:58:20.281985Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3031202,
    events_root: None,
}
2023-01-23T15:58:20.282008Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 1
2023-01-23T15:58:20.282014Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "lt"::Istanbul::1
2023-01-23T15:58:20.282017Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmBitwiseLogicOperation/lt.json"
2023-01-23T15:58:20.282019Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:58:20.282021Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:58:20.282228Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3955993,
    events_root: None,
}
2023-01-23T15:58:20.282237Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 2
2023-01-23T15:58:20.282240Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "lt"::Istanbul::2
2023-01-23T15:58:20.282241Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmBitwiseLogicOperation/lt.json"
2023-01-23T15:58:20.282244Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:58:20.282245Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:58:20.282471Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3030605,
    events_root: None,
}
2023-01-23T15:58:20.282483Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 3
2023-01-23T15:58:20.282486Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "lt"::Istanbul::3
2023-01-23T15:58:20.282489Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmBitwiseLogicOperation/lt.json"
2023-01-23T15:58:20.282493Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:58:20.282495Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:58:20.282690Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3955396,
    events_root: None,
}
2023-01-23T15:58:20.282699Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-23T15:58:20.282702Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "lt"::Berlin::0
2023-01-23T15:58:20.282704Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmBitwiseLogicOperation/lt.json"
2023-01-23T15:58:20.282707Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:58:20.282708Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:58:20.282878Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3031202,
    events_root: None,
}
2023-01-23T15:58:20.282886Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 1
2023-01-23T15:58:20.282889Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "lt"::Berlin::1
2023-01-23T15:58:20.282891Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmBitwiseLogicOperation/lt.json"
2023-01-23T15:58:20.282893Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:58:20.282895Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:58:20.283081Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3060407,
    events_root: None,
}
2023-01-23T15:58:20.283090Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 2
2023-01-23T15:58:20.283093Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "lt"::Berlin::2
2023-01-23T15:58:20.283095Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmBitwiseLogicOperation/lt.json"
2023-01-23T15:58:20.283097Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:58:20.283099Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:58:20.283267Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3030605,
    events_root: None,
}
2023-01-23T15:58:20.283276Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 3
2023-01-23T15:58:20.283279Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "lt"::Berlin::3
2023-01-23T15:58:20.283280Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmBitwiseLogicOperation/lt.json"
2023-01-23T15:58:20.283283Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:58:20.283284Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:58:20.283455Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3060174,
    events_root: None,
}
2023-01-23T15:58:20.283464Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-23T15:58:20.283467Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "lt"::London::0
2023-01-23T15:58:20.283468Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmBitwiseLogicOperation/lt.json"
2023-01-23T15:58:20.283471Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:58:20.283472Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:58:20.283643Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3031202,
    events_root: None,
}
2023-01-23T15:58:20.283652Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 1
2023-01-23T15:58:20.283654Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "lt"::London::1
2023-01-23T15:58:20.283656Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmBitwiseLogicOperation/lt.json"
2023-01-23T15:58:20.283660Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:58:20.283662Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:58:20.283834Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3060407,
    events_root: None,
}
2023-01-23T15:58:20.283842Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 2
2023-01-23T15:58:20.283845Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "lt"::London::2
2023-01-23T15:58:20.283847Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmBitwiseLogicOperation/lt.json"
2023-01-23T15:58:20.283850Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:58:20.283851Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:58:20.284074Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3030605,
    events_root: None,
}
2023-01-23T15:58:20.284087Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 3
2023-01-23T15:58:20.284091Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "lt"::London::3
2023-01-23T15:58:20.284093Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmBitwiseLogicOperation/lt.json"
2023-01-23T15:58:20.284097Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:58:20.284099Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:58:20.284273Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3060174,
    events_root: None,
}
2023-01-23T15:58:20.284282Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-23T15:58:20.284285Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "lt"::Merge::0
2023-01-23T15:58:20.284286Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmBitwiseLogicOperation/lt.json"
2023-01-23T15:58:20.284289Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:58:20.284290Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:58:20.284460Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3031202,
    events_root: None,
}
2023-01-23T15:58:20.284468Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 1
2023-01-23T15:58:20.284471Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "lt"::Merge::1
2023-01-23T15:58:20.284473Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmBitwiseLogicOperation/lt.json"
2023-01-23T15:58:20.284475Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:58:20.284477Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:58:20.284647Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3060407,
    events_root: None,
}
2023-01-23T15:58:20.284657Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 2
2023-01-23T15:58:20.284660Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "lt"::Merge::2
2023-01-23T15:58:20.284662Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmBitwiseLogicOperation/lt.json"
2023-01-23T15:58:20.284664Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:58:20.284666Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:58:20.284834Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3030605,
    events_root: None,
}
2023-01-23T15:58:20.284842Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 3
2023-01-23T15:58:20.284845Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "lt"::Merge::3
2023-01-23T15:58:20.284846Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmBitwiseLogicOperation/lt.json"
2023-01-23T15:58:20.284849Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:58:20.284850Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:58:20.285021Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3060174,
    events_root: None,
}
2023-01-23T15:58:20.286463Z TRACE evm_eth_compliance::statetest::runner: TestDone => "test-vectors/tests/GeneralStateTests/VMTests/vmBitwiseLogicOperation/lt.json"
2023-01-23T15:58:20.286490Z TRACE evm_eth_compliance::statetest::runner: Calling testfile => "test-vectors/tests/GeneralStateTests/VMTests/vmBitwiseLogicOperation/not.json"
2023-01-23T15:58:20.313907Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-23T15:58:20.314035Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-23T15:58:20.314039Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-23T15:58:20.314102Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-23T15:58:20.314105Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 2
2023-01-23T15:58:20.314178Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-23T15:58:20.314180Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 3
2023-01-23T15:58:20.314245Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-23T15:58:20.314248Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 4
2023-01-23T15:58:20.314308Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-23T15:58:20.314310Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 5
2023-01-23T15:58:20.314391Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-23T15:58:20.314394Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 6
2023-01-23T15:58:20.314463Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-23T15:58:20.314466Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 7
2023-01-23T15:58:20.314523Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-23T15:58:20.314623Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-23T15:58:20.314632Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "not"::Istanbul::0
2023-01-23T15:58:20.314635Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmBitwiseLogicOperation/not.json"
2023-01-23T15:58:20.314639Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:58:20.314641Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:58:20.685380Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3997282,
    events_root: None,
}
2023-01-23T15:58:20.685406Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 1
2023-01-23T15:58:20.685412Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "not"::Istanbul::1
2023-01-23T15:58:20.685415Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmBitwiseLogicOperation/not.json"
2023-01-23T15:58:20.685418Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:58:20.685419Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:58:20.685619Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3997282,
    events_root: None,
}
2023-01-23T15:58:20.685638Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 2
2023-01-23T15:58:20.685641Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "not"::Istanbul::2
2023-01-23T15:58:20.685643Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmBitwiseLogicOperation/not.json"
2023-01-23T15:58:20.685646Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:58:20.685647Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:58:20.685825Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3029897,
    events_root: None,
}
2023-01-23T15:58:20.685834Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 3
2023-01-23T15:58:20.685836Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "not"::Istanbul::3
2023-01-23T15:58:20.685839Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmBitwiseLogicOperation/not.json"
2023-01-23T15:58:20.685841Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:58:20.685843Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:58:20.686039Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3955148,
    events_root: None,
}
2023-01-23T15:58:20.686050Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 4
2023-01-23T15:58:20.686053Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "not"::Istanbul::4
2023-01-23T15:58:20.686056Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmBitwiseLogicOperation/not.json"
2023-01-23T15:58:20.686058Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:58:20.686060Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:58:20.686248Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 4000324,
    events_root: None,
}
2023-01-23T15:58:20.686259Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 5
2023-01-23T15:58:20.686262Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "not"::Istanbul::5
2023-01-23T15:58:20.686264Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmBitwiseLogicOperation/not.json"
2023-01-23T15:58:20.686266Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:58:20.686268Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:58:20.686453Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3999089,
    events_root: None,
}
2023-01-23T15:58:20.686465Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-23T15:58:20.686467Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "not"::Berlin::0
2023-01-23T15:58:20.686469Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmBitwiseLogicOperation/not.json"
2023-01-23T15:58:20.686472Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:58:20.686473Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:58:20.686648Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3059028,
    events_root: None,
}
2023-01-23T15:58:20.686657Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 1
2023-01-23T15:58:20.686659Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "not"::Berlin::1
2023-01-23T15:58:20.686661Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmBitwiseLogicOperation/not.json"
2023-01-23T15:58:20.686664Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:58:20.686665Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:58:20.686843Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3059028,
    events_root: None,
}
2023-01-23T15:58:20.686852Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 2
2023-01-23T15:58:20.686854Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "not"::Berlin::2
2023-01-23T15:58:20.686856Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmBitwiseLogicOperation/not.json"
2023-01-23T15:58:20.686859Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:58:20.686860Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:58:20.687030Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3029897,
    events_root: None,
}
2023-01-23T15:58:20.687039Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 3
2023-01-23T15:58:20.687042Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "not"::Berlin::3
2023-01-23T15:58:20.687044Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmBitwiseLogicOperation/not.json"
2023-01-23T15:58:20.687046Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:58:20.687047Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:58:20.687221Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3059562,
    events_root: None,
}
2023-01-23T15:58:20.687229Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 4
2023-01-23T15:58:20.687232Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "not"::Berlin::4
2023-01-23T15:58:20.687234Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmBitwiseLogicOperation/not.json"
2023-01-23T15:58:20.687236Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:58:20.687238Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:58:20.687411Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3061225,
    events_root: None,
}
2023-01-23T15:58:20.687421Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 5
2023-01-23T15:58:20.687423Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "not"::Berlin::5
2023-01-23T15:58:20.687425Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmBitwiseLogicOperation/not.json"
2023-01-23T15:58:20.687427Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:58:20.687429Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:58:20.687605Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3060835,
    events_root: None,
}
2023-01-23T15:58:20.687614Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-23T15:58:20.687616Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "not"::London::0
2023-01-23T15:58:20.687618Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmBitwiseLogicOperation/not.json"
2023-01-23T15:58:20.687621Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:58:20.687622Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:58:20.687796Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3059028,
    events_root: None,
}
2023-01-23T15:58:20.687805Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 1
2023-01-23T15:58:20.687807Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "not"::London::1
2023-01-23T15:58:20.687809Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmBitwiseLogicOperation/not.json"
2023-01-23T15:58:20.687811Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:58:20.687813Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:58:20.687985Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3059028,
    events_root: None,
}
2023-01-23T15:58:20.687994Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 2
2023-01-23T15:58:20.687996Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "not"::London::2
2023-01-23T15:58:20.687998Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmBitwiseLogicOperation/not.json"
2023-01-23T15:58:20.688001Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:58:20.688002Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:58:20.688172Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3029897,
    events_root: None,
}
2023-01-23T15:58:20.688181Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 3
2023-01-23T15:58:20.688183Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "not"::London::3
2023-01-23T15:58:20.688185Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmBitwiseLogicOperation/not.json"
2023-01-23T15:58:20.688188Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:58:20.688189Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:58:20.688363Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3059562,
    events_root: None,
}
2023-01-23T15:58:20.688372Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 4
2023-01-23T15:58:20.688374Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "not"::London::4
2023-01-23T15:58:20.688376Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmBitwiseLogicOperation/not.json"
2023-01-23T15:58:20.688379Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:58:20.688380Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:58:20.688556Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3061225,
    events_root: None,
}
2023-01-23T15:58:20.688565Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 5
2023-01-23T15:58:20.688567Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "not"::London::5
2023-01-23T15:58:20.688569Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmBitwiseLogicOperation/not.json"
2023-01-23T15:58:20.688571Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:58:20.688573Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:58:20.688745Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3060835,
    events_root: None,
}
2023-01-23T15:58:20.688754Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-23T15:58:20.688757Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "not"::Merge::0
2023-01-23T15:58:20.688759Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmBitwiseLogicOperation/not.json"
2023-01-23T15:58:20.688761Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:58:20.688763Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:58:20.688936Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3059028,
    events_root: None,
}
2023-01-23T15:58:20.688945Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 1
2023-01-23T15:58:20.688947Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "not"::Merge::1
2023-01-23T15:58:20.688949Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmBitwiseLogicOperation/not.json"
2023-01-23T15:58:20.688952Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:58:20.688953Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:58:20.689125Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3059028,
    events_root: None,
}
2023-01-23T15:58:20.689134Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 2
2023-01-23T15:58:20.689136Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "not"::Merge::2
2023-01-23T15:58:20.689138Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmBitwiseLogicOperation/not.json"
2023-01-23T15:58:20.689141Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:58:20.689142Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:58:20.689312Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3029897,
    events_root: None,
}
2023-01-23T15:58:20.689320Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 3
2023-01-23T15:58:20.689323Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "not"::Merge::3
2023-01-23T15:58:20.689325Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmBitwiseLogicOperation/not.json"
2023-01-23T15:58:20.689327Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:58:20.689329Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:58:20.689503Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3059562,
    events_root: None,
}
2023-01-23T15:58:20.689512Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 4
2023-01-23T15:58:20.689514Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "not"::Merge::4
2023-01-23T15:58:20.689516Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmBitwiseLogicOperation/not.json"
2023-01-23T15:58:20.689519Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:58:20.689520Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:58:20.689701Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3061225,
    events_root: None,
}
2023-01-23T15:58:20.689710Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 5
2023-01-23T15:58:20.689713Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "not"::Merge::5
2023-01-23T15:58:20.689715Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmBitwiseLogicOperation/not.json"
2023-01-23T15:58:20.689717Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:58:20.689719Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:58:20.689893Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3060835,
    events_root: None,
}
2023-01-23T15:58:20.691146Z TRACE evm_eth_compliance::statetest::runner: TestDone => "test-vectors/tests/GeneralStateTests/VMTests/vmBitwiseLogicOperation/not.json"
2023-01-23T15:58:20.691176Z TRACE evm_eth_compliance::statetest::runner: Calling testfile => "test-vectors/tests/GeneralStateTests/VMTests/vmBitwiseLogicOperation/or.json"
2023-01-23T15:58:20.716354Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-23T15:58:20.716458Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-23T15:58:20.716462Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-23T15:58:20.716513Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-23T15:58:20.716516Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 2
2023-01-23T15:58:20.716572Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-23T15:58:20.716574Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 3
2023-01-23T15:58:20.716627Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-23T15:58:20.716629Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 4
2023-01-23T15:58:20.716675Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-23T15:58:20.716676Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 5
2023-01-23T15:58:20.716738Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-23T15:58:20.716740Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 6
2023-01-23T15:58:20.716795Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-23T15:58:20.716797Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 7
2023-01-23T15:58:20.716842Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-23T15:58:20.716913Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-23T15:58:20.716917Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "or"::Istanbul::0
2023-01-23T15:58:20.716920Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmBitwiseLogicOperation/or.json"
2023-01-23T15:58:20.716923Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:58:20.716924Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:58:21.070191Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3954202,
    events_root: None,
}
2023-01-23T15:58:21.070218Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 1
2023-01-23T15:58:21.070226Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "or"::Istanbul::1
2023-01-23T15:58:21.070228Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmBitwiseLogicOperation/or.json"
2023-01-23T15:58:21.070231Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:58:21.070233Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:58:21.070438Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3954202,
    events_root: None,
}
2023-01-23T15:58:21.070450Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 2
2023-01-23T15:58:21.070452Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "or"::Istanbul::2
2023-01-23T15:58:21.070454Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmBitwiseLogicOperation/or.json"
2023-01-23T15:58:21.070457Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:58:21.070458Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:58:21.070653Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3954202,
    events_root: None,
}
2023-01-23T15:58:21.070665Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 3
2023-01-23T15:58:21.070668Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "or"::Istanbul::3
2023-01-23T15:58:21.070669Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmBitwiseLogicOperation/or.json"
2023-01-23T15:58:21.070672Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:58:21.070673Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:58:21.070873Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 4000836,
    events_root: None,
}
2023-01-23T15:58:21.070885Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 4
2023-01-23T15:58:21.070888Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "or"::Istanbul::4
2023-01-23T15:58:21.070890Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmBitwiseLogicOperation/or.json"
2023-01-23T15:58:21.070893Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:58:21.070896Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:58:21.071098Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 4000836,
    events_root: None,
}
2023-01-23T15:58:21.071110Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 5
2023-01-23T15:58:21.071112Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "or"::Istanbul::5
2023-01-23T15:58:21.071114Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmBitwiseLogicOperation/or.json"
2023-01-23T15:58:21.071117Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:58:21.071118Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:58:21.071310Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 4000836,
    events_root: None,
}
2023-01-23T15:58:21.071321Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-23T15:58:21.071325Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "or"::Berlin::0
2023-01-23T15:58:21.071327Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmBitwiseLogicOperation/or.json"
2023-01-23T15:58:21.071330Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:58:21.071331Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:58:21.071512Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3058615,
    events_root: None,
}
2023-01-23T15:58:21.071521Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 1
2023-01-23T15:58:21.071524Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "or"::Berlin::1
2023-01-23T15:58:21.071525Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmBitwiseLogicOperation/or.json"
2023-01-23T15:58:21.071528Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:58:21.071529Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:58:21.071710Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3058615,
    events_root: None,
}
2023-01-23T15:58:21.071719Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 2
2023-01-23T15:58:21.071721Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "or"::Berlin::2
2023-01-23T15:58:21.071723Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmBitwiseLogicOperation/or.json"
2023-01-23T15:58:21.071726Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:58:21.071727Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:58:21.071910Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3058615,
    events_root: None,
}
2023-01-23T15:58:21.071920Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 3
2023-01-23T15:58:21.071923Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "or"::Berlin::3
2023-01-23T15:58:21.071925Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmBitwiseLogicOperation/or.json"
2023-01-23T15:58:21.071928Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:58:21.071929Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:58:21.072123Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3062101,
    events_root: None,
}
2023-01-23T15:58:21.072131Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 4
2023-01-23T15:58:21.072134Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "or"::Berlin::4
2023-01-23T15:58:21.072135Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmBitwiseLogicOperation/or.json"
2023-01-23T15:58:21.072138Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:58:21.072139Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:58:21.072326Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3062101,
    events_root: None,
}
2023-01-23T15:58:21.072336Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 5
2023-01-23T15:58:21.072338Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "or"::Berlin::5
2023-01-23T15:58:21.072341Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmBitwiseLogicOperation/or.json"
2023-01-23T15:58:21.072344Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:58:21.072345Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:58:21.072545Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3062101,
    events_root: None,
}
2023-01-23T15:58:21.072554Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-23T15:58:21.072556Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "or"::London::0
2023-01-23T15:58:21.072558Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmBitwiseLogicOperation/or.json"
2023-01-23T15:58:21.072560Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:58:21.072562Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:58:21.072743Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3058615,
    events_root: None,
}
2023-01-23T15:58:21.072752Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 1
2023-01-23T15:58:21.072754Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "or"::London::1
2023-01-23T15:58:21.072756Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmBitwiseLogicOperation/or.json"
2023-01-23T15:58:21.072759Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:58:21.072760Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:58:21.072940Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3058615,
    events_root: None,
}
2023-01-23T15:58:21.072949Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 2
2023-01-23T15:58:21.072952Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "or"::London::2
2023-01-23T15:58:21.072954Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmBitwiseLogicOperation/or.json"
2023-01-23T15:58:21.072956Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:58:21.072957Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:58:21.073136Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3058615,
    events_root: None,
}
2023-01-23T15:58:21.073145Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 3
2023-01-23T15:58:21.073148Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "or"::London::3
2023-01-23T15:58:21.073150Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmBitwiseLogicOperation/or.json"
2023-01-23T15:58:21.073154Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:58:21.073155Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:58:21.073334Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3062101,
    events_root: None,
}
2023-01-23T15:58:21.073344Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 4
2023-01-23T15:58:21.073347Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "or"::London::4
2023-01-23T15:58:21.073349Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmBitwiseLogicOperation/or.json"
2023-01-23T15:58:21.073351Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:58:21.073352Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:58:21.073533Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3062101,
    events_root: None,
}
2023-01-23T15:58:21.073541Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 5
2023-01-23T15:58:21.073544Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "or"::London::5
2023-01-23T15:58:21.073546Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmBitwiseLogicOperation/or.json"
2023-01-23T15:58:21.073549Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:58:21.073550Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:58:21.073739Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3062101,
    events_root: None,
}
2023-01-23T15:58:21.073749Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-23T15:58:21.073752Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "or"::Merge::0
2023-01-23T15:58:21.073756Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmBitwiseLogicOperation/or.json"
2023-01-23T15:58:21.073759Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:58:21.073761Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:58:21.073956Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3058615,
    events_root: None,
}
2023-01-23T15:58:21.073966Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 1
2023-01-23T15:58:21.073968Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "or"::Merge::1
2023-01-23T15:58:21.073971Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmBitwiseLogicOperation/or.json"
2023-01-23T15:58:21.073974Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:58:21.073975Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:58:21.074168Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3058615,
    events_root: None,
}
2023-01-23T15:58:21.074178Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 2
2023-01-23T15:58:21.074180Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "or"::Merge::2
2023-01-23T15:58:21.074183Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmBitwiseLogicOperation/or.json"
2023-01-23T15:58:21.074186Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:58:21.074187Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:58:21.074382Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3058615,
    events_root: None,
}
2023-01-23T15:58:21.074392Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 3
2023-01-23T15:58:21.074394Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "or"::Merge::3
2023-01-23T15:58:21.074397Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmBitwiseLogicOperation/or.json"
2023-01-23T15:58:21.074400Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:58:21.074401Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:58:21.074594Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3062101,
    events_root: None,
}
2023-01-23T15:58:21.074604Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 4
2023-01-23T15:58:21.074607Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "or"::Merge::4
2023-01-23T15:58:21.074609Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmBitwiseLogicOperation/or.json"
2023-01-23T15:58:21.074612Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:58:21.074614Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:58:21.074804Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3062101,
    events_root: None,
}
2023-01-23T15:58:21.074812Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 5
2023-01-23T15:58:21.074815Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "or"::Merge::5
2023-01-23T15:58:21.074817Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmBitwiseLogicOperation/or.json"
2023-01-23T15:58:21.074819Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:58:21.074821Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:58:21.075000Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3062101,
    events_root: None,
}
2023-01-23T15:58:21.076313Z TRACE evm_eth_compliance::statetest::runner: TestDone => "test-vectors/tests/GeneralStateTests/VMTests/vmBitwiseLogicOperation/or.json"
2023-01-23T15:58:21.076338Z TRACE evm_eth_compliance::statetest::runner: Calling testfile => "test-vectors/tests/GeneralStateTests/VMTests/vmBitwiseLogicOperation/sgt.json"
2023-01-23T15:58:21.101831Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-23T15:58:21.101937Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-23T15:58:21.101941Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-23T15:58:21.101994Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-23T15:58:21.101997Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 2
2023-01-23T15:58:21.102054Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-23T15:58:21.102056Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 3
2023-01-23T15:58:21.102109Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-23T15:58:21.102111Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 4
2023-01-23T15:58:21.102163Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-23T15:58:21.102166Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 5
2023-01-23T15:58:21.102230Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-23T15:58:21.102302Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-23T15:58:21.102307Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "sgt"::Istanbul::0
2023-01-23T15:58:21.102310Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmBitwiseLogicOperation/sgt.json"
2023-01-23T15:58:21.102313Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:58:21.102314Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:58:21.448580Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3031206,
    events_root: None,
}
2023-01-23T15:58:21.448601Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 1
2023-01-23T15:58:21.448609Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "sgt"::Istanbul::1
2023-01-23T15:58:21.448612Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmBitwiseLogicOperation/sgt.json"
2023-01-23T15:58:21.448615Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:58:21.448616Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:58:21.448831Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3955997,
    events_root: None,
}
2023-01-23T15:58:21.448841Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 2
2023-01-23T15:58:21.448844Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "sgt"::Istanbul::2
2023-01-23T15:58:21.448846Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmBitwiseLogicOperation/sgt.json"
2023-01-23T15:58:21.448848Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:58:21.448850Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:58:21.449024Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3030609,
    events_root: None,
}
2023-01-23T15:58:21.449033Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 3
2023-01-23T15:58:21.449035Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "sgt"::Istanbul::3
2023-01-23T15:58:21.449038Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmBitwiseLogicOperation/sgt.json"
2023-01-23T15:58:21.449040Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:58:21.449042Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:58:21.449236Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3955400,
    events_root: None,
}
2023-01-23T15:58:21.449245Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-23T15:58:21.449248Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "sgt"::Berlin::0
2023-01-23T15:58:21.449250Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmBitwiseLogicOperation/sgt.json"
2023-01-23T15:58:21.449253Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:58:21.449254Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:58:21.449424Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3031206,
    events_root: None,
}
2023-01-23T15:58:21.449433Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 1
2023-01-23T15:58:21.449436Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "sgt"::Berlin::1
2023-01-23T15:58:21.449437Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmBitwiseLogicOperation/sgt.json"
2023-01-23T15:58:21.449440Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:58:21.449441Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:58:21.449620Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3060411,
    events_root: None,
}
2023-01-23T15:58:21.449637Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 2
2023-01-23T15:58:21.449640Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "sgt"::Berlin::2
2023-01-23T15:58:21.449642Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmBitwiseLogicOperation/sgt.json"
2023-01-23T15:58:21.449645Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:58:21.449646Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:58:21.449818Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3030609,
    events_root: None,
}
2023-01-23T15:58:21.449827Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 3
2023-01-23T15:58:21.449829Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "sgt"::Berlin::3
2023-01-23T15:58:21.449831Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmBitwiseLogicOperation/sgt.json"
2023-01-23T15:58:21.449834Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:58:21.449835Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:58:21.450008Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3060178,
    events_root: None,
}
2023-01-23T15:58:21.450017Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-23T15:58:21.450020Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "sgt"::London::0
2023-01-23T15:58:21.450022Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmBitwiseLogicOperation/sgt.json"
2023-01-23T15:58:21.450024Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:58:21.450026Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:58:21.450200Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3031206,
    events_root: None,
}
2023-01-23T15:58:21.450209Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 1
2023-01-23T15:58:21.450212Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "sgt"::London::1
2023-01-23T15:58:21.450214Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmBitwiseLogicOperation/sgt.json"
2023-01-23T15:58:21.450217Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:58:21.450218Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:58:21.450393Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3060411,
    events_root: None,
}
2023-01-23T15:58:21.450402Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 2
2023-01-23T15:58:21.450404Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "sgt"::London::2
2023-01-23T15:58:21.450406Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmBitwiseLogicOperation/sgt.json"
2023-01-23T15:58:21.450408Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:58:21.450410Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:58:21.450579Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3030609,
    events_root: None,
}
2023-01-23T15:58:21.450587Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 3
2023-01-23T15:58:21.450590Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "sgt"::London::3
2023-01-23T15:58:21.450591Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmBitwiseLogicOperation/sgt.json"
2023-01-23T15:58:21.450594Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:58:21.450596Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:58:21.450769Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3060178,
    events_root: None,
}
2023-01-23T15:58:21.450778Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-23T15:58:21.450780Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "sgt"::Merge::0
2023-01-23T15:58:21.450782Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmBitwiseLogicOperation/sgt.json"
2023-01-23T15:58:21.450784Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:58:21.450786Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:58:21.450954Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3031206,
    events_root: None,
}
2023-01-23T15:58:21.450963Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 1
2023-01-23T15:58:21.450965Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "sgt"::Merge::1
2023-01-23T15:58:21.450967Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmBitwiseLogicOperation/sgt.json"
2023-01-23T15:58:21.450969Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:58:21.450970Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:58:21.451148Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3060411,
    events_root: None,
}
2023-01-23T15:58:21.451157Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 2
2023-01-23T15:58:21.451159Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "sgt"::Merge::2
2023-01-23T15:58:21.451161Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmBitwiseLogicOperation/sgt.json"
2023-01-23T15:58:21.451163Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:58:21.451165Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:58:21.451332Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3030609,
    events_root: None,
}
2023-01-23T15:58:21.451341Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 3
2023-01-23T15:58:21.451343Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "sgt"::Merge::3
2023-01-23T15:58:21.451345Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmBitwiseLogicOperation/sgt.json"
2023-01-23T15:58:21.451347Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:58:21.451350Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:58:21.451523Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3060178,
    events_root: None,
}
2023-01-23T15:58:21.453208Z TRACE evm_eth_compliance::statetest::runner: TestDone => "test-vectors/tests/GeneralStateTests/VMTests/vmBitwiseLogicOperation/sgt.json"
2023-01-23T15:58:21.453236Z TRACE evm_eth_compliance::statetest::runner: Calling testfile => "test-vectors/tests/GeneralStateTests/VMTests/vmBitwiseLogicOperation/slt.json"
2023-01-23T15:58:21.479180Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-23T15:58:21.479286Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-23T15:58:21.479289Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-23T15:58:21.479340Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-23T15:58:21.479342Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 2
2023-01-23T15:58:21.479397Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-23T15:58:21.479398Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 3
2023-01-23T15:58:21.479449Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-23T15:58:21.479451Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 4
2023-01-23T15:58:21.479501Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-23T15:58:21.479503Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 5
2023-01-23T15:58:21.479565Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-23T15:58:21.479637Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-23T15:58:21.479641Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "slt"::Istanbul::0
2023-01-23T15:58:21.479644Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmBitwiseLogicOperation/slt.json"
2023-01-23T15:58:21.479647Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:58:21.479649Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:58:21.826046Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3955997,
    events_root: None,
}
2023-01-23T15:58:21.826071Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 1
2023-01-23T15:58:21.826077Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "slt"::Istanbul::1
2023-01-23T15:58:21.826079Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmBitwiseLogicOperation/slt.json"
2023-01-23T15:58:21.826082Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:58:21.826084Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:58:21.826264Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3031206,
    events_root: None,
}
2023-01-23T15:58:21.826273Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 2
2023-01-23T15:58:21.826276Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "slt"::Istanbul::2
2023-01-23T15:58:21.826278Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmBitwiseLogicOperation/slt.json"
2023-01-23T15:58:21.826281Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:58:21.826282Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:58:21.826464Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3955400,
    events_root: None,
}
2023-01-23T15:58:21.826473Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 3
2023-01-23T15:58:21.826475Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "slt"::Istanbul::3
2023-01-23T15:58:21.826477Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmBitwiseLogicOperation/slt.json"
2023-01-23T15:58:21.826479Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:58:21.826481Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:58:21.826647Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3030609,
    events_root: None,
}
2023-01-23T15:58:21.826656Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-23T15:58:21.826659Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "slt"::Berlin::0
2023-01-23T15:58:21.826660Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmBitwiseLogicOperation/slt.json"
2023-01-23T15:58:21.826663Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:58:21.826664Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:58:21.826839Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3060411,
    events_root: None,
}
2023-01-23T15:58:21.826848Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 1
2023-01-23T15:58:21.826851Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "slt"::Berlin::1
2023-01-23T15:58:21.826853Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmBitwiseLogicOperation/slt.json"
2023-01-23T15:58:21.826855Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:58:21.826856Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:58:21.827021Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3031206,
    events_root: None,
}
2023-01-23T15:58:21.827029Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 2
2023-01-23T15:58:21.827031Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "slt"::Berlin::2
2023-01-23T15:58:21.827033Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmBitwiseLogicOperation/slt.json"
2023-01-23T15:58:21.827036Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:58:21.827037Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:58:21.827205Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3060178,
    events_root: None,
}
2023-01-23T15:58:21.827213Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 3
2023-01-23T15:58:21.827215Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "slt"::Berlin::3
2023-01-23T15:58:21.827217Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmBitwiseLogicOperation/slt.json"
2023-01-23T15:58:21.827220Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:58:21.827221Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:58:21.827386Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3030609,
    events_root: None,
}
2023-01-23T15:58:21.827394Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-23T15:58:21.827397Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "slt"::London::0
2023-01-23T15:58:21.827399Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmBitwiseLogicOperation/slt.json"
2023-01-23T15:58:21.827401Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:58:21.827403Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:58:21.827569Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3060411,
    events_root: None,
}
2023-01-23T15:58:21.827577Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 1
2023-01-23T15:58:21.827580Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "slt"::London::1
2023-01-23T15:58:21.827582Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmBitwiseLogicOperation/slt.json"
2023-01-23T15:58:21.827584Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:58:21.827585Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:58:21.827749Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3031206,
    events_root: None,
}
2023-01-23T15:58:21.827757Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 2
2023-01-23T15:58:21.827759Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "slt"::London::2
2023-01-23T15:58:21.827761Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmBitwiseLogicOperation/slt.json"
2023-01-23T15:58:21.827764Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:58:21.827765Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:58:21.827937Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3060178,
    events_root: None,
}
2023-01-23T15:58:21.827946Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 3
2023-01-23T15:58:21.827948Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "slt"::London::3
2023-01-23T15:58:21.827950Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmBitwiseLogicOperation/slt.json"
2023-01-23T15:58:21.827952Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:58:21.827954Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:58:21.828118Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3030609,
    events_root: None,
}
2023-01-23T15:58:21.828126Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-23T15:58:21.828129Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "slt"::Merge::0
2023-01-23T15:58:21.828130Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmBitwiseLogicOperation/slt.json"
2023-01-23T15:58:21.828133Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:58:21.828134Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:58:21.828301Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3060411,
    events_root: None,
}
2023-01-23T15:58:21.828309Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 1
2023-01-23T15:58:21.828311Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "slt"::Merge::1
2023-01-23T15:58:21.828313Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmBitwiseLogicOperation/slt.json"
2023-01-23T15:58:21.828316Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:58:21.828317Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:58:21.828481Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3031206,
    events_root: None,
}
2023-01-23T15:58:21.828489Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 2
2023-01-23T15:58:21.828491Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "slt"::Merge::2
2023-01-23T15:58:21.828493Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmBitwiseLogicOperation/slt.json"
2023-01-23T15:58:21.828495Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:58:21.828497Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:58:21.828663Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3060178,
    events_root: None,
}
2023-01-23T15:58:21.828671Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 3
2023-01-23T15:58:21.828674Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "slt"::Merge::3
2023-01-23T15:58:21.828676Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmBitwiseLogicOperation/slt.json"
2023-01-23T15:58:21.828678Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:58:21.828680Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:58:21.828842Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3030609,
    events_root: None,
}
2023-01-23T15:58:21.830284Z TRACE evm_eth_compliance::statetest::runner: TestDone => "test-vectors/tests/GeneralStateTests/VMTests/vmBitwiseLogicOperation/slt.json"
2023-01-23T15:58:21.830309Z TRACE evm_eth_compliance::statetest::runner: Calling testfile => "test-vectors/tests/GeneralStateTests/VMTests/vmBitwiseLogicOperation/xor.json"
2023-01-23T15:58:21.856802Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-23T15:58:21.856911Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-23T15:58:21.856915Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-23T15:58:21.856968Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-23T15:58:21.856971Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 2
2023-01-23T15:58:21.857029Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-23T15:58:21.857032Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 3
2023-01-23T15:58:21.857085Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-23T15:58:21.857088Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 4
2023-01-23T15:58:21.857135Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-23T15:58:21.857137Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 5
2023-01-23T15:58:21.857197Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-23T15:58:21.857200Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 6
2023-01-23T15:58:21.857255Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-23T15:58:21.857257Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 7
2023-01-23T15:58:21.857303Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-23T15:58:21.857375Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-23T15:58:21.857380Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "xor"::Istanbul::0
2023-01-23T15:58:21.857382Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmBitwiseLogicOperation/xor.json"
2023-01-23T15:58:21.857386Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:58:21.857387Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:58:22.238479Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3029411,
    events_root: None,
}
2023-01-23T15:58:22.238501Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 1
2023-01-23T15:58:22.238508Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "xor"::Istanbul::1
2023-01-23T15:58:22.238511Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmBitwiseLogicOperation/xor.json"
2023-01-23T15:58:22.238514Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:58:22.238515Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:58:22.238718Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3954202,
    events_root: None,
}
2023-01-23T15:58:22.238729Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 2
2023-01-23T15:58:22.238732Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "xor"::Istanbul::2
2023-01-23T15:58:22.238734Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmBitwiseLogicOperation/xor.json"
2023-01-23T15:58:22.238737Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:58:22.238738Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:58:22.238967Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3954202,
    events_root: None,
}
2023-01-23T15:58:22.238981Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 3
2023-01-23T15:58:22.238984Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "xor"::Istanbul::3
2023-01-23T15:58:22.238987Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmBitwiseLogicOperation/xor.json"
2023-01-23T15:58:22.238990Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:58:22.238992Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:58:22.239196Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 4000836,
    events_root: None,
}
2023-01-23T15:58:22.239209Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 4
2023-01-23T15:58:22.239211Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "xor"::Istanbul::4
2023-01-23T15:58:22.239214Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmBitwiseLogicOperation/xor.json"
2023-01-23T15:58:22.239216Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:58:22.239218Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:58:22.239403Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 4000836,
    events_root: None,
}
2023-01-23T15:58:22.239415Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 5
2023-01-23T15:58:22.239418Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "xor"::Istanbul::5
2023-01-23T15:58:22.239420Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmBitwiseLogicOperation/xor.json"
2023-01-23T15:58:22.239423Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:58:22.239424Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:58:22.239610Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 4000836,
    events_root: None,
}
2023-01-23T15:58:22.239621Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-23T15:58:22.239625Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "xor"::Berlin::0
2023-01-23T15:58:22.239627Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmBitwiseLogicOperation/xor.json"
2023-01-23T15:58:22.239629Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:58:22.239631Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:58:22.239801Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3029411,
    events_root: None,
}
2023-01-23T15:58:22.239811Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 1
2023-01-23T15:58:22.239814Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "xor"::Berlin::1
2023-01-23T15:58:22.239816Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmBitwiseLogicOperation/xor.json"
2023-01-23T15:58:22.239819Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:58:22.239820Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:58:22.239994Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3058615,
    events_root: None,
}
2023-01-23T15:58:22.240005Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 2
2023-01-23T15:58:22.240008Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "xor"::Berlin::2
2023-01-23T15:58:22.240010Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmBitwiseLogicOperation/xor.json"
2023-01-23T15:58:22.240012Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:58:22.240014Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:58:22.240183Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3058615,
    events_root: None,
}
2023-01-23T15:58:22.240193Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 3
2023-01-23T15:58:22.240196Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "xor"::Berlin::3
2023-01-23T15:58:22.240198Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmBitwiseLogicOperation/xor.json"
2023-01-23T15:58:22.240201Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:58:22.240202Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:58:22.240372Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3062101,
    events_root: None,
}
2023-01-23T15:58:22.240383Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 4
2023-01-23T15:58:22.240385Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "xor"::Berlin::4
2023-01-23T15:58:22.240388Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmBitwiseLogicOperation/xor.json"
2023-01-23T15:58:22.240390Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:58:22.240391Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:58:22.240563Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3062101,
    events_root: None,
}
2023-01-23T15:58:22.240574Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 5
2023-01-23T15:58:22.240577Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "xor"::Berlin::5
2023-01-23T15:58:22.240578Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmBitwiseLogicOperation/xor.json"
2023-01-23T15:58:22.240581Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:58:22.240583Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:58:22.240755Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3062101,
    events_root: None,
}
2023-01-23T15:58:22.240765Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-23T15:58:22.240769Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "xor"::London::0
2023-01-23T15:58:22.240771Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmBitwiseLogicOperation/xor.json"
2023-01-23T15:58:22.240773Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:58:22.240774Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:58:22.240941Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3029411,
    events_root: None,
}
2023-01-23T15:58:22.240952Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 1
2023-01-23T15:58:22.240955Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "xor"::London::1
2023-01-23T15:58:22.240957Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmBitwiseLogicOperation/xor.json"
2023-01-23T15:58:22.240960Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:58:22.240961Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:58:22.241131Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3058615,
    events_root: None,
}
2023-01-23T15:58:22.241142Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 2
2023-01-23T15:58:22.241145Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "xor"::London::2
2023-01-23T15:58:22.241146Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmBitwiseLogicOperation/xor.json"
2023-01-23T15:58:22.241149Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:58:22.241150Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:58:22.241320Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3058615,
    events_root: None,
}
2023-01-23T15:58:22.241330Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 3
2023-01-23T15:58:22.241333Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "xor"::London::3
2023-01-23T15:58:22.241335Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmBitwiseLogicOperation/xor.json"
2023-01-23T15:58:22.241338Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:58:22.241339Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:58:22.241570Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3062101,
    events_root: None,
}
2023-01-23T15:58:22.241582Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 4
2023-01-23T15:58:22.241585Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "xor"::London::4
2023-01-23T15:58:22.241587Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmBitwiseLogicOperation/xor.json"
2023-01-23T15:58:22.241589Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:58:22.241591Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:58:22.241783Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3062101,
    events_root: None,
}
2023-01-23T15:58:22.241794Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 5
2023-01-23T15:58:22.241796Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "xor"::London::5
2023-01-23T15:58:22.241799Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmBitwiseLogicOperation/xor.json"
2023-01-23T15:58:22.241801Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:58:22.241802Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:58:22.241973Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3062101,
    events_root: None,
}
2023-01-23T15:58:22.241984Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-23T15:58:22.241987Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "xor"::Merge::0
2023-01-23T15:58:22.241989Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmBitwiseLogicOperation/xor.json"
2023-01-23T15:58:22.241991Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:58:22.241993Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:58:22.242159Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3029411,
    events_root: None,
}
2023-01-23T15:58:22.242170Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 1
2023-01-23T15:58:22.242173Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "xor"::Merge::1
2023-01-23T15:58:22.242175Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmBitwiseLogicOperation/xor.json"
2023-01-23T15:58:22.242177Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:58:22.242178Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:58:22.242348Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3058615,
    events_root: None,
}
2023-01-23T15:58:22.242359Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 2
2023-01-23T15:58:22.242361Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "xor"::Merge::2
2023-01-23T15:58:22.242363Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmBitwiseLogicOperation/xor.json"
2023-01-23T15:58:22.242366Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:58:22.242368Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:58:22.242537Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3058615,
    events_root: None,
}
2023-01-23T15:58:22.242547Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 3
2023-01-23T15:58:22.242550Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "xor"::Merge::3
2023-01-23T15:58:22.242552Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmBitwiseLogicOperation/xor.json"
2023-01-23T15:58:22.242555Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:58:22.242556Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:58:22.242726Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3062101,
    events_root: None,
}
2023-01-23T15:58:22.242737Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 4
2023-01-23T15:58:22.242740Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "xor"::Merge::4
2023-01-23T15:58:22.242742Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmBitwiseLogicOperation/xor.json"
2023-01-23T15:58:22.242746Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:58:22.242747Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:58:22.242915Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3062101,
    events_root: None,
}
2023-01-23T15:58:22.242927Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 5
2023-01-23T15:58:22.242930Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "xor"::Merge::5
2023-01-23T15:58:22.242932Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmBitwiseLogicOperation/xor.json"
2023-01-23T15:58:22.242934Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:58:22.242936Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:58:22.243107Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3062101,
    events_root: None,
}
2023-01-23T15:58:22.244542Z TRACE evm_eth_compliance::statetest::runner: TestDone => "test-vectors/tests/GeneralStateTests/VMTests/vmBitwiseLogicOperation/xor.json"
2023-01-23T15:58:22.244697Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 11 Files in Time:3.933589322s
```