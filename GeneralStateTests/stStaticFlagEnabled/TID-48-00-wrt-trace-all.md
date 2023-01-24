> Status

| Status | Context |
| --- | --- |
| OK | under WASM RT context |
| TODO | under native RT context |

> Test Suite

https://github.com/ethereum/tests/blob/develop/GeneralStateTests/stStaticFlagEnabled

> Command to execute

```
clear && \
	RUST_LOG=evm_eth_compliance=trace \
	VECTOR=test-vectors/tests/GeneralStateTests/stStaticFlagEnabled \
	cargo run --release \
	-- \
	statetest
```

> For Review

* Execution Looks OK, all use-cases passed.

> Execution Trace

```
2023-01-24T10:53:06.175960Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "test-vectors/tests/GeneralStateTests/stStaticFlagEnabled", Total Files :: 13
2023-01-24T10:53:06.176191Z TRACE evm_eth_compliance::statetest::runner: Calling testfile => "test-vectors/tests/GeneralStateTests/stStaticFlagEnabled/CallWithNOTZeroValueToPrecompileFromCalledContract.json"
2023-01-24T10:53:06.205186Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-24T10:53:06.205385Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T10:53:06.205388Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-24T10:53:06.205445Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T10:53:06.205447Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 2
2023-01-24T10:53:06.205504Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T10:53:06.205506Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 3
2023-01-24T10:53:06.205562Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T10:53:06.205564Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 4
2023-01-24T10:53:06.205614Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T10:53:06.205617Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 5
2023-01-24T10:53:06.205679Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T10:53:06.205681Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 6
2023-01-24T10:53:06.205734Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T10:53:06.205736Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 7
2023-01-24T10:53:06.205781Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T10:53:06.205783Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 8
2023-01-24T10:53:06.205829Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T10:53:06.205831Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 9
2023-01-24T10:53:06.205887Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T10:53:06.205889Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 10
2023-01-24T10:53:06.205934Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T10:53:06.206009Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-24T10:53:06.206012Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CallWithNOTZeroValueToPrecompileFromCalledContract"::Istanbul::0
2023-01-24T10:53:06.206016Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stStaticFlagEnabled/CallWithNOTZeroValueToPrecompileFromCalledContract.json"
2023-01-24T10:53:06.206019Z  INFO evm_eth_compliance::statetest::runner: TX len : 32
2023-01-24T10:53:06.206020Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T10:53:06.571705Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 10477146,
    events_root: None,
}
2023-01-24T10:53:06.571735Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 1
2023-01-24T10:53:06.571743Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CallWithNOTZeroValueToPrecompileFromCalledContract"::Istanbul::1
2023-01-24T10:53:06.571746Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stStaticFlagEnabled/CallWithNOTZeroValueToPrecompileFromCalledContract.json"
2023-01-24T10:53:06.571749Z  INFO evm_eth_compliance::statetest::runner: TX len : 32
2023-01-24T10:53:06.571750Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T10:53:06.572111Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 5948727,
    events_root: None,
}
2023-01-24T10:53:06.572127Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 2
2023-01-24T10:53:06.572130Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CallWithNOTZeroValueToPrecompileFromCalledContract"::Istanbul::2
2023-01-24T10:53:06.572133Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stStaticFlagEnabled/CallWithNOTZeroValueToPrecompileFromCalledContract.json"
2023-01-24T10:53:06.572136Z  INFO evm_eth_compliance::statetest::runner: TX len : 32
2023-01-24T10:53:06.572137Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T10:53:06.572483Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 5948727,
    events_root: None,
}
2023-01-24T10:53:06.572502Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 3
2023-01-24T10:53:06.572506Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CallWithNOTZeroValueToPrecompileFromCalledContract"::Istanbul::3
2023-01-24T10:53:06.572510Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stStaticFlagEnabled/CallWithNOTZeroValueToPrecompileFromCalledContract.json"
2023-01-24T10:53:06.572513Z  INFO evm_eth_compliance::statetest::runner: TX len : 32
2023-01-24T10:53:06.572516Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T10:53:06.572885Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 5948727,
    events_root: None,
}
2023-01-24T10:53:06.572905Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 4
2023-01-24T10:53:06.572909Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CallWithNOTZeroValueToPrecompileFromCalledContract"::Istanbul::4
2023-01-24T10:53:06.572912Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stStaticFlagEnabled/CallWithNOTZeroValueToPrecompileFromCalledContract.json"
2023-01-24T10:53:06.572916Z  INFO evm_eth_compliance::statetest::runner: TX len : 32
2023-01-24T10:53:06.572918Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T10:53:06.573383Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 5970687,
    events_root: None,
}
2023-01-24T10:53:06.573403Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 5
2023-01-24T10:53:06.573408Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CallWithNOTZeroValueToPrecompileFromCalledContract"::Istanbul::5
2023-01-24T10:53:06.573410Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stStaticFlagEnabled/CallWithNOTZeroValueToPrecompileFromCalledContract.json"
2023-01-24T10:53:06.573414Z  INFO evm_eth_compliance::statetest::runner: TX len : 32
2023-01-24T10:53:06.573416Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T10:53:06.573810Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 5964416,
    events_root: None,
}
2023-01-24T10:53:06.573830Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 6
2023-01-24T10:53:06.573833Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CallWithNOTZeroValueToPrecompileFromCalledContract"::Istanbul::6
2023-01-24T10:53:06.573836Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stStaticFlagEnabled/CallWithNOTZeroValueToPrecompileFromCalledContract.json"
2023-01-24T10:53:06.573839Z  INFO evm_eth_compliance::statetest::runner: TX len : 32
2023-01-24T10:53:06.573840Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T10:53:06.574236Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 5957743,
    events_root: None,
}
2023-01-24T10:53:06.574253Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 7
2023-01-24T10:53:06.574256Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CallWithNOTZeroValueToPrecompileFromCalledContract"::Istanbul::7
2023-01-24T10:53:06.574259Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stStaticFlagEnabled/CallWithNOTZeroValueToPrecompileFromCalledContract.json"
2023-01-24T10:53:06.574262Z  INFO evm_eth_compliance::statetest::runner: TX len : 32
2023-01-24T10:53:06.574263Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T10:53:06.574605Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 6007146,
    events_root: None,
}
2023-01-24T10:53:06.574621Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-24T10:53:06.574624Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CallWithNOTZeroValueToPrecompileFromCalledContract"::Berlin::0
2023-01-24T10:53:06.574627Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stStaticFlagEnabled/CallWithNOTZeroValueToPrecompileFromCalledContract.json"
2023-01-24T10:53:06.574630Z  INFO evm_eth_compliance::statetest::runner: TX len : 32
2023-01-24T10:53:06.574631Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T10:53:06.574962Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 5963094,
    events_root: None,
}
2023-01-24T10:53:06.574978Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 1
2023-01-24T10:53:06.574981Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CallWithNOTZeroValueToPrecompileFromCalledContract"::Berlin::1
2023-01-24T10:53:06.574983Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stStaticFlagEnabled/CallWithNOTZeroValueToPrecompileFromCalledContract.json"
2023-01-24T10:53:06.574986Z  INFO evm_eth_compliance::statetest::runner: TX len : 32
2023-01-24T10:53:06.574987Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T10:53:06.575330Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 5948727,
    events_root: None,
}
2023-01-24T10:53:06.575349Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 2
2023-01-24T10:53:06.575352Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CallWithNOTZeroValueToPrecompileFromCalledContract"::Berlin::2
2023-01-24T10:53:06.575355Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stStaticFlagEnabled/CallWithNOTZeroValueToPrecompileFromCalledContract.json"
2023-01-24T10:53:06.575359Z  INFO evm_eth_compliance::statetest::runner: TX len : 32
2023-01-24T10:53:06.575361Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T10:53:06.575753Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 5948727,
    events_root: None,
}
2023-01-24T10:53:06.575768Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 3
2023-01-24T10:53:06.575772Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CallWithNOTZeroValueToPrecompileFromCalledContract"::Berlin::3
2023-01-24T10:53:06.575774Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stStaticFlagEnabled/CallWithNOTZeroValueToPrecompileFromCalledContract.json"
2023-01-24T10:53:06.575777Z  INFO evm_eth_compliance::statetest::runner: TX len : 32
2023-01-24T10:53:06.575779Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T10:53:06.576118Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 5948727,
    events_root: None,
}
2023-01-24T10:53:06.576132Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 4
2023-01-24T10:53:06.576135Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CallWithNOTZeroValueToPrecompileFromCalledContract"::Berlin::4
2023-01-24T10:53:06.576139Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stStaticFlagEnabled/CallWithNOTZeroValueToPrecompileFromCalledContract.json"
2023-01-24T10:53:06.576141Z  INFO evm_eth_compliance::statetest::runner: TX len : 32
2023-01-24T10:53:06.576143Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T10:53:06.576480Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 5970687,
    events_root: None,
}
2023-01-24T10:53:06.576495Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 5
2023-01-24T10:53:06.576498Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CallWithNOTZeroValueToPrecompileFromCalledContract"::Berlin::5
2023-01-24T10:53:06.576500Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stStaticFlagEnabled/CallWithNOTZeroValueToPrecompileFromCalledContract.json"
2023-01-24T10:53:06.576504Z  INFO evm_eth_compliance::statetest::runner: TX len : 32
2023-01-24T10:53:06.576506Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T10:53:06.576837Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 5964416,
    events_root: None,
}
2023-01-24T10:53:06.576852Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 6
2023-01-24T10:53:06.576854Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CallWithNOTZeroValueToPrecompileFromCalledContract"::Berlin::6
2023-01-24T10:53:06.576857Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stStaticFlagEnabled/CallWithNOTZeroValueToPrecompileFromCalledContract.json"
2023-01-24T10:53:06.576860Z  INFO evm_eth_compliance::statetest::runner: TX len : 32
2023-01-24T10:53:06.576861Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T10:53:06.577202Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 5957743,
    events_root: None,
}
2023-01-24T10:53:06.577220Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 7
2023-01-24T10:53:06.577223Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CallWithNOTZeroValueToPrecompileFromCalledContract"::Berlin::7
2023-01-24T10:53:06.577226Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stStaticFlagEnabled/CallWithNOTZeroValueToPrecompileFromCalledContract.json"
2023-01-24T10:53:06.577230Z  INFO evm_eth_compliance::statetest::runner: TX len : 32
2023-01-24T10:53:06.577231Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T10:53:06.577674Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 6007146,
    events_root: None,
}
2023-01-24T10:53:06.577692Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-24T10:53:06.577696Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CallWithNOTZeroValueToPrecompileFromCalledContract"::London::0
2023-01-24T10:53:06.577699Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stStaticFlagEnabled/CallWithNOTZeroValueToPrecompileFromCalledContract.json"
2023-01-24T10:53:06.577703Z  INFO evm_eth_compliance::statetest::runner: TX len : 32
2023-01-24T10:53:06.577705Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T10:53:06.578053Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 5963094,
    events_root: None,
}
2023-01-24T10:53:06.578071Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 1
2023-01-24T10:53:06.578074Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CallWithNOTZeroValueToPrecompileFromCalledContract"::London::1
2023-01-24T10:53:06.578077Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stStaticFlagEnabled/CallWithNOTZeroValueToPrecompileFromCalledContract.json"
2023-01-24T10:53:06.578081Z  INFO evm_eth_compliance::statetest::runner: TX len : 32
2023-01-24T10:53:06.578083Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T10:53:06.578445Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 5948727,
    events_root: None,
}
2023-01-24T10:53:06.578461Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 2
2023-01-24T10:53:06.578464Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CallWithNOTZeroValueToPrecompileFromCalledContract"::London::2
2023-01-24T10:53:06.578467Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stStaticFlagEnabled/CallWithNOTZeroValueToPrecompileFromCalledContract.json"
2023-01-24T10:53:06.578470Z  INFO evm_eth_compliance::statetest::runner: TX len : 32
2023-01-24T10:53:06.578472Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T10:53:06.578825Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 5948727,
    events_root: None,
}
2023-01-24T10:53:06.578841Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 3
2023-01-24T10:53:06.578843Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CallWithNOTZeroValueToPrecompileFromCalledContract"::London::3
2023-01-24T10:53:06.578846Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stStaticFlagEnabled/CallWithNOTZeroValueToPrecompileFromCalledContract.json"
2023-01-24T10:53:06.578849Z  INFO evm_eth_compliance::statetest::runner: TX len : 32
2023-01-24T10:53:06.578850Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T10:53:06.579185Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 5948727,
    events_root: None,
}
2023-01-24T10:53:06.579202Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 4
2023-01-24T10:53:06.579204Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CallWithNOTZeroValueToPrecompileFromCalledContract"::London::4
2023-01-24T10:53:06.579207Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stStaticFlagEnabled/CallWithNOTZeroValueToPrecompileFromCalledContract.json"
2023-01-24T10:53:06.579210Z  INFO evm_eth_compliance::statetest::runner: TX len : 32
2023-01-24T10:53:06.579211Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T10:53:06.579548Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 5970687,
    events_root: None,
}
2023-01-24T10:53:06.579564Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 5
2023-01-24T10:53:06.579567Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CallWithNOTZeroValueToPrecompileFromCalledContract"::London::5
2023-01-24T10:53:06.579570Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stStaticFlagEnabled/CallWithNOTZeroValueToPrecompileFromCalledContract.json"
2023-01-24T10:53:06.579573Z  INFO evm_eth_compliance::statetest::runner: TX len : 32
2023-01-24T10:53:06.579574Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T10:53:06.579911Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 5964416,
    events_root: None,
}
2023-01-24T10:53:06.579928Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 6
2023-01-24T10:53:06.579931Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CallWithNOTZeroValueToPrecompileFromCalledContract"::London::6
2023-01-24T10:53:06.579934Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stStaticFlagEnabled/CallWithNOTZeroValueToPrecompileFromCalledContract.json"
2023-01-24T10:53:06.579937Z  INFO evm_eth_compliance::statetest::runner: TX len : 32
2023-01-24T10:53:06.579938Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T10:53:06.580268Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 5957743,
    events_root: None,
}
2023-01-24T10:53:06.580282Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 7
2023-01-24T10:53:06.580285Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CallWithNOTZeroValueToPrecompileFromCalledContract"::London::7
2023-01-24T10:53:06.580288Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stStaticFlagEnabled/CallWithNOTZeroValueToPrecompileFromCalledContract.json"
2023-01-24T10:53:06.580292Z  INFO evm_eth_compliance::statetest::runner: TX len : 32
2023-01-24T10:53:06.580293Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T10:53:06.580627Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 6007146,
    events_root: None,
}
2023-01-24T10:53:06.580642Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-24T10:53:06.580645Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CallWithNOTZeroValueToPrecompileFromCalledContract"::Merge::0
2023-01-24T10:53:06.580647Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stStaticFlagEnabled/CallWithNOTZeroValueToPrecompileFromCalledContract.json"
2023-01-24T10:53:06.580650Z  INFO evm_eth_compliance::statetest::runner: TX len : 32
2023-01-24T10:53:06.580652Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T10:53:06.580982Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 5963094,
    events_root: None,
}
2023-01-24T10:53:06.580997Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 1
2023-01-24T10:53:06.580999Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CallWithNOTZeroValueToPrecompileFromCalledContract"::Merge::1
2023-01-24T10:53:06.581002Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stStaticFlagEnabled/CallWithNOTZeroValueToPrecompileFromCalledContract.json"
2023-01-24T10:53:06.581005Z  INFO evm_eth_compliance::statetest::runner: TX len : 32
2023-01-24T10:53:06.581007Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T10:53:06.581335Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 5948727,
    events_root: None,
}
2023-01-24T10:53:06.581350Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 2
2023-01-24T10:53:06.581353Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CallWithNOTZeroValueToPrecompileFromCalledContract"::Merge::2
2023-01-24T10:53:06.581355Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stStaticFlagEnabled/CallWithNOTZeroValueToPrecompileFromCalledContract.json"
2023-01-24T10:53:06.581358Z  INFO evm_eth_compliance::statetest::runner: TX len : 32
2023-01-24T10:53:06.581359Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T10:53:06.581694Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 5948727,
    events_root: None,
}
2023-01-24T10:53:06.581709Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 3
2023-01-24T10:53:06.581712Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CallWithNOTZeroValueToPrecompileFromCalledContract"::Merge::3
2023-01-24T10:53:06.581714Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stStaticFlagEnabled/CallWithNOTZeroValueToPrecompileFromCalledContract.json"
2023-01-24T10:53:06.581717Z  INFO evm_eth_compliance::statetest::runner: TX len : 32
2023-01-24T10:53:06.581719Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T10:53:06.582047Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 5948727,
    events_root: None,
}
2023-01-24T10:53:06.582063Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 4
2023-01-24T10:53:06.582065Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CallWithNOTZeroValueToPrecompileFromCalledContract"::Merge::4
2023-01-24T10:53:06.582068Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stStaticFlagEnabled/CallWithNOTZeroValueToPrecompileFromCalledContract.json"
2023-01-24T10:53:06.582072Z  INFO evm_eth_compliance::statetest::runner: TX len : 32
2023-01-24T10:53:06.582073Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T10:53:06.582407Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 5970687,
    events_root: None,
}
2023-01-24T10:53:06.582422Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 5
2023-01-24T10:53:06.582425Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CallWithNOTZeroValueToPrecompileFromCalledContract"::Merge::5
2023-01-24T10:53:06.582428Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stStaticFlagEnabled/CallWithNOTZeroValueToPrecompileFromCalledContract.json"
2023-01-24T10:53:06.582431Z  INFO evm_eth_compliance::statetest::runner: TX len : 32
2023-01-24T10:53:06.582432Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T10:53:06.582759Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 5964416,
    events_root: None,
}
2023-01-24T10:53:06.582774Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 6
2023-01-24T10:53:06.582777Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CallWithNOTZeroValueToPrecompileFromCalledContract"::Merge::6
2023-01-24T10:53:06.582780Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stStaticFlagEnabled/CallWithNOTZeroValueToPrecompileFromCalledContract.json"
2023-01-24T10:53:06.582783Z  INFO evm_eth_compliance::statetest::runner: TX len : 32
2023-01-24T10:53:06.582784Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T10:53:06.583121Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 5957743,
    events_root: None,
}
2023-01-24T10:53:06.583136Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 7
2023-01-24T10:53:06.583138Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CallWithNOTZeroValueToPrecompileFromCalledContract"::Merge::7
2023-01-24T10:53:06.583141Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stStaticFlagEnabled/CallWithNOTZeroValueToPrecompileFromCalledContract.json"
2023-01-24T10:53:06.583143Z  INFO evm_eth_compliance::statetest::runner: TX len : 32
2023-01-24T10:53:06.583145Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T10:53:06.583482Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 6007146,
    events_root: None,
}
2023-01-24T10:53:06.585179Z TRACE evm_eth_compliance::statetest::runner: TestDone => "test-vectors/tests/GeneralStateTests/stStaticFlagEnabled/CallWithNOTZeroValueToPrecompileFromCalledContract.json"
2023-01-24T10:53:06.585209Z TRACE evm_eth_compliance::statetest::runner: Calling testfile => "test-vectors/tests/GeneralStateTests/stStaticFlagEnabled/CallWithNOTZeroValueToPrecompileFromContractInitialization.json"
2023-01-24T10:53:06.612494Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-24T10:53:06.612598Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T10:53:06.612602Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-24T10:53:06.612657Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T10:53:06.612659Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 2
2023-01-24T10:53:06.612718Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T10:53:06.612720Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 3
2023-01-24T10:53:06.612771Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T10:53:06.612773Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 4
2023-01-24T10:53:06.612821Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T10:53:06.612823Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 5
2023-01-24T10:53:06.612884Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T10:53:06.612886Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 6
2023-01-24T10:53:06.612941Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T10:53:06.612943Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 7
2023-01-24T10:53:06.612990Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T10:53:06.612992Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 8
2023-01-24T10:53:06.613036Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T10:53:06.613037Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 9
2023-01-24T10:53:06.613090Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T10:53:06.613161Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-24T10:53:06.613165Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CallWithNOTZeroValueToPrecompileFromContractInitialization"::Istanbul::0
2023-01-24T10:53:06.613168Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stStaticFlagEnabled/CallWithNOTZeroValueToPrecompileFromContractInitialization.json"
2023-01-24T10:53:06.613172Z  INFO evm_eth_compliance::statetest::runner: TX len : 107
2023-01-24T10:53:06.613173Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [247, 176, 195, 144, 108, 223, 192, 184, 166, 56, 210, 116, 211, 188, 187, 214, 49, 142, 154, 193, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([215, 166, 242, 208, 200, 186, 79, 10, 126, 8, 221, 102, 9, 12, 200, 158, 203, 19, 78, 227]) }
2023-01-24T10:53:07.210030Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 19717425,
    events_root: None,
}
2023-01-24T10:53:07.210065Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 1
2023-01-24T10:53:07.210072Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CallWithNOTZeroValueToPrecompileFromContractInitialization"::Istanbul::1
2023-01-24T10:53:07.210076Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stStaticFlagEnabled/CallWithNOTZeroValueToPrecompileFromContractInitialization.json"
2023-01-24T10:53:07.210080Z  INFO evm_eth_compliance::statetest::runner: TX len : 107
2023-01-24T10:53:07.210081Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [204, 95, 191, 89, 90, 201, 38, 240, 35, 20, 126, 81, 247, 119, 89, 31, 12, 43, 109, 90, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([67, 35, 255, 1, 46, 226, 200, 90, 20, 150, 237, 153, 222, 171, 201, 9, 99, 31, 101, 211]) }
2023-01-24T10:53:07.210879Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 20266747,
    events_root: None,
}
2023-01-24T10:53:07.210902Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 2
2023-01-24T10:53:07.210905Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CallWithNOTZeroValueToPrecompileFromContractInitialization"::Istanbul::2
2023-01-24T10:53:07.210908Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stStaticFlagEnabled/CallWithNOTZeroValueToPrecompileFromContractInitialization.json"
2023-01-24T10:53:07.210911Z  INFO evm_eth_compliance::statetest::runner: TX len : 107
2023-01-24T10:53:07.210912Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [237, 155, 26, 37, 139, 6, 141, 194, 170, 202, 85, 85, 242, 170, 138, 250, 134, 21, 223, 239, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([28, 35, 125, 168, 212, 11, 234, 180, 81, 129, 48, 219, 76, 10, 52, 89, 217, 159, 194, 2]) }
2023-01-24T10:53:07.211632Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 19937466,
    events_root: None,
}
2023-01-24T10:53:07.211654Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 3
2023-01-24T10:53:07.211657Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CallWithNOTZeroValueToPrecompileFromContractInitialization"::Istanbul::3
2023-01-24T10:53:07.211660Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stStaticFlagEnabled/CallWithNOTZeroValueToPrecompileFromContractInitialization.json"
2023-01-24T10:53:07.211663Z  INFO evm_eth_compliance::statetest::runner: TX len : 107
2023-01-24T10:53:07.211664Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [227, 138, 102, 90, 154, 155, 103, 16, 1, 71, 158, 30, 64, 222, 133, 228, 121, 42, 144, 99, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([132, 105, 76, 107, 184, 77, 78, 105, 101, 219, 134, 121, 221, 254, 217, 203, 72, 121, 220, 83]) }
2023-01-24T10:53:07.212397Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 19942636,
    events_root: None,
}
2023-01-24T10:53:07.212422Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 4
2023-01-24T10:53:07.212424Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CallWithNOTZeroValueToPrecompileFromContractInitialization"::Istanbul::4
2023-01-24T10:53:07.212427Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stStaticFlagEnabled/CallWithNOTZeroValueToPrecompileFromContractInitialization.json"
2023-01-24T10:53:07.212430Z  INFO evm_eth_compliance::statetest::runner: TX len : 107
2023-01-24T10:53:07.212434Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [43, 202, 179, 93, 195, 38, 117, 125, 85, 104, 48, 226, 65, 82, 34, 44, 173, 29, 131, 42, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([236, 70, 216, 243, 101, 99, 189, 62, 205, 26, 208, 253, 84, 36, 48, 143, 166, 88, 135, 41]) }
2023-01-24T10:53:07.213129Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 18455661,
    events_root: None,
}
2023-01-24T10:53:07.213152Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 5
2023-01-24T10:53:07.213155Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CallWithNOTZeroValueToPrecompileFromContractInitialization"::Istanbul::5
2023-01-24T10:53:07.213157Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stStaticFlagEnabled/CallWithNOTZeroValueToPrecompileFromContractInitialization.json"
2023-01-24T10:53:07.213160Z  INFO evm_eth_compliance::statetest::runner: TX len : 107
2023-01-24T10:53:07.213162Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [66, 149, 94, 6, 36, 147, 152, 157, 27, 16, 207, 0, 74, 128, 23, 193, 148, 187, 138, 90, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([155, 99, 140, 31, 46, 96, 27, 93, 44, 60, 131, 66, 80, 136, 87, 209, 224, 27, 216, 212]) }
2023-01-24T10:53:07.213871Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 18749881,
    events_root: None,
}
2023-01-24T10:53:07.213894Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 6
2023-01-24T10:53:07.213897Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CallWithNOTZeroValueToPrecompileFromContractInitialization"::Istanbul::6
2023-01-24T10:53:07.213900Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stStaticFlagEnabled/CallWithNOTZeroValueToPrecompileFromContractInitialization.json"
2023-01-24T10:53:07.213903Z  INFO evm_eth_compliance::statetest::runner: TX len : 107
2023-01-24T10:53:07.213904Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [206, 152, 104, 10, 137, 101, 86, 85, 117, 10, 11, 202, 117, 68, 76, 21, 98, 239, 225, 140, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([188, 149, 186, 245, 1, 91, 222, 203, 63, 25, 86, 169, 35, 110, 18, 124, 122, 60, 238, 128]) }
2023-01-24T10:53:07.214637Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 19888187,
    events_root: None,
}
2023-01-24T10:53:07.214660Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 7
2023-01-24T10:53:07.214663Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CallWithNOTZeroValueToPrecompileFromContractInitialization"::Istanbul::7
2023-01-24T10:53:07.214666Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stStaticFlagEnabled/CallWithNOTZeroValueToPrecompileFromContractInitialization.json"
2023-01-24T10:53:07.214669Z  INFO evm_eth_compliance::statetest::runner: TX len : 107
2023-01-24T10:53:07.214670Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [160, 4, 193, 118, 225, 38, 156, 162, 151, 246, 126, 113, 142, 135, 179, 72, 224, 23, 97, 203, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([20, 3, 204, 71, 166, 252, 88, 221, 29, 77, 14, 224, 191, 132, 61, 100, 47, 53, 166, 175]) }
2023-01-24T10:53:07.215389Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 19657551,
    events_root: None,
}
2023-01-24T10:53:07.215412Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-24T10:53:07.215415Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CallWithNOTZeroValueToPrecompileFromContractInitialization"::Berlin::0
2023-01-24T10:53:07.215417Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stStaticFlagEnabled/CallWithNOTZeroValueToPrecompileFromContractInitialization.json"
2023-01-24T10:53:07.215422Z  INFO evm_eth_compliance::statetest::runner: TX len : 107
2023-01-24T10:53:07.215423Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [155, 74, 171, 14, 183, 23, 110, 196, 74, 82, 38, 249, 24, 45, 107, 99, 160, 194, 165, 248, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([177, 189, 137, 170, 161, 168, 98, 8, 218, 14, 105, 2, 242, 92, 44, 234, 2, 122, 233, 63]) }
2023-01-24T10:53:07.216155Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 19839501,
    events_root: None,
}
2023-01-24T10:53:07.216179Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 1
2023-01-24T10:53:07.216181Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CallWithNOTZeroValueToPrecompileFromContractInitialization"::Berlin::1
2023-01-24T10:53:07.216184Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stStaticFlagEnabled/CallWithNOTZeroValueToPrecompileFromContractInitialization.json"
2023-01-24T10:53:07.216188Z  INFO evm_eth_compliance::statetest::runner: TX len : 107
2023-01-24T10:53:07.216189Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [110, 153, 206, 222, 16, 227, 228, 120, 25, 157, 55, 177, 142, 165, 119, 128, 66, 251, 157, 179, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([178, 221, 99, 117, 94, 25, 113, 14, 55, 217, 63, 213, 179, 235, 175, 240, 178, 120, 15, 225]) }
2023-01-24T10:53:07.216914Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 20205655,
    events_root: None,
}
2023-01-24T10:53:07.216937Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 2
2023-01-24T10:53:07.216940Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CallWithNOTZeroValueToPrecompileFromContractInitialization"::Berlin::2
2023-01-24T10:53:07.216943Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stStaticFlagEnabled/CallWithNOTZeroValueToPrecompileFromContractInitialization.json"
2023-01-24T10:53:07.216946Z  INFO evm_eth_compliance::statetest::runner: TX len : 107
2023-01-24T10:53:07.216947Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [146, 72, 8, 171, 191, 205, 224, 82, 124, 236, 200, 94, 245, 135, 240, 199, 164, 248, 185, 194, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([251, 114, 94, 192, 108, 10, 201, 112, 101, 197, 5, 103, 36, 134, 180, 68, 48, 44, 184, 84]) }
2023-01-24T10:53:07.217739Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 19990150,
    events_root: None,
}
2023-01-24T10:53:07.217764Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 3
2023-01-24T10:53:07.217767Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CallWithNOTZeroValueToPrecompileFromContractInitialization"::Berlin::3
2023-01-24T10:53:07.217769Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stStaticFlagEnabled/CallWithNOTZeroValueToPrecompileFromContractInitialization.json"
2023-01-24T10:53:07.217773Z  INFO evm_eth_compliance::statetest::runner: TX len : 107
2023-01-24T10:53:07.217774Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [168, 177, 241, 77, 101, 135, 255, 60, 218, 213, 37, 154, 16, 136, 175, 26, 186, 154, 48, 99, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([90, 217, 32, 146, 24, 201, 117, 10, 10, 210, 28, 70, 31, 30, 132, 56, 243, 180, 75, 35]) }
2023-01-24T10:53:07.218492Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 20273429,
    events_root: None,
}
2023-01-24T10:53:07.218515Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 4
2023-01-24T10:53:07.218518Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CallWithNOTZeroValueToPrecompileFromContractInitialization"::Berlin::4
2023-01-24T10:53:07.218521Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stStaticFlagEnabled/CallWithNOTZeroValueToPrecompileFromContractInitialization.json"
2023-01-24T10:53:07.218524Z  INFO evm_eth_compliance::statetest::runner: TX len : 107
2023-01-24T10:53:07.218525Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [159, 94, 142, 10, 52, 116, 25, 132, 183, 218, 185, 125, 93, 178, 227, 21, 253, 142, 14, 140, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([128, 138, 188, 155, 213, 11, 225, 143, 246, 50, 199, 246, 94, 148, 129, 183, 56, 152, 76, 55]) }
2023-01-24T10:53:07.219233Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 19305190,
    events_root: None,
}
2023-01-24T10:53:07.219256Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 5
2023-01-24T10:53:07.219259Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CallWithNOTZeroValueToPrecompileFromContractInitialization"::Berlin::5
2023-01-24T10:53:07.219262Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stStaticFlagEnabled/CallWithNOTZeroValueToPrecompileFromContractInitialization.json"
2023-01-24T10:53:07.219265Z  INFO evm_eth_compliance::statetest::runner: TX len : 107
2023-01-24T10:53:07.219267Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [184, 198, 148, 130, 217, 28, 169, 15, 35, 37, 34, 46, 11, 82, 74, 182, 4, 134, 208, 239, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([55, 124, 170, 147, 221, 2, 18, 238, 216, 76, 43, 142, 118, 199, 246, 132, 57, 223, 23, 100]) }
2023-01-24T10:53:07.219981Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 19691037,
    events_root: None,
}
2023-01-24T10:53:07.220004Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 6
2023-01-24T10:53:07.220008Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CallWithNOTZeroValueToPrecompileFromContractInitialization"::Berlin::6
2023-01-24T10:53:07.220011Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stStaticFlagEnabled/CallWithNOTZeroValueToPrecompileFromContractInitialization.json"
2023-01-24T10:53:07.220014Z  INFO evm_eth_compliance::statetest::runner: TX len : 107
2023-01-24T10:53:07.220015Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [69, 106, 105, 88, 248, 212, 40, 28, 28, 5, 212, 171, 224, 70, 49, 136, 28, 37, 68, 125, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([171, 234, 181, 15, 37, 193, 240, 156, 211, 60, 172, 98, 156, 55, 186, 0, 159, 236, 160, 247]) }
2023-01-24T10:53:07.220721Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 19849829,
    events_root: None,
}
2023-01-24T10:53:07.220743Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 7
2023-01-24T10:53:07.220746Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CallWithNOTZeroValueToPrecompileFromContractInitialization"::Berlin::7
2023-01-24T10:53:07.220749Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stStaticFlagEnabled/CallWithNOTZeroValueToPrecompileFromContractInitialization.json"
2023-01-24T10:53:07.220752Z  INFO evm_eth_compliance::statetest::runner: TX len : 107
2023-01-24T10:53:07.220753Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [8, 169, 134, 57, 246, 121, 232, 145, 165, 64, 124, 226, 177, 80, 118, 135, 102, 232, 138, 43, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([167, 18, 209, 255, 80, 109, 220, 136, 239, 83, 214, 196, 45, 184, 19, 227, 137, 201, 135, 105]) }
2023-01-24T10:53:07.221486Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 19736669,
    events_root: None,
}
2023-01-24T10:53:07.221509Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-24T10:53:07.221512Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CallWithNOTZeroValueToPrecompileFromContractInitialization"::London::0
2023-01-24T10:53:07.221515Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stStaticFlagEnabled/CallWithNOTZeroValueToPrecompileFromContractInitialization.json"
2023-01-24T10:53:07.221517Z  INFO evm_eth_compliance::statetest::runner: TX len : 107
2023-01-24T10:53:07.221519Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [224, 142, 213, 104, 242, 244, 54, 150, 32, 160, 202, 123, 216, 36, 232, 53, 133, 112, 142, 174, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([143, 33, 161, 133, 93, 209, 38, 110, 16, 16, 237, 126, 30, 78, 59, 192, 15, 148, 83, 57]) }
2023-01-24T10:53:07.222219Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 19743369,
    events_root: None,
}
2023-01-24T10:53:07.222242Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 1
2023-01-24T10:53:07.222244Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CallWithNOTZeroValueToPrecompileFromContractInitialization"::London::1
2023-01-24T10:53:07.222247Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stStaticFlagEnabled/CallWithNOTZeroValueToPrecompileFromContractInitialization.json"
2023-01-24T10:53:07.222250Z  INFO evm_eth_compliance::statetest::runner: TX len : 107
2023-01-24T10:53:07.222252Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [140, 203, 45, 21, 21, 153, 30, 133, 45, 65, 185, 49, 159, 233, 153, 200, 43, 254, 5, 127, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([115, 209, 18, 63, 181, 115, 165, 219, 137, 112, 100, 108, 193, 38, 167, 163, 136, 114, 38, 238]) }
2023-01-24T10:53:07.222961Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 20021479,
    events_root: None,
}
2023-01-24T10:53:07.222985Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 2
2023-01-24T10:53:07.222988Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CallWithNOTZeroValueToPrecompileFromContractInitialization"::London::2
2023-01-24T10:53:07.222990Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stStaticFlagEnabled/CallWithNOTZeroValueToPrecompileFromContractInitialization.json"
2023-01-24T10:53:07.222993Z  INFO evm_eth_compliance::statetest::runner: TX len : 107
2023-01-24T10:53:07.222994Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [231, 215, 234, 218, 161, 254, 174, 100, 50, 109, 91, 39, 115, 68, 74, 180, 232, 17, 175, 97, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([164, 19, 188, 157, 123, 198, 227, 16, 99, 7, 112, 55, 126, 183, 242, 167, 190, 31, 240, 147]) }
2023-01-24T10:53:07.223714Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 19813783,
    events_root: None,
}
2023-01-24T10:53:07.223738Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 3
2023-01-24T10:53:07.223741Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CallWithNOTZeroValueToPrecompileFromContractInitialization"::London::3
2023-01-24T10:53:07.223744Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stStaticFlagEnabled/CallWithNOTZeroValueToPrecompileFromContractInitialization.json"
2023-01-24T10:53:07.223747Z  INFO evm_eth_compliance::statetest::runner: TX len : 107
2023-01-24T10:53:07.223748Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [156, 214, 50, 207, 220, 239, 83, 52, 36, 191, 122, 138, 197, 27, 70, 203, 136, 111, 158, 107, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([40, 113, 131, 83, 213, 98, 3, 231, 134, 49, 131, 92, 170, 242, 84, 90, 74, 151, 72, 246]) }
2023-01-24T10:53:07.224446Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 19914108,
    events_root: None,
}
2023-01-24T10:53:07.224469Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 4
2023-01-24T10:53:07.224472Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CallWithNOTZeroValueToPrecompileFromContractInitialization"::London::4
2023-01-24T10:53:07.224475Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stStaticFlagEnabled/CallWithNOTZeroValueToPrecompileFromContractInitialization.json"
2023-01-24T10:53:07.224478Z  INFO evm_eth_compliance::statetest::runner: TX len : 107
2023-01-24T10:53:07.224480Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [181, 126, 113, 52, 213, 108, 49, 112, 250, 168, 103, 29, 127, 159, 36, 102, 2, 207, 253, 165, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([40, 182, 218, 235, 33, 11, 225, 5, 136, 185, 130, 124, 42, 168, 16, 11, 169, 12, 214, 166]) }
2023-01-24T10:53:07.225222Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 20120534,
    events_root: None,
}
2023-01-24T10:53:07.225247Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 5
2023-01-24T10:53:07.225251Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CallWithNOTZeroValueToPrecompileFromContractInitialization"::London::5
2023-01-24T10:53:07.225254Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stStaticFlagEnabled/CallWithNOTZeroValueToPrecompileFromContractInitialization.json"
2023-01-24T10:53:07.225257Z  INFO evm_eth_compliance::statetest::runner: TX len : 107
2023-01-24T10:53:07.225258Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [174, 145, 87, 26, 233, 213, 158, 160, 74, 4, 17, 181, 204, 96, 167, 5, 5, 88, 89, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([120, 103, 96, 100, 116, 249, 190, 222, 117, 123, 178, 182, 219, 22, 101, 99, 7, 208, 237, 37]) }
2023-01-24T10:53:07.225961Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 19854067,
    events_root: None,
}
2023-01-24T10:53:07.225985Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 6
2023-01-24T10:53:07.225987Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CallWithNOTZeroValueToPrecompileFromContractInitialization"::London::6
2023-01-24T10:53:07.225990Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stStaticFlagEnabled/CallWithNOTZeroValueToPrecompileFromContractInitialization.json"
2023-01-24T10:53:07.225993Z  INFO evm_eth_compliance::statetest::runner: TX len : 107
2023-01-24T10:53:07.225994Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [159, 54, 60, 230, 162, 88, 31, 10, 203, 242, 232, 210, 28, 94, 179, 85, 219, 63, 152, 97, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([173, 101, 220, 118, 126, 227, 221, 111, 130, 239, 232, 201, 210, 70, 69, 50, 207, 38, 17, 72]) }
2023-01-24T10:53:07.226707Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 19786657,
    events_root: None,
}
2023-01-24T10:53:07.226730Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 7
2023-01-24T10:53:07.226733Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CallWithNOTZeroValueToPrecompileFromContractInitialization"::London::7
2023-01-24T10:53:07.226735Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stStaticFlagEnabled/CallWithNOTZeroValueToPrecompileFromContractInitialization.json"
2023-01-24T10:53:07.226739Z  INFO evm_eth_compliance::statetest::runner: TX len : 107
2023-01-24T10:53:07.226740Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [7, 81, 181, 141, 138, 77, 58, 212, 11, 45, 213, 205, 28, 226, 10, 225, 174, 189, 22, 175, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([21, 34, 247, 70, 142, 122, 19, 174, 255, 98, 183, 37, 253, 210, 62, 191, 224, 79, 199, 228]) }
2023-01-24T10:53:07.227529Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 20055358,
    events_root: None,
}
2023-01-24T10:53:07.227558Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-24T10:53:07.227562Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CallWithNOTZeroValueToPrecompileFromContractInitialization"::Merge::0
2023-01-24T10:53:07.227565Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stStaticFlagEnabled/CallWithNOTZeroValueToPrecompileFromContractInitialization.json"
2023-01-24T10:53:07.227569Z  INFO evm_eth_compliance::statetest::runner: TX len : 107
2023-01-24T10:53:07.227571Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [206, 106, 65, 176, 141, 142, 168, 86, 202, 42, 89, 72, 234, 204, 82, 180, 34, 166, 115, 66, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([121, 200, 128, 32, 100, 47, 163, 168, 222, 154, 90, 196, 49, 165, 55, 116, 4, 152, 177, 42]) }
2023-01-24T10:53:07.228329Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 20242942,
    events_root: None,
}
2023-01-24T10:53:07.228352Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 1
2023-01-24T10:53:07.228355Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CallWithNOTZeroValueToPrecompileFromContractInitialization"::Merge::1
2023-01-24T10:53:07.228358Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stStaticFlagEnabled/CallWithNOTZeroValueToPrecompileFromContractInitialization.json"
2023-01-24T10:53:07.228361Z  INFO evm_eth_compliance::statetest::runner: TX len : 107
2023-01-24T10:53:07.228362Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [128, 53, 82, 149, 252, 153, 84, 4, 15, 235, 250, 191, 98, 140, 135, 85, 27, 144, 169, 194, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([39, 202, 0, 61, 220, 84, 98, 79, 206, 62, 176, 253, 44, 186, 245, 199, 23, 163, 253, 50]) }
2023-01-24T10:53:07.229069Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 19908170,
    events_root: None,
}
2023-01-24T10:53:07.229092Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 2
2023-01-24T10:53:07.229095Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CallWithNOTZeroValueToPrecompileFromContractInitialization"::Merge::2
2023-01-24T10:53:07.229097Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stStaticFlagEnabled/CallWithNOTZeroValueToPrecompileFromContractInitialization.json"
2023-01-24T10:53:07.229100Z  INFO evm_eth_compliance::statetest::runner: TX len : 107
2023-01-24T10:53:07.229102Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [251, 49, 17, 150, 79, 184, 11, 240, 24, 210, 111, 25, 84, 245, 214, 237, 91, 116, 118, 185, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([192, 88, 99, 161, 23, 254, 175, 39, 213, 169, 153, 253, 197, 254, 95, 117, 145, 246, 7, 95]) }
2023-01-24T10:53:07.229816Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 20205472,
    events_root: None,
}
2023-01-24T10:53:07.229839Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 3
2023-01-24T10:53:07.229842Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CallWithNOTZeroValueToPrecompileFromContractInitialization"::Merge::3
2023-01-24T10:53:07.229845Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stStaticFlagEnabled/CallWithNOTZeroValueToPrecompileFromContractInitialization.json"
2023-01-24T10:53:07.229848Z  INFO evm_eth_compliance::statetest::runner: TX len : 107
2023-01-24T10:53:07.229849Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [239, 105, 67, 62, 144, 118, 217, 198, 107, 30, 173, 161, 198, 231, 136, 216, 45, 141, 40, 123, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([96, 33, 187, 115, 222, 53, 224, 244, 47, 32, 70, 11, 226, 18, 129, 166, 126, 239, 230, 44]) }
2023-01-24T10:53:07.230545Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 19727308,
    events_root: None,
}
2023-01-24T10:53:07.230572Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 4
2023-01-24T10:53:07.230575Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CallWithNOTZeroValueToPrecompileFromContractInitialization"::Merge::4
2023-01-24T10:53:07.230578Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stStaticFlagEnabled/CallWithNOTZeroValueToPrecompileFromContractInitialization.json"
2023-01-24T10:53:07.230581Z  INFO evm_eth_compliance::statetest::runner: TX len : 107
2023-01-24T10:53:07.230582Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [247, 50, 166, 226, 25, 129, 68, 39, 30, 52, 197, 93, 99, 203, 53, 110, 225, 135, 7, 104, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([221, 202, 25, 212, 34, 2, 50, 123, 41, 75, 186, 155, 123, 166, 127, 9, 228, 237, 116, 209]) }
2023-01-24T10:53:07.231306Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 20438519,
    events_root: None,
}
2023-01-24T10:53:07.231329Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 5
2023-01-24T10:53:07.231332Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CallWithNOTZeroValueToPrecompileFromContractInitialization"::Merge::5
2023-01-24T10:53:07.231334Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stStaticFlagEnabled/CallWithNOTZeroValueToPrecompileFromContractInitialization.json"
2023-01-24T10:53:07.231339Z  INFO evm_eth_compliance::statetest::runner: TX len : 107
2023-01-24T10:53:07.231340Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [107, 5, 11, 148, 139, 152, 86, 170, 220, 111, 185, 9, 172, 128, 16, 36, 214, 13, 33, 161, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([96, 157, 121, 180, 71, 136, 28, 182, 195, 187, 216, 146, 44, 166, 42, 126, 234, 16, 198, 148]) }
2023-01-24T10:53:07.232126Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 19851532,
    events_root: None,
}
2023-01-24T10:53:07.232150Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 6
2023-01-24T10:53:07.232154Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CallWithNOTZeroValueToPrecompileFromContractInitialization"::Merge::6
2023-01-24T10:53:07.232156Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stStaticFlagEnabled/CallWithNOTZeroValueToPrecompileFromContractInitialization.json"
2023-01-24T10:53:07.232159Z  INFO evm_eth_compliance::statetest::runner: TX len : 107
2023-01-24T10:53:07.232161Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [21, 141, 247, 201, 85, 54, 177, 165, 42, 81, 159, 82, 62, 163, 208, 65, 185, 11, 245, 116, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([125, 213, 185, 126, 102, 183, 165, 62, 81, 45, 4, 229, 242, 150, 184, 46, 206, 140, 135, 167]) }
2023-01-24T10:53:07.232977Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 20681151,
    events_root: None,
}
2023-01-24T10:53:07.233009Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 7
2023-01-24T10:53:07.233013Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CallWithNOTZeroValueToPrecompileFromContractInitialization"::Merge::7
2023-01-24T10:53:07.233017Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stStaticFlagEnabled/CallWithNOTZeroValueToPrecompileFromContractInitialization.json"
2023-01-24T10:53:07.233021Z  INFO evm_eth_compliance::statetest::runner: TX len : 107
2023-01-24T10:53:07.233023Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [16, 46, 89, 89, 142, 195, 139, 178, 198, 8, 251, 132, 101, 98, 20, 238, 179, 253, 19, 109, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([57, 47, 201, 253, 31, 210, 216, 45, 82, 53, 15, 10, 140, 189, 182, 38, 139, 193, 227, 148]) }
2023-01-24T10:53:07.233818Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 20497923,
    events_root: None,
}
2023-01-24T10:53:07.235627Z TRACE evm_eth_compliance::statetest::runner: TestDone => "test-vectors/tests/GeneralStateTests/stStaticFlagEnabled/CallWithNOTZeroValueToPrecompileFromContractInitialization.json"
2023-01-24T10:53:07.235655Z TRACE evm_eth_compliance::statetest::runner: Calling testfile => "test-vectors/tests/GeneralStateTests/stStaticFlagEnabled/CallWithNOTZeroValueToPrecompileFromTransaction.json"
2023-01-24T10:53:07.261144Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-24T10:53:07.261250Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T10:53:07.261253Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-24T10:53:07.261308Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T10:53:07.261310Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 2
2023-01-24T10:53:07.261369Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T10:53:07.261371Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 3
2023-01-24T10:53:07.261429Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T10:53:07.261432Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 4
2023-01-24T10:53:07.261483Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T10:53:07.261485Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 5
2023-01-24T10:53:07.261545Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T10:53:07.261547Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 6
2023-01-24T10:53:07.261608Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T10:53:07.261610Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 7
2023-01-24T10:53:07.261656Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T10:53:07.261658Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 8
2023-01-24T10:53:07.261700Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T10:53:07.261702Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 9
2023-01-24T10:53:07.261753Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T10:53:07.261824Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-24T10:53:07.261828Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CallWithNOTZeroValueToPrecompileFromTransaction"::Istanbul::0
2023-01-24T10:53:07.261832Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stStaticFlagEnabled/CallWithNOTZeroValueToPrecompileFromTransaction.json"
2023-01-24T10:53:07.261836Z  INFO evm_eth_compliance::statetest::runner: TX len : 32
2023-01-24T10:53:07.261837Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T10:53:07.620138Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 5710216,
    events_root: None,
}
2023-01-24T10:53:07.620164Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 1
2023-01-24T10:53:07.620172Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CallWithNOTZeroValueToPrecompileFromTransaction"::Istanbul::1
2023-01-24T10:53:07.620175Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stStaticFlagEnabled/CallWithNOTZeroValueToPrecompileFromTransaction.json"
2023-01-24T10:53:07.620178Z  INFO evm_eth_compliance::statetest::runner: TX len : 32
2023-01-24T10:53:07.620179Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T10:53:07.620414Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3595980,
    events_root: None,
}
2023-01-24T10:53:07.620424Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 2
2023-01-24T10:53:07.620426Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CallWithNOTZeroValueToPrecompileFromTransaction"::Istanbul::2
2023-01-24T10:53:07.620428Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stStaticFlagEnabled/CallWithNOTZeroValueToPrecompileFromTransaction.json"
2023-01-24T10:53:07.620434Z  INFO evm_eth_compliance::statetest::runner: TX len : 32
2023-01-24T10:53:07.620435Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T10:53:07.620657Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3595980,
    events_root: None,
}
2023-01-24T10:53:07.620667Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 3
2023-01-24T10:53:07.620671Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CallWithNOTZeroValueToPrecompileFromTransaction"::Istanbul::3
2023-01-24T10:53:07.620674Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stStaticFlagEnabled/CallWithNOTZeroValueToPrecompileFromTransaction.json"
2023-01-24T10:53:07.620678Z  INFO evm_eth_compliance::statetest::runner: TX len : 32
2023-01-24T10:53:07.620680Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T10:53:07.620900Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3595980,
    events_root: None,
}
2023-01-24T10:53:07.620910Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 4
2023-01-24T10:53:07.620914Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CallWithNOTZeroValueToPrecompileFromTransaction"::Istanbul::4
2023-01-24T10:53:07.620917Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stStaticFlagEnabled/CallWithNOTZeroValueToPrecompileFromTransaction.json"
2023-01-24T10:53:07.620921Z  INFO evm_eth_compliance::statetest::runner: TX len : 32
2023-01-24T10:53:07.620923Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T10:53:07.621143Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3617940,
    events_root: None,
}
2023-01-24T10:53:07.621153Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 5
2023-01-24T10:53:07.621157Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CallWithNOTZeroValueToPrecompileFromTransaction"::Istanbul::5
2023-01-24T10:53:07.621159Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stStaticFlagEnabled/CallWithNOTZeroValueToPrecompileFromTransaction.json"
2023-01-24T10:53:07.621163Z  INFO evm_eth_compliance::statetest::runner: TX len : 32
2023-01-24T10:53:07.621165Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T10:53:07.621453Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3611669,
    events_root: None,
}
2023-01-24T10:53:07.621463Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 6
2023-01-24T10:53:07.621467Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CallWithNOTZeroValueToPrecompileFromTransaction"::Istanbul::6
2023-01-24T10:53:07.621470Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stStaticFlagEnabled/CallWithNOTZeroValueToPrecompileFromTransaction.json"
2023-01-24T10:53:07.621474Z  INFO evm_eth_compliance::statetest::runner: TX len : 32
2023-01-24T10:53:07.621476Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T10:53:07.621696Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3604995,
    events_root: None,
}
2023-01-24T10:53:07.621707Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 7
2023-01-24T10:53:07.621710Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CallWithNOTZeroValueToPrecompileFromTransaction"::Istanbul::7
2023-01-24T10:53:07.621713Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stStaticFlagEnabled/CallWithNOTZeroValueToPrecompileFromTransaction.json"
2023-01-24T10:53:07.621718Z  INFO evm_eth_compliance::statetest::runner: TX len : 32
2023-01-24T10:53:07.621720Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T10:53:07.621944Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3654398,
    events_root: None,
}
2023-01-24T10:53:07.621954Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-24T10:53:07.621957Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CallWithNOTZeroValueToPrecompileFromTransaction"::Berlin::0
2023-01-24T10:53:07.621961Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stStaticFlagEnabled/CallWithNOTZeroValueToPrecompileFromTransaction.json"
2023-01-24T10:53:07.621965Z  INFO evm_eth_compliance::statetest::runner: TX len : 32
2023-01-24T10:53:07.621967Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T10:53:07.622187Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3610346,
    events_root: None,
}
2023-01-24T10:53:07.622198Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 1
2023-01-24T10:53:07.622201Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CallWithNOTZeroValueToPrecompileFromTransaction"::Berlin::1
2023-01-24T10:53:07.622204Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stStaticFlagEnabled/CallWithNOTZeroValueToPrecompileFromTransaction.json"
2023-01-24T10:53:07.622208Z  INFO evm_eth_compliance::statetest::runner: TX len : 32
2023-01-24T10:53:07.622211Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T10:53:07.622432Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3595980,
    events_root: None,
}
2023-01-24T10:53:07.622443Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 2
2023-01-24T10:53:07.622446Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CallWithNOTZeroValueToPrecompileFromTransaction"::Berlin::2
2023-01-24T10:53:07.622450Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stStaticFlagEnabled/CallWithNOTZeroValueToPrecompileFromTransaction.json"
2023-01-24T10:53:07.622453Z  INFO evm_eth_compliance::statetest::runner: TX len : 32
2023-01-24T10:53:07.622456Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T10:53:07.622673Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3595980,
    events_root: None,
}
2023-01-24T10:53:07.622684Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 3
2023-01-24T10:53:07.622687Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CallWithNOTZeroValueToPrecompileFromTransaction"::Berlin::3
2023-01-24T10:53:07.622690Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stStaticFlagEnabled/CallWithNOTZeroValueToPrecompileFromTransaction.json"
2023-01-24T10:53:07.622695Z  INFO evm_eth_compliance::statetest::runner: TX len : 32
2023-01-24T10:53:07.622697Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T10:53:07.622916Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3595980,
    events_root: None,
}
2023-01-24T10:53:07.622926Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 4
2023-01-24T10:53:07.622929Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CallWithNOTZeroValueToPrecompileFromTransaction"::Berlin::4
2023-01-24T10:53:07.622932Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stStaticFlagEnabled/CallWithNOTZeroValueToPrecompileFromTransaction.json"
2023-01-24T10:53:07.622936Z  INFO evm_eth_compliance::statetest::runner: TX len : 32
2023-01-24T10:53:07.622938Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T10:53:07.623214Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3617940,
    events_root: None,
}
2023-01-24T10:53:07.623225Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 5
2023-01-24T10:53:07.623229Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CallWithNOTZeroValueToPrecompileFromTransaction"::Berlin::5
2023-01-24T10:53:07.623232Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stStaticFlagEnabled/CallWithNOTZeroValueToPrecompileFromTransaction.json"
2023-01-24T10:53:07.623236Z  INFO evm_eth_compliance::statetest::runner: TX len : 32
2023-01-24T10:53:07.623238Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T10:53:07.623464Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3611669,
    events_root: None,
}
2023-01-24T10:53:07.623474Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 6
2023-01-24T10:53:07.623477Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CallWithNOTZeroValueToPrecompileFromTransaction"::Berlin::6
2023-01-24T10:53:07.623481Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stStaticFlagEnabled/CallWithNOTZeroValueToPrecompileFromTransaction.json"
2023-01-24T10:53:07.623484Z  INFO evm_eth_compliance::statetest::runner: TX len : 32
2023-01-24T10:53:07.623487Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T10:53:07.623709Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3604995,
    events_root: None,
}
2023-01-24T10:53:07.623720Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 7
2023-01-24T10:53:07.623724Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CallWithNOTZeroValueToPrecompileFromTransaction"::Berlin::7
2023-01-24T10:53:07.623727Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stStaticFlagEnabled/CallWithNOTZeroValueToPrecompileFromTransaction.json"
2023-01-24T10:53:07.623731Z  INFO evm_eth_compliance::statetest::runner: TX len : 32
2023-01-24T10:53:07.623733Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T10:53:07.623954Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3654398,
    events_root: None,
}
2023-01-24T10:53:07.623965Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-24T10:53:07.623968Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CallWithNOTZeroValueToPrecompileFromTransaction"::London::0
2023-01-24T10:53:07.623972Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stStaticFlagEnabled/CallWithNOTZeroValueToPrecompileFromTransaction.json"
2023-01-24T10:53:07.623976Z  INFO evm_eth_compliance::statetest::runner: TX len : 32
2023-01-24T10:53:07.623978Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T10:53:07.624196Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3610346,
    events_root: None,
}
2023-01-24T10:53:07.624206Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 1
2023-01-24T10:53:07.624210Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CallWithNOTZeroValueToPrecompileFromTransaction"::London::1
2023-01-24T10:53:07.624214Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stStaticFlagEnabled/CallWithNOTZeroValueToPrecompileFromTransaction.json"
2023-01-24T10:53:07.624218Z  INFO evm_eth_compliance::statetest::runner: TX len : 32
2023-01-24T10:53:07.624220Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T10:53:07.624443Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3595980,
    events_root: None,
}
2023-01-24T10:53:07.624454Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 2
2023-01-24T10:53:07.624457Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CallWithNOTZeroValueToPrecompileFromTransaction"::London::2
2023-01-24T10:53:07.624460Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stStaticFlagEnabled/CallWithNOTZeroValueToPrecompileFromTransaction.json"
2023-01-24T10:53:07.624464Z  INFO evm_eth_compliance::statetest::runner: TX len : 32
2023-01-24T10:53:07.624467Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T10:53:07.624684Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3595980,
    events_root: None,
}
2023-01-24T10:53:07.624695Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 3
2023-01-24T10:53:07.624698Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CallWithNOTZeroValueToPrecompileFromTransaction"::London::3
2023-01-24T10:53:07.624701Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stStaticFlagEnabled/CallWithNOTZeroValueToPrecompileFromTransaction.json"
2023-01-24T10:53:07.624705Z  INFO evm_eth_compliance::statetest::runner: TX len : 32
2023-01-24T10:53:07.624707Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T10:53:07.624924Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3595980,
    events_root: None,
}
2023-01-24T10:53:07.624935Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 4
2023-01-24T10:53:07.624938Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CallWithNOTZeroValueToPrecompileFromTransaction"::London::4
2023-01-24T10:53:07.624941Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stStaticFlagEnabled/CallWithNOTZeroValueToPrecompileFromTransaction.json"
2023-01-24T10:53:07.624945Z  INFO evm_eth_compliance::statetest::runner: TX len : 32
2023-01-24T10:53:07.624947Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T10:53:07.625224Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3617940,
    events_root: None,
}
2023-01-24T10:53:07.625235Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 5
2023-01-24T10:53:07.625238Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CallWithNOTZeroValueToPrecompileFromTransaction"::London::5
2023-01-24T10:53:07.625241Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stStaticFlagEnabled/CallWithNOTZeroValueToPrecompileFromTransaction.json"
2023-01-24T10:53:07.625245Z  INFO evm_eth_compliance::statetest::runner: TX len : 32
2023-01-24T10:53:07.625247Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T10:53:07.625470Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3611669,
    events_root: None,
}
2023-01-24T10:53:07.625481Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 6
2023-01-24T10:53:07.625485Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CallWithNOTZeroValueToPrecompileFromTransaction"::London::6
2023-01-24T10:53:07.625488Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stStaticFlagEnabled/CallWithNOTZeroValueToPrecompileFromTransaction.json"
2023-01-24T10:53:07.625493Z  INFO evm_eth_compliance::statetest::runner: TX len : 32
2023-01-24T10:53:07.625495Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T10:53:07.625713Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3604995,
    events_root: None,
}
2023-01-24T10:53:07.625723Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 7
2023-01-24T10:53:07.625727Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CallWithNOTZeroValueToPrecompileFromTransaction"::London::7
2023-01-24T10:53:07.625730Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stStaticFlagEnabled/CallWithNOTZeroValueToPrecompileFromTransaction.json"
2023-01-24T10:53:07.625734Z  INFO evm_eth_compliance::statetest::runner: TX len : 32
2023-01-24T10:53:07.625736Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T10:53:07.625955Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3654398,
    events_root: None,
}
2023-01-24T10:53:07.625966Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-24T10:53:07.625969Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CallWithNOTZeroValueToPrecompileFromTransaction"::Merge::0
2023-01-24T10:53:07.625972Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stStaticFlagEnabled/CallWithNOTZeroValueToPrecompileFromTransaction.json"
2023-01-24T10:53:07.625977Z  INFO evm_eth_compliance::statetest::runner: TX len : 32
2023-01-24T10:53:07.625978Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T10:53:07.626239Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3610346,
    events_root: None,
}
2023-01-24T10:53:07.626251Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 1
2023-01-24T10:53:07.626254Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CallWithNOTZeroValueToPrecompileFromTransaction"::Merge::1
2023-01-24T10:53:07.626258Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stStaticFlagEnabled/CallWithNOTZeroValueToPrecompileFromTransaction.json"
2023-01-24T10:53:07.626262Z  INFO evm_eth_compliance::statetest::runner: TX len : 32
2023-01-24T10:53:07.626264Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T10:53:07.626489Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3595980,
    events_root: None,
}
2023-01-24T10:53:07.626499Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 2
2023-01-24T10:53:07.626503Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CallWithNOTZeroValueToPrecompileFromTransaction"::Merge::2
2023-01-24T10:53:07.626506Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stStaticFlagEnabled/CallWithNOTZeroValueToPrecompileFromTransaction.json"
2023-01-24T10:53:07.626510Z  INFO evm_eth_compliance::statetest::runner: TX len : 32
2023-01-24T10:53:07.626512Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T10:53:07.626735Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3595980,
    events_root: None,
}
2023-01-24T10:53:07.626745Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 3
2023-01-24T10:53:07.626748Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CallWithNOTZeroValueToPrecompileFromTransaction"::Merge::3
2023-01-24T10:53:07.626752Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stStaticFlagEnabled/CallWithNOTZeroValueToPrecompileFromTransaction.json"
2023-01-24T10:53:07.626756Z  INFO evm_eth_compliance::statetest::runner: TX len : 32
2023-01-24T10:53:07.626757Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T10:53:07.626973Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3595980,
    events_root: None,
}
2023-01-24T10:53:07.626985Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 4
2023-01-24T10:53:07.626988Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CallWithNOTZeroValueToPrecompileFromTransaction"::Merge::4
2023-01-24T10:53:07.626991Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stStaticFlagEnabled/CallWithNOTZeroValueToPrecompileFromTransaction.json"
2023-01-24T10:53:07.627009Z  INFO evm_eth_compliance::statetest::runner: TX len : 32
2023-01-24T10:53:07.627017Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T10:53:07.627296Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3617940,
    events_root: None,
}
2023-01-24T10:53:07.627307Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 5
2023-01-24T10:53:07.627310Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CallWithNOTZeroValueToPrecompileFromTransaction"::Merge::5
2023-01-24T10:53:07.627313Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stStaticFlagEnabled/CallWithNOTZeroValueToPrecompileFromTransaction.json"
2023-01-24T10:53:07.627317Z  INFO evm_eth_compliance::statetest::runner: TX len : 32
2023-01-24T10:53:07.627320Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T10:53:07.627544Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3611669,
    events_root: None,
}
2023-01-24T10:53:07.627555Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 6
2023-01-24T10:53:07.627558Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CallWithNOTZeroValueToPrecompileFromTransaction"::Merge::6
2023-01-24T10:53:07.627563Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stStaticFlagEnabled/CallWithNOTZeroValueToPrecompileFromTransaction.json"
2023-01-24T10:53:07.627567Z  INFO evm_eth_compliance::statetest::runner: TX len : 32
2023-01-24T10:53:07.627569Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T10:53:07.627811Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3604995,
    events_root: None,
}
2023-01-24T10:53:07.627836Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 7
2023-01-24T10:53:07.627840Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CallWithNOTZeroValueToPrecompileFromTransaction"::Merge::7
2023-01-24T10:53:07.627843Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stStaticFlagEnabled/CallWithNOTZeroValueToPrecompileFromTransaction.json"
2023-01-24T10:53:07.627847Z  INFO evm_eth_compliance::statetest::runner: TX len : 32
2023-01-24T10:53:07.627849Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T10:53:07.628072Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3654398,
    events_root: None,
}
2023-01-24T10:53:07.629617Z TRACE evm_eth_compliance::statetest::runner: TestDone => "test-vectors/tests/GeneralStateTests/stStaticFlagEnabled/CallWithNOTZeroValueToPrecompileFromTransaction.json"
2023-01-24T10:53:07.629651Z TRACE evm_eth_compliance::statetest::runner: Calling testfile => "test-vectors/tests/GeneralStateTests/stStaticFlagEnabled/CallWithZeroValueToPrecompileFromCalledContract.json"
2023-01-24T10:53:07.655003Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-24T10:53:07.655131Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T10:53:07.655138Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-24T10:53:07.655206Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T10:53:07.655209Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 2
2023-01-24T10:53:07.655280Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T10:53:07.655284Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 3
2023-01-24T10:53:07.655354Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T10:53:07.655463Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-24T10:53:07.655470Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CallWithZeroValueToPrecompileFromCalledContract"::Istanbul::0
2023-01-24T10:53:07.655475Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stStaticFlagEnabled/CallWithZeroValueToPrecompileFromCalledContract.json"
2023-01-24T10:53:07.655482Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-24T10:53:07.655484Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[INFO] Call Precompile:
	address: 0000000000000000000000000000000000000001
	context: PrecompileContext { call_type: Call, gas_limit: 8797746683386669, value: 0 }
	input: 18c547e4f7b0f325ad1e56f57e26c745b09a3e503d86e00e5255ff7f715d3d1c000000000000000000000000000000000000000000000000000000000000001c73b1693892219d736caba55bdb67216e485557ea6b6af75f37096c9aa6a5a75feeb940b1d03b21e36b0e47e79769f095fe2ab855bd91e3a38756b7d75a9c4549
[INFO] Call Precompile:
	address: 0000000000000000000000000000000000000002
	context: PrecompileContext { call_type: Call, gas_limit: 8797746680645593, value: 0 }
	input: 0000000ccccccccccccccccccccccccccccccccccccccccccccccccccc000000
[INFO] Call Precompile:
	address: 0000000000000000000000000000000000000003
	context: PrecompileContext { call_type: Call, gas_limit: 8797746680456198, value: 0 }
	input: 0000000ccccccccccccccccccccccccccccccccccccccccccccccccccc000000
[INFO] Call Precompile:
	address: 0000000000000000000000000000000000000004
	context: PrecompileContext { call_type: Call, gas_limit: 8797746680261321, value: 0 }
	input: 0000000ccccccccccccccccccccccccccccccccccccccccccccccccccc000000
[INFO] Call Precompile:
	address: 0000000000000000000000000000000000000005
	context: PrecompileContext { call_type: Call, gas_limit: 8797746669792339, value: 0 }
	input: 00000000000000000000000000000000000000000000000000000000000000010000000000000000000000000000000000000000000000000000000000000020000000000000000000000000000000000000000000000000000000000000002003fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2efffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f
[INFO] Call Precompile:
	address: 0000000000000000000000000000000000000006
	context: PrecompileContext { call_type: Call, gas_limit: 8797746658374692, value: 0 }
	input: 0f25929bcb43d5a57391564615c9e70a992b10eafa4db109709649cf48c50dd216da2f5cb6be7a0aa72c440c53c9bbdfec6c36c7d515536431b3a865468acbba1de49a4b0233273bba8146af82042d004f2085ec982397db0d97da17204cc2860217327ffc463919bef80cc166d09c6172639d8589799928761bcd9f22c903d4
[INFO] Call Precompile:
	address: 0000000000000000000000000000000000000007
	context: PrecompileContext { call_type: Call, gas_limit: 8797746657164237, value: 0 }
	input: 0f25929bcb43d5a57391564615c9e70a992b10eafa4db109709649cf48c50dd216da2f5cb6be7a0aa72c440c53c9bbdfec6c36c7d515536431b3a865468acbba0000000000000000000000000000000000000000000000000000000000000003
[INFO] Call Precompile:
	address: 0000000000000000000000000000000000000008
	context: PrecompileContext { call_type: Call, gas_limit: 8797746655798979, value: 0 }
	input: 1c76476f4def4bb94541d57ebba1193381ffa7aa76ada664dd31c16024c43f593034dd2920f673e204fee2811c678745fc819b55d3e9d294e45c9b03a76aef41209dd15ebff5d46c4bd888e51a93cf99a7329636c63514396b4a452003a35bf704bf11ca01483bfa8b34b43561848d28905960114c8ac04049af4b6315a416782bb8324af6cfc93537a2ad1a445cfd0ca2a71acd7ac41fadbf933c2a51be344d120a2a4cf30c1bf9845f20c6fe39e07ea2cce61f0c9bb048165fe5e4de877550111e129f1cf1097710d41c4ac70fcdfa5ba2023c6ff1cbeac322de49d1b6df7c2032c61a830e3c17286de9462bf242fca2883585b93870a73853face6a6bf411198e9393920d483a7260bfb731fb5d25f1aa493335a9e71297e485b7aef312c21800deef121f1e76426a00665e5c4479674322d4f75edadd46debd5cd992f6ed090689d0585ff075ec9e99ad690c3395bc4b313370b38ef355acdadcd122975b12c85ea5db8c6deb4aab71808dcb408fe3d1e7690c43d37b4ce6cc0166fa7daa
2023-01-24T10:53:08.031226Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1201476849,
    events_root: None,
}
2023-01-24T10:53:08.031266Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-24T10:53:08.031273Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CallWithZeroValueToPrecompileFromCalledContract"::Berlin::0
2023-01-24T10:53:08.031276Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stStaticFlagEnabled/CallWithZeroValueToPrecompileFromCalledContract.json"
2023-01-24T10:53:08.031281Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-24T10:53:08.031282Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[INFO] Call Precompile:
	address: 0000000000000000000000000000000000000001
	context: PrecompileContext { call_type: Call, gas_limit: 8797746682468399, value: 0 }
	input: 18c547e4f7b0f325ad1e56f57e26c745b09a3e503d86e00e5255ff7f715d3d1c000000000000000000000000000000000000000000000000000000000000001c73b1693892219d736caba55bdb67216e485557ea6b6af75f37096c9aa6a5a75feeb940b1d03b21e36b0e47e79769f095fe2ab855bd91e3a38756b7d75a9c4549
[INFO] Call Precompile:
	address: 0000000000000000000000000000000000000002
	context: PrecompileContext { call_type: Call, gas_limit: 8797746679727323, value: 0 }
	input: 0000000ccccccccccccccccccccccccccccccccccccccccccccccccccc000000
[INFO] Call Precompile:
	address: 0000000000000000000000000000000000000003
	context: PrecompileContext { call_type: Call, gas_limit: 8797746679537927, value: 0 }
	input: 0000000ccccccccccccccccccccccccccccccccccccccccccccccccccc000000
[INFO] Call Precompile:
	address: 0000000000000000000000000000000000000004
	context: PrecompileContext { call_type: Call, gas_limit: 8797746679343051, value: 0 }
	input: 0000000ccccccccccccccccccccccccccccccccccccccccccccccccccc000000
[INFO] Call Precompile:
	address: 0000000000000000000000000000000000000005
	context: PrecompileContext { call_type: Call, gas_limit: 8797746668874069, value: 0 }
	input: 00000000000000000000000000000000000000000000000000000000000000010000000000000000000000000000000000000000000000000000000000000020000000000000000000000000000000000000000000000000000000000000002003fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2efffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f
[INFO] Call Precompile:
	address: 0000000000000000000000000000000000000006
	context: PrecompileContext { call_type: Call, gas_limit: 8797746657456421, value: 0 }
	input: 0f25929bcb43d5a57391564615c9e70a992b10eafa4db109709649cf48c50dd216da2f5cb6be7a0aa72c440c53c9bbdfec6c36c7d515536431b3a865468acbba1de49a4b0233273bba8146af82042d004f2085ec982397db0d97da17204cc2860217327ffc463919bef80cc166d09c6172639d8589799928761bcd9f22c903d4
[INFO] Call Precompile:
	address: 0000000000000000000000000000000000000007
	context: PrecompileContext { call_type: Call, gas_limit: 8797746656245967, value: 0 }
	input: 0f25929bcb43d5a57391564615c9e70a992b10eafa4db109709649cf48c50dd216da2f5cb6be7a0aa72c440c53c9bbdfec6c36c7d515536431b3a865468acbba0000000000000000000000000000000000000000000000000000000000000003
[INFO] Call Precompile:
	address: 0000000000000000000000000000000000000008
	context: PrecompileContext { call_type: Call, gas_limit: 8797746654880709, value: 0 }
	input: 1c76476f4def4bb94541d57ebba1193381ffa7aa76ada664dd31c16024c43f593034dd2920f673e204fee2811c678745fc819b55d3e9d294e45c9b03a76aef41209dd15ebff5d46c4bd888e51a93cf99a7329636c63514396b4a452003a35bf704bf11ca01483bfa8b34b43561848d28905960114c8ac04049af4b6315a416782bb8324af6cfc93537a2ad1a445cfd0ca2a71acd7ac41fadbf933c2a51be344d120a2a4cf30c1bf9845f20c6fe39e07ea2cce61f0c9bb048165fe5e4de877550111e129f1cf1097710d41c4ac70fcdfa5ba2023c6ff1cbeac322de49d1b6df7c2032c61a830e3c17286de9462bf242fca2883585b93870a73853face6a6bf411198e9393920d483a7260bfb731fb5d25f1aa493335a9e71297e485b7aef312c21800deef121f1e76426a00665e5c4479674322d4f75edadd46debd5cd992f6ed090689d0585ff075ec9e99ad690c3395bc4b313370b38ef355acdadcd122975b12c85ea5db8c6deb4aab71808dcb408fe3d1e7690c43d37b4ce6cc0166fa7daa
2023-01-24T10:53:08.066735Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1194410856,
    events_root: None,
}
2023-01-24T10:53:08.066780Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-24T10:53:08.066788Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CallWithZeroValueToPrecompileFromCalledContract"::London::0
2023-01-24T10:53:08.066791Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stStaticFlagEnabled/CallWithZeroValueToPrecompileFromCalledContract.json"
2023-01-24T10:53:08.066794Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-24T10:53:08.066796Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[INFO] Call Precompile:
	address: 0000000000000000000000000000000000000001
	context: PrecompileContext { call_type: Call, gas_limit: 8797746682468399, value: 0 }
	input: 18c547e4f7b0f325ad1e56f57e26c745b09a3e503d86e00e5255ff7f715d3d1c000000000000000000000000000000000000000000000000000000000000001c73b1693892219d736caba55bdb67216e485557ea6b6af75f37096c9aa6a5a75feeb940b1d03b21e36b0e47e79769f095fe2ab855bd91e3a38756b7d75a9c4549
[INFO] Call Precompile:
	address: 0000000000000000000000000000000000000002
	context: PrecompileContext { call_type: Call, gas_limit: 8797746679727323, value: 0 }
	input: 0000000ccccccccccccccccccccccccccccccccccccccccccccccccccc000000
[INFO] Call Precompile:
	address: 0000000000000000000000000000000000000003
	context: PrecompileContext { call_type: Call, gas_limit: 8797746679537927, value: 0 }
	input: 0000000ccccccccccccccccccccccccccccccccccccccccccccccccccc000000
[INFO] Call Precompile:
	address: 0000000000000000000000000000000000000004
	context: PrecompileContext { call_type: Call, gas_limit: 8797746679343051, value: 0 }
	input: 0000000ccccccccccccccccccccccccccccccccccccccccccccccccccc000000
[INFO] Call Precompile:
	address: 0000000000000000000000000000000000000005
	context: PrecompileContext { call_type: Call, gas_limit: 8797746668874069, value: 0 }
	input: 00000000000000000000000000000000000000000000000000000000000000010000000000000000000000000000000000000000000000000000000000000020000000000000000000000000000000000000000000000000000000000000002003fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2efffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f
[INFO] Call Precompile:
	address: 0000000000000000000000000000000000000006
	context: PrecompileContext { call_type: Call, gas_limit: 8797746657456421, value: 0 }
	input: 0f25929bcb43d5a57391564615c9e70a992b10eafa4db109709649cf48c50dd216da2f5cb6be7a0aa72c440c53c9bbdfec6c36c7d515536431b3a865468acbba1de49a4b0233273bba8146af82042d004f2085ec982397db0d97da17204cc2860217327ffc463919bef80cc166d09c6172639d8589799928761bcd9f22c903d4
[INFO] Call Precompile:
	address: 0000000000000000000000000000000000000007
	context: PrecompileContext { call_type: Call, gas_limit: 8797746656245967, value: 0 }
	input: 0f25929bcb43d5a57391564615c9e70a992b10eafa4db109709649cf48c50dd216da2f5cb6be7a0aa72c440c53c9bbdfec6c36c7d515536431b3a865468acbba0000000000000000000000000000000000000000000000000000000000000003
[INFO] Call Precompile:
	address: 0000000000000000000000000000000000000008
	context: PrecompileContext { call_type: Call, gas_limit: 8797746654880709, value: 0 }
	input: 1c76476f4def4bb94541d57ebba1193381ffa7aa76ada664dd31c16024c43f593034dd2920f673e204fee2811c678745fc819b55d3e9d294e45c9b03a76aef41209dd15ebff5d46c4bd888e51a93cf99a7329636c63514396b4a452003a35bf704bf11ca01483bfa8b34b43561848d28905960114c8ac04049af4b6315a416782bb8324af6cfc93537a2ad1a445cfd0ca2a71acd7ac41fadbf933c2a51be344d120a2a4cf30c1bf9845f20c6fe39e07ea2cce61f0c9bb048165fe5e4de877550111e129f1cf1097710d41c4ac70fcdfa5ba2023c6ff1cbeac322de49d1b6df7c2032c61a830e3c17286de9462bf242fca2883585b93870a73853face6a6bf411198e9393920d483a7260bfb731fb5d25f1aa493335a9e71297e485b7aef312c21800deef121f1e76426a00665e5c4479674322d4f75edadd46debd5cd992f6ed090689d0585ff075ec9e99ad690c3395bc4b313370b38ef355acdadcd122975b12c85ea5db8c6deb4aab71808dcb408fe3d1e7690c43d37b4ce6cc0166fa7daa
2023-01-24T10:53:08.102856Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1194410856,
    events_root: None,
}
2023-01-24T10:53:08.102901Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-24T10:53:08.102907Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CallWithZeroValueToPrecompileFromCalledContract"::Merge::0
2023-01-24T10:53:08.102911Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stStaticFlagEnabled/CallWithZeroValueToPrecompileFromCalledContract.json"
2023-01-24T10:53:08.102914Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-24T10:53:08.102915Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[INFO] Call Precompile:
	address: 0000000000000000000000000000000000000001
	context: PrecompileContext { call_type: Call, gas_limit: 8797746682468399, value: 0 }
	input: 18c547e4f7b0f325ad1e56f57e26c745b09a3e503d86e00e5255ff7f715d3d1c000000000000000000000000000000000000000000000000000000000000001c73b1693892219d736caba55bdb67216e485557ea6b6af75f37096c9aa6a5a75feeb940b1d03b21e36b0e47e79769f095fe2ab855bd91e3a38756b7d75a9c4549
[INFO] Call Precompile:
	address: 0000000000000000000000000000000000000002
	context: PrecompileContext { call_type: Call, gas_limit: 8797746679727323, value: 0 }
	input: 0000000ccccccccccccccccccccccccccccccccccccccccccccccccccc000000
[INFO] Call Precompile:
	address: 0000000000000000000000000000000000000003
	context: PrecompileContext { call_type: Call, gas_limit: 8797746679537927, value: 0 }
	input: 0000000ccccccccccccccccccccccccccccccccccccccccccccccccccc000000
[INFO] Call Precompile:
	address: 0000000000000000000000000000000000000004
	context: PrecompileContext { call_type: Call, gas_limit: 8797746679343051, value: 0 }
	input: 0000000ccccccccccccccccccccccccccccccccccccccccccccccccccc000000
[INFO] Call Precompile:
	address: 0000000000000000000000000000000000000005
	context: PrecompileContext { call_type: Call, gas_limit: 8797746668874069, value: 0 }
	input: 00000000000000000000000000000000000000000000000000000000000000010000000000000000000000000000000000000000000000000000000000000020000000000000000000000000000000000000000000000000000000000000002003fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2efffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f
[INFO] Call Precompile:
	address: 0000000000000000000000000000000000000006
	context: PrecompileContext { call_type: Call, gas_limit: 8797746657456421, value: 0 }
	input: 0f25929bcb43d5a57391564615c9e70a992b10eafa4db109709649cf48c50dd216da2f5cb6be7a0aa72c440c53c9bbdfec6c36c7d515536431b3a865468acbba1de49a4b0233273bba8146af82042d004f2085ec982397db0d97da17204cc2860217327ffc463919bef80cc166d09c6172639d8589799928761bcd9f22c903d4
[INFO] Call Precompile:
	address: 0000000000000000000000000000000000000007
	context: PrecompileContext { call_type: Call, gas_limit: 8797746656245967, value: 0 }
	input: 0f25929bcb43d5a57391564615c9e70a992b10eafa4db109709649cf48c50dd216da2f5cb6be7a0aa72c440c53c9bbdfec6c36c7d515536431b3a865468acbba0000000000000000000000000000000000000000000000000000000000000003
[INFO] Call Precompile:
	address: 0000000000000000000000000000000000000008
	context: PrecompileContext { call_type: Call, gas_limit: 8797746654880709, value: 0 }
	input: 1c76476f4def4bb94541d57ebba1193381ffa7aa76ada664dd31c16024c43f593034dd2920f673e204fee2811c678745fc819b55d3e9d294e45c9b03a76aef41209dd15ebff5d46c4bd888e51a93cf99a7329636c63514396b4a452003a35bf704bf11ca01483bfa8b34b43561848d28905960114c8ac04049af4b6315a416782bb8324af6cfc93537a2ad1a445cfd0ca2a71acd7ac41fadbf933c2a51be344d120a2a4cf30c1bf9845f20c6fe39e07ea2cce61f0c9bb048165fe5e4de877550111e129f1cf1097710d41c4ac70fcdfa5ba2023c6ff1cbeac322de49d1b6df7c2032c61a830e3c17286de9462bf242fca2883585b93870a73853face6a6bf411198e9393920d483a7260bfb731fb5d25f1aa493335a9e71297e485b7aef312c21800deef121f1e76426a00665e5c4479674322d4f75edadd46debd5cd992f6ed090689d0585ff075ec9e99ad690c3395bc4b313370b38ef355acdadcd122975b12c85ea5db8c6deb4aab71808dcb408fe3d1e7690c43d37b4ce6cc0166fa7daa
2023-01-24T10:53:08.138531Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1194410856,
    events_root: None,
}
2023-01-24T10:53:08.139958Z TRACE evm_eth_compliance::statetest::runner: TestDone => "test-vectors/tests/GeneralStateTests/stStaticFlagEnabled/CallWithZeroValueToPrecompileFromCalledContract.json"
2023-01-24T10:53:08.139987Z TRACE evm_eth_compliance::statetest::runner: Calling testfile => "test-vectors/tests/GeneralStateTests/stStaticFlagEnabled/CallWithZeroValueToPrecompileFromContractInitialization.json"
2023-01-24T10:53:08.165980Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-24T10:53:08.166096Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T10:53:08.166100Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-24T10:53:08.166155Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T10:53:08.166158Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 2
2023-01-24T10:53:08.166222Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T10:53:08.166323Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-24T10:53:08.166331Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CallWithZeroValueToPrecompileFromContractInitialization"::Istanbul::0
2023-01-24T10:53:08.166335Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stStaticFlagEnabled/CallWithZeroValueToPrecompileFromContractInitialization.json"
2023-01-24T10:53:08.166340Z  INFO evm_eth_compliance::statetest::runner: TX len : 298
2023-01-24T10:53:08.166342Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [253, 119, 118, 177, 166, 52, 176, 220, 25, 48, 27, 23, 76, 207, 48, 212, 210, 64, 112, 168, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([215, 166, 242, 208, 200, 186, 79, 10, 126, 8, 221, 102, 9, 12, 200, 158, 203, 19, 78, 227]) }
[INFO] Call Precompile:
	address: 0000000000000000000000000000000000000001
	context: PrecompileContext { call_type: Call, gas_limit: 8937393447114531, value: 0 }
	input: 18c547e4f7b0f325ad1e56f57e26c745b09a3e503d86e00e5255ff7f715d3d1c000000000000000000000000000000000000000000000000000000000000001c73b1693892219d736caba55bdb67216e485557ea6b6af75f37096c9aa6a5a75feeb940b1d03b21e36b0e47e79769f095fe2ab855bd91e3a38756b7d75a9c4549
[INFO] Call Precompile:
	address: 0000000000000000000000000000000000000002
	context: PrecompileContext { call_type: Call, gas_limit: 8937393444373455, value: 0 }
	input: 0000000ccccccccccccccccccccccccccccccccccccccccccccccccccc000000
[INFO] Call Precompile:
	address: 0000000000000000000000000000000000000003
	context: PrecompileContext { call_type: Call, gas_limit: 8937393444184059, value: 0 }
	input: 0000000ccccccccccccccccccccccccccccccccccccccccccccccccccc000000
[INFO] Call Precompile:
	address: 0000000000000000000000000000000000000004
	context: PrecompileContext { call_type: Call, gas_limit: 8937393443989182, value: 0 }
	input: 0000000ccccccccccccccccccccccccccccccccccccccccccccccccccc000000
[INFO] Call Precompile:
	address: 0000000000000000000000000000000000000005
	context: PrecompileContext { call_type: Call, gas_limit: 8937393433520201, value: 0 }
	input: 00000000000000000000000000000000000000000000000000000000000000010000000000000000000000000000000000000000000000000000000000000020000000000000000000000000000000000000000000000000000000000000002003fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2efffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f
[INFO] Call Precompile:
	address: 0000000000000000000000000000000000000006
	context: PrecompileContext { call_type: Call, gas_limit: 8937393422102553, value: 0 }
	input: 0f25929bcb43d5a57391564615c9e70a992b10eafa4db109709649cf48c50dd216da2f5cb6be7a0aa72c440c53c9bbdfec6c36c7d515536431b3a865468acbba1de49a4b0233273bba8146af82042d004f2085ec982397db0d97da17204cc2860217327ffc463919bef80cc166d09c6172639d8589799928761bcd9f22c903d4
[INFO] Call Precompile:
	address: 0000000000000000000000000000000000000007
	context: PrecompileContext { call_type: Call, gas_limit: 8937393420892099, value: 0 }
	input: 0f25929bcb43d5a57391564615c9e70a992b10eafa4db109709649cf48c50dd216da2f5cb6be7a0aa72c440c53c9bbdfec6c36c7d515536431b3a865468acbba0000000000000000000000000000000000000000000000000000000000000003
[INFO] Call Precompile:
	address: 0000000000000000000000000000000000000008
	context: PrecompileContext { call_type: Call, gas_limit: 8937393419526840, value: 0 }
	input: 1c76476f4def4bb94541d57ebba1193381ffa7aa76ada664dd31c16024c43f593034dd2920f673e204fee2811c678745fc819b55d3e9d294e45c9b03a76aef41209dd15ebff5d46c4bd888e51a93cf99a7329636c63514396b4a452003a35bf704bf11ca01483bfa8b34b43561848d28905960114c8ac04049af4b6315a416782bb8324af6cfc93537a2ad1a445cfd0ca2a71acd7ac41fadbf933c2a51be344d120a2a4cf30c1bf9845f20c6fe39e07ea2cce61f0c9bb048165fe5e4de877550111e129f1cf1097710d41c4ac70fcdfa5ba2023c6ff1cbeac322de49d1b6df7c2032c61a830e3c17286de9462bf242fca2883585b93870a73853face6a6bf411198e9393920d483a7260bfb731fb5d25f1aa493335a9e71297e485b7aef312c21800deef121f1e76426a00665e5c4479674322d4f75edadd46debd5cd992f6ed090689d0585ff075ec9e99ad690c3395bc4b313370b38ef355acdadcd122975b12c85ea5db8c6deb4aab71808dcb408fe3d1e7690c43d37b4ce6cc0166fa7daa
2023-01-24T10:53:08.824162Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1211254116,
    events_root: None,
}
2023-01-24T10:53:08.824204Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-24T10:53:08.824212Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CallWithZeroValueToPrecompileFromContractInitialization"::Berlin::0
2023-01-24T10:53:08.824216Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stStaticFlagEnabled/CallWithZeroValueToPrecompileFromContractInitialization.json"
2023-01-24T10:53:08.824221Z  INFO evm_eth_compliance::statetest::runner: TX len : 298
2023-01-24T10:53:08.824223Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T10:53:08.824629Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 6181156,
    events_root: None,
}
2023-01-24T10:53:08.824643Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-24T10:53:08.824647Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CallWithZeroValueToPrecompileFromContractInitialization"::London::0
2023-01-24T10:53:08.824649Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stStaticFlagEnabled/CallWithZeroValueToPrecompileFromContractInitialization.json"
2023-01-24T10:53:08.824652Z  INFO evm_eth_compliance::statetest::runner: TX len : 298
2023-01-24T10:53:08.824654Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T10:53:08.824933Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 4394525,
    events_root: None,
}
2023-01-24T10:53:08.824943Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-24T10:53:08.824946Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CallWithZeroValueToPrecompileFromContractInitialization"::Merge::0
2023-01-24T10:53:08.824949Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stStaticFlagEnabled/CallWithZeroValueToPrecompileFromContractInitialization.json"
2023-01-24T10:53:08.824951Z  INFO evm_eth_compliance::statetest::runner: TX len : 298
2023-01-24T10:53:08.824953Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T10:53:08.825230Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 4394525,
    events_root: None,
}
2023-01-24T10:53:08.826745Z TRACE evm_eth_compliance::statetest::runner: TestDone => "test-vectors/tests/GeneralStateTests/stStaticFlagEnabled/CallWithZeroValueToPrecompileFromContractInitialization.json"
2023-01-24T10:53:08.826771Z TRACE evm_eth_compliance::statetest::runner: Calling testfile => "test-vectors/tests/GeneralStateTests/stStaticFlagEnabled/CallWithZeroValueToPrecompileFromTransaction.json"
2023-01-24T10:53:08.851454Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-24T10:53:08.851565Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T10:53:08.851568Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-24T10:53:08.851621Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T10:53:08.851623Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 2
2023-01-24T10:53:08.851676Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T10:53:08.851753Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-24T10:53:08.851757Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CallWithZeroValueToPrecompileFromTransaction"::Istanbul::0
2023-01-24T10:53:08.851761Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stStaticFlagEnabled/CallWithZeroValueToPrecompileFromTransaction.json"
2023-01-24T10:53:08.851764Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-24T10:53:08.851766Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[INFO] Call Precompile:
	address: 0000000000000000000000000000000000000001
	context: PrecompileContext { call_type: Call, gas_limit: 8937393457544937, value: 0 }
	input: 18c547e4f7b0f325ad1e56f57e26c745b09a3e503d86e00e5255ff7f715d3d1c000000000000000000000000000000000000000000000000000000000000001c73b1693892219d736caba55bdb67216e485557ea6b6af75f37096c9aa6a5a75feeb940b1d03b21e36b0e47e79769f095fe2ab855bd91e3a38756b7d75a9c4549
[INFO] Call Precompile:
	address: 0000000000000000000000000000000000000002
	context: PrecompileContext { call_type: Call, gas_limit: 8937393454803861, value: 0 }
	input: 0000000ccccccccccccccccccccccccccccccccccccccccccccccccccc000000
[INFO] Call Precompile:
	address: 0000000000000000000000000000000000000003
	context: PrecompileContext { call_type: Call, gas_limit: 8937393454614465, value: 0 }
	input: 0000000ccccccccccccccccccccccccccccccccccccccccccccccccccc000000
[INFO] Call Precompile:
	address: 0000000000000000000000000000000000000004
	context: PrecompileContext { call_type: Call, gas_limit: 8937393454419588, value: 0 }
	input: 0000000ccccccccccccccccccccccccccccccccccccccccccccccccccc000000
[INFO] Call Precompile:
	address: 0000000000000000000000000000000000000005
	context: PrecompileContext { call_type: Call, gas_limit: 8937393443950607, value: 0 }
	input: 00000000000000000000000000000000000000000000000000000000000000010000000000000000000000000000000000000000000000000000000000000020000000000000000000000000000000000000000000000000000000000000002003fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2efffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f
[INFO] Call Precompile:
	address: 0000000000000000000000000000000000000006
	context: PrecompileContext { call_type: Call, gas_limit: 8937393432532959, value: 0 }
	input: 0f25929bcb43d5a57391564615c9e70a992b10eafa4db109709649cf48c50dd216da2f5cb6be7a0aa72c440c53c9bbdfec6c36c7d515536431b3a865468acbba1de49a4b0233273bba8146af82042d004f2085ec982397db0d97da17204cc2860217327ffc463919bef80cc166d09c6172639d8589799928761bcd9f22c903d4
[INFO] Call Precompile:
	address: 0000000000000000000000000000000000000007
	context: PrecompileContext { call_type: Call, gas_limit: 8937393431322505, value: 0 }
	input: 0f25929bcb43d5a57391564615c9e70a992b10eafa4db109709649cf48c50dd216da2f5cb6be7a0aa72c440c53c9bbdfec6c36c7d515536431b3a865468acbba0000000000000000000000000000000000000000000000000000000000000003
[INFO] Call Precompile:
	address: 0000000000000000000000000000000000000008
	context: PrecompileContext { call_type: Call, gas_limit: 8937393429957246, value: 0 }
	input: 1c76476f4def4bb94541d57ebba1193381ffa7aa76ada664dd31c16024c43f593034dd2920f673e204fee2811c678745fc819b55d3e9d294e45c9b03a76aef41209dd15ebff5d46c4bd888e51a93cf99a7329636c63514396b4a452003a35bf704bf11ca01483bfa8b34b43561848d28905960114c8ac04049af4b6315a416782bb8324af6cfc93537a2ad1a445cfd0ca2a71acd7ac41fadbf933c2a51be344d120a2a4cf30c1bf9845f20c6fe39e07ea2cce61f0c9bb048165fe5e4de877550111e129f1cf1097710d41c4ac70fcdfa5ba2023c6ff1cbeac322de49d1b6df7c2032c61a830e3c17286de9462bf242fca2883585b93870a73853face6a6bf411198e9393920d483a7260bfb731fb5d25f1aa493335a9e71297e485b7aef312c21800deef121f1e76426a00665e5c4479674322d4f75edadd46debd5cd992f6ed090689d0585ff075ec9e99ad690c3395bc4b313370b38ef355acdadcd122975b12c85ea5db8c6deb4aab71808dcb408fe3d1e7690c43d37b4ce6cc0166fa7daa
2023-01-24T10:53:09.221394Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1197359667,
    events_root: None,
}
2023-01-24T10:53:09.221431Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-24T10:53:09.221439Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CallWithZeroValueToPrecompileFromTransaction"::Berlin::0
2023-01-24T10:53:09.221442Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stStaticFlagEnabled/CallWithZeroValueToPrecompileFromTransaction.json"
2023-01-24T10:53:09.221446Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-24T10:53:09.221447Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[INFO] Call Precompile:
	address: 0000000000000000000000000000000000000001
	context: PrecompileContext { call_type: Call, gas_limit: 8937393456959302, value: 0 }
	input: 18c547e4f7b0f325ad1e56f57e26c745b09a3e503d86e00e5255ff7f715d3d1c000000000000000000000000000000000000000000000000000000000000001c73b1693892219d736caba55bdb67216e485557ea6b6af75f37096c9aa6a5a75feeb940b1d03b21e36b0e47e79769f095fe2ab855bd91e3a38756b7d75a9c4549
[INFO] Call Precompile:
	address: 0000000000000000000000000000000000000002
	context: PrecompileContext { call_type: Call, gas_limit: 8937393454218226, value: 0 }
	input: 0000000ccccccccccccccccccccccccccccccccccccccccccccccccccc000000
[INFO] Call Precompile:
	address: 0000000000000000000000000000000000000003
	context: PrecompileContext { call_type: Call, gas_limit: 8937393454028831, value: 0 }
	input: 0000000ccccccccccccccccccccccccccccccccccccccccccccccccccc000000
[INFO] Call Precompile:
	address: 0000000000000000000000000000000000000004
	context: PrecompileContext { call_type: Call, gas_limit: 8937393453833954, value: 0 }
	input: 0000000ccccccccccccccccccccccccccccccccccccccccccccccccccc000000
[INFO] Call Precompile:
	address: 0000000000000000000000000000000000000005
	context: PrecompileContext { call_type: Call, gas_limit: 8937393443364972, value: 0 }
	input: 00000000000000000000000000000000000000000000000000000000000000010000000000000000000000000000000000000000000000000000000000000020000000000000000000000000000000000000000000000000000000000000002003fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2efffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f
[INFO] Call Precompile:
	address: 0000000000000000000000000000000000000006
	context: PrecompileContext { call_type: Call, gas_limit: 8937393431947325, value: 0 }
	input: 0f25929bcb43d5a57391564615c9e70a992b10eafa4db109709649cf48c50dd216da2f5cb6be7a0aa72c440c53c9bbdfec6c36c7d515536431b3a865468acbba1de49a4b0233273bba8146af82042d004f2085ec982397db0d97da17204cc2860217327ffc463919bef80cc166d09c6172639d8589799928761bcd9f22c903d4
[INFO] Call Precompile:
	address: 0000000000000000000000000000000000000007
	context: PrecompileContext { call_type: Call, gas_limit: 8937393430736870, value: 0 }
	input: 0f25929bcb43d5a57391564615c9e70a992b10eafa4db109709649cf48c50dd216da2f5cb6be7a0aa72c440c53c9bbdfec6c36c7d515536431b3a865468acbba0000000000000000000000000000000000000000000000000000000000000003
[INFO] Call Precompile:
	address: 0000000000000000000000000000000000000008
	context: PrecompileContext { call_type: Call, gas_limit: 8937393429371612, value: 0 }
	input: 1c76476f4def4bb94541d57ebba1193381ffa7aa76ada664dd31c16024c43f593034dd2920f673e204fee2811c678745fc819b55d3e9d294e45c9b03a76aef41209dd15ebff5d46c4bd888e51a93cf99a7329636c63514396b4a452003a35bf704bf11ca01483bfa8b34b43561848d28905960114c8ac04049af4b6315a416782bb8324af6cfc93537a2ad1a445cfd0ca2a71acd7ac41fadbf933c2a51be344d120a2a4cf30c1bf9845f20c6fe39e07ea2cce61f0c9bb048165fe5e4de877550111e129f1cf1097710d41c4ac70fcdfa5ba2023c6ff1cbeac322de49d1b6df7c2032c61a830e3c17286de9462bf242fca2883585b93870a73853face6a6bf411198e9393920d483a7260bfb731fb5d25f1aa493335a9e71297e485b7aef312c21800deef121f1e76426a00665e5c4479674322d4f75edadd46debd5cd992f6ed090689d0585ff075ec9e99ad690c3395bc4b313370b38ef355acdadcd122975b12c85ea5db8c6deb4aab71808dcb408fe3d1e7690c43d37b4ce6cc0166fa7daa
2023-01-24T10:53:09.256059Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1192453948,
    events_root: None,
}
2023-01-24T10:53:09.256093Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-24T10:53:09.256099Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CallWithZeroValueToPrecompileFromTransaction"::London::0
2023-01-24T10:53:09.256103Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stStaticFlagEnabled/CallWithZeroValueToPrecompileFromTransaction.json"
2023-01-24T10:53:09.256106Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-24T10:53:09.256108Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[INFO] Call Precompile:
	address: 0000000000000000000000000000000000000001
	context: PrecompileContext { call_type: Call, gas_limit: 8937393456959302, value: 0 }
	input: 18c547e4f7b0f325ad1e56f57e26c745b09a3e503d86e00e5255ff7f715d3d1c000000000000000000000000000000000000000000000000000000000000001c73b1693892219d736caba55bdb67216e485557ea6b6af75f37096c9aa6a5a75feeb940b1d03b21e36b0e47e79769f095fe2ab855bd91e3a38756b7d75a9c4549
[INFO] Call Precompile:
	address: 0000000000000000000000000000000000000002
	context: PrecompileContext { call_type: Call, gas_limit: 8937393454218226, value: 0 }
	input: 0000000ccccccccccccccccccccccccccccccccccccccccccccccccccc000000
[INFO] Call Precompile:
	address: 0000000000000000000000000000000000000003
	context: PrecompileContext { call_type: Call, gas_limit: 8937393454028831, value: 0 }
	input: 0000000ccccccccccccccccccccccccccccccccccccccccccccccccccc000000
[INFO] Call Precompile:
	address: 0000000000000000000000000000000000000004
	context: PrecompileContext { call_type: Call, gas_limit: 8937393453833954, value: 0 }
	input: 0000000ccccccccccccccccccccccccccccccccccccccccccccccccccc000000
[INFO] Call Precompile:
	address: 0000000000000000000000000000000000000005
	context: PrecompileContext { call_type: Call, gas_limit: 8937393443364972, value: 0 }
	input: 00000000000000000000000000000000000000000000000000000000000000010000000000000000000000000000000000000000000000000000000000000020000000000000000000000000000000000000000000000000000000000000002003fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2efffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f
[INFO] Call Precompile:
	address: 0000000000000000000000000000000000000006
	context: PrecompileContext { call_type: Call, gas_limit: 8937393431947325, value: 0 }
	input: 0f25929bcb43d5a57391564615c9e70a992b10eafa4db109709649cf48c50dd216da2f5cb6be7a0aa72c440c53c9bbdfec6c36c7d515536431b3a865468acbba1de49a4b0233273bba8146af82042d004f2085ec982397db0d97da17204cc2860217327ffc463919bef80cc166d09c6172639d8589799928761bcd9f22c903d4
[INFO] Call Precompile:
	address: 0000000000000000000000000000000000000007
	context: PrecompileContext { call_type: Call, gas_limit: 8937393430736870, value: 0 }
	input: 0f25929bcb43d5a57391564615c9e70a992b10eafa4db109709649cf48c50dd216da2f5cb6be7a0aa72c440c53c9bbdfec6c36c7d515536431b3a865468acbba0000000000000000000000000000000000000000000000000000000000000003
[INFO] Call Precompile:
	address: 0000000000000000000000000000000000000008
	context: PrecompileContext { call_type: Call, gas_limit: 8937393429371612, value: 0 }
	input: 1c76476f4def4bb94541d57ebba1193381ffa7aa76ada664dd31c16024c43f593034dd2920f673e204fee2811c678745fc819b55d3e9d294e45c9b03a76aef41209dd15ebff5d46c4bd888e51a93cf99a7329636c63514396b4a452003a35bf704bf11ca01483bfa8b34b43561848d28905960114c8ac04049af4b6315a416782bb8324af6cfc93537a2ad1a445cfd0ca2a71acd7ac41fadbf933c2a51be344d120a2a4cf30c1bf9845f20c6fe39e07ea2cce61f0c9bb048165fe5e4de877550111e129f1cf1097710d41c4ac70fcdfa5ba2023c6ff1cbeac322de49d1b6df7c2032c61a830e3c17286de9462bf242fca2883585b93870a73853face6a6bf411198e9393920d483a7260bfb731fb5d25f1aa493335a9e71297e485b7aef312c21800deef121f1e76426a00665e5c4479674322d4f75edadd46debd5cd992f6ed090689d0585ff075ec9e99ad690c3395bc4b313370b38ef355acdadcd122975b12c85ea5db8c6deb4aab71808dcb408fe3d1e7690c43d37b4ce6cc0166fa7daa
2023-01-24T10:53:09.290662Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1192453948,
    events_root: None,
}
2023-01-24T10:53:09.290698Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-24T10:53:09.290704Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CallWithZeroValueToPrecompileFromTransaction"::Merge::0
2023-01-24T10:53:09.290708Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stStaticFlagEnabled/CallWithZeroValueToPrecompileFromTransaction.json"
2023-01-24T10:53:09.290712Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-24T10:53:09.290713Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[INFO] Call Precompile:
	address: 0000000000000000000000000000000000000001
	context: PrecompileContext { call_type: Call, gas_limit: 8937393456959302, value: 0 }
	input: 18c547e4f7b0f325ad1e56f57e26c745b09a3e503d86e00e5255ff7f715d3d1c000000000000000000000000000000000000000000000000000000000000001c73b1693892219d736caba55bdb67216e485557ea6b6af75f37096c9aa6a5a75feeb940b1d03b21e36b0e47e79769f095fe2ab855bd91e3a38756b7d75a9c4549
[INFO] Call Precompile:
	address: 0000000000000000000000000000000000000002
	context: PrecompileContext { call_type: Call, gas_limit: 8937393454218226, value: 0 }
	input: 0000000ccccccccccccccccccccccccccccccccccccccccccccccccccc000000
[INFO] Call Precompile:
	address: 0000000000000000000000000000000000000003
	context: PrecompileContext { call_type: Call, gas_limit: 8937393454028831, value: 0 }
	input: 0000000ccccccccccccccccccccccccccccccccccccccccccccccccccc000000
[INFO] Call Precompile:
	address: 0000000000000000000000000000000000000004
	context: PrecompileContext { call_type: Call, gas_limit: 8937393453833954, value: 0 }
	input: 0000000ccccccccccccccccccccccccccccccccccccccccccccccccccc000000
[INFO] Call Precompile:
	address: 0000000000000000000000000000000000000005
	context: PrecompileContext { call_type: Call, gas_limit: 8937393443364972, value: 0 }
	input: 00000000000000000000000000000000000000000000000000000000000000010000000000000000000000000000000000000000000000000000000000000020000000000000000000000000000000000000000000000000000000000000002003fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2efffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f
[INFO] Call Precompile:
	address: 0000000000000000000000000000000000000006
	context: PrecompileContext { call_type: Call, gas_limit: 8937393431947325, value: 0 }
	input: 0f25929bcb43d5a57391564615c9e70a992b10eafa4db109709649cf48c50dd216da2f5cb6be7a0aa72c440c53c9bbdfec6c36c7d515536431b3a865468acbba1de49a4b0233273bba8146af82042d004f2085ec982397db0d97da17204cc2860217327ffc463919bef80cc166d09c6172639d8589799928761bcd9f22c903d4
[INFO] Call Precompile:
	address: 0000000000000000000000000000000000000007
	context: PrecompileContext { call_type: Call, gas_limit: 8937393430736870, value: 0 }
	input: 0f25929bcb43d5a57391564615c9e70a992b10eafa4db109709649cf48c50dd216da2f5cb6be7a0aa72c440c53c9bbdfec6c36c7d515536431b3a865468acbba0000000000000000000000000000000000000000000000000000000000000003
[INFO] Call Precompile:
	address: 0000000000000000000000000000000000000008
	context: PrecompileContext { call_type: Call, gas_limit: 8937393429371612, value: 0 }
	input: 1c76476f4def4bb94541d57ebba1193381ffa7aa76ada664dd31c16024c43f593034dd2920f673e204fee2811c678745fc819b55d3e9d294e45c9b03a76aef41209dd15ebff5d46c4bd888e51a93cf99a7329636c63514396b4a452003a35bf704bf11ca01483bfa8b34b43561848d28905960114c8ac04049af4b6315a416782bb8324af6cfc93537a2ad1a445cfd0ca2a71acd7ac41fadbf933c2a51be344d120a2a4cf30c1bf9845f20c6fe39e07ea2cce61f0c9bb048165fe5e4de877550111e129f1cf1097710d41c4ac70fcdfa5ba2023c6ff1cbeac322de49d1b6df7c2032c61a830e3c17286de9462bf242fca2883585b93870a73853face6a6bf411198e9393920d483a7260bfb731fb5d25f1aa493335a9e71297e485b7aef312c21800deef121f1e76426a00665e5c4479674322d4f75edadd46debd5cd992f6ed090689d0585ff075ec9e99ad690c3395bc4b313370b38ef355acdadcd122975b12c85ea5db8c6deb4aab71808dcb408fe3d1e7690c43d37b4ce6cc0166fa7daa
2023-01-24T10:53:09.324542Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1192453948,
    events_root: None,
}
2023-01-24T10:53:09.326039Z TRACE evm_eth_compliance::statetest::runner: TestDone => "test-vectors/tests/GeneralStateTests/stStaticFlagEnabled/CallWithZeroValueToPrecompileFromTransaction.json"
2023-01-24T10:53:09.326069Z TRACE evm_eth_compliance::statetest::runner: Calling testfile => "test-vectors/tests/GeneralStateTests/stStaticFlagEnabled/CallcodeToPrecompileFromCalledContract.json"
2023-01-24T10:53:09.351516Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-24T10:53:09.351630Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T10:53:09.351633Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-24T10:53:09.351693Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T10:53:09.351695Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 2
2023-01-24T10:53:09.351751Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T10:53:09.351753Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 3
2023-01-24T10:53:09.351803Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T10:53:09.351873Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-24T10:53:09.351878Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CallcodeToPrecompileFromCalledContract"::Istanbul::0
2023-01-24T10:53:09.351881Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stStaticFlagEnabled/CallcodeToPrecompileFromCalledContract.json"
2023-01-24T10:53:09.351885Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-24T10:53:09.351886Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T10:53:09.694640Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 13522878,
    events_root: None,
}
2023-01-24T10:53:09.694666Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-24T10:53:09.694673Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CallcodeToPrecompileFromCalledContract"::Berlin::0
2023-01-24T10:53:09.694676Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stStaticFlagEnabled/CallcodeToPrecompileFromCalledContract.json"
2023-01-24T10:53:09.694679Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-24T10:53:09.694680Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T10:53:09.695317Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 9171159,
    events_root: None,
}
2023-01-24T10:53:09.695330Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-24T10:53:09.695333Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CallcodeToPrecompileFromCalledContract"::London::0
2023-01-24T10:53:09.695335Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stStaticFlagEnabled/CallcodeToPrecompileFromCalledContract.json"
2023-01-24T10:53:09.695338Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-24T10:53:09.695339Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T10:53:09.695971Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 9171159,
    events_root: None,
}
2023-01-24T10:53:09.695985Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-24T10:53:09.695988Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CallcodeToPrecompileFromCalledContract"::Merge::0
2023-01-24T10:53:09.695991Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stStaticFlagEnabled/CallcodeToPrecompileFromCalledContract.json"
2023-01-24T10:53:09.695994Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-24T10:53:09.695996Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T10:53:09.696678Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 9171159,
    events_root: None,
}
2023-01-24T10:53:09.698235Z TRACE evm_eth_compliance::statetest::runner: TestDone => "test-vectors/tests/GeneralStateTests/stStaticFlagEnabled/CallcodeToPrecompileFromCalledContract.json"
2023-01-24T10:53:09.698267Z TRACE evm_eth_compliance::statetest::runner: Calling testfile => "test-vectors/tests/GeneralStateTests/stStaticFlagEnabled/CallcodeToPrecompileFromContractInitialization.json"
2023-01-24T10:53:09.725242Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-24T10:53:09.725374Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T10:53:09.725379Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-24T10:53:09.725437Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T10:53:09.725439Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 2
2023-01-24T10:53:09.725495Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T10:53:09.725575Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-24T10:53:09.725580Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CallcodeToPrecompileFromContractInitialization"::Istanbul::0
2023-01-24T10:53:09.725584Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stStaticFlagEnabled/CallcodeToPrecompileFromContractInitialization.json"
2023-01-24T10:53:09.725587Z  INFO evm_eth_compliance::statetest::runner: TX len : 487
2023-01-24T10:53:09.725588Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [178, 188, 66, 162, 211, 179, 79, 34, 139, 163, 153, 229, 58, 182, 241, 179, 210, 103, 33, 119, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([215, 166, 242, 208, 200, 186, 79, 10, 126, 8, 221, 102, 9, 12, 200, 158, 203, 19, 78, 227]) }
2023-01-24T10:53:10.345797Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 23474856,
    events_root: None,
}
2023-01-24T10:53:10.345831Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-24T10:53:10.345838Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CallcodeToPrecompileFromContractInitialization"::Berlin::0
2023-01-24T10:53:10.345841Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stStaticFlagEnabled/CallcodeToPrecompileFromContractInitialization.json"
2023-01-24T10:53:10.345844Z  INFO evm_eth_compliance::statetest::runner: TX len : 487
2023-01-24T10:53:10.345846Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T10:53:10.346232Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 6193473,
    events_root: None,
}
2023-01-24T10:53:10.346244Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-24T10:53:10.346247Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CallcodeToPrecompileFromContractInitialization"::London::0
2023-01-24T10:53:10.346249Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stStaticFlagEnabled/CallcodeToPrecompileFromContractInitialization.json"
2023-01-24T10:53:10.346252Z  INFO evm_eth_compliance::statetest::runner: TX len : 487
2023-01-24T10:53:10.346254Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T10:53:10.346539Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 4406834,
    events_root: None,
}
2023-01-24T10:53:10.346550Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-24T10:53:10.346553Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CallcodeToPrecompileFromContractInitialization"::Merge::0
2023-01-24T10:53:10.346556Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stStaticFlagEnabled/CallcodeToPrecompileFromContractInitialization.json"
2023-01-24T10:53:10.346559Z  INFO evm_eth_compliance::statetest::runner: TX len : 487
2023-01-24T10:53:10.346560Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T10:53:10.346837Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 4406834,
    events_root: None,
}
2023-01-24T10:53:10.348216Z TRACE evm_eth_compliance::statetest::runner: TestDone => "test-vectors/tests/GeneralStateTests/stStaticFlagEnabled/CallcodeToPrecompileFromContractInitialization.json"
2023-01-24T10:53:10.348243Z TRACE evm_eth_compliance::statetest::runner: Calling testfile => "test-vectors/tests/GeneralStateTests/stStaticFlagEnabled/CallcodeToPrecompileFromTransaction.json"
2023-01-24T10:53:10.373282Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-24T10:53:10.373392Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T10:53:10.373398Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-24T10:53:10.373450Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T10:53:10.373452Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 2
2023-01-24T10:53:10.373506Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T10:53:10.373575Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-24T10:53:10.373580Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CallcodeToPrecompileFromTransaction"::Istanbul::0
2023-01-24T10:53:10.373583Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stStaticFlagEnabled/CallcodeToPrecompileFromTransaction.json"
2023-01-24T10:53:10.373586Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-24T10:53:10.373588Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T10:53:10.733169Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 9400256,
    events_root: None,
}
2023-01-24T10:53:10.733194Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-24T10:53:10.733200Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CallcodeToPrecompileFromTransaction"::Berlin::0
2023-01-24T10:53:10.733203Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stStaticFlagEnabled/CallcodeToPrecompileFromTransaction.json"
2023-01-24T10:53:10.733206Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-24T10:53:10.733208Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T10:53:10.733751Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 7216458,
    events_root: None,
}
2023-01-24T10:53:10.733761Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-24T10:53:10.733764Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CallcodeToPrecompileFromTransaction"::London::0
2023-01-24T10:53:10.733766Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stStaticFlagEnabled/CallcodeToPrecompileFromTransaction.json"
2023-01-24T10:53:10.733769Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-24T10:53:10.733770Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T10:53:10.734288Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 7216458,
    events_root: None,
}
2023-01-24T10:53:10.734298Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-24T10:53:10.734301Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CallcodeToPrecompileFromTransaction"::Merge::0
2023-01-24T10:53:10.734303Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stStaticFlagEnabled/CallcodeToPrecompileFromTransaction.json"
2023-01-24T10:53:10.734306Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-24T10:53:10.734307Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T10:53:10.734826Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 7216458,
    events_root: None,
}
2023-01-24T10:53:10.736557Z TRACE evm_eth_compliance::statetest::runner: TestDone => "test-vectors/tests/GeneralStateTests/stStaticFlagEnabled/CallcodeToPrecompileFromTransaction.json"
2023-01-24T10:53:10.736583Z TRACE evm_eth_compliance::statetest::runner: Calling testfile => "test-vectors/tests/GeneralStateTests/stStaticFlagEnabled/DelegatecallToPrecompileFromCalledContract.json"
2023-01-24T10:53:10.762648Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-24T10:53:10.762764Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T10:53:10.762768Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-24T10:53:10.762822Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T10:53:10.762824Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 2
2023-01-24T10:53:10.762879Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T10:53:10.762881Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 3
2023-01-24T10:53:10.762939Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T10:53:10.763019Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-24T10:53:10.763025Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "DelegatecallToPrecompileFromCalledContract"::Istanbul::0
2023-01-24T10:53:10.763029Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stStaticFlagEnabled/DelegatecallToPrecompileFromCalledContract.json"
2023-01-24T10:53:10.763033Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-24T10:53:10.763035Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[INFO] Call Precompile:
	address: 0000000000000000000000000000000000000001
	context: PrecompileContext { call_type: DelegateCall, gas_limit: 8797746683388802, value: 0 }
	input: 18c547e4f7b0f325ad1e56f57e26c745b09a3e503d86e00e5255ff7f715d3d1c000000000000000000000000000000000000000000000000000000000000001c73b1693892219d736caba55bdb67216e485557ea6b6af75f37096c9aa6a5a75feeb940b1d03b21e36b0e47e79769f095fe2ab855bd91e3a38756b7d75a9c4549
[INFO] Call Precompile:
	address: 0000000000000000000000000000000000000002
	context: PrecompileContext { call_type: DelegateCall, gas_limit: 8797746680647867, value: 0 }
	input: 0000000ccccccccccccccccccccccccccccccccccccccccccccccccccc000000
[INFO] Call Precompile:
	address: 0000000000000000000000000000000000000003
	context: PrecompileContext { call_type: DelegateCall, gas_limit: 8797746680458613, value: 0 }
	input: 0000000ccccccccccccccccccccccccccccccccccccccccccccccccccc000000
[INFO] Call Precompile:
	address: 0000000000000000000000000000000000000004
	context: PrecompileContext { call_type: DelegateCall, gas_limit: 8797746680263879, value: 0 }
	input: 0000000ccccccccccccccccccccccccccccccccccccccccccccccccccc000000
[INFO] Call Precompile:
	address: 0000000000000000000000000000000000000005
	context: PrecompileContext { call_type: DelegateCall, gas_limit: 8797746669795039, value: 0 }
	input: 00000000000000000000000000000000000000000000000000000000000000010000000000000000000000000000000000000000000000000000000000000020000000000000000000000000000000000000000000000000000000000000002003fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2efffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f
[INFO] Call Precompile:
	address: 0000000000000000000000000000000000000006
	context: PrecompileContext { call_type: DelegateCall, gas_limit: 8797746658377534, value: 0 }
	input: 0f25929bcb43d5a57391564615c9e70a992b10eafa4db109709649cf48c50dd216da2f5cb6be7a0aa72c440c53c9bbdfec6c36c7d515536431b3a865468acbba1de49a4b0233273bba8146af82042d004f2085ec982397db0d97da17204cc2860217327ffc463919bef80cc166d09c6172639d8589799928761bcd9f22c903d4
[INFO] Call Precompile:
	address: 0000000000000000000000000000000000000007
	context: PrecompileContext { call_type: DelegateCall, gas_limit: 8797746657167221, value: 0 }
	input: 0f25929bcb43d5a57391564615c9e70a992b10eafa4db109709649cf48c50dd216da2f5cb6be7a0aa72c440c53c9bbdfec6c36c7d515536431b3a865468acbba0000000000000000000000000000000000000000000000000000000000000003
[INFO] Call Precompile:
	address: 0000000000000000000000000000000000000008
	context: PrecompileContext { call_type: DelegateCall, gas_limit: 8797746655802103, value: 0 }
	input: 1c76476f4def4bb94541d57ebba1193381ffa7aa76ada664dd31c16024c43f593034dd2920f673e204fee2811c678745fc819b55d3e9d294e45c9b03a76aef41209dd15ebff5d46c4bd888e51a93cf99a7329636c63514396b4a452003a35bf704bf11ca01483bfa8b34b43561848d28905960114c8ac04049af4b6315a416782bb8324af6cfc93537a2ad1a445cfd0ca2a71acd7ac41fadbf933c2a51be344d120a2a4cf30c1bf9845f20c6fe39e07ea2cce61f0c9bb048165fe5e4de877550111e129f1cf1097710d41c4ac70fcdfa5ba2023c6ff1cbeac322de49d1b6df7c2032c61a830e3c17286de9462bf242fca2883585b93870a73853face6a6bf411198e9393920d483a7260bfb731fb5d25f1aa493335a9e71297e485b7aef312c21800deef121f1e76426a00665e5c4479674322d4f75edadd46debd5cd992f6ed090689d0585ff075ec9e99ad690c3395bc4b313370b38ef355acdadcd122975b12c85ea5db8c6deb4aab71808dcb408fe3d1e7690c43d37b4ce6cc0166fa7daa
2023-01-24T10:53:11.173142Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1201474155,
    events_root: None,
}
2023-01-24T10:53:11.173176Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-24T10:53:11.173184Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "DelegatecallToPrecompileFromCalledContract"::Berlin::0
2023-01-24T10:53:11.173187Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stStaticFlagEnabled/DelegatecallToPrecompileFromCalledContract.json"
2023-01-24T10:53:11.173192Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-24T10:53:11.173195Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[INFO] Call Precompile:
	address: 0000000000000000000000000000000000000001
	context: PrecompileContext { call_type: DelegateCall, gas_limit: 8797746682470532, value: 0 }
	input: 18c547e4f7b0f325ad1e56f57e26c745b09a3e503d86e00e5255ff7f715d3d1c000000000000000000000000000000000000000000000000000000000000001c73b1693892219d736caba55bdb67216e485557ea6b6af75f37096c9aa6a5a75feeb940b1d03b21e36b0e47e79769f095fe2ab855bd91e3a38756b7d75a9c4549
[INFO] Call Precompile:
	address: 0000000000000000000000000000000000000002
	context: PrecompileContext { call_type: DelegateCall, gas_limit: 8797746679729597, value: 0 }
	input: 0000000ccccccccccccccccccccccccccccccccccccccccccccccccccc000000
[INFO] Call Precompile:
	address: 0000000000000000000000000000000000000003
	context: PrecompileContext { call_type: DelegateCall, gas_limit: 8797746679540343, value: 0 }
	input: 0000000ccccccccccccccccccccccccccccccccccccccccccccccccccc000000
[INFO] Call Precompile:
	address: 0000000000000000000000000000000000000004
	context: PrecompileContext { call_type: DelegateCall, gas_limit: 8797746679345609, value: 0 }
	input: 0000000ccccccccccccccccccccccccccccccccccccccccccccccccccc000000
[INFO] Call Precompile:
	address: 0000000000000000000000000000000000000005
	context: PrecompileContext { call_type: DelegateCall, gas_limit: 8797746668876769, value: 0 }
	input: 00000000000000000000000000000000000000000000000000000000000000010000000000000000000000000000000000000000000000000000000000000020000000000000000000000000000000000000000000000000000000000000002003fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2efffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f
[INFO] Call Precompile:
	address: 0000000000000000000000000000000000000006
	context: PrecompileContext { call_type: DelegateCall, gas_limit: 8797746657459263, value: 0 }
	input: 0f25929bcb43d5a57391564615c9e70a992b10eafa4db109709649cf48c50dd216da2f5cb6be7a0aa72c440c53c9bbdfec6c36c7d515536431b3a865468acbba1de49a4b0233273bba8146af82042d004f2085ec982397db0d97da17204cc2860217327ffc463919bef80cc166d09c6172639d8589799928761bcd9f22c903d4
[INFO] Call Precompile:
	address: 0000000000000000000000000000000000000007
	context: PrecompileContext { call_type: DelegateCall, gas_limit: 8797746656248951, value: 0 }
	input: 0f25929bcb43d5a57391564615c9e70a992b10eafa4db109709649cf48c50dd216da2f5cb6be7a0aa72c440c53c9bbdfec6c36c7d515536431b3a865468acbba0000000000000000000000000000000000000000000000000000000000000003
[INFO] Call Precompile:
	address: 0000000000000000000000000000000000000008
	context: PrecompileContext { call_type: DelegateCall, gas_limit: 8797746654883833, value: 0 }
	input: 1c76476f4def4bb94541d57ebba1193381ffa7aa76ada664dd31c16024c43f593034dd2920f673e204fee2811c678745fc819b55d3e9d294e45c9b03a76aef41209dd15ebff5d46c4bd888e51a93cf99a7329636c63514396b4a452003a35bf704bf11ca01483bfa8b34b43561848d28905960114c8ac04049af4b6315a416782bb8324af6cfc93537a2ad1a445cfd0ca2a71acd7ac41fadbf933c2a51be344d120a2a4cf30c1bf9845f20c6fe39e07ea2cce61f0c9bb048165fe5e4de877550111e129f1cf1097710d41c4ac70fcdfa5ba2023c6ff1cbeac322de49d1b6df7c2032c61a830e3c17286de9462bf242fca2883585b93870a73853face6a6bf411198e9393920d483a7260bfb731fb5d25f1aa493335a9e71297e485b7aef312c21800deef121f1e76426a00665e5c4479674322d4f75edadd46debd5cd992f6ed090689d0585ff075ec9e99ad690c3395bc4b313370b38ef355acdadcd122975b12c85ea5db8c6deb4aab71808dcb408fe3d1e7690c43d37b4ce6cc0166fa7daa
2023-01-24T10:53:11.207775Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1194408162,
    events_root: None,
}
2023-01-24T10:53:11.207809Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-24T10:53:11.207816Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "DelegatecallToPrecompileFromCalledContract"::London::0
2023-01-24T10:53:11.207819Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stStaticFlagEnabled/DelegatecallToPrecompileFromCalledContract.json"
2023-01-24T10:53:11.207824Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-24T10:53:11.207826Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[INFO] Call Precompile:
	address: 0000000000000000000000000000000000000001
	context: PrecompileContext { call_type: DelegateCall, gas_limit: 8797746682470532, value: 0 }
	input: 18c547e4f7b0f325ad1e56f57e26c745b09a3e503d86e00e5255ff7f715d3d1c000000000000000000000000000000000000000000000000000000000000001c73b1693892219d736caba55bdb67216e485557ea6b6af75f37096c9aa6a5a75feeb940b1d03b21e36b0e47e79769f095fe2ab855bd91e3a38756b7d75a9c4549
[INFO] Call Precompile:
	address: 0000000000000000000000000000000000000002
	context: PrecompileContext { call_type: DelegateCall, gas_limit: 8797746679729597, value: 0 }
	input: 0000000ccccccccccccccccccccccccccccccccccccccccccccccccccc000000
[INFO] Call Precompile:
	address: 0000000000000000000000000000000000000003
	context: PrecompileContext { call_type: DelegateCall, gas_limit: 8797746679540343, value: 0 }
	input: 0000000ccccccccccccccccccccccccccccccccccccccccccccccccccc000000
[INFO] Call Precompile:
	address: 0000000000000000000000000000000000000004
	context: PrecompileContext { call_type: DelegateCall, gas_limit: 8797746679345609, value: 0 }
	input: 0000000ccccccccccccccccccccccccccccccccccccccccccccccccccc000000
[INFO] Call Precompile:
	address: 0000000000000000000000000000000000000005
	context: PrecompileContext { call_type: DelegateCall, gas_limit: 8797746668876769, value: 0 }
	input: 00000000000000000000000000000000000000000000000000000000000000010000000000000000000000000000000000000000000000000000000000000020000000000000000000000000000000000000000000000000000000000000002003fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2efffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f
[INFO] Call Precompile:
	address: 0000000000000000000000000000000000000006
	context: PrecompileContext { call_type: DelegateCall, gas_limit: 8797746657459263, value: 0 }
	input: 0f25929bcb43d5a57391564615c9e70a992b10eafa4db109709649cf48c50dd216da2f5cb6be7a0aa72c440c53c9bbdfec6c36c7d515536431b3a865468acbba1de49a4b0233273bba8146af82042d004f2085ec982397db0d97da17204cc2860217327ffc463919bef80cc166d09c6172639d8589799928761bcd9f22c903d4
[INFO] Call Precompile:
	address: 0000000000000000000000000000000000000007
	context: PrecompileContext { call_type: DelegateCall, gas_limit: 8797746656248951, value: 0 }
	input: 0f25929bcb43d5a57391564615c9e70a992b10eafa4db109709649cf48c50dd216da2f5cb6be7a0aa72c440c53c9bbdfec6c36c7d515536431b3a865468acbba0000000000000000000000000000000000000000000000000000000000000003
[INFO] Call Precompile:
	address: 0000000000000000000000000000000000000008
	context: PrecompileContext { call_type: DelegateCall, gas_limit: 8797746654883833, value: 0 }
	input: 1c76476f4def4bb94541d57ebba1193381ffa7aa76ada664dd31c16024c43f593034dd2920f673e204fee2811c678745fc819b55d3e9d294e45c9b03a76aef41209dd15ebff5d46c4bd888e51a93cf99a7329636c63514396b4a452003a35bf704bf11ca01483bfa8b34b43561848d28905960114c8ac04049af4b6315a416782bb8324af6cfc93537a2ad1a445cfd0ca2a71acd7ac41fadbf933c2a51be344d120a2a4cf30c1bf9845f20c6fe39e07ea2cce61f0c9bb048165fe5e4de877550111e129f1cf1097710d41c4ac70fcdfa5ba2023c6ff1cbeac322de49d1b6df7c2032c61a830e3c17286de9462bf242fca2883585b93870a73853face6a6bf411198e9393920d483a7260bfb731fb5d25f1aa493335a9e71297e485b7aef312c21800deef121f1e76426a00665e5c4479674322d4f75edadd46debd5cd992f6ed090689d0585ff075ec9e99ad690c3395bc4b313370b38ef355acdadcd122975b12c85ea5db8c6deb4aab71808dcb408fe3d1e7690c43d37b4ce6cc0166fa7daa
2023-01-24T10:53:11.242350Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1194408162,
    events_root: None,
}
2023-01-24T10:53:11.242379Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-24T10:53:11.242384Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "DelegatecallToPrecompileFromCalledContract"::Merge::0
2023-01-24T10:53:11.242388Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stStaticFlagEnabled/DelegatecallToPrecompileFromCalledContract.json"
2023-01-24T10:53:11.242392Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-24T10:53:11.242394Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[INFO] Call Precompile:
	address: 0000000000000000000000000000000000000001
	context: PrecompileContext { call_type: DelegateCall, gas_limit: 8797746682470532, value: 0 }
	input: 18c547e4f7b0f325ad1e56f57e26c745b09a3e503d86e00e5255ff7f715d3d1c000000000000000000000000000000000000000000000000000000000000001c73b1693892219d736caba55bdb67216e485557ea6b6af75f37096c9aa6a5a75feeb940b1d03b21e36b0e47e79769f095fe2ab855bd91e3a38756b7d75a9c4549
[INFO] Call Precompile:
	address: 0000000000000000000000000000000000000002
	context: PrecompileContext { call_type: DelegateCall, gas_limit: 8797746679729597, value: 0 }
	input: 0000000ccccccccccccccccccccccccccccccccccccccccccccccccccc000000
[INFO] Call Precompile:
	address: 0000000000000000000000000000000000000003
	context: PrecompileContext { call_type: DelegateCall, gas_limit: 8797746679540343, value: 0 }
	input: 0000000ccccccccccccccccccccccccccccccccccccccccccccccccccc000000
[INFO] Call Precompile:
	address: 0000000000000000000000000000000000000004
	context: PrecompileContext { call_type: DelegateCall, gas_limit: 8797746679345609, value: 0 }
	input: 0000000ccccccccccccccccccccccccccccccccccccccccccccccccccc000000
[INFO] Call Precompile:
	address: 0000000000000000000000000000000000000005
	context: PrecompileContext { call_type: DelegateCall, gas_limit: 8797746668876769, value: 0 }
	input: 00000000000000000000000000000000000000000000000000000000000000010000000000000000000000000000000000000000000000000000000000000020000000000000000000000000000000000000000000000000000000000000002003fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2efffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f
[INFO] Call Precompile:
	address: 0000000000000000000000000000000000000006
	context: PrecompileContext { call_type: DelegateCall, gas_limit: 8797746657459263, value: 0 }
	input: 0f25929bcb43d5a57391564615c9e70a992b10eafa4db109709649cf48c50dd216da2f5cb6be7a0aa72c440c53c9bbdfec6c36c7d515536431b3a865468acbba1de49a4b0233273bba8146af82042d004f2085ec982397db0d97da17204cc2860217327ffc463919bef80cc166d09c6172639d8589799928761bcd9f22c903d4
[INFO] Call Precompile:
	address: 0000000000000000000000000000000000000007
	context: PrecompileContext { call_type: DelegateCall, gas_limit: 8797746656248951, value: 0 }
	input: 0f25929bcb43d5a57391564615c9e70a992b10eafa4db109709649cf48c50dd216da2f5cb6be7a0aa72c440c53c9bbdfec6c36c7d515536431b3a865468acbba0000000000000000000000000000000000000000000000000000000000000003
[INFO] Call Precompile:
	address: 0000000000000000000000000000000000000008
	context: PrecompileContext { call_type: DelegateCall, gas_limit: 8797746654883833, value: 0 }
	input: 1c76476f4def4bb94541d57ebba1193381ffa7aa76ada664dd31c16024c43f593034dd2920f673e204fee2811c678745fc819b55d3e9d294e45c9b03a76aef41209dd15ebff5d46c4bd888e51a93cf99a7329636c63514396b4a452003a35bf704bf11ca01483bfa8b34b43561848d28905960114c8ac04049af4b6315a416782bb8324af6cfc93537a2ad1a445cfd0ca2a71acd7ac41fadbf933c2a51be344d120a2a4cf30c1bf9845f20c6fe39e07ea2cce61f0c9bb048165fe5e4de877550111e129f1cf1097710d41c4ac70fcdfa5ba2023c6ff1cbeac322de49d1b6df7c2032c61a830e3c17286de9462bf242fca2883585b93870a73853face6a6bf411198e9393920d483a7260bfb731fb5d25f1aa493335a9e71297e485b7aef312c21800deef121f1e76426a00665e5c4479674322d4f75edadd46debd5cd992f6ed090689d0585ff075ec9e99ad690c3395bc4b313370b38ef355acdadcd122975b12c85ea5db8c6deb4aab71808dcb408fe3d1e7690c43d37b4ce6cc0166fa7daa
2023-01-24T10:53:11.277752Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1194408162,
    events_root: None,
}
2023-01-24T10:53:11.279356Z TRACE evm_eth_compliance::statetest::runner: TestDone => "test-vectors/tests/GeneralStateTests/stStaticFlagEnabled/DelegatecallToPrecompileFromCalledContract.json"
2023-01-24T10:53:11.279383Z TRACE evm_eth_compliance::statetest::runner: Calling testfile => "test-vectors/tests/GeneralStateTests/stStaticFlagEnabled/DelegatecallToPrecompileFromContractInitialization.json"
2023-01-24T10:53:11.304833Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-24T10:53:11.304951Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T10:53:11.304955Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-24T10:53:11.305017Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T10:53:11.305020Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 2
2023-01-24T10:53:11.305078Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T10:53:11.305157Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-24T10:53:11.305163Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "DelegatecallToPrecompileFromContractInitialization"::Istanbul::0
2023-01-24T10:53:11.305167Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stStaticFlagEnabled/DelegatecallToPrecompileFromContractInitialization.json"
2023-01-24T10:53:11.305172Z  INFO evm_eth_compliance::statetest::runner: TX len : 298
2023-01-24T10:53:11.305174Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [253, 119, 118, 177, 166, 52, 176, 220, 25, 48, 27, 23, 76, 207, 48, 212, 210, 64, 112, 168, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([215, 166, 242, 208, 200, 186, 79, 10, 126, 8, 221, 102, 9, 12, 200, 158, 203, 19, 78, 227]) }
[INFO] Call Precompile:
	address: 0000000000000000000000000000000000000001
	context: PrecompileContext { call_type: DelegateCall, gas_limit: 8937393447116664, value: 0 }
	input: 18c547e4f7b0f325ad1e56f57e26c745b09a3e503d86e00e5255ff7f715d3d1c000000000000000000000000000000000000000000000000000000000000001c73b1693892219d736caba55bdb67216e485557ea6b6af75f37096c9aa6a5a75feeb940b1d03b21e36b0e47e79769f095fe2ab855bd91e3a38756b7d75a9c4549
[INFO] Call Precompile:
	address: 0000000000000000000000000000000000000002
	context: PrecompileContext { call_type: DelegateCall, gas_limit: 8937393444375729, value: 0 }
	input: 0000000ccccccccccccccccccccccccccccccccccccccccccccccccccc000000
[INFO] Call Precompile:
	address: 0000000000000000000000000000000000000003
	context: PrecompileContext { call_type: DelegateCall, gas_limit: 8937393444186475, value: 0 }
	input: 0000000ccccccccccccccccccccccccccccccccccccccccccccccccccc000000
[INFO] Call Precompile:
	address: 0000000000000000000000000000000000000004
	context: PrecompileContext { call_type: DelegateCall, gas_limit: 8937393443991741, value: 0 }
	input: 0000000ccccccccccccccccccccccccccccccccccccccccccccccccccc000000
[INFO] Call Precompile:
	address: 0000000000000000000000000000000000000005
	context: PrecompileContext { call_type: DelegateCall, gas_limit: 8937393433522901, value: 0 }
	input: 00000000000000000000000000000000000000000000000000000000000000010000000000000000000000000000000000000000000000000000000000000020000000000000000000000000000000000000000000000000000000000000002003fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2efffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f
[INFO] Call Precompile:
	address: 0000000000000000000000000000000000000006
	context: PrecompileContext { call_type: DelegateCall, gas_limit: 8937393422105395, value: 0 }
	input: 0f25929bcb43d5a57391564615c9e70a992b10eafa4db109709649cf48c50dd216da2f5cb6be7a0aa72c440c53c9bbdfec6c36c7d515536431b3a865468acbba1de49a4b0233273bba8146af82042d004f2085ec982397db0d97da17204cc2860217327ffc463919bef80cc166d09c6172639d8589799928761bcd9f22c903d4
[INFO] Call Precompile:
	address: 0000000000000000000000000000000000000007
	context: PrecompileContext { call_type: DelegateCall, gas_limit: 8937393420895082, value: 0 }
	input: 0f25929bcb43d5a57391564615c9e70a992b10eafa4db109709649cf48c50dd216da2f5cb6be7a0aa72c440c53c9bbdfec6c36c7d515536431b3a865468acbba0000000000000000000000000000000000000000000000000000000000000003
[INFO] Call Precompile:
	address: 0000000000000000000000000000000000000008
	context: PrecompileContext { call_type: DelegateCall, gas_limit: 8937393419529965, value: 0 }
	input: 1c76476f4def4bb94541d57ebba1193381ffa7aa76ada664dd31c16024c43f593034dd2920f673e204fee2811c678745fc819b55d3e9d294e45c9b03a76aef41209dd15ebff5d46c4bd888e51a93cf99a7329636c63514396b4a452003a35bf704bf11ca01483bfa8b34b43561848d28905960114c8ac04049af4b6315a416782bb8324af6cfc93537a2ad1a445cfd0ca2a71acd7ac41fadbf933c2a51be344d120a2a4cf30c1bf9845f20c6fe39e07ea2cce61f0c9bb048165fe5e4de877550111e129f1cf1097710d41c4ac70fcdfa5ba2023c6ff1cbeac322de49d1b6df7c2032c61a830e3c17286de9462bf242fca2883585b93870a73853face6a6bf411198e9393920d483a7260bfb731fb5d25f1aa493335a9e71297e485b7aef312c21800deef121f1e76426a00665e5c4479674322d4f75edadd46debd5cd992f6ed090689d0585ff075ec9e99ad690c3395bc4b313370b38ef355acdadcd122975b12c85ea5db8c6deb4aab71808dcb408fe3d1e7690c43d37b4ce6cc0166fa7daa
2023-01-24T10:53:11.956992Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1211251421,
    events_root: None,
}
2023-01-24T10:53:11.957032Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-24T10:53:11.957038Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "DelegatecallToPrecompileFromContractInitialization"::Berlin::0
2023-01-24T10:53:11.957041Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stStaticFlagEnabled/DelegatecallToPrecompileFromContractInitialization.json"
2023-01-24T10:53:11.957044Z  INFO evm_eth_compliance::statetest::runner: TX len : 298
2023-01-24T10:53:11.957046Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T10:53:11.957436Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 6181156,
    events_root: None,
}
2023-01-24T10:53:11.957448Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-24T10:53:11.957450Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "DelegatecallToPrecompileFromContractInitialization"::London::0
2023-01-24T10:53:11.957453Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stStaticFlagEnabled/DelegatecallToPrecompileFromContractInitialization.json"
2023-01-24T10:53:11.957456Z  INFO evm_eth_compliance::statetest::runner: TX len : 298
2023-01-24T10:53:11.957457Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T10:53:11.957735Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 4394525,
    events_root: None,
}
2023-01-24T10:53:11.957746Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-24T10:53:11.957748Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "DelegatecallToPrecompileFromContractInitialization"::Merge::0
2023-01-24T10:53:11.957751Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stStaticFlagEnabled/DelegatecallToPrecompileFromContractInitialization.json"
2023-01-24T10:53:11.957754Z  INFO evm_eth_compliance::statetest::runner: TX len : 298
2023-01-24T10:53:11.957756Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T10:53:11.958028Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 4394525,
    events_root: None,
}
2023-01-24T10:53:11.960270Z TRACE evm_eth_compliance::statetest::runner: TestDone => "test-vectors/tests/GeneralStateTests/stStaticFlagEnabled/DelegatecallToPrecompileFromContractInitialization.json"
2023-01-24T10:53:11.960295Z TRACE evm_eth_compliance::statetest::runner: Calling testfile => "test-vectors/tests/GeneralStateTests/stStaticFlagEnabled/DelegatecallToPrecompileFromTransaction.json"
2023-01-24T10:53:11.985609Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-24T10:53:11.985718Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T10:53:11.985722Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-24T10:53:11.985776Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T10:53:11.985778Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 2
2023-01-24T10:53:11.985832Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T10:53:11.985902Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-24T10:53:11.985906Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "DelegatecallToPrecompileFromTransaction"::Istanbul::0
2023-01-24T10:53:11.985910Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stStaticFlagEnabled/DelegatecallToPrecompileFromTransaction.json"
2023-01-24T10:53:11.985913Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-24T10:53:11.985915Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[INFO] Call Precompile:
	address: 0000000000000000000000000000000000000001
	context: PrecompileContext { call_type: DelegateCall, gas_limit: 8937393457547070, value: 0 }
	input: 18c547e4f7b0f325ad1e56f57e26c745b09a3e503d86e00e5255ff7f715d3d1c000000000000000000000000000000000000000000000000000000000000001c73b1693892219d736caba55bdb67216e485557ea6b6af75f37096c9aa6a5a75feeb940b1d03b21e36b0e47e79769f095fe2ab855bd91e3a38756b7d75a9c4549
[INFO] Call Precompile:
	address: 0000000000000000000000000000000000000002
	context: PrecompileContext { call_type: DelegateCall, gas_limit: 8937393454806135, value: 0 }
	input: 0000000ccccccccccccccccccccccccccccccccccccccccccccccccccc000000
[INFO] Call Precompile:
	address: 0000000000000000000000000000000000000003
	context: PrecompileContext { call_type: DelegateCall, gas_limit: 8937393454616881, value: 0 }
	input: 0000000ccccccccccccccccccccccccccccccccccccccccccccccccccc000000
[INFO] Call Precompile:
	address: 0000000000000000000000000000000000000004
	context: PrecompileContext { call_type: DelegateCall, gas_limit: 8937393454422147, value: 0 }
	input: 0000000ccccccccccccccccccccccccccccccccccccccccccccccccccc000000
[INFO] Call Precompile:
	address: 0000000000000000000000000000000000000005
	context: PrecompileContext { call_type: DelegateCall, gas_limit: 8937393443953307, value: 0 }
	input: 00000000000000000000000000000000000000000000000000000000000000010000000000000000000000000000000000000000000000000000000000000020000000000000000000000000000000000000000000000000000000000000002003fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2efffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f
[INFO] Call Precompile:
	address: 0000000000000000000000000000000000000006
	context: PrecompileContext { call_type: DelegateCall, gas_limit: 8937393432535801, value: 0 }
	input: 0f25929bcb43d5a57391564615c9e70a992b10eafa4db109709649cf48c50dd216da2f5cb6be7a0aa72c440c53c9bbdfec6c36c7d515536431b3a865468acbba1de49a4b0233273bba8146af82042d004f2085ec982397db0d97da17204cc2860217327ffc463919bef80cc166d09c6172639d8589799928761bcd9f22c903d4
[INFO] Call Precompile:
	address: 0000000000000000000000000000000000000007
	context: PrecompileContext { call_type: DelegateCall, gas_limit: 8937393431325488, value: 0 }
	input: 0f25929bcb43d5a57391564615c9e70a992b10eafa4db109709649cf48c50dd216da2f5cb6be7a0aa72c440c53c9bbdfec6c36c7d515536431b3a865468acbba0000000000000000000000000000000000000000000000000000000000000003
[INFO] Call Precompile:
	address: 0000000000000000000000000000000000000008
	context: PrecompileContext { call_type: DelegateCall, gas_limit: 8937393429960371, value: 0 }
	input: 1c76476f4def4bb94541d57ebba1193381ffa7aa76ada664dd31c16024c43f593034dd2920f673e204fee2811c678745fc819b55d3e9d294e45c9b03a76aef41209dd15ebff5d46c4bd888e51a93cf99a7329636c63514396b4a452003a35bf704bf11ca01483bfa8b34b43561848d28905960114c8ac04049af4b6315a416782bb8324af6cfc93537a2ad1a445cfd0ca2a71acd7ac41fadbf933c2a51be344d120a2a4cf30c1bf9845f20c6fe39e07ea2cce61f0c9bb048165fe5e4de877550111e129f1cf1097710d41c4ac70fcdfa5ba2023c6ff1cbeac322de49d1b6df7c2032c61a830e3c17286de9462bf242fca2883585b93870a73853face6a6bf411198e9393920d483a7260bfb731fb5d25f1aa493335a9e71297e485b7aef312c21800deef121f1e76426a00665e5c4479674322d4f75edadd46debd5cd992f6ed090689d0585ff075ec9e99ad690c3395bc4b313370b38ef355acdadcd122975b12c85ea5db8c6deb4aab71808dcb408fe3d1e7690c43d37b4ce6cc0166fa7daa
2023-01-24T10:53:12.373186Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1197356973,
    events_root: None,
}
2023-01-24T10:53:12.373228Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-24T10:53:12.373235Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "DelegatecallToPrecompileFromTransaction"::Berlin::0
2023-01-24T10:53:12.373238Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stStaticFlagEnabled/DelegatecallToPrecompileFromTransaction.json"
2023-01-24T10:53:12.373242Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-24T10:53:12.373243Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[INFO] Call Precompile:
	address: 0000000000000000000000000000000000000001
	context: PrecompileContext { call_type: DelegateCall, gas_limit: 8937393456961435, value: 0 }
	input: 18c547e4f7b0f325ad1e56f57e26c745b09a3e503d86e00e5255ff7f715d3d1c000000000000000000000000000000000000000000000000000000000000001c73b1693892219d736caba55bdb67216e485557ea6b6af75f37096c9aa6a5a75feeb940b1d03b21e36b0e47e79769f095fe2ab855bd91e3a38756b7d75a9c4549
[INFO] Call Precompile:
	address: 0000000000000000000000000000000000000002
	context: PrecompileContext { call_type: DelegateCall, gas_limit: 8937393454220500, value: 0 }
	input: 0000000ccccccccccccccccccccccccccccccccccccccccccccccccccc000000
[INFO] Call Precompile:
	address: 0000000000000000000000000000000000000003
	context: PrecompileContext { call_type: DelegateCall, gas_limit: 8937393454031246, value: 0 }
	input: 0000000ccccccccccccccccccccccccccccccccccccccccccccccccccc000000
[INFO] Call Precompile:
	address: 0000000000000000000000000000000000000004
	context: PrecompileContext { call_type: DelegateCall, gas_limit: 8937393453836512, value: 0 }
	input: 0000000ccccccccccccccccccccccccccccccccccccccccccccccccccc000000
[INFO] Call Precompile:
	address: 0000000000000000000000000000000000000005
	context: PrecompileContext { call_type: DelegateCall, gas_limit: 8937393443367672, value: 0 }
	input: 00000000000000000000000000000000000000000000000000000000000000010000000000000000000000000000000000000000000000000000000000000020000000000000000000000000000000000000000000000000000000000000002003fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2efffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f
[INFO] Call Precompile:
	address: 0000000000000000000000000000000000000006
	context: PrecompileContext { call_type: DelegateCall, gas_limit: 8937393431950167, value: 0 }
	input: 0f25929bcb43d5a57391564615c9e70a992b10eafa4db109709649cf48c50dd216da2f5cb6be7a0aa72c440c53c9bbdfec6c36c7d515536431b3a865468acbba1de49a4b0233273bba8146af82042d004f2085ec982397db0d97da17204cc2860217327ffc463919bef80cc166d09c6172639d8589799928761bcd9f22c903d4
[INFO] Call Precompile:
	address: 0000000000000000000000000000000000000007
	context: PrecompileContext { call_type: DelegateCall, gas_limit: 8937393430739854, value: 0 }
	input: 0f25929bcb43d5a57391564615c9e70a992b10eafa4db109709649cf48c50dd216da2f5cb6be7a0aa72c440c53c9bbdfec6c36c7d515536431b3a865468acbba0000000000000000000000000000000000000000000000000000000000000003
[INFO] Call Precompile:
	address: 0000000000000000000000000000000000000008
	context: PrecompileContext { call_type: DelegateCall, gas_limit: 8937393429374737, value: 0 }
	input: 1c76476f4def4bb94541d57ebba1193381ffa7aa76ada664dd31c16024c43f593034dd2920f673e204fee2811c678745fc819b55d3e9d294e45c9b03a76aef41209dd15ebff5d46c4bd888e51a93cf99a7329636c63514396b4a452003a35bf704bf11ca01483bfa8b34b43561848d28905960114c8ac04049af4b6315a416782bb8324af6cfc93537a2ad1a445cfd0ca2a71acd7ac41fadbf933c2a51be344d120a2a4cf30c1bf9845f20c6fe39e07ea2cce61f0c9bb048165fe5e4de877550111e129f1cf1097710d41c4ac70fcdfa5ba2023c6ff1cbeac322de49d1b6df7c2032c61a830e3c17286de9462bf242fca2883585b93870a73853face6a6bf411198e9393920d483a7260bfb731fb5d25f1aa493335a9e71297e485b7aef312c21800deef121f1e76426a00665e5c4479674322d4f75edadd46debd5cd992f6ed090689d0585ff075ec9e99ad690c3395bc4b313370b38ef355acdadcd122975b12c85ea5db8c6deb4aab71808dcb408fe3d1e7690c43d37b4ce6cc0166fa7daa
2023-01-24T10:53:12.408008Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1192451253,
    events_root: None,
}
2023-01-24T10:53:12.408045Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-24T10:53:12.408051Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "DelegatecallToPrecompileFromTransaction"::London::0
2023-01-24T10:53:12.408054Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stStaticFlagEnabled/DelegatecallToPrecompileFromTransaction.json"
2023-01-24T10:53:12.408058Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-24T10:53:12.408059Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[INFO] Call Precompile:
	address: 0000000000000000000000000000000000000001
	context: PrecompileContext { call_type: DelegateCall, gas_limit: 8937393456961435, value: 0 }
	input: 18c547e4f7b0f325ad1e56f57e26c745b09a3e503d86e00e5255ff7f715d3d1c000000000000000000000000000000000000000000000000000000000000001c73b1693892219d736caba55bdb67216e485557ea6b6af75f37096c9aa6a5a75feeb940b1d03b21e36b0e47e79769f095fe2ab855bd91e3a38756b7d75a9c4549
[INFO] Call Precompile:
	address: 0000000000000000000000000000000000000002
	context: PrecompileContext { call_type: DelegateCall, gas_limit: 8937393454220500, value: 0 }
	input: 0000000ccccccccccccccccccccccccccccccccccccccccccccccccccc000000
[INFO] Call Precompile:
	address: 0000000000000000000000000000000000000003
	context: PrecompileContext { call_type: DelegateCall, gas_limit: 8937393454031246, value: 0 }
	input: 0000000ccccccccccccccccccccccccccccccccccccccccccccccccccc000000
[INFO] Call Precompile:
	address: 0000000000000000000000000000000000000004
	context: PrecompileContext { call_type: DelegateCall, gas_limit: 8937393453836512, value: 0 }
	input: 0000000ccccccccccccccccccccccccccccccccccccccccccccccccccc000000
[INFO] Call Precompile:
	address: 0000000000000000000000000000000000000005
	context: PrecompileContext { call_type: DelegateCall, gas_limit: 8937393443367672, value: 0 }
	input: 00000000000000000000000000000000000000000000000000000000000000010000000000000000000000000000000000000000000000000000000000000020000000000000000000000000000000000000000000000000000000000000002003fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2efffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f
[INFO] Call Precompile:
	address: 0000000000000000000000000000000000000006
	context: PrecompileContext { call_type: DelegateCall, gas_limit: 8937393431950167, value: 0 }
	input: 0f25929bcb43d5a57391564615c9e70a992b10eafa4db109709649cf48c50dd216da2f5cb6be7a0aa72c440c53c9bbdfec6c36c7d515536431b3a865468acbba1de49a4b0233273bba8146af82042d004f2085ec982397db0d97da17204cc2860217327ffc463919bef80cc166d09c6172639d8589799928761bcd9f22c903d4
[INFO] Call Precompile:
	address: 0000000000000000000000000000000000000007
	context: PrecompileContext { call_type: DelegateCall, gas_limit: 8937393430739854, value: 0 }
	input: 0f25929bcb43d5a57391564615c9e70a992b10eafa4db109709649cf48c50dd216da2f5cb6be7a0aa72c440c53c9bbdfec6c36c7d515536431b3a865468acbba0000000000000000000000000000000000000000000000000000000000000003
[INFO] Call Precompile:
	address: 0000000000000000000000000000000000000008
	context: PrecompileContext { call_type: DelegateCall, gas_limit: 8937393429374737, value: 0 }
	input: 1c76476f4def4bb94541d57ebba1193381ffa7aa76ada664dd31c16024c43f593034dd2920f673e204fee2811c678745fc819b55d3e9d294e45c9b03a76aef41209dd15ebff5d46c4bd888e51a93cf99a7329636c63514396b4a452003a35bf704bf11ca01483bfa8b34b43561848d28905960114c8ac04049af4b6315a416782bb8324af6cfc93537a2ad1a445cfd0ca2a71acd7ac41fadbf933c2a51be344d120a2a4cf30c1bf9845f20c6fe39e07ea2cce61f0c9bb048165fe5e4de877550111e129f1cf1097710d41c4ac70fcdfa5ba2023c6ff1cbeac322de49d1b6df7c2032c61a830e3c17286de9462bf242fca2883585b93870a73853face6a6bf411198e9393920d483a7260bfb731fb5d25f1aa493335a9e71297e485b7aef312c21800deef121f1e76426a00665e5c4479674322d4f75edadd46debd5cd992f6ed090689d0585ff075ec9e99ad690c3395bc4b313370b38ef355acdadcd122975b12c85ea5db8c6deb4aab71808dcb408fe3d1e7690c43d37b4ce6cc0166fa7daa
2023-01-24T10:53:12.443043Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1192451253,
    events_root: None,
}
2023-01-24T10:53:12.443082Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-24T10:53:12.443087Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "DelegatecallToPrecompileFromTransaction"::Merge::0
2023-01-24T10:53:12.443091Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stStaticFlagEnabled/DelegatecallToPrecompileFromTransaction.json"
2023-01-24T10:53:12.443095Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-24T10:53:12.443097Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[INFO] Call Precompile:
	address: 0000000000000000000000000000000000000001
	context: PrecompileContext { call_type: DelegateCall, gas_limit: 8937393456961435, value: 0 }
	input: 18c547e4f7b0f325ad1e56f57e26c745b09a3e503d86e00e5255ff7f715d3d1c000000000000000000000000000000000000000000000000000000000000001c73b1693892219d736caba55bdb67216e485557ea6b6af75f37096c9aa6a5a75feeb940b1d03b21e36b0e47e79769f095fe2ab855bd91e3a38756b7d75a9c4549
[INFO] Call Precompile:
	address: 0000000000000000000000000000000000000002
	context: PrecompileContext { call_type: DelegateCall, gas_limit: 8937393454220500, value: 0 }
	input: 0000000ccccccccccccccccccccccccccccccccccccccccccccccccccc000000
[INFO] Call Precompile:
	address: 0000000000000000000000000000000000000003
	context: PrecompileContext { call_type: DelegateCall, gas_limit: 8937393454031246, value: 0 }
	input: 0000000ccccccccccccccccccccccccccccccccccccccccccccccccccc000000
[INFO] Call Precompile:
	address: 0000000000000000000000000000000000000004
	context: PrecompileContext { call_type: DelegateCall, gas_limit: 8937393453836512, value: 0 }
	input: 0000000ccccccccccccccccccccccccccccccccccccccccccccccccccc000000
[INFO] Call Precompile:
	address: 0000000000000000000000000000000000000005
	context: PrecompileContext { call_type: DelegateCall, gas_limit: 8937393443367672, value: 0 }
	input: 00000000000000000000000000000000000000000000000000000000000000010000000000000000000000000000000000000000000000000000000000000020000000000000000000000000000000000000000000000000000000000000002003fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2efffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f
[INFO] Call Precompile:
	address: 0000000000000000000000000000000000000006
	context: PrecompileContext { call_type: DelegateCall, gas_limit: 8937393431950167, value: 0 }
	input: 0f25929bcb43d5a57391564615c9e70a992b10eafa4db109709649cf48c50dd216da2f5cb6be7a0aa72c440c53c9bbdfec6c36c7d515536431b3a865468acbba1de49a4b0233273bba8146af82042d004f2085ec982397db0d97da17204cc2860217327ffc463919bef80cc166d09c6172639d8589799928761bcd9f22c903d4
[INFO] Call Precompile:
	address: 0000000000000000000000000000000000000007
	context: PrecompileContext { call_type: DelegateCall, gas_limit: 8937393430739854, value: 0 }
	input: 0f25929bcb43d5a57391564615c9e70a992b10eafa4db109709649cf48c50dd216da2f5cb6be7a0aa72c440c53c9bbdfec6c36c7d515536431b3a865468acbba0000000000000000000000000000000000000000000000000000000000000003
[INFO] Call Precompile:
	address: 0000000000000000000000000000000000000008
	context: PrecompileContext { call_type: DelegateCall, gas_limit: 8937393429374737, value: 0 }
	input: 1c76476f4def4bb94541d57ebba1193381ffa7aa76ada664dd31c16024c43f593034dd2920f673e204fee2811c678745fc819b55d3e9d294e45c9b03a76aef41209dd15ebff5d46c4bd888e51a93cf99a7329636c63514396b4a452003a35bf704bf11ca01483bfa8b34b43561848d28905960114c8ac04049af4b6315a416782bb8324af6cfc93537a2ad1a445cfd0ca2a71acd7ac41fadbf933c2a51be344d120a2a4cf30c1bf9845f20c6fe39e07ea2cce61f0c9bb048165fe5e4de877550111e129f1cf1097710d41c4ac70fcdfa5ba2023c6ff1cbeac322de49d1b6df7c2032c61a830e3c17286de9462bf242fca2883585b93870a73853face6a6bf411198e9393920d483a7260bfb731fb5d25f1aa493335a9e71297e485b7aef312c21800deef121f1e76426a00665e5c4479674322d4f75edadd46debd5cd992f6ed090689d0585ff075ec9e99ad690c3395bc4b313370b38ef355acdadcd122975b12c85ea5db8c6deb4aab71808dcb408fe3d1e7690c43d37b4ce6cc0166fa7daa
2023-01-24T10:53:12.477574Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1192451253,
    events_root: None,
}
2023-01-24T10:53:12.479595Z TRACE evm_eth_compliance::statetest::runner: TestDone => "test-vectors/tests/GeneralStateTests/stStaticFlagEnabled/DelegatecallToPrecompileFromTransaction.json"
2023-01-24T10:53:12.479622Z TRACE evm_eth_compliance::statetest::runner: Calling testfile => "test-vectors/tests/GeneralStateTests/stStaticFlagEnabled/StaticcallForPrecompilesIssue683.json"
2023-01-24T10:53:12.504578Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-24T10:53:12.504687Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T10:53:12.504690Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-24T10:53:12.504745Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T10:53:12.504815Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-24T10:53:12.504821Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "StaticcallForPrecompilesIssue683"::Istanbul::0
2023-01-24T10:53:12.504824Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stStaticFlagEnabled/StaticcallForPrecompilesIssue683.json"
2023-01-24T10:53:12.504827Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-24T10:53:12.504829Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T10:53:12.883322Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 4052917,
    events_root: None,
}
2023-01-24T10:53:12.883348Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-24T10:53:12.883354Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "StaticcallForPrecompilesIssue683"::Berlin::0
2023-01-24T10:53:12.883358Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stStaticFlagEnabled/StaticcallForPrecompilesIssue683.json"
2023-01-24T10:53:12.883360Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-24T10:53:12.883362Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[INFO] Call Precompile:
	address: 0000000000000000000000000000000000000002
	context: PrecompileContext { call_type: Call, gas_limit: 9079256847240644, value: 1 }
	input:
2023-01-24T10:53:12.883546Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3162584,
    events_root: None,
}
2023-01-24T10:53:12.883554Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-24T10:53:12.883558Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "StaticcallForPrecompilesIssue683"::London::0
2023-01-24T10:53:12.883560Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stStaticFlagEnabled/StaticcallForPrecompilesIssue683.json"
2023-01-24T10:53:12.883563Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-24T10:53:12.883565Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[INFO] Call Precompile:
	address: 0000000000000000000000000000000000000002
	context: PrecompileContext { call_type: Call, gas_limit: 9079256847240644, value: 1 }
	input:
2023-01-24T10:53:12.883696Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1955330,
    events_root: None,
}
2023-01-24T10:53:12.883704Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-24T10:53:12.883707Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "StaticcallForPrecompilesIssue683"::Merge::0
2023-01-24T10:53:12.883709Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stStaticFlagEnabled/StaticcallForPrecompilesIssue683.json"
2023-01-24T10:53:12.883712Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-24T10:53:12.883713Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[INFO] Call Precompile:
	address: 0000000000000000000000000000000000000002
	context: PrecompileContext { call_type: Call, gas_limit: 9079256847240644, value: 1 }
	input:
2023-01-24T10:53:12.883831Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1955330,
    events_root: None,
}
2023-01-24T10:53:12.885223Z TRACE evm_eth_compliance::statetest::runner: TestDone => "test-vectors/tests/GeneralStateTests/stStaticFlagEnabled/StaticcallForPrecompilesIssue683.json"
2023-01-24T10:53:12.885341Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 13 Files in Time:6.35053366s
```