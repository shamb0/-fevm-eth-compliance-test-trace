> Status

| Status | Context |
| --- | --- |
| OK | under WASM RT context |
| TODO | under native RT context |

> Test Suite

https://github.com/ethereum/tests/blob/develop/GeneralStateTests/stEIP2930

> Command to execute

```
clear && \
	RUST_LOG=evm_eth_compliance=trace \
	VECTOR=test-vectors/tests/GeneralStateTests/stEIP2930 \
	cargo run --release \
	-- \
	statetest
```

> For Review

* Following use-case failed

* Following use-case are skipped due to `transaction.tx` empty. Have to re-check on revm

| Test ID | Use-Case |
| --- | --- |
| TID-20-04 | manualCreate |

> Execution Trace

```
2023-01-26T11:04:51.576720Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "./test-vectors/tests/GeneralStateTests/stEIP2930/addressOpcodes.json", Total Files :: 1
2023-01-26T11:04:51.608411Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-26T11:04:51.608598Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T11:04:51.608601Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-26T11:04:51.608656Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T11:04:51.608659Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 2
2023-01-26T11:04:51.608720Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T11:04:51.608792Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-26T11:04:51.608795Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "addressOpcodes"::Berlin::0
2023-01-26T11:04:51.608798Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stEIP2930/addressOpcodes.json"
2023-01-26T11:04:51.608801Z  INFO evm_eth_compliance::statetest::runner: TX len : 68
2023-01-26T11:04:51.608802Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T11:04:51.978557Z  INFO evm_eth_compliance::statetest::runner: UC : "addressOpcodes"
2023-01-26T11:04:51.978571Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 4924192,
    events_root: None,
}
2023-01-26T11:04:51.978588Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 1
2023-01-26T11:04:51.978594Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "addressOpcodes"::Berlin::1
2023-01-26T11:04:51.978596Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stEIP2930/addressOpcodes.json"
2023-01-26T11:04:51.978599Z  INFO evm_eth_compliance::statetest::runner: TX len : 68
2023-01-26T11:04:51.978602Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T11:04:51.978888Z  INFO evm_eth_compliance::statetest::runner: UC : "addressOpcodes"
2023-01-26T11:04:51.978893Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 5222256,
    events_root: None,
}
2023-01-26T11:04:51.978905Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 4
2023-01-26T11:04:51.978908Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "addressOpcodes"::Berlin::4
2023-01-26T11:04:51.978910Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stEIP2930/addressOpcodes.json"
2023-01-26T11:04:51.978913Z  INFO evm_eth_compliance::statetest::runner: TX len : 68
2023-01-26T11:04:51.978914Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T11:04:51.979159Z  INFO evm_eth_compliance::statetest::runner: UC : "addressOpcodes"
2023-01-26T11:04:51.979163Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 5229157,
    events_root: None,
}
2023-01-26T11:04:51.979174Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 5
2023-01-26T11:04:51.979176Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "addressOpcodes"::Berlin::5
2023-01-26T11:04:51.979178Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stEIP2930/addressOpcodes.json"
2023-01-26T11:04:51.979181Z  INFO evm_eth_compliance::statetest::runner: TX len : 68
2023-01-26T11:04:51.979182Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T11:04:51.979404Z  INFO evm_eth_compliance::statetest::runner: UC : "addressOpcodes"
2023-01-26T11:04:51.979408Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3814067,
    events_root: None,
}
2023-01-26T11:04:51.979418Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 6
2023-01-26T11:04:51.979421Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "addressOpcodes"::Berlin::6
2023-01-26T11:04:51.979423Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stEIP2930/addressOpcodes.json"
2023-01-26T11:04:51.979425Z  INFO evm_eth_compliance::statetest::runner: TX len : 68
2023-01-26T11:04:51.979427Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T11:04:51.979668Z  INFO evm_eth_compliance::statetest::runner: UC : "addressOpcodes"
2023-01-26T11:04:51.979673Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 5270704,
    events_root: None,
}
2023-01-26T11:04:51.979684Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 7
2023-01-26T11:04:51.979687Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "addressOpcodes"::Berlin::7
2023-01-26T11:04:51.979688Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stEIP2930/addressOpcodes.json"
2023-01-26T11:04:51.979692Z  INFO evm_eth_compliance::statetest::runner: TX len : 68
2023-01-26T11:04:51.979694Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T11:04:51.979916Z  INFO evm_eth_compliance::statetest::runner: UC : "addressOpcodes"
2023-01-26T11:04:51.979921Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3853090,
    events_root: None,
}
2023-01-26T11:04:51.979930Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 8
2023-01-26T11:04:51.979933Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "addressOpcodes"::Berlin::8
2023-01-26T11:04:51.979936Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stEIP2930/addressOpcodes.json"
2023-01-26T11:04:51.979938Z  INFO evm_eth_compliance::statetest::runner: TX len : 68
2023-01-26T11:04:51.979940Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T11:04:51.980167Z  INFO evm_eth_compliance::statetest::runner: UC : "addressOpcodes"
2023-01-26T11:04:51.980171Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3853090,
    events_root: None,
}
2023-01-26T11:04:51.980183Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 9
2023-01-26T11:04:51.980185Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "addressOpcodes"::Berlin::9
2023-01-26T11:04:51.980187Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stEIP2930/addressOpcodes.json"
2023-01-26T11:04:51.980191Z  INFO evm_eth_compliance::statetest::runner: TX len : 68
2023-01-26T11:04:51.980192Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T11:04:51.980421Z  INFO evm_eth_compliance::statetest::runner: UC : "addressOpcodes"
2023-01-26T11:04:51.980426Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3853090,
    events_root: None,
}
2023-01-26T11:04:51.980436Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 10
2023-01-26T11:04:51.980439Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "addressOpcodes"::Berlin::10
2023-01-26T11:04:51.980440Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stEIP2930/addressOpcodes.json"
2023-01-26T11:04:51.980443Z  INFO evm_eth_compliance::statetest::runner: TX len : 68
2023-01-26T11:04:51.980444Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T11:04:51.980706Z  INFO evm_eth_compliance::statetest::runner: UC : "addressOpcodes"
2023-01-26T11:04:51.980711Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 5222289,
    events_root: None,
}
2023-01-26T11:04:51.980722Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 11
2023-01-26T11:04:51.980724Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "addressOpcodes"::Berlin::11
2023-01-26T11:04:51.980726Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stEIP2930/addressOpcodes.json"
2023-01-26T11:04:51.980730Z  INFO evm_eth_compliance::statetest::runner: TX len : 68
2023-01-26T11:04:51.980731Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T11:04:51.980975Z  INFO evm_eth_compliance::statetest::runner: UC : "addressOpcodes"
2023-01-26T11:04:51.980979Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3807430,
    events_root: None,
}
2023-01-26T11:04:51.980988Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 12
2023-01-26T11:04:51.980991Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "addressOpcodes"::Berlin::12
2023-01-26T11:04:51.980993Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stEIP2930/addressOpcodes.json"
2023-01-26T11:04:51.980995Z  INFO evm_eth_compliance::statetest::runner: TX len : 68
2023-01-26T11:04:51.980997Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T11:04:51.981256Z  INFO evm_eth_compliance::statetest::runner: UC : "addressOpcodes"
2023-01-26T11:04:51.981261Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 5229814,
    events_root: None,
}
2023-01-26T11:04:51.981271Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 13
2023-01-26T11:04:51.981274Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "addressOpcodes"::Berlin::13
2023-01-26T11:04:51.981276Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stEIP2930/addressOpcodes.json"
2023-01-26T11:04:51.981279Z  INFO evm_eth_compliance::statetest::runner: TX len : 68
2023-01-26T11:04:51.981280Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T11:04:51.981532Z  INFO evm_eth_compliance::statetest::runner: UC : "addressOpcodes"
2023-01-26T11:04:51.981537Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3815037,
    events_root: None,
}
2023-01-26T11:04:51.981546Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 16
2023-01-26T11:04:51.981550Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "addressOpcodes"::Berlin::16
2023-01-26T11:04:51.981551Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stEIP2930/addressOpcodes.json"
2023-01-26T11:04:51.981554Z  INFO evm_eth_compliance::statetest::runner: TX len : 68
2023-01-26T11:04:51.981555Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T11:04:51.981796Z  INFO evm_eth_compliance::statetest::runner: UC : "addressOpcodes"
2023-01-26T11:04:51.981801Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 5268775,
    events_root: None,
}
2023-01-26T11:04:51.981812Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 17
2023-01-26T11:04:51.981815Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "addressOpcodes"::Berlin::17
2023-01-26T11:04:51.981817Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stEIP2930/addressOpcodes.json"
2023-01-26T11:04:51.981819Z  INFO evm_eth_compliance::statetest::runner: TX len : 68
2023-01-26T11:04:51.981820Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T11:04:51.982041Z  INFO evm_eth_compliance::statetest::runner: UC : "addressOpcodes"
2023-01-26T11:04:51.982046Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3853998,
    events_root: None,
}
2023-01-26T11:04:51.982056Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 18
2023-01-26T11:04:51.982058Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "addressOpcodes"::Berlin::18
2023-01-26T11:04:51.982060Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stEIP2930/addressOpcodes.json"
2023-01-26T11:04:51.982063Z  INFO evm_eth_compliance::statetest::runner: TX len : 68
2023-01-26T11:04:51.982064Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T11:04:51.982490Z  INFO evm_eth_compliance::statetest::runner: UC : "addressOpcodes"
2023-01-26T11:04:51.982494Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 8952707,
    events_root: None,
}
2023-01-26T11:04:51.982510Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 19
2023-01-26T11:04:51.982513Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "addressOpcodes"::Berlin::19
2023-01-26T11:04:51.982516Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stEIP2930/addressOpcodes.json"
2023-01-26T11:04:51.982519Z  INFO evm_eth_compliance::statetest::runner: TX len : 68
2023-01-26T11:04:51.982520Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T11:04:51.982896Z  INFO evm_eth_compliance::statetest::runner: UC : "addressOpcodes"
2023-01-26T11:04:51.982900Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 7530305,
    events_root: None,
}
2023-01-26T11:04:51.982914Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 20
2023-01-26T11:04:51.982916Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "addressOpcodes"::Berlin::20
2023-01-26T11:04:51.982918Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stEIP2930/addressOpcodes.json"
2023-01-26T11:04:51.982921Z  INFO evm_eth_compliance::statetest::runner: TX len : 68
2023-01-26T11:04:51.982922Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T11:04:51.983373Z  INFO evm_eth_compliance::statetest::runner: UC : "addressOpcodes"
2023-01-26T11:04:51.983378Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 8968641,
    events_root: None,
}
2023-01-26T11:04:51.983394Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 21
2023-01-26T11:04:51.983398Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "addressOpcodes"::Berlin::21
2023-01-26T11:04:51.983400Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stEIP2930/addressOpcodes.json"
2023-01-26T11:04:51.983404Z  INFO evm_eth_compliance::statetest::runner: TX len : 68
2023-01-26T11:04:51.983405Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T11:04:51.983862Z  INFO evm_eth_compliance::statetest::runner: UC : "addressOpcodes"
2023-01-26T11:04:51.983867Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 7544853,
    events_root: None,
}
2023-01-26T11:04:51.983881Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 22
2023-01-26T11:04:51.983883Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "addressOpcodes"::Berlin::22
2023-01-26T11:04:51.983886Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stEIP2930/addressOpcodes.json"
2023-01-26T11:04:51.983888Z  INFO evm_eth_compliance::statetest::runner: TX len : 68
2023-01-26T11:04:51.983890Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T11:04:51.984127Z  INFO evm_eth_compliance::statetest::runner: UC : "addressOpcodes"
2023-01-26T11:04:51.984132Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 5176533,
    events_root: None,
}
2023-01-26T11:04:51.984142Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 23
2023-01-26T11:04:51.984145Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "addressOpcodes"::Berlin::23
2023-01-26T11:04:51.984148Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stEIP2930/addressOpcodes.json"
2023-01-26T11:04:51.984151Z  INFO evm_eth_compliance::statetest::runner: TX len : 68
2023-01-26T11:04:51.984153Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T11:04:51.984385Z  INFO evm_eth_compliance::statetest::runner: UC : "addressOpcodes"
2023-01-26T11:04:51.984391Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 5182856,
    events_root: None,
}
2023-01-26T11:04:51.984401Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 24
2023-01-26T11:04:51.984404Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "addressOpcodes"::Berlin::24
2023-01-26T11:04:51.984406Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stEIP2930/addressOpcodes.json"
2023-01-26T11:04:51.984408Z  INFO evm_eth_compliance::statetest::runner: TX len : 68
2023-01-26T11:04:51.984410Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T11:04:51.984668Z  INFO evm_eth_compliance::statetest::runner: UC : "addressOpcodes"
2023-01-26T11:04:51.984673Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 5230094,
    events_root: None,
}
2023-01-26T11:04:51.984684Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 25
2023-01-26T11:04:51.984686Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "addressOpcodes"::Berlin::25
2023-01-26T11:04:51.984688Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stEIP2930/addressOpcodes.json"
2023-01-26T11:04:51.984690Z  INFO evm_eth_compliance::statetest::runner: TX len : 68
2023-01-26T11:04:51.984691Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T11:04:51.984940Z  INFO evm_eth_compliance::statetest::runner: UC : "addressOpcodes"
2023-01-26T11:04:51.984945Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3815317,
    events_root: None,
}
2023-01-26T11:04:51.984955Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 28
2023-01-26T11:04:51.984957Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "addressOpcodes"::Berlin::28
2023-01-26T11:04:51.984959Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stEIP2930/addressOpcodes.json"
2023-01-26T11:04:51.984962Z  INFO evm_eth_compliance::statetest::runner: TX len : 68
2023-01-26T11:04:51.984963Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T11:04:51.985203Z  INFO evm_eth_compliance::statetest::runner: UC : "addressOpcodes"
2023-01-26T11:04:51.985207Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 5268935,
    events_root: None,
}
2023-01-26T11:04:51.985218Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 29
2023-01-26T11:04:51.985221Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "addressOpcodes"::Berlin::29
2023-01-26T11:04:51.985223Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stEIP2930/addressOpcodes.json"
2023-01-26T11:04:51.985225Z  INFO evm_eth_compliance::statetest::runner: TX len : 68
2023-01-26T11:04:51.985226Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T11:04:51.985455Z  INFO evm_eth_compliance::statetest::runner: UC : "addressOpcodes"
2023-01-26T11:04:51.985459Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3854158,
    events_root: None,
}
2023-01-26T11:04:51.985470Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 30
2023-01-26T11:04:51.985473Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "addressOpcodes"::Berlin::30
2023-01-26T11:04:51.985475Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stEIP2930/addressOpcodes.json"
2023-01-26T11:04:51.985478Z  INFO evm_eth_compliance::statetest::runner: TX len : 68
2023-01-26T11:04:51.985480Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T11:04:51.985870Z  INFO evm_eth_compliance::statetest::runner: UC : "addressOpcodes"
2023-01-26T11:04:51.985875Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 8483872,
    events_root: None,
}
2023-01-26T11:04:51.985889Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 31
2023-01-26T11:04:51.985891Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "addressOpcodes"::Berlin::31
2023-01-26T11:04:51.985894Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stEIP2930/addressOpcodes.json"
2023-01-26T11:04:51.985896Z  INFO evm_eth_compliance::statetest::runner: TX len : 68
2023-01-26T11:04:51.985897Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T11:04:51.986263Z  INFO evm_eth_compliance::statetest::runner: UC : "addressOpcodes"
2023-01-26T11:04:51.986268Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 7061469,
    events_root: None,
}
2023-01-26T11:04:51.986281Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 32
2023-01-26T11:04:51.986285Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "addressOpcodes"::Berlin::32
2023-01-26T11:04:51.986287Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stEIP2930/addressOpcodes.json"
2023-01-26T11:04:51.986289Z  INFO evm_eth_compliance::statetest::runner: TX len : 68
2023-01-26T11:04:51.986291Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T11:04:51.986677Z  INFO evm_eth_compliance::statetest::runner: UC : "addressOpcodes"
2023-01-26T11:04:51.986682Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 8492089,
    events_root: None,
}
2023-01-26T11:04:51.986696Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 33
2023-01-26T11:04:51.986698Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "addressOpcodes"::Berlin::33
2023-01-26T11:04:51.986700Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stEIP2930/addressOpcodes.json"
2023-01-26T11:04:51.986702Z  INFO evm_eth_compliance::statetest::runner: TX len : 68
2023-01-26T11:04:51.986705Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T11:04:51.987071Z  INFO evm_eth_compliance::statetest::runner: UC : "addressOpcodes"
2023-01-26T11:04:51.987077Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 7068301,
    events_root: None,
}
2023-01-26T11:04:51.987090Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 34
2023-01-26T11:04:51.987093Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "addressOpcodes"::Berlin::34
2023-01-26T11:04:51.987095Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stEIP2930/addressOpcodes.json"
2023-01-26T11:04:51.987097Z  INFO evm_eth_compliance::statetest::runner: TX len : 68
2023-01-26T11:04:51.987098Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T11:04:51.987346Z  INFO evm_eth_compliance::statetest::runner: UC : "addressOpcodes"
2023-01-26T11:04:51.987351Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 5176693,
    events_root: None,
}
2023-01-26T11:04:51.987361Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 35
2023-01-26T11:04:51.987364Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "addressOpcodes"::Berlin::35
2023-01-26T11:04:51.987366Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stEIP2930/addressOpcodes.json"
2023-01-26T11:04:51.987368Z  INFO evm_eth_compliance::statetest::runner: TX len : 68
2023-01-26T11:04:51.987370Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T11:04:51.987593Z  INFO evm_eth_compliance::statetest::runner: UC : "addressOpcodes"
2023-01-26T11:04:51.987597Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3761834,
    events_root: None,
}
2023-01-26T11:04:51.987606Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 36
2023-01-26T11:04:51.987609Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "addressOpcodes"::Berlin::36
2023-01-26T11:04:51.987611Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stEIP2930/addressOpcodes.json"
2023-01-26T11:04:51.987613Z  INFO evm_eth_compliance::statetest::runner: TX len : 68
2023-01-26T11:04:51.987615Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T11:04:51.987880Z  INFO evm_eth_compliance::statetest::runner: UC : "addressOpcodes"
2023-01-26T11:04:51.987884Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 5240153,
    events_root: None,
}
2023-01-26T11:04:51.987895Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 37
2023-01-26T11:04:51.987897Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "addressOpcodes"::Berlin::37
2023-01-26T11:04:51.987899Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stEIP2930/addressOpcodes.json"
2023-01-26T11:04:51.987901Z  INFO evm_eth_compliance::statetest::runner: TX len : 68
2023-01-26T11:04:51.987903Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T11:04:51.988143Z  INFO evm_eth_compliance::statetest::runner: UC : "addressOpcodes"
2023-01-26T11:04:51.988148Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3825376,
    events_root: None,
}
2023-01-26T11:04:51.988157Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 40
2023-01-26T11:04:51.988160Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "addressOpcodes"::Berlin::40
2023-01-26T11:04:51.988162Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stEIP2930/addressOpcodes.json"
2023-01-26T11:04:51.988164Z  INFO evm_eth_compliance::statetest::runner: TX len : 68
2023-01-26T11:04:51.988166Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T11:04:51.988409Z  INFO evm_eth_compliance::statetest::runner: UC : "addressOpcodes"
2023-01-26T11:04:51.988413Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 5281720,
    events_root: None,
}
2023-01-26T11:04:51.988424Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 41
2023-01-26T11:04:51.988428Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "addressOpcodes"::Berlin::41
2023-01-26T11:04:51.988430Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stEIP2930/addressOpcodes.json"
2023-01-26T11:04:51.988432Z  INFO evm_eth_compliance::statetest::runner: TX len : 68
2023-01-26T11:04:51.988434Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T11:04:51.988677Z  INFO evm_eth_compliance::statetest::runner: UC : "addressOpcodes"
2023-01-26T11:04:51.988681Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 5288206,
    events_root: None,
}
2023-01-26T11:04:51.988692Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 42
2023-01-26T11:04:51.988694Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "addressOpcodes"::Berlin::42
2023-01-26T11:04:51.988696Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stEIP2930/addressOpcodes.json"
2023-01-26T11:04:51.988698Z  INFO evm_eth_compliance::statetest::runner: TX len : 68
2023-01-26T11:04:51.988699Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T11:04:51.989106Z  INFO evm_eth_compliance::statetest::runner: UC : "addressOpcodes"
2023-01-26T11:04:51.989110Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 8964471,
    events_root: None,
}
2023-01-26T11:04:51.989124Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 43
2023-01-26T11:04:51.989126Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "addressOpcodes"::Berlin::43
2023-01-26T11:04:51.989128Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stEIP2930/addressOpcodes.json"
2023-01-26T11:04:51.989130Z  INFO evm_eth_compliance::statetest::runner: TX len : 68
2023-01-26T11:04:51.989132Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T11:04:51.989520Z  INFO evm_eth_compliance::statetest::runner: UC : "addressOpcodes"
2023-01-26T11:04:51.989525Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 7540684,
    events_root: None,
}
2023-01-26T11:04:51.989538Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 44
2023-01-26T11:04:51.989541Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "addressOpcodes"::Berlin::44
2023-01-26T11:04:51.989543Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stEIP2930/addressOpcodes.json"
2023-01-26T11:04:51.989545Z  INFO evm_eth_compliance::statetest::runner: TX len : 68
2023-01-26T11:04:51.989547Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T11:04:51.989968Z  INFO evm_eth_compliance::statetest::runner: UC : "addressOpcodes"
2023-01-26T11:04:51.989972Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 8979020,
    events_root: None,
}
2023-01-26T11:04:51.989986Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 45
2023-01-26T11:04:51.989990Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "addressOpcodes"::Berlin::45
2023-01-26T11:04:51.989992Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stEIP2930/addressOpcodes.json"
2023-01-26T11:04:51.989994Z  INFO evm_eth_compliance::statetest::runner: TX len : 68
2023-01-26T11:04:51.989995Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T11:04:51.990375Z  INFO evm_eth_compliance::statetest::runner: UC : "addressOpcodes"
2023-01-26T11:04:51.990379Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 7555233,
    events_root: None,
}
2023-01-26T11:04:51.990393Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 46
2023-01-26T11:04:51.990396Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "addressOpcodes"::Berlin::46
2023-01-26T11:04:51.990398Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stEIP2930/addressOpcodes.json"
2023-01-26T11:04:51.990400Z  INFO evm_eth_compliance::statetest::runner: TX len : 68
2023-01-26T11:04:51.990402Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T11:04:51.990638Z  INFO evm_eth_compliance::statetest::runner: UC : "addressOpcodes"
2023-01-26T11:04:51.990643Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 5186873,
    events_root: None,
}
2023-01-26T11:04:51.990652Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 47
2023-01-26T11:04:51.990655Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "addressOpcodes"::Berlin::47
2023-01-26T11:04:51.990657Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stEIP2930/addressOpcodes.json"
2023-01-26T11:04:51.990660Z  INFO evm_eth_compliance::statetest::runner: TX len : 68
2023-01-26T11:04:51.990662Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T11:04:51.990895Z  INFO evm_eth_compliance::statetest::runner: UC : "addressOpcodes"
2023-01-26T11:04:51.990899Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 5193195,
    events_root: None,
}
2023-01-26T11:04:51.990910Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 2
2023-01-26T11:04:51.990913Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "addressOpcodes"::Berlin::2
2023-01-26T11:04:51.990915Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stEIP2930/addressOpcodes.json"
2023-01-26T11:04:51.990917Z  INFO evm_eth_compliance::statetest::runner: TX len : 68
2023-01-26T11:04:51.990918Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T11:04:51.991176Z  INFO evm_eth_compliance::statetest::runner: UC : "addressOpcodes"
2023-01-26T11:04:51.991181Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 5222256,
    events_root: None,
}
2023-01-26T11:04:51.991191Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 3
2023-01-26T11:04:51.991193Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "addressOpcodes"::Berlin::3
2023-01-26T11:04:51.991195Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stEIP2930/addressOpcodes.json"
2023-01-26T11:04:51.991197Z  INFO evm_eth_compliance::statetest::runner: TX len : 68
2023-01-26T11:04:51.991199Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T11:04:51.991436Z  INFO evm_eth_compliance::statetest::runner: UC : "addressOpcodes"
2023-01-26T11:04:51.991441Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3807478,
    events_root: None,
}
2023-01-26T11:04:51.991451Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 14
2023-01-26T11:04:51.991454Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "addressOpcodes"::Berlin::14
2023-01-26T11:04:51.991456Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stEIP2930/addressOpcodes.json"
2023-01-26T11:04:51.991458Z  INFO evm_eth_compliance::statetest::runner: TX len : 68
2023-01-26T11:04:51.991460Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T11:04:51.991724Z  INFO evm_eth_compliance::statetest::runner: UC : "addressOpcodes"
2023-01-26T11:04:51.991729Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 5229814,
    events_root: None,
}
2023-01-26T11:04:51.991740Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 15
2023-01-26T11:04:51.991742Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "addressOpcodes"::Berlin::15
2023-01-26T11:04:51.991744Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stEIP2930/addressOpcodes.json"
2023-01-26T11:04:51.991746Z  INFO evm_eth_compliance::statetest::runner: TX len : 68
2023-01-26T11:04:51.991748Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T11:04:51.992014Z  INFO evm_eth_compliance::statetest::runner: UC : "addressOpcodes"
2023-01-26T11:04:51.992020Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3815037,
    events_root: None,
}
2023-01-26T11:04:51.992029Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 26
2023-01-26T11:04:51.992032Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "addressOpcodes"::Berlin::26
2023-01-26T11:04:51.992034Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stEIP2930/addressOpcodes.json"
2023-01-26T11:04:51.992036Z  INFO evm_eth_compliance::statetest::runner: TX len : 68
2023-01-26T11:04:51.992038Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T11:04:51.992295Z  INFO evm_eth_compliance::statetest::runner: UC : "addressOpcodes"
2023-01-26T11:04:51.992300Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 5230094,
    events_root: None,
}
2023-01-26T11:04:51.992311Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 27
2023-01-26T11:04:51.992313Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "addressOpcodes"::Berlin::27
2023-01-26T11:04:51.992315Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stEIP2930/addressOpcodes.json"
2023-01-26T11:04:51.992317Z  INFO evm_eth_compliance::statetest::runner: TX len : 68
2023-01-26T11:04:51.992319Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T11:04:51.992564Z  INFO evm_eth_compliance::statetest::runner: UC : "addressOpcodes"
2023-01-26T11:04:51.992570Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3815317,
    events_root: None,
}
2023-01-26T11:04:51.992579Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 38
2023-01-26T11:04:51.992582Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "addressOpcodes"::Berlin::38
2023-01-26T11:04:51.992584Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stEIP2930/addressOpcodes.json"
2023-01-26T11:04:51.992586Z  INFO evm_eth_compliance::statetest::runner: TX len : 68
2023-01-26T11:04:51.992587Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T11:04:51.992845Z  INFO evm_eth_compliance::statetest::runner: UC : "addressOpcodes"
2023-01-26T11:04:51.992849Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 5240153,
    events_root: None,
}
2023-01-26T11:04:51.992860Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 39
2023-01-26T11:04:51.992863Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "addressOpcodes"::Berlin::39
2023-01-26T11:04:51.992865Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stEIP2930/addressOpcodes.json"
2023-01-26T11:04:51.992867Z  INFO evm_eth_compliance::statetest::runner: TX len : 68
2023-01-26T11:04:51.992869Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T11:04:51.993108Z  INFO evm_eth_compliance::statetest::runner: UC : "addressOpcodes"
2023-01-26T11:04:51.993113Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3825376,
    events_root: None,
}
2023-01-26T11:04:51.993124Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-26T11:04:51.993127Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "addressOpcodes"::London::0
2023-01-26T11:04:51.993129Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stEIP2930/addressOpcodes.json"
2023-01-26T11:04:51.993131Z  INFO evm_eth_compliance::statetest::runner: TX len : 68
2023-01-26T11:04:51.993132Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T11:04:51.993395Z  INFO evm_eth_compliance::statetest::runner: UC : "addressOpcodes"
2023-01-26T11:04:51.993400Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 5222256,
    events_root: None,
}
2023-01-26T11:04:51.993411Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 1
2023-01-26T11:04:51.993413Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "addressOpcodes"::London::1
2023-01-26T11:04:51.993416Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stEIP2930/addressOpcodes.json"
2023-01-26T11:04:51.993418Z  INFO evm_eth_compliance::statetest::runner: TX len : 68
2023-01-26T11:04:51.993419Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T11:04:51.993661Z  INFO evm_eth_compliance::statetest::runner: UC : "addressOpcodes"
2023-01-26T11:04:51.993665Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3807478,
    events_root: None,
}
2023-01-26T11:04:51.993676Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 4
2023-01-26T11:04:51.993678Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "addressOpcodes"::London::4
2023-01-26T11:04:51.993680Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stEIP2930/addressOpcodes.json"
2023-01-26T11:04:51.993682Z  INFO evm_eth_compliance::statetest::runner: TX len : 68
2023-01-26T11:04:51.993684Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T11:04:51.993936Z  INFO evm_eth_compliance::statetest::runner: UC : "addressOpcodes"
2023-01-26T11:04:51.993941Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 5229157,
    events_root: None,
}
2023-01-26T11:04:51.993951Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 5
2023-01-26T11:04:51.993953Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "addressOpcodes"::London::5
2023-01-26T11:04:51.993955Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stEIP2930/addressOpcodes.json"
2023-01-26T11:04:51.993958Z  INFO evm_eth_compliance::statetest::runner: TX len : 68
2023-01-26T11:04:51.993960Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T11:04:51.994185Z  INFO evm_eth_compliance::statetest::runner: UC : "addressOpcodes"
2023-01-26T11:04:51.994190Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3814067,
    events_root: None,
}
2023-01-26T11:04:51.994199Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 6
2023-01-26T11:04:51.994202Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "addressOpcodes"::London::6
2023-01-26T11:04:51.994205Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stEIP2930/addressOpcodes.json"
2023-01-26T11:04:51.994208Z  INFO evm_eth_compliance::statetest::runner: TX len : 68
2023-01-26T11:04:51.994209Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T11:04:51.994458Z  INFO evm_eth_compliance::statetest::runner: UC : "addressOpcodes"
2023-01-26T11:04:51.994464Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 5270704,
    events_root: None,
}
2023-01-26T11:04:51.994474Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 7
2023-01-26T11:04:51.994477Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "addressOpcodes"::London::7
2023-01-26T11:04:51.994479Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stEIP2930/addressOpcodes.json"
2023-01-26T11:04:51.994481Z  INFO evm_eth_compliance::statetest::runner: TX len : 68
2023-01-26T11:04:51.994483Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T11:04:51.994701Z  INFO evm_eth_compliance::statetest::runner: UC : "addressOpcodes"
2023-01-26T11:04:51.994706Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3853090,
    events_root: None,
}
2023-01-26T11:04:51.994716Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 8
2023-01-26T11:04:51.994719Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "addressOpcodes"::London::8
2023-01-26T11:04:51.994721Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stEIP2930/addressOpcodes.json"
2023-01-26T11:04:51.994723Z  INFO evm_eth_compliance::statetest::runner: TX len : 68
2023-01-26T11:04:51.994725Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T11:04:51.994943Z  INFO evm_eth_compliance::statetest::runner: UC : "addressOpcodes"
2023-01-26T11:04:51.994947Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3853090,
    events_root: None,
}
2023-01-26T11:04:51.994958Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 9
2023-01-26T11:04:51.994960Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "addressOpcodes"::London::9
2023-01-26T11:04:51.994962Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stEIP2930/addressOpcodes.json"
2023-01-26T11:04:51.994964Z  INFO evm_eth_compliance::statetest::runner: TX len : 68
2023-01-26T11:04:51.994966Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T11:04:51.995184Z  INFO evm_eth_compliance::statetest::runner: UC : "addressOpcodes"
2023-01-26T11:04:51.995188Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3853090,
    events_root: None,
}
2023-01-26T11:04:51.995198Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 10
2023-01-26T11:04:51.995201Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "addressOpcodes"::London::10
2023-01-26T11:04:51.995203Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stEIP2930/addressOpcodes.json"
2023-01-26T11:04:51.995205Z  INFO evm_eth_compliance::statetest::runner: TX len : 68
2023-01-26T11:04:51.995207Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T11:04:51.995465Z  INFO evm_eth_compliance::statetest::runner: UC : "addressOpcodes"
2023-01-26T11:04:51.995469Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 5222289,
    events_root: None,
}
2023-01-26T11:04:51.995480Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 11
2023-01-26T11:04:51.995483Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "addressOpcodes"::London::11
2023-01-26T11:04:51.995485Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stEIP2930/addressOpcodes.json"
2023-01-26T11:04:51.995487Z  INFO evm_eth_compliance::statetest::runner: TX len : 68
2023-01-26T11:04:51.995489Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T11:04:51.995728Z  INFO evm_eth_compliance::statetest::runner: UC : "addressOpcodes"
2023-01-26T11:04:51.995733Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3807430,
    events_root: None,
}
2023-01-26T11:04:51.995743Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 12
2023-01-26T11:04:51.995746Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "addressOpcodes"::London::12
2023-01-26T11:04:51.995747Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stEIP2930/addressOpcodes.json"
2023-01-26T11:04:51.995750Z  INFO evm_eth_compliance::statetest::runner: TX len : 68
2023-01-26T11:04:51.995751Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T11:04:51.996007Z  INFO evm_eth_compliance::statetest::runner: UC : "addressOpcodes"
2023-01-26T11:04:51.996011Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 5229814,
    events_root: None,
}
2023-01-26T11:04:51.996021Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 13
2023-01-26T11:04:51.996024Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "addressOpcodes"::London::13
2023-01-26T11:04:51.996026Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stEIP2930/addressOpcodes.json"
2023-01-26T11:04:51.996028Z  INFO evm_eth_compliance::statetest::runner: TX len : 68
2023-01-26T11:04:51.996030Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T11:04:51.996266Z  INFO evm_eth_compliance::statetest::runner: UC : "addressOpcodes"
2023-01-26T11:04:51.996271Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3815037,
    events_root: None,
}
2023-01-26T11:04:51.996281Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 16
2023-01-26T11:04:51.996283Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "addressOpcodes"::London::16
2023-01-26T11:04:51.996285Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stEIP2930/addressOpcodes.json"
2023-01-26T11:04:51.996287Z  INFO evm_eth_compliance::statetest::runner: TX len : 68
2023-01-26T11:04:51.996288Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T11:04:51.996529Z  INFO evm_eth_compliance::statetest::runner: UC : "addressOpcodes"
2023-01-26T11:04:51.996534Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 5268775,
    events_root: None,
}
2023-01-26T11:04:51.996548Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 17
2023-01-26T11:04:51.996551Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "addressOpcodes"::London::17
2023-01-26T11:04:51.996552Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stEIP2930/addressOpcodes.json"
2023-01-26T11:04:51.996555Z  INFO evm_eth_compliance::statetest::runner: TX len : 68
2023-01-26T11:04:51.996557Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T11:04:51.996778Z  INFO evm_eth_compliance::statetest::runner: UC : "addressOpcodes"
2023-01-26T11:04:51.996783Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3853998,
    events_root: None,
}
2023-01-26T11:04:51.996793Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 18
2023-01-26T11:04:51.996796Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "addressOpcodes"::London::18
2023-01-26T11:04:51.996798Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stEIP2930/addressOpcodes.json"
2023-01-26T11:04:51.996800Z  INFO evm_eth_compliance::statetest::runner: TX len : 68
2023-01-26T11:04:51.996801Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T11:04:51.997198Z  INFO evm_eth_compliance::statetest::runner: UC : "addressOpcodes"
2023-01-26T11:04:51.997203Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 8952707,
    events_root: None,
}
2023-01-26T11:04:51.997218Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 19
2023-01-26T11:04:51.997221Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "addressOpcodes"::London::19
2023-01-26T11:04:51.997223Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stEIP2930/addressOpcodes.json"
2023-01-26T11:04:51.997225Z  INFO evm_eth_compliance::statetest::runner: TX len : 68
2023-01-26T11:04:51.997226Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T11:04:51.997612Z  INFO evm_eth_compliance::statetest::runner: UC : "addressOpcodes"
2023-01-26T11:04:51.997617Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 7530305,
    events_root: None,
}
2023-01-26T11:04:51.997630Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 20
2023-01-26T11:04:51.997633Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "addressOpcodes"::London::20
2023-01-26T11:04:51.997636Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stEIP2930/addressOpcodes.json"
2023-01-26T11:04:51.997640Z  INFO evm_eth_compliance::statetest::runner: TX len : 68
2023-01-26T11:04:51.997641Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T11:04:51.998038Z  INFO evm_eth_compliance::statetest::runner: UC : "addressOpcodes"
2023-01-26T11:04:51.998043Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 8968641,
    events_root: None,
}
2023-01-26T11:04:51.998057Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 21
2023-01-26T11:04:51.998060Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "addressOpcodes"::London::21
2023-01-26T11:04:51.998063Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stEIP2930/addressOpcodes.json"
2023-01-26T11:04:51.998066Z  INFO evm_eth_compliance::statetest::runner: TX len : 68
2023-01-26T11:04:51.998067Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T11:04:51.998444Z  INFO evm_eth_compliance::statetest::runner: UC : "addressOpcodes"
2023-01-26T11:04:51.998449Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 7544853,
    events_root: None,
}
2023-01-26T11:04:51.998462Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 22
2023-01-26T11:04:51.998465Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "addressOpcodes"::London::22
2023-01-26T11:04:51.998468Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stEIP2930/addressOpcodes.json"
2023-01-26T11:04:51.998471Z  INFO evm_eth_compliance::statetest::runner: TX len : 68
2023-01-26T11:04:51.998472Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T11:04:51.998745Z  INFO evm_eth_compliance::statetest::runner: UC : "addressOpcodes"
2023-01-26T11:04:51.998750Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 5176533,
    events_root: None,
}
2023-01-26T11:04:51.998761Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 23
2023-01-26T11:04:51.998763Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "addressOpcodes"::London::23
2023-01-26T11:04:51.998765Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stEIP2930/addressOpcodes.json"
2023-01-26T11:04:51.998767Z  INFO evm_eth_compliance::statetest::runner: TX len : 68
2023-01-26T11:04:51.998769Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T11:04:51.999003Z  INFO evm_eth_compliance::statetest::runner: UC : "addressOpcodes"
2023-01-26T11:04:51.999007Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 5182856,
    events_root: None,
}
2023-01-26T11:04:51.999017Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 24
2023-01-26T11:04:51.999019Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "addressOpcodes"::London::24
2023-01-26T11:04:51.999022Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stEIP2930/addressOpcodes.json"
2023-01-26T11:04:51.999024Z  INFO evm_eth_compliance::statetest::runner: TX len : 68
2023-01-26T11:04:51.999026Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T11:04:51.999339Z  INFO evm_eth_compliance::statetest::runner: UC : "addressOpcodes"
2023-01-26T11:04:51.999346Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 5230094,
    events_root: None,
}
2023-01-26T11:04:51.999361Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 25
2023-01-26T11:04:51.999364Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "addressOpcodes"::London::25
2023-01-26T11:04:51.999367Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stEIP2930/addressOpcodes.json"
2023-01-26T11:04:51.999371Z  INFO evm_eth_compliance::statetest::runner: TX len : 68
2023-01-26T11:04:51.999372Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T11:04:51.999626Z  INFO evm_eth_compliance::statetest::runner: UC : "addressOpcodes"
2023-01-26T11:04:51.999631Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3815317,
    events_root: None,
}
2023-01-26T11:04:51.999641Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 28
2023-01-26T11:04:51.999644Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "addressOpcodes"::London::28
2023-01-26T11:04:51.999645Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stEIP2930/addressOpcodes.json"
2023-01-26T11:04:51.999649Z  INFO evm_eth_compliance::statetest::runner: TX len : 68
2023-01-26T11:04:51.999650Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T11:04:51.999890Z  INFO evm_eth_compliance::statetest::runner: UC : "addressOpcodes"
2023-01-26T11:04:51.999896Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 5268935,
    events_root: None,
}
2023-01-26T11:04:51.999906Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 29
2023-01-26T11:04:51.999909Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "addressOpcodes"::London::29
2023-01-26T11:04:51.999911Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stEIP2930/addressOpcodes.json"
2023-01-26T11:04:51.999914Z  INFO evm_eth_compliance::statetest::runner: TX len : 68
2023-01-26T11:04:51.999915Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T11:04:52.000135Z  INFO evm_eth_compliance::statetest::runner: UC : "addressOpcodes"
2023-01-26T11:04:52.000141Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3854158,
    events_root: None,
}
2023-01-26T11:04:52.000150Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 30
2023-01-26T11:04:52.000153Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "addressOpcodes"::London::30
2023-01-26T11:04:52.000155Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stEIP2930/addressOpcodes.json"
2023-01-26T11:04:52.000157Z  INFO evm_eth_compliance::statetest::runner: TX len : 68
2023-01-26T11:04:52.000159Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T11:04:52.000554Z  INFO evm_eth_compliance::statetest::runner: UC : "addressOpcodes"
2023-01-26T11:04:52.000559Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 8483872,
    events_root: None,
}
2023-01-26T11:04:52.000574Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 31
2023-01-26T11:04:52.000576Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "addressOpcodes"::London::31
2023-01-26T11:04:52.000578Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stEIP2930/addressOpcodes.json"
2023-01-26T11:04:52.000580Z  INFO evm_eth_compliance::statetest::runner: TX len : 68
2023-01-26T11:04:52.000582Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T11:04:52.000950Z  INFO evm_eth_compliance::statetest::runner: UC : "addressOpcodes"
2023-01-26T11:04:52.000955Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 7061469,
    events_root: None,
}
2023-01-26T11:04:52.000968Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 32
2023-01-26T11:04:52.000970Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "addressOpcodes"::London::32
2023-01-26T11:04:52.000972Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stEIP2930/addressOpcodes.json"
2023-01-26T11:04:52.000975Z  INFO evm_eth_compliance::statetest::runner: TX len : 68
2023-01-26T11:04:52.000977Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T11:04:52.001377Z  INFO evm_eth_compliance::statetest::runner: UC : "addressOpcodes"
2023-01-26T11:04:52.001383Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 8492089,
    events_root: None,
}
2023-01-26T11:04:52.001398Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 33
2023-01-26T11:04:52.001401Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "addressOpcodes"::London::33
2023-01-26T11:04:52.001403Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stEIP2930/addressOpcodes.json"
2023-01-26T11:04:52.001406Z  INFO evm_eth_compliance::statetest::runner: TX len : 68
2023-01-26T11:04:52.001407Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T11:04:52.001796Z  INFO evm_eth_compliance::statetest::runner: UC : "addressOpcodes"
2023-01-26T11:04:52.001801Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 7068301,
    events_root: None,
}
2023-01-26T11:04:52.001813Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 34
2023-01-26T11:04:52.001816Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "addressOpcodes"::London::34
2023-01-26T11:04:52.001817Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stEIP2930/addressOpcodes.json"
2023-01-26T11:04:52.001820Z  INFO evm_eth_compliance::statetest::runner: TX len : 68
2023-01-26T11:04:52.001821Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T11:04:52.002053Z  INFO evm_eth_compliance::statetest::runner: UC : "addressOpcodes"
2023-01-26T11:04:52.002058Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 5176693,
    events_root: None,
}
2023-01-26T11:04:52.002067Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 35
2023-01-26T11:04:52.002070Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "addressOpcodes"::London::35
2023-01-26T11:04:52.002071Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stEIP2930/addressOpcodes.json"
2023-01-26T11:04:52.002074Z  INFO evm_eth_compliance::statetest::runner: TX len : 68
2023-01-26T11:04:52.002076Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T11:04:52.002288Z  INFO evm_eth_compliance::statetest::runner: UC : "addressOpcodes"
2023-01-26T11:04:52.002292Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3761834,
    events_root: None,
}
2023-01-26T11:04:52.002301Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 36
2023-01-26T11:04:52.002304Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "addressOpcodes"::London::36
2023-01-26T11:04:52.002305Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stEIP2930/addressOpcodes.json"
2023-01-26T11:04:52.002308Z  INFO evm_eth_compliance::statetest::runner: TX len : 68
2023-01-26T11:04:52.002309Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T11:04:52.002574Z  INFO evm_eth_compliance::statetest::runner: UC : "addressOpcodes"
2023-01-26T11:04:52.002580Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 5240153,
    events_root: None,
}
2023-01-26T11:04:52.002590Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 37
2023-01-26T11:04:52.002593Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "addressOpcodes"::London::37
2023-01-26T11:04:52.002594Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stEIP2930/addressOpcodes.json"
2023-01-26T11:04:52.002597Z  INFO evm_eth_compliance::statetest::runner: TX len : 68
2023-01-26T11:04:52.002598Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T11:04:52.002836Z  INFO evm_eth_compliance::statetest::runner: UC : "addressOpcodes"
2023-01-26T11:04:52.002841Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3825376,
    events_root: None,
}
2023-01-26T11:04:52.002851Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 40
2023-01-26T11:04:52.002853Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "addressOpcodes"::London::40
2023-01-26T11:04:52.002855Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stEIP2930/addressOpcodes.json"
2023-01-26T11:04:52.002857Z  INFO evm_eth_compliance::statetest::runner: TX len : 68
2023-01-26T11:04:52.002859Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T11:04:52.003098Z  INFO evm_eth_compliance::statetest::runner: UC : "addressOpcodes"
2023-01-26T11:04:52.003102Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 5281720,
    events_root: None,
}
2023-01-26T11:04:52.003113Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 41
2023-01-26T11:04:52.003116Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "addressOpcodes"::London::41
2023-01-26T11:04:52.003118Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stEIP2930/addressOpcodes.json"
2023-01-26T11:04:52.003120Z  INFO evm_eth_compliance::statetest::runner: TX len : 68
2023-01-26T11:04:52.003122Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T11:04:52.003362Z  INFO evm_eth_compliance::statetest::runner: UC : "addressOpcodes"
2023-01-26T11:04:52.003367Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 5288206,
    events_root: None,
}
2023-01-26T11:04:52.003378Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 42
2023-01-26T11:04:52.003381Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "addressOpcodes"::London::42
2023-01-26T11:04:52.003382Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stEIP2930/addressOpcodes.json"
2023-01-26T11:04:52.003385Z  INFO evm_eth_compliance::statetest::runner: TX len : 68
2023-01-26T11:04:52.003386Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T11:04:52.003793Z  INFO evm_eth_compliance::statetest::runner: UC : "addressOpcodes"
2023-01-26T11:04:52.003799Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 8964471,
    events_root: None,
}
2023-01-26T11:04:52.003814Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 43
2023-01-26T11:04:52.003816Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "addressOpcodes"::London::43
2023-01-26T11:04:52.003818Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stEIP2930/addressOpcodes.json"
2023-01-26T11:04:52.003820Z  INFO evm_eth_compliance::statetest::runner: TX len : 68
2023-01-26T11:04:52.003821Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T11:04:52.004199Z  INFO evm_eth_compliance::statetest::runner: UC : "addressOpcodes"
2023-01-26T11:04:52.004203Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 7540684,
    events_root: None,
}
2023-01-26T11:04:52.004217Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 44
2023-01-26T11:04:52.004220Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "addressOpcodes"::London::44
2023-01-26T11:04:52.004222Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stEIP2930/addressOpcodes.json"
2023-01-26T11:04:52.004224Z  INFO evm_eth_compliance::statetest::runner: TX len : 68
2023-01-26T11:04:52.004226Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T11:04:52.004623Z  INFO evm_eth_compliance::statetest::runner: UC : "addressOpcodes"
2023-01-26T11:04:52.004627Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 8979020,
    events_root: None,
}
2023-01-26T11:04:52.004642Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 45
2023-01-26T11:04:52.004645Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "addressOpcodes"::London::45
2023-01-26T11:04:52.004647Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stEIP2930/addressOpcodes.json"
2023-01-26T11:04:52.004649Z  INFO evm_eth_compliance::statetest::runner: TX len : 68
2023-01-26T11:04:52.004650Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T11:04:52.005031Z  INFO evm_eth_compliance::statetest::runner: UC : "addressOpcodes"
2023-01-26T11:04:52.005035Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 7555233,
    events_root: None,
}
2023-01-26T11:04:52.005049Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 46
2023-01-26T11:04:52.005052Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "addressOpcodes"::London::46
2023-01-26T11:04:52.005054Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stEIP2930/addressOpcodes.json"
2023-01-26T11:04:52.005056Z  INFO evm_eth_compliance::statetest::runner: TX len : 68
2023-01-26T11:04:52.005058Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T11:04:52.005292Z  INFO evm_eth_compliance::statetest::runner: UC : "addressOpcodes"
2023-01-26T11:04:52.005297Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 5186873,
    events_root: None,
}
2023-01-26T11:04:52.005307Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 47
2023-01-26T11:04:52.005310Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "addressOpcodes"::London::47
2023-01-26T11:04:52.005312Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stEIP2930/addressOpcodes.json"
2023-01-26T11:04:52.005314Z  INFO evm_eth_compliance::statetest::runner: TX len : 68
2023-01-26T11:04:52.005316Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T11:04:52.005584Z  INFO evm_eth_compliance::statetest::runner: UC : "addressOpcodes"
2023-01-26T11:04:52.005590Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 5193195,
    events_root: None,
}
2023-01-26T11:04:52.005600Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 2
2023-01-26T11:04:52.005604Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "addressOpcodes"::London::2
2023-01-26T11:04:52.005605Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stEIP2930/addressOpcodes.json"
2023-01-26T11:04:52.005608Z  INFO evm_eth_compliance::statetest::runner: TX len : 68
2023-01-26T11:04:52.005609Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T11:04:52.005870Z  INFO evm_eth_compliance::statetest::runner: UC : "addressOpcodes"
2023-01-26T11:04:52.005876Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 5222256,
    events_root: None,
}
2023-01-26T11:04:52.005886Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 3
2023-01-26T11:04:52.005889Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "addressOpcodes"::London::3
2023-01-26T11:04:52.005891Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stEIP2930/addressOpcodes.json"
2023-01-26T11:04:52.005893Z  INFO evm_eth_compliance::statetest::runner: TX len : 68
2023-01-26T11:04:52.005894Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T11:04:52.006134Z  INFO evm_eth_compliance::statetest::runner: UC : "addressOpcodes"
2023-01-26T11:04:52.006138Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3807478,
    events_root: None,
}
2023-01-26T11:04:52.006147Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 14
2023-01-26T11:04:52.006149Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "addressOpcodes"::London::14
2023-01-26T11:04:52.006151Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stEIP2930/addressOpcodes.json"
2023-01-26T11:04:52.006153Z  INFO evm_eth_compliance::statetest::runner: TX len : 68
2023-01-26T11:04:52.006155Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T11:04:52.006414Z  INFO evm_eth_compliance::statetest::runner: UC : "addressOpcodes"
2023-01-26T11:04:52.006418Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 5229814,
    events_root: None,
}
2023-01-26T11:04:52.006429Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 15
2023-01-26T11:04:52.006433Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "addressOpcodes"::London::15
2023-01-26T11:04:52.006434Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stEIP2930/addressOpcodes.json"
2023-01-26T11:04:52.006437Z  INFO evm_eth_compliance::statetest::runner: TX len : 68
2023-01-26T11:04:52.006438Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T11:04:52.006682Z  INFO evm_eth_compliance::statetest::runner: UC : "addressOpcodes"
2023-01-26T11:04:52.006686Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3815037,
    events_root: None,
}
2023-01-26T11:04:52.006696Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 26
2023-01-26T11:04:52.006698Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "addressOpcodes"::London::26
2023-01-26T11:04:52.006700Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stEIP2930/addressOpcodes.json"
2023-01-26T11:04:52.006703Z  INFO evm_eth_compliance::statetest::runner: TX len : 68
2023-01-26T11:04:52.006704Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T11:04:52.006960Z  INFO evm_eth_compliance::statetest::runner: UC : "addressOpcodes"
2023-01-26T11:04:52.006965Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 5230094,
    events_root: None,
}
2023-01-26T11:04:52.006976Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 27
2023-01-26T11:04:52.006978Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "addressOpcodes"::London::27
2023-01-26T11:04:52.006980Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stEIP2930/addressOpcodes.json"
2023-01-26T11:04:52.006983Z  INFO evm_eth_compliance::statetest::runner: TX len : 68
2023-01-26T11:04:52.006984Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T11:04:52.007225Z  INFO evm_eth_compliance::statetest::runner: UC : "addressOpcodes"
2023-01-26T11:04:52.007229Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3815317,
    events_root: None,
}
2023-01-26T11:04:52.007239Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 38
2023-01-26T11:04:52.007241Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "addressOpcodes"::London::38
2023-01-26T11:04:52.007243Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stEIP2930/addressOpcodes.json"
2023-01-26T11:04:52.007246Z  INFO evm_eth_compliance::statetest::runner: TX len : 68
2023-01-26T11:04:52.007247Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T11:04:52.007525Z  INFO evm_eth_compliance::statetest::runner: UC : "addressOpcodes"
2023-01-26T11:04:52.007530Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 5240153,
    events_root: None,
}
2023-01-26T11:04:52.007541Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 39
2023-01-26T11:04:52.007543Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "addressOpcodes"::London::39
2023-01-26T11:04:52.007546Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stEIP2930/addressOpcodes.json"
2023-01-26T11:04:52.007548Z  INFO evm_eth_compliance::statetest::runner: TX len : 68
2023-01-26T11:04:52.007550Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T11:04:52.007788Z  INFO evm_eth_compliance::statetest::runner: UC : "addressOpcodes"
2023-01-26T11:04:52.007793Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3825376,
    events_root: None,
}
2023-01-26T11:04:52.007802Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-26T11:04:52.007805Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "addressOpcodes"::Merge::0
2023-01-26T11:04:52.007807Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stEIP2930/addressOpcodes.json"
2023-01-26T11:04:52.007809Z  INFO evm_eth_compliance::statetest::runner: TX len : 68
2023-01-26T11:04:52.007811Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T11:04:52.008068Z  INFO evm_eth_compliance::statetest::runner: UC : "addressOpcodes"
2023-01-26T11:04:52.008073Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 5222256,
    events_root: None,
}
2023-01-26T11:04:52.008083Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 1
2023-01-26T11:04:52.008086Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "addressOpcodes"::Merge::1
2023-01-26T11:04:52.008088Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stEIP2930/addressOpcodes.json"
2023-01-26T11:04:52.008091Z  INFO evm_eth_compliance::statetest::runner: TX len : 68
2023-01-26T11:04:52.008092Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T11:04:52.008329Z  INFO evm_eth_compliance::statetest::runner: UC : "addressOpcodes"
2023-01-26T11:04:52.008334Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3807478,
    events_root: None,
}
2023-01-26T11:04:52.008343Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 4
2023-01-26T11:04:52.008345Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "addressOpcodes"::Merge::4
2023-01-26T11:04:52.008347Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stEIP2930/addressOpcodes.json"
2023-01-26T11:04:52.008350Z  INFO evm_eth_compliance::statetest::runner: TX len : 68
2023-01-26T11:04:52.008351Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T11:04:52.008593Z  INFO evm_eth_compliance::statetest::runner: UC : "addressOpcodes"
2023-01-26T11:04:52.008598Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 5229157,
    events_root: None,
}
2023-01-26T11:04:52.008609Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 5
2023-01-26T11:04:52.008612Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "addressOpcodes"::Merge::5
2023-01-26T11:04:52.008613Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stEIP2930/addressOpcodes.json"
2023-01-26T11:04:52.008616Z  INFO evm_eth_compliance::statetest::runner: TX len : 68
2023-01-26T11:04:52.008617Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T11:04:52.008949Z  INFO evm_eth_compliance::statetest::runner: UC : "addressOpcodes"
2023-01-26T11:04:52.008954Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3814067,
    events_root: None,
}
2023-01-26T11:04:52.008972Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 6
2023-01-26T11:04:52.008974Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "addressOpcodes"::Merge::6
2023-01-26T11:04:52.008976Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stEIP2930/addressOpcodes.json"
2023-01-26T11:04:52.008979Z  INFO evm_eth_compliance::statetest::runner: TX len : 68
2023-01-26T11:04:52.008980Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T11:04:52.009246Z  INFO evm_eth_compliance::statetest::runner: UC : "addressOpcodes"
2023-01-26T11:04:52.009250Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 5270704,
    events_root: None,
}
2023-01-26T11:04:52.009261Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 7
2023-01-26T11:04:52.009263Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "addressOpcodes"::Merge::7
2023-01-26T11:04:52.009265Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stEIP2930/addressOpcodes.json"
2023-01-26T11:04:52.009267Z  INFO evm_eth_compliance::statetest::runner: TX len : 68
2023-01-26T11:04:52.009269Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T11:04:52.009624Z  INFO evm_eth_compliance::statetest::runner: UC : "addressOpcodes"
2023-01-26T11:04:52.009629Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3853090,
    events_root: None,
}
2023-01-26T11:04:52.009639Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 8
2023-01-26T11:04:52.009642Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "addressOpcodes"::Merge::8
2023-01-26T11:04:52.009644Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stEIP2930/addressOpcodes.json"
2023-01-26T11:04:52.009646Z  INFO evm_eth_compliance::statetest::runner: TX len : 68
2023-01-26T11:04:52.009648Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T11:04:52.009867Z  INFO evm_eth_compliance::statetest::runner: UC : "addressOpcodes"
2023-01-26T11:04:52.009872Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3853090,
    events_root: None,
}
2023-01-26T11:04:52.009881Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 9
2023-01-26T11:04:52.009884Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "addressOpcodes"::Merge::9
2023-01-26T11:04:52.009886Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stEIP2930/addressOpcodes.json"
2023-01-26T11:04:52.009889Z  INFO evm_eth_compliance::statetest::runner: TX len : 68
2023-01-26T11:04:52.009890Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T11:04:52.010110Z  INFO evm_eth_compliance::statetest::runner: UC : "addressOpcodes"
2023-01-26T11:04:52.010114Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3853090,
    events_root: None,
}
2023-01-26T11:04:52.010123Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 10
2023-01-26T11:04:52.010126Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "addressOpcodes"::Merge::10
2023-01-26T11:04:52.010128Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stEIP2930/addressOpcodes.json"
2023-01-26T11:04:52.010131Z  INFO evm_eth_compliance::statetest::runner: TX len : 68
2023-01-26T11:04:52.010132Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T11:04:52.010392Z  INFO evm_eth_compliance::statetest::runner: UC : "addressOpcodes"
2023-01-26T11:04:52.010397Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 5222289,
    events_root: None,
}
2023-01-26T11:04:52.010407Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 11
2023-01-26T11:04:52.010410Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "addressOpcodes"::Merge::11
2023-01-26T11:04:52.010412Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stEIP2930/addressOpcodes.json"
2023-01-26T11:04:52.010414Z  INFO evm_eth_compliance::statetest::runner: TX len : 68
2023-01-26T11:04:52.010416Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T11:04:52.010656Z  INFO evm_eth_compliance::statetest::runner: UC : "addressOpcodes"
2023-01-26T11:04:52.010660Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3807430,
    events_root: None,
}
2023-01-26T11:04:52.010669Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 12
2023-01-26T11:04:52.010672Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "addressOpcodes"::Merge::12
2023-01-26T11:04:52.010673Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stEIP2930/addressOpcodes.json"
2023-01-26T11:04:52.010676Z  INFO evm_eth_compliance::statetest::runner: TX len : 68
2023-01-26T11:04:52.010677Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T11:04:52.010934Z  INFO evm_eth_compliance::statetest::runner: UC : "addressOpcodes"
2023-01-26T11:04:52.010938Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 5229814,
    events_root: None,
}
2023-01-26T11:04:52.010949Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 13
2023-01-26T11:04:52.010952Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "addressOpcodes"::Merge::13
2023-01-26T11:04:52.010954Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stEIP2930/addressOpcodes.json"
2023-01-26T11:04:52.010956Z  INFO evm_eth_compliance::statetest::runner: TX len : 68
2023-01-26T11:04:52.010958Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T11:04:52.011196Z  INFO evm_eth_compliance::statetest::runner: UC : "addressOpcodes"
2023-01-26T11:04:52.011200Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3815037,
    events_root: None,
}
2023-01-26T11:04:52.011209Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 16
2023-01-26T11:04:52.011212Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "addressOpcodes"::Merge::16
2023-01-26T11:04:52.011213Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stEIP2930/addressOpcodes.json"
2023-01-26T11:04:52.011216Z  INFO evm_eth_compliance::statetest::runner: TX len : 68
2023-01-26T11:04:52.011217Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T11:04:52.011456Z  INFO evm_eth_compliance::statetest::runner: UC : "addressOpcodes"
2023-01-26T11:04:52.011461Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 5268775,
    events_root: None,
}
2023-01-26T11:04:52.011471Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 17
2023-01-26T11:04:52.011474Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "addressOpcodes"::Merge::17
2023-01-26T11:04:52.011476Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stEIP2930/addressOpcodes.json"
2023-01-26T11:04:52.011478Z  INFO evm_eth_compliance::statetest::runner: TX len : 68
2023-01-26T11:04:52.011480Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T11:04:52.011715Z  INFO evm_eth_compliance::statetest::runner: UC : "addressOpcodes"
2023-01-26T11:04:52.011720Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3853998,
    events_root: None,
}
2023-01-26T11:04:52.011729Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 18
2023-01-26T11:04:52.011732Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "addressOpcodes"::Merge::18
2023-01-26T11:04:52.011735Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stEIP2930/addressOpcodes.json"
2023-01-26T11:04:52.011737Z  INFO evm_eth_compliance::statetest::runner: TX len : 68
2023-01-26T11:04:52.011739Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T11:04:52.012137Z  INFO evm_eth_compliance::statetest::runner: UC : "addressOpcodes"
2023-01-26T11:04:52.012142Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 8952707,
    events_root: None,
}
2023-01-26T11:04:52.012157Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 19
2023-01-26T11:04:52.012159Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "addressOpcodes"::Merge::19
2023-01-26T11:04:52.012162Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stEIP2930/addressOpcodes.json"
2023-01-26T11:04:52.012165Z  INFO evm_eth_compliance::statetest::runner: TX len : 68
2023-01-26T11:04:52.012166Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T11:04:52.012543Z  INFO evm_eth_compliance::statetest::runner: UC : "addressOpcodes"
2023-01-26T11:04:52.012549Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 7530305,
    events_root: None,
}
2023-01-26T11:04:52.012564Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 20
2023-01-26T11:04:52.012567Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "addressOpcodes"::Merge::20
2023-01-26T11:04:52.012569Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stEIP2930/addressOpcodes.json"
2023-01-26T11:04:52.012573Z  INFO evm_eth_compliance::statetest::runner: TX len : 68
2023-01-26T11:04:52.012575Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T11:04:52.012979Z  INFO evm_eth_compliance::statetest::runner: UC : "addressOpcodes"
2023-01-26T11:04:52.012983Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 8968641,
    events_root: None,
}
2023-01-26T11:04:52.012998Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 21
2023-01-26T11:04:52.013001Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "addressOpcodes"::Merge::21
2023-01-26T11:04:52.013003Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stEIP2930/addressOpcodes.json"
2023-01-26T11:04:52.013005Z  INFO evm_eth_compliance::statetest::runner: TX len : 68
2023-01-26T11:04:52.013007Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T11:04:52.013393Z  INFO evm_eth_compliance::statetest::runner: UC : "addressOpcodes"
2023-01-26T11:04:52.013398Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 7544853,
    events_root: None,
}
2023-01-26T11:04:52.013412Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 22
2023-01-26T11:04:52.013415Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "addressOpcodes"::Merge::22
2023-01-26T11:04:52.013417Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stEIP2930/addressOpcodes.json"
2023-01-26T11:04:52.013419Z  INFO evm_eth_compliance::statetest::runner: TX len : 68
2023-01-26T11:04:52.013421Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T11:04:52.013657Z  INFO evm_eth_compliance::statetest::runner: UC : "addressOpcodes"
2023-01-26T11:04:52.013661Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 5176533,
    events_root: None,
}
2023-01-26T11:04:52.013672Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 23
2023-01-26T11:04:52.013674Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "addressOpcodes"::Merge::23
2023-01-26T11:04:52.013676Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stEIP2930/addressOpcodes.json"
2023-01-26T11:04:52.013679Z  INFO evm_eth_compliance::statetest::runner: TX len : 68
2023-01-26T11:04:52.013680Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T11:04:52.013912Z  INFO evm_eth_compliance::statetest::runner: UC : "addressOpcodes"
2023-01-26T11:04:52.013917Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 5182856,
    events_root: None,
}
2023-01-26T11:04:52.013927Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 24
2023-01-26T11:04:52.013931Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "addressOpcodes"::Merge::24
2023-01-26T11:04:52.013933Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stEIP2930/addressOpcodes.json"
2023-01-26T11:04:52.013935Z  INFO evm_eth_compliance::statetest::runner: TX len : 68
2023-01-26T11:04:52.013937Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T11:04:52.014222Z  INFO evm_eth_compliance::statetest::runner: UC : "addressOpcodes"
2023-01-26T11:04:52.014226Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 5230094,
    events_root: None,
}
2023-01-26T11:04:52.014237Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 25
2023-01-26T11:04:52.014240Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "addressOpcodes"::Merge::25
2023-01-26T11:04:52.014242Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stEIP2930/addressOpcodes.json"
2023-01-26T11:04:52.014245Z  INFO evm_eth_compliance::statetest::runner: TX len : 68
2023-01-26T11:04:52.014247Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T11:04:52.014492Z  INFO evm_eth_compliance::statetest::runner: UC : "addressOpcodes"
2023-01-26T11:04:52.014496Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3815317,
    events_root: None,
}
2023-01-26T11:04:52.014506Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 28
2023-01-26T11:04:52.014509Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "addressOpcodes"::Merge::28
2023-01-26T11:04:52.014510Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stEIP2930/addressOpcodes.json"
2023-01-26T11:04:52.014513Z  INFO evm_eth_compliance::statetest::runner: TX len : 68
2023-01-26T11:04:52.014514Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T11:04:52.014756Z  INFO evm_eth_compliance::statetest::runner: UC : "addressOpcodes"
2023-01-26T11:04:52.014760Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 5268935,
    events_root: None,
}
2023-01-26T11:04:52.014771Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 29
2023-01-26T11:04:52.014774Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "addressOpcodes"::Merge::29
2023-01-26T11:04:52.014776Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stEIP2930/addressOpcodes.json"
2023-01-26T11:04:52.014778Z  INFO evm_eth_compliance::statetest::runner: TX len : 68
2023-01-26T11:04:52.014780Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T11:04:52.015000Z  INFO evm_eth_compliance::statetest::runner: UC : "addressOpcodes"
2023-01-26T11:04:52.015004Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3854158,
    events_root: None,
}
2023-01-26T11:04:52.015014Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 30
2023-01-26T11:04:52.015017Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "addressOpcodes"::Merge::30
2023-01-26T11:04:52.015019Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stEIP2930/addressOpcodes.json"
2023-01-26T11:04:52.015021Z  INFO evm_eth_compliance::statetest::runner: TX len : 68
2023-01-26T11:04:52.015022Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T11:04:52.015411Z  INFO evm_eth_compliance::statetest::runner: UC : "addressOpcodes"
2023-01-26T11:04:52.015416Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 8483872,
    events_root: None,
}
2023-01-26T11:04:52.015430Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 31
2023-01-26T11:04:52.015432Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "addressOpcodes"::Merge::31
2023-01-26T11:04:52.015434Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stEIP2930/addressOpcodes.json"
2023-01-26T11:04:52.015437Z  INFO evm_eth_compliance::statetest::runner: TX len : 68
2023-01-26T11:04:52.015438Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T11:04:52.015816Z  INFO evm_eth_compliance::statetest::runner: UC : "addressOpcodes"
2023-01-26T11:04:52.015821Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 7061469,
    events_root: None,
}
2023-01-26T11:04:52.015835Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 32
2023-01-26T11:04:52.015838Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "addressOpcodes"::Merge::32
2023-01-26T11:04:52.015840Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stEIP2930/addressOpcodes.json"
2023-01-26T11:04:52.015842Z  INFO evm_eth_compliance::statetest::runner: TX len : 68
2023-01-26T11:04:52.015844Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T11:04:52.016233Z  INFO evm_eth_compliance::statetest::runner: UC : "addressOpcodes"
2023-01-26T11:04:52.016238Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 8492089,
    events_root: None,
}
2023-01-26T11:04:52.016252Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 33
2023-01-26T11:04:52.016255Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "addressOpcodes"::Merge::33
2023-01-26T11:04:52.016257Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stEIP2930/addressOpcodes.json"
2023-01-26T11:04:52.016260Z  INFO evm_eth_compliance::statetest::runner: TX len : 68
2023-01-26T11:04:52.016261Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T11:04:52.016649Z  INFO evm_eth_compliance::statetest::runner: UC : "addressOpcodes"
2023-01-26T11:04:52.016653Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 7068301,
    events_root: None,
}
2023-01-26T11:04:52.016667Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 34
2023-01-26T11:04:52.016670Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "addressOpcodes"::Merge::34
2023-01-26T11:04:52.016672Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stEIP2930/addressOpcodes.json"
2023-01-26T11:04:52.016674Z  INFO evm_eth_compliance::statetest::runner: TX len : 68
2023-01-26T11:04:52.016676Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T11:04:52.016911Z  INFO evm_eth_compliance::statetest::runner: UC : "addressOpcodes"
2023-01-26T11:04:52.016916Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 5176693,
    events_root: None,
}
2023-01-26T11:04:52.016926Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 35
2023-01-26T11:04:52.016929Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "addressOpcodes"::Merge::35
2023-01-26T11:04:52.016931Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stEIP2930/addressOpcodes.json"
2023-01-26T11:04:52.016934Z  INFO evm_eth_compliance::statetest::runner: TX len : 68
2023-01-26T11:04:52.016935Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T11:04:52.017149Z  INFO evm_eth_compliance::statetest::runner: UC : "addressOpcodes"
2023-01-26T11:04:52.017153Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3761834,
    events_root: None,
}
2023-01-26T11:04:52.017162Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 36
2023-01-26T11:04:52.017166Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "addressOpcodes"::Merge::36
2023-01-26T11:04:52.017168Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stEIP2930/addressOpcodes.json"
2023-01-26T11:04:52.017170Z  INFO evm_eth_compliance::statetest::runner: TX len : 68
2023-01-26T11:04:52.017172Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T11:04:52.017436Z  INFO evm_eth_compliance::statetest::runner: UC : "addressOpcodes"
2023-01-26T11:04:52.017441Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 5240153,
    events_root: None,
}
2023-01-26T11:04:52.017452Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 37
2023-01-26T11:04:52.017455Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "addressOpcodes"::Merge::37
2023-01-26T11:04:52.017457Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stEIP2930/addressOpcodes.json"
2023-01-26T11:04:52.017460Z  INFO evm_eth_compliance::statetest::runner: TX len : 68
2023-01-26T11:04:52.017461Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T11:04:52.017708Z  INFO evm_eth_compliance::statetest::runner: UC : "addressOpcodes"
2023-01-26T11:04:52.017713Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3825376,
    events_root: None,
}
2023-01-26T11:04:52.017723Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 40
2023-01-26T11:04:52.017726Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "addressOpcodes"::Merge::40
2023-01-26T11:04:52.017728Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stEIP2930/addressOpcodes.json"
2023-01-26T11:04:52.017731Z  INFO evm_eth_compliance::statetest::runner: TX len : 68
2023-01-26T11:04:52.017732Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T11:04:52.017974Z  INFO evm_eth_compliance::statetest::runner: UC : "addressOpcodes"
2023-01-26T11:04:52.017979Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 5281720,
    events_root: None,
}
2023-01-26T11:04:52.017989Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 41
2023-01-26T11:04:52.017991Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "addressOpcodes"::Merge::41
2023-01-26T11:04:52.017993Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stEIP2930/addressOpcodes.json"
2023-01-26T11:04:52.017995Z  INFO evm_eth_compliance::statetest::runner: TX len : 68
2023-01-26T11:04:52.017997Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T11:04:52.018238Z  INFO evm_eth_compliance::statetest::runner: UC : "addressOpcodes"
2023-01-26T11:04:52.018243Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 5288206,
    events_root: None,
}
2023-01-26T11:04:52.018254Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 42
2023-01-26T11:04:52.018257Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "addressOpcodes"::Merge::42
2023-01-26T11:04:52.018258Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stEIP2930/addressOpcodes.json"
2023-01-26T11:04:52.018261Z  INFO evm_eth_compliance::statetest::runner: TX len : 68
2023-01-26T11:04:52.018262Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T11:04:52.018665Z  INFO evm_eth_compliance::statetest::runner: UC : "addressOpcodes"
2023-01-26T11:04:52.018670Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 8964471,
    events_root: None,
}
2023-01-26T11:04:52.018685Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 43
2023-01-26T11:04:52.018687Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "addressOpcodes"::Merge::43
2023-01-26T11:04:52.018689Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stEIP2930/addressOpcodes.json"
2023-01-26T11:04:52.018694Z  INFO evm_eth_compliance::statetest::runner: TX len : 68
2023-01-26T11:04:52.018695Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T11:04:52.019097Z  INFO evm_eth_compliance::statetest::runner: UC : "addressOpcodes"
2023-01-26T11:04:52.019102Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 7540684,
    events_root: None,
}
2023-01-26T11:04:52.019116Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 44
2023-01-26T11:04:52.019120Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "addressOpcodes"::Merge::44
2023-01-26T11:04:52.019122Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stEIP2930/addressOpcodes.json"
2023-01-26T11:04:52.019124Z  INFO evm_eth_compliance::statetest::runner: TX len : 68
2023-01-26T11:04:52.019126Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T11:04:52.019526Z  INFO evm_eth_compliance::statetest::runner: UC : "addressOpcodes"
2023-01-26T11:04:52.019531Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 8979020,
    events_root: None,
}
2023-01-26T11:04:52.019545Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 45
2023-01-26T11:04:52.019548Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "addressOpcodes"::Merge::45
2023-01-26T11:04:52.019550Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stEIP2930/addressOpcodes.json"
2023-01-26T11:04:52.019553Z  INFO evm_eth_compliance::statetest::runner: TX len : 68
2023-01-26T11:04:52.019554Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T11:04:52.019929Z  INFO evm_eth_compliance::statetest::runner: UC : "addressOpcodes"
2023-01-26T11:04:52.019935Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 7555233,
    events_root: None,
}
2023-01-26T11:04:52.019948Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 46
2023-01-26T11:04:52.019950Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "addressOpcodes"::Merge::46
2023-01-26T11:04:52.019952Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stEIP2930/addressOpcodes.json"
2023-01-26T11:04:52.019954Z  INFO evm_eth_compliance::statetest::runner: TX len : 68
2023-01-26T11:04:52.019957Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T11:04:52.020190Z  INFO evm_eth_compliance::statetest::runner: UC : "addressOpcodes"
2023-01-26T11:04:52.020194Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 5186873,
    events_root: None,
}
2023-01-26T11:04:52.020205Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 47
2023-01-26T11:04:52.020207Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "addressOpcodes"::Merge::47
2023-01-26T11:04:52.020209Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stEIP2930/addressOpcodes.json"
2023-01-26T11:04:52.020212Z  INFO evm_eth_compliance::statetest::runner: TX len : 68
2023-01-26T11:04:52.020213Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T11:04:52.020446Z  INFO evm_eth_compliance::statetest::runner: UC : "addressOpcodes"
2023-01-26T11:04:52.020450Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 5193195,
    events_root: None,
}
2023-01-26T11:04:52.020460Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 2
2023-01-26T11:04:52.020464Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "addressOpcodes"::Merge::2
2023-01-26T11:04:52.020466Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stEIP2930/addressOpcodes.json"
2023-01-26T11:04:52.020468Z  INFO evm_eth_compliance::statetest::runner: TX len : 68
2023-01-26T11:04:52.020470Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T11:04:52.020730Z  INFO evm_eth_compliance::statetest::runner: UC : "addressOpcodes"
2023-01-26T11:04:52.020735Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 5222256,
    events_root: None,
}
2023-01-26T11:04:52.020745Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 3
2023-01-26T11:04:52.020748Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "addressOpcodes"::Merge::3
2023-01-26T11:04:52.020750Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stEIP2930/addressOpcodes.json"
2023-01-26T11:04:52.020753Z  INFO evm_eth_compliance::statetest::runner: TX len : 68
2023-01-26T11:04:52.020754Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T11:04:52.020993Z  INFO evm_eth_compliance::statetest::runner: UC : "addressOpcodes"
2023-01-26T11:04:52.020998Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3807478,
    events_root: None,
}
2023-01-26T11:04:52.021007Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 14
2023-01-26T11:04:52.021009Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "addressOpcodes"::Merge::14
2023-01-26T11:04:52.021012Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stEIP2930/addressOpcodes.json"
2023-01-26T11:04:52.021015Z  INFO evm_eth_compliance::statetest::runner: TX len : 68
2023-01-26T11:04:52.021016Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T11:04:52.021303Z  INFO evm_eth_compliance::statetest::runner: UC : "addressOpcodes"
2023-01-26T11:04:52.021307Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 5229814,
    events_root: None,
}
2023-01-26T11:04:52.021320Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 15
2023-01-26T11:04:52.021323Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "addressOpcodes"::Merge::15
2023-01-26T11:04:52.021325Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stEIP2930/addressOpcodes.json"
2023-01-26T11:04:52.021328Z  INFO evm_eth_compliance::statetest::runner: TX len : 68
2023-01-26T11:04:52.021330Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T11:04:52.021618Z  INFO evm_eth_compliance::statetest::runner: UC : "addressOpcodes"
2023-01-26T11:04:52.021624Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3815037,
    events_root: None,
}
2023-01-26T11:04:52.021633Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 26
2023-01-26T11:04:52.021636Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "addressOpcodes"::Merge::26
2023-01-26T11:04:52.021638Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stEIP2930/addressOpcodes.json"
2023-01-26T11:04:52.021640Z  INFO evm_eth_compliance::statetest::runner: TX len : 68
2023-01-26T11:04:52.021642Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T11:04:52.021901Z  INFO evm_eth_compliance::statetest::runner: UC : "addressOpcodes"
2023-01-26T11:04:52.021905Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 5230094,
    events_root: None,
}
2023-01-26T11:04:52.021916Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 27
2023-01-26T11:04:52.021919Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "addressOpcodes"::Merge::27
2023-01-26T11:04:52.021921Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stEIP2930/addressOpcodes.json"
2023-01-26T11:04:52.021923Z  INFO evm_eth_compliance::statetest::runner: TX len : 68
2023-01-26T11:04:52.021924Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T11:04:52.022165Z  INFO evm_eth_compliance::statetest::runner: UC : "addressOpcodes"
2023-01-26T11:04:52.022169Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3815317,
    events_root: None,
}
2023-01-26T11:04:52.022180Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 38
2023-01-26T11:04:52.022182Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "addressOpcodes"::Merge::38
2023-01-26T11:04:52.022184Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stEIP2930/addressOpcodes.json"
2023-01-26T11:04:52.022187Z  INFO evm_eth_compliance::statetest::runner: TX len : 68
2023-01-26T11:04:52.022188Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T11:04:52.022463Z  INFO evm_eth_compliance::statetest::runner: UC : "addressOpcodes"
2023-01-26T11:04:52.022467Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 5240153,
    events_root: None,
}
2023-01-26T11:04:52.022478Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 39
2023-01-26T11:04:52.022481Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "addressOpcodes"::Merge::39
2023-01-26T11:04:52.022483Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stEIP2930/addressOpcodes.json"
2023-01-26T11:04:52.022485Z  INFO evm_eth_compliance::statetest::runner: TX len : 68
2023-01-26T11:04:52.022486Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T11:04:52.022726Z  INFO evm_eth_compliance::statetest::runner: UC : "addressOpcodes"
2023-01-26T11:04:52.022730Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3825376,
    events_root: None,
}
2023-01-26T11:04:52.024723Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:414.334541ms
2023-01-26T11:04:52.301567Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "./test-vectors/tests/GeneralStateTests/stEIP2930/coinbaseT01.json", Total Files :: 1
2023-01-26T11:04:52.331287Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-26T11:04:52.331478Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T11:04:52.331482Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-26T11:04:52.331536Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T11:04:52.331538Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 2
2023-01-26T11:04:52.331605Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T11:04:52.331680Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 1
2023-01-26T11:04:52.331683Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "coinbaseT01"::Berlin::1
2023-01-26T11:04:52.331686Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stEIP2930/coinbaseT01.json"
2023-01-26T11:04:52.331689Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-26T11:04:52.331690Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T11:04:52.682746Z  INFO evm_eth_compliance::statetest::runner: UC : "coinbaseT01"
2023-01-26T11:04:52.682762Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 4008984,
    events_root: None,
}
2023-01-26T11:04:52.682778Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-26T11:04:52.682785Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "coinbaseT01"::Berlin::0
2023-01-26T11:04:52.682787Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stEIP2930/coinbaseT01.json"
2023-01-26T11:04:52.682791Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-26T11:04:52.682792Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T11:04:52.682991Z  INFO evm_eth_compliance::statetest::runner: UC : "coinbaseT01"
2023-01-26T11:04:52.682996Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3110225,
    events_root: None,
}
2023-01-26T11:04:52.683007Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 2
2023-01-26T11:04:52.683010Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "coinbaseT01"::Berlin::2
2023-01-26T11:04:52.683013Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stEIP2930/coinbaseT01.json"
2023-01-26T11:04:52.683016Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-26T11:04:52.683019Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T11:04:52.683202Z  INFO evm_eth_compliance::statetest::runner: UC : "coinbaseT01"
2023-01-26T11:04:52.683206Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3110225,
    events_root: None,
}
2023-01-26T11:04:52.683218Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 1
2023-01-26T11:04:52.683221Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "coinbaseT01"::London::1
2023-01-26T11:04:52.683224Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stEIP2930/coinbaseT01.json"
2023-01-26T11:04:52.683227Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-26T11:04:52.683229Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T11:04:52.683411Z  INFO evm_eth_compliance::statetest::runner: UC : "coinbaseT01"
2023-01-26T11:04:52.683416Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3110225,
    events_root: None,
}
2023-01-26T11:04:52.683427Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-26T11:04:52.683430Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "coinbaseT01"::London::0
2023-01-26T11:04:52.683433Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stEIP2930/coinbaseT01.json"
2023-01-26T11:04:52.683436Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-26T11:04:52.683438Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T11:04:52.683617Z  INFO evm_eth_compliance::statetest::runner: UC : "coinbaseT01"
2023-01-26T11:04:52.683622Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3110225,
    events_root: None,
}
2023-01-26T11:04:52.683634Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 2
2023-01-26T11:04:52.683637Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "coinbaseT01"::London::2
2023-01-26T11:04:52.683640Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stEIP2930/coinbaseT01.json"
2023-01-26T11:04:52.683643Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-26T11:04:52.683645Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T11:04:52.683826Z  INFO evm_eth_compliance::statetest::runner: UC : "coinbaseT01"
2023-01-26T11:04:52.683831Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3110225,
    events_root: None,
}
2023-01-26T11:04:52.683842Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 1
2023-01-26T11:04:52.683846Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "coinbaseT01"::Merge::1
2023-01-26T11:04:52.683848Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stEIP2930/coinbaseT01.json"
2023-01-26T11:04:52.683852Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-26T11:04:52.683854Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T11:04:52.684034Z  INFO evm_eth_compliance::statetest::runner: UC : "coinbaseT01"
2023-01-26T11:04:52.684039Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3110225,
    events_root: None,
}
2023-01-26T11:04:52.684050Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-26T11:04:52.684054Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "coinbaseT01"::Merge::0
2023-01-26T11:04:52.684056Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stEIP2930/coinbaseT01.json"
2023-01-26T11:04:52.684060Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-26T11:04:52.684062Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T11:04:52.684240Z  INFO evm_eth_compliance::statetest::runner: UC : "coinbaseT01"
2023-01-26T11:04:52.684245Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3110225,
    events_root: None,
}
2023-01-26T11:04:52.684255Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 2
2023-01-26T11:04:52.684258Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "coinbaseT01"::Merge::2
2023-01-26T11:04:52.684261Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stEIP2930/coinbaseT01.json"
2023-01-26T11:04:52.684266Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-26T11:04:52.684268Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T11:04:52.684460Z  INFO evm_eth_compliance::statetest::runner: UC : "coinbaseT01"
2023-01-26T11:04:52.684465Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3110225,
    events_root: None,
}
2023-01-26T11:04:52.686138Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:353.19324ms
2023-01-26T11:04:52.955926Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "./test-vectors/tests/GeneralStateTests/stEIP2930/coinbaseT2.json", Total Files :: 1
2023-01-26T11:04:52.985126Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-26T11:04:52.985321Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T11:04:52.985325Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-26T11:04:52.985390Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T11:04:52.985394Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 2
2023-01-26T11:04:52.985462Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T11:04:52.985545Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-26T11:04:52.985549Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "coinbaseT2"::London::0
2023-01-26T11:04:52.985552Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stEIP2930/coinbaseT2.json"
2023-01-26T11:04:52.985555Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-26T11:04:52.985557Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T11:04:53.370499Z  INFO evm_eth_compliance::statetest::runner: UC : "coinbaseT2"
2023-01-26T11:04:53.370514Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 4008984,
    events_root: None,
}
2023-01-26T11:04:53.370527Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 1
2023-01-26T11:04:53.370533Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "coinbaseT2"::London::1
2023-01-26T11:04:53.370535Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stEIP2930/coinbaseT2.json"
2023-01-26T11:04:53.370538Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-26T11:04:53.370539Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T11:04:53.370735Z  INFO evm_eth_compliance::statetest::runner: UC : "coinbaseT2"
2023-01-26T11:04:53.370740Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3110225,
    events_root: None,
}
2023-01-26T11:04:53.370749Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-26T11:04:53.370751Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "coinbaseT2"::Merge::0
2023-01-26T11:04:53.370753Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stEIP2930/coinbaseT2.json"
2023-01-26T11:04:53.370757Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-26T11:04:53.370759Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T11:04:53.370933Z  INFO evm_eth_compliance::statetest::runner: UC : "coinbaseT2"
2023-01-26T11:04:53.370937Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3110225,
    events_root: None,
}
2023-01-26T11:04:53.370945Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 1
2023-01-26T11:04:53.370949Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "coinbaseT2"::Merge::1
2023-01-26T11:04:53.370951Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stEIP2930/coinbaseT2.json"
2023-01-26T11:04:53.370954Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-26T11:04:53.370955Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T11:04:53.371129Z  INFO evm_eth_compliance::statetest::runner: UC : "coinbaseT2"
2023-01-26T11:04:53.371134Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3110225,
    events_root: None,
}
2023-01-26T11:04:53.372851Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:386.018973ms
2023-01-26T11:04:53.644278Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "./test-vectors/tests/GeneralStateTests/stEIP2930/manualCreate.json", Total Files :: 1
2023-01-26T11:04:53.673633Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-26T11:04:53.673823Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T11:04:53.673898Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 2
2023-01-26T11:04:53.673901Z  WARN evm_eth_compliance::statetest::runner: Skipping TestCase no valid actor "manualCreate"::Berlin::2
2023-01-26T11:04:53.673904Z  WARN evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stEIP2930/manualCreate.json"
2023-01-26T11:04:53.673907Z  WARN evm_eth_compliance::statetest::runner: TX len : 23
2023-01-26T11:04:53.673909Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-26T11:04:53.673911Z  WARN evm_eth_compliance::statetest::runner: Skipping TestCase no valid actor "manualCreate"::Berlin::0
2023-01-26T11:04:53.673913Z  WARN evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stEIP2930/manualCreate.json"
2023-01-26T11:04:53.673916Z  WARN evm_eth_compliance::statetest::runner: TX len : 23
2023-01-26T11:04:53.673917Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 1
2023-01-26T11:04:53.673919Z  WARN evm_eth_compliance::statetest::runner: Skipping TestCase no valid actor "manualCreate"::Berlin::1
2023-01-26T11:04:53.673920Z  WARN evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stEIP2930/manualCreate.json"
2023-01-26T11:04:53.673923Z  WARN evm_eth_compliance::statetest::runner: TX len : 23
2023-01-26T11:04:53.673924Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 2
2023-01-26T11:04:53.673926Z  WARN evm_eth_compliance::statetest::runner: Skipping TestCase no valid actor "manualCreate"::London::2
2023-01-26T11:04:53.673927Z  WARN evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stEIP2930/manualCreate.json"
2023-01-26T11:04:53.673929Z  WARN evm_eth_compliance::statetest::runner: TX len : 23
2023-01-26T11:04:53.673931Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-26T11:04:53.673932Z  WARN evm_eth_compliance::statetest::runner: Skipping TestCase no valid actor "manualCreate"::London::0
2023-01-26T11:04:53.673934Z  WARN evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stEIP2930/manualCreate.json"
2023-01-26T11:04:53.673936Z  WARN evm_eth_compliance::statetest::runner: TX len : 23
2023-01-26T11:04:53.673937Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 1
2023-01-26T11:04:53.673939Z  WARN evm_eth_compliance::statetest::runner: Skipping TestCase no valid actor "manualCreate"::London::1
2023-01-26T11:04:53.673940Z  WARN evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stEIP2930/manualCreate.json"
2023-01-26T11:04:53.673942Z  WARN evm_eth_compliance::statetest::runner: TX len : 23
2023-01-26T11:04:53.673944Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 2
2023-01-26T11:04:53.673945Z  WARN evm_eth_compliance::statetest::runner: Skipping TestCase no valid actor "manualCreate"::Merge::2
2023-01-26T11:04:53.673947Z  WARN evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stEIP2930/manualCreate.json"
2023-01-26T11:04:53.673949Z  WARN evm_eth_compliance::statetest::runner: TX len : 23
2023-01-26T11:04:53.673950Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-26T11:04:53.673952Z  WARN evm_eth_compliance::statetest::runner: Skipping TestCase no valid actor "manualCreate"::Merge::0
2023-01-26T11:04:53.673953Z  WARN evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stEIP2930/manualCreate.json"
2023-01-26T11:04:53.673955Z  WARN evm_eth_compliance::statetest::runner: TX len : 23
2023-01-26T11:04:53.673957Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 1
2023-01-26T11:04:53.673958Z  WARN evm_eth_compliance::statetest::runner: Skipping TestCase no valid actor "manualCreate"::Merge::1
2023-01-26T11:04:53.673961Z  WARN evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stEIP2930/manualCreate.json"
2023-01-26T11:04:53.673963Z  WARN evm_eth_compliance::statetest::runner: TX len : 23
2023-01-26T11:04:53.674592Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:335.682s
2023-01-26T11:04:53.939620Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "./test-vectors/tests/GeneralStateTests/stEIP2930/storageCosts.json", Total Files :: 1
2023-01-26T11:04:53.969193Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-26T11:04:53.969383Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T11:04:53.969387Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-26T11:04:53.969440Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T11:04:53.969442Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 2
2023-01-26T11:04:53.969500Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T11:04:53.969502Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 3
2023-01-26T11:04:53.969556Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T11:04:53.969558Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 4
2023-01-26T11:04:53.969605Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T11:04:53.969607Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 5
2023-01-26T11:04:53.969667Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T11:04:53.969669Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 6
2023-01-26T11:04:53.969721Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T11:04:53.969723Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 7
2023-01-26T11:04:53.969762Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T11:04:53.969764Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 8
2023-01-26T11:04:53.969806Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T11:04:53.969808Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 9
2023-01-26T11:04:53.969865Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T11:04:53.969867Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 10
2023-01-26T11:04:53.969909Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T11:04:53.969910Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 11
2023-01-26T11:04:53.969954Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T11:04:53.970026Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-26T11:04:53.970029Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "storageCosts"::Berlin::0
2023-01-26T11:04:53.970032Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stEIP2930/storageCosts.json"
2023-01-26T11:04:53.970035Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-26T11:04:53.970036Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T11:04:54.316309Z  INFO evm_eth_compliance::statetest::runner: UC : "storageCosts"
2023-01-26T11:04:54.316357Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 6900765,
    events_root: None,
}
2023-01-26T11:04:54.316386Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 35
2023-01-26T11:04:54.316401Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "storageCosts"::Berlin::35
2023-01-26T11:04:54.316408Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stEIP2930/storageCosts.json"
2023-01-26T11:04:54.316417Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-26T11:04:54.316423Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T11:04:54.316804Z  INFO evm_eth_compliance::statetest::runner: UC : "storageCosts"
2023-01-26T11:04:54.316820Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 7767621,
    events_root: None,
}
2023-01-26T11:04:54.316842Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 6
2023-01-26T11:04:54.316851Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "storageCosts"::Berlin::6
2023-01-26T11:04:54.316857Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stEIP2930/storageCosts.json"
2023-01-26T11:04:54.316865Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-26T11:04:54.316871Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T11:04:54.317228Z  INFO evm_eth_compliance::statetest::runner: UC : "storageCosts"
2023-01-26T11:04:54.317244Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 7773387,
    events_root: None,
}
2023-01-26T11:04:54.317265Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 12
2023-01-26T11:04:54.317273Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "storageCosts"::Berlin::12
2023-01-26T11:04:54.317279Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stEIP2930/storageCosts.json"
2023-01-26T11:04:54.317287Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-26T11:04:54.317294Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T11:04:54.317630Z  INFO evm_eth_compliance::statetest::runner: UC : "storageCosts"
2023-01-26T11:04:54.317647Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 6348753,
    events_root: None,
}
2023-01-26T11:04:54.317667Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 18
2023-01-26T11:04:54.317675Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "storageCosts"::Berlin::18
2023-01-26T11:04:54.317682Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stEIP2930/storageCosts.json"
2023-01-26T11:04:54.317690Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-26T11:04:54.317696Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T11:04:54.318029Z  INFO evm_eth_compliance::statetest::runner: UC : "storageCosts"
2023-01-26T11:04:54.318045Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 5954701,
    events_root: None,
}
2023-01-26T11:04:54.318064Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 3
2023-01-26T11:04:54.318068Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "storageCosts"::Berlin::3
2023-01-26T11:04:54.318071Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stEIP2930/storageCosts.json"
2023-01-26T11:04:54.318074Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-26T11:04:54.318075Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T11:04:54.318395Z  INFO evm_eth_compliance::statetest::runner: UC : "storageCosts"
2023-01-26T11:04:54.318412Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 5595490,
    events_root: None,
}
2023-01-26T11:04:54.318432Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 9
2023-01-26T11:04:54.318440Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "storageCosts"::Berlin::9
2023-01-26T11:04:54.318446Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stEIP2930/storageCosts.json"
2023-01-26T11:04:54.318454Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-26T11:04:54.318460Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T11:04:54.318798Z  INFO evm_eth_compliance::statetest::runner: UC : "storageCosts"
2023-01-26T11:04:54.318815Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 5896229,
    events_root: None,
}
2023-01-26T11:04:54.318835Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 15
2023-01-26T11:04:54.318840Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "storageCosts"::Berlin::15
2023-01-26T11:04:54.318842Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stEIP2930/storageCosts.json"
2023-01-26T11:04:54.318845Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-26T11:04:54.318847Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T11:04:54.319144Z  INFO evm_eth_compliance::statetest::runner: UC : "storageCosts"
2023-01-26T11:04:54.319150Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 7768927,
    events_root: None,
}
2023-01-26T11:04:54.319165Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 21
2023-01-26T11:04:54.319168Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "storageCosts"::Berlin::21
2023-01-26T11:04:54.319171Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stEIP2930/storageCosts.json"
2023-01-26T11:04:54.319174Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-26T11:04:54.319176Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T11:04:54.319439Z  INFO evm_eth_compliance::statetest::runner: UC : "storageCosts"
2023-01-26T11:04:54.319445Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 6348727,
    events_root: None,
}
2023-01-26T11:04:54.319458Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 4
2023-01-26T11:04:54.319461Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "storageCosts"::Berlin::4
2023-01-26T11:04:54.319464Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stEIP2930/storageCosts.json"
2023-01-26T11:04:54.319467Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-26T11:04:54.319469Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T11:04:54.319737Z  INFO evm_eth_compliance::statetest::runner: UC : "storageCosts"
2023-01-26T11:04:54.319742Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 7079869,
    events_root: None,
}
2023-01-26T11:04:54.319756Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 10
2023-01-26T11:04:54.319759Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "storageCosts"::Berlin::10
2023-01-26T11:04:54.319762Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stEIP2930/storageCosts.json"
2023-01-26T11:04:54.319765Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-26T11:04:54.319767Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T11:04:54.320045Z  INFO evm_eth_compliance::statetest::runner: UC : "storageCosts"
2023-01-26T11:04:54.320050Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 5896229,
    events_root: None,
}
2023-01-26T11:04:54.320064Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 16
2023-01-26T11:04:54.320067Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "storageCosts"::Berlin::16
2023-01-26T11:04:54.320070Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stEIP2930/storageCosts.json"
2023-01-26T11:04:54.320073Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-26T11:04:54.320075Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T11:04:54.320359Z  INFO evm_eth_compliance::statetest::runner: UC : "storageCosts"
2023-01-26T11:04:54.320364Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 7768927,
    events_root: None,
}
2023-01-26T11:04:54.320378Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 22
2023-01-26T11:04:54.320381Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "storageCosts"::Berlin::22
2023-01-26T11:04:54.320384Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stEIP2930/storageCosts.json"
2023-01-26T11:04:54.320387Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-26T11:04:54.320389Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T11:04:54.320654Z  INFO evm_eth_compliance::statetest::runner: UC : "storageCosts"
2023-01-26T11:04:54.320659Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 6348727,
    events_root: None,
}
2023-01-26T11:04:54.320672Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 5
2023-01-26T11:04:54.320675Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "storageCosts"::Berlin::5
2023-01-26T11:04:54.320679Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stEIP2930/storageCosts.json"
2023-01-26T11:04:54.320682Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-26T11:04:54.320684Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T11:04:54.320940Z  INFO evm_eth_compliance::statetest::runner: UC : "storageCosts"
2023-01-26T11:04:54.320945Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 6443019,
    events_root: None,
}
2023-01-26T11:04:54.320959Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 11
2023-01-26T11:04:54.320962Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "storageCosts"::Berlin::11
2023-01-26T11:04:54.320964Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stEIP2930/storageCosts.json"
2023-01-26T11:04:54.320967Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-26T11:04:54.320969Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T11:04:54.321239Z  INFO evm_eth_compliance::statetest::runner: UC : "storageCosts"
2023-01-26T11:04:54.321244Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 4975174,
    events_root: None,
}
2023-01-26T11:04:54.321257Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 17
2023-01-26T11:04:54.321260Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "storageCosts"::Berlin::17
2023-01-26T11:04:54.321263Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stEIP2930/storageCosts.json"
2023-01-26T11:04:54.321267Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-26T11:04:54.321269Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T11:04:54.321531Z  INFO evm_eth_compliance::statetest::runner: UC : "storageCosts"
2023-01-26T11:04:54.321537Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 5935081,
    events_root: None,
}
2023-01-26T11:04:54.321550Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 23
2023-01-26T11:04:54.321553Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "storageCosts"::Berlin::23
2023-01-26T11:04:54.321556Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stEIP2930/storageCosts.json"
2023-01-26T11:04:54.321560Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-26T11:04:54.321562Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T11:04:54.321806Z  INFO evm_eth_compliance::statetest::runner: UC : "storageCosts"
2023-01-26T11:04:54.321811Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 5546772,
    events_root: None,
}
2023-01-26T11:04:54.321824Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 2
2023-01-26T11:04:54.321827Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "storageCosts"::Berlin::2
2023-01-26T11:04:54.321830Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stEIP2930/storageCosts.json"
2023-01-26T11:04:54.321833Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-26T11:04:54.321835Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T11:04:54.322092Z  INFO evm_eth_compliance::statetest::runner: UC : "storageCosts"
2023-01-26T11:04:54.322097Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 6831327,
    events_root: None,
}
2023-01-26T11:04:54.322111Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 8
2023-01-26T11:04:54.322114Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "storageCosts"::Berlin::8
2023-01-26T11:04:54.322116Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stEIP2930/storageCosts.json"
2023-01-26T11:04:54.322120Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-26T11:04:54.322122Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T11:04:54.322376Z  INFO evm_eth_compliance::statetest::runner: UC : "storageCosts"
2023-01-26T11:04:54.322381Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 6459553,
    events_root: None,
}
2023-01-26T11:04:54.322395Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 14
2023-01-26T11:04:54.322398Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "storageCosts"::Berlin::14
2023-01-26T11:04:54.322400Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stEIP2930/storageCosts.json"
2023-01-26T11:04:54.322403Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-26T11:04:54.322406Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T11:04:54.322670Z  INFO evm_eth_compliance::statetest::runner: UC : "storageCosts"
2023-01-26T11:04:54.322675Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 5935081,
    events_root: None,
}
2023-01-26T11:04:54.322691Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 20
2023-01-26T11:04:54.322695Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "storageCosts"::Berlin::20
2023-01-26T11:04:54.322698Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stEIP2930/storageCosts.json"
2023-01-26T11:04:54.322702Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-26T11:04:54.322703Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T11:04:54.322957Z  INFO evm_eth_compliance::statetest::runner: UC : "storageCosts"
2023-01-26T11:04:54.322962Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 5546772,
    events_root: None,
}
2023-01-26T11:04:54.322975Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 1
2023-01-26T11:04:54.322978Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "storageCosts"::Berlin::1
2023-01-26T11:04:54.322980Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stEIP2930/storageCosts.json"
2023-01-26T11:04:54.322984Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-26T11:04:54.322986Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T11:04:54.323229Z  INFO evm_eth_compliance::statetest::runner: UC : "storageCosts"
2023-01-26T11:04:54.323234Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 4958442,
    events_root: None,
}
2023-01-26T11:04:54.323247Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 7
2023-01-26T11:04:54.323250Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "storageCosts"::Berlin::7
2023-01-26T11:04:54.323253Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stEIP2930/storageCosts.json"
2023-01-26T11:04:54.323256Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-26T11:04:54.323258Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T11:04:54.323553Z  INFO evm_eth_compliance::statetest::runner: UC : "storageCosts"
2023-01-26T11:04:54.323559Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 4974992,
    events_root: None,
}
2023-01-26T11:04:54.323572Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 13
2023-01-26T11:04:54.323576Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "storageCosts"::Berlin::13
2023-01-26T11:04:54.323578Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stEIP2930/storageCosts.json"
2023-01-26T11:04:54.323581Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-26T11:04:54.323583Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T11:04:54.323876Z  INFO evm_eth_compliance::statetest::runner: UC : "storageCosts"
2023-01-26T11:04:54.323881Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 5934899,
    events_root: None,
}
2023-01-26T11:04:54.323892Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 19
2023-01-26T11:04:54.323896Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "storageCosts"::Berlin::19
2023-01-26T11:04:54.323898Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stEIP2930/storageCosts.json"
2023-01-26T11:04:54.323900Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-26T11:04:54.323901Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T11:04:54.324144Z  INFO evm_eth_compliance::statetest::runner: UC : "storageCosts"
2023-01-26T11:04:54.324148Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 5546590,
    events_root: None,
}
2023-01-26T11:04:54.324159Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 24
2023-01-26T11:04:54.324161Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "storageCosts"::Berlin::24
2023-01-26T11:04:54.324163Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stEIP2930/storageCosts.json"
2023-01-26T11:04:54.324165Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-26T11:04:54.324167Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T11:04:54.324415Z  INFO evm_eth_compliance::statetest::runner: UC : "storageCosts"
2023-01-26T11:04:54.324419Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 5604459,
    events_root: None,
}
2023-01-26T11:04:54.324430Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 25
2023-01-26T11:04:54.324433Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "storageCosts"::Berlin::25
2023-01-26T11:04:54.324435Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stEIP2930/storageCosts.json"
2023-01-26T11:04:54.324437Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-26T11:04:54.324438Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T11:04:54.324692Z  INFO evm_eth_compliance::statetest::runner: UC : "storageCosts"
2023-01-26T11:04:54.324697Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 5967735,
    events_root: None,
}
2023-01-26T11:04:54.324707Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 26
2023-01-26T11:04:54.324710Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "storageCosts"::Berlin::26
2023-01-26T11:04:54.324712Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stEIP2930/storageCosts.json"
2023-01-26T11:04:54.324714Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-26T11:04:54.324715Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T11:04:54.324983Z  INFO evm_eth_compliance::statetest::runner: UC : "storageCosts"
2023-01-26T11:04:54.324988Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 7477043,
    events_root: None,
}
2023-01-26T11:04:54.325000Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 27
2023-01-26T11:04:54.325002Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "storageCosts"::Berlin::27
2023-01-26T11:04:54.325004Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stEIP2930/storageCosts.json"
2023-01-26T11:04:54.325006Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-26T11:04:54.325008Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T11:04:54.325281Z  INFO evm_eth_compliance::statetest::runner: UC : "storageCosts"
2023-01-26T11:04:54.325286Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 7458001,
    events_root: None,
}
2023-01-26T11:04:54.325298Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 28
2023-01-26T11:04:54.325301Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "storageCosts"::Berlin::28
2023-01-26T11:04:54.325303Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stEIP2930/storageCosts.json"
2023-01-26T11:04:54.325305Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-26T11:04:54.325306Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T11:04:54.325579Z  INFO evm_eth_compliance::statetest::runner: UC : "storageCosts"
2023-01-26T11:04:54.325584Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 7473267,
    events_root: None,
}
2023-01-26T11:04:54.325596Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 29
2023-01-26T11:04:54.325599Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "storageCosts"::Berlin::29
2023-01-26T11:04:54.325600Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stEIP2930/storageCosts.json"
2023-01-26T11:04:54.325604Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-26T11:04:54.325605Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T11:04:54.325880Z  INFO evm_eth_compliance::statetest::runner: UC : "storageCosts"
2023-01-26T11:04:54.325885Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 7458887,
    events_root: None,
}
2023-01-26T11:04:54.325897Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 30
2023-01-26T11:04:54.325900Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "storageCosts"::Berlin::30
2023-01-26T11:04:54.325902Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stEIP2930/storageCosts.json"
2023-01-26T11:04:54.325904Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-26T11:04:54.325905Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T11:04:54.326136Z  INFO evm_eth_compliance::statetest::runner: UC : "storageCosts"
2023-01-26T11:04:54.326141Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 4964789,
    events_root: None,
}
2023-01-26T11:04:54.326151Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 31
2023-01-26T11:04:54.326154Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "storageCosts"::Berlin::31
2023-01-26T11:04:54.326156Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stEIP2930/storageCosts.json"
2023-01-26T11:04:54.326158Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-26T11:04:54.326160Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T11:04:54.326391Z  INFO evm_eth_compliance::statetest::runner: UC : "storageCosts"
2023-01-26T11:04:54.326395Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 4982927,
    events_root: None,
}
2023-01-26T11:04:54.326406Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 32
2023-01-26T11:04:54.326408Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "storageCosts"::Berlin::32
2023-01-26T11:04:54.326410Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stEIP2930/storageCosts.json"
2023-01-26T11:04:54.326413Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-26T11:04:54.326414Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T11:04:54.326566Z  INFO evm_eth_compliance::statetest::runner: UC : "storageCosts"
2023-01-26T11:04:54.326570Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2524286,
    events_root: None,
}
2023-01-26T11:04:54.326576Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 33
2023-01-26T11:04:54.326579Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "storageCosts"::Berlin::33
2023-01-26T11:04:54.326581Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stEIP2930/storageCosts.json"
2023-01-26T11:04:54.326584Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-26T11:04:54.326585Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T11:04:54.326727Z  INFO evm_eth_compliance::statetest::runner: UC : "storageCosts"
2023-01-26T11:04:54.326731Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2524286,
    events_root: None,
}
2023-01-26T11:04:54.326737Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 34
2023-01-26T11:04:54.326739Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "storageCosts"::Berlin::34
2023-01-26T11:04:54.326741Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stEIP2930/storageCosts.json"
2023-01-26T11:04:54.326744Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-26T11:04:54.326745Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T11:04:54.326884Z  INFO evm_eth_compliance::statetest::runner: UC : "storageCosts"
2023-01-26T11:04:54.326889Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2524286,
    events_root: None,
}
2023-01-26T11:04:54.326895Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-26T11:04:54.326898Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "storageCosts"::London::0
2023-01-26T11:04:54.326899Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stEIP2930/storageCosts.json"
2023-01-26T11:04:54.326903Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-26T11:04:54.326905Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T11:04:54.327138Z  INFO evm_eth_compliance::statetest::runner: UC : "storageCosts"
2023-01-26T11:04:54.327143Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 4470322,
    events_root: None,
}
2023-01-26T11:04:54.327152Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 35
2023-01-26T11:04:54.327155Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "storageCosts"::London::35
2023-01-26T11:04:54.327156Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stEIP2930/storageCosts.json"
2023-01-26T11:04:54.327159Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-26T11:04:54.327160Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T11:04:54.327391Z  INFO evm_eth_compliance::statetest::runner: UC : "storageCosts"
2023-01-26T11:04:54.327395Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 4470322,
    events_root: None,
}
2023-01-26T11:04:54.327405Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 6
2023-01-26T11:04:54.327408Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "storageCosts"::London::6
2023-01-26T11:04:54.327409Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stEIP2930/storageCosts.json"
2023-01-26T11:04:54.327412Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-26T11:04:54.327413Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T11:04:54.327642Z  INFO evm_eth_compliance::statetest::runner: UC : "storageCosts"
2023-01-26T11:04:54.327646Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 4470322,
    events_root: None,
}
2023-01-26T11:04:54.327656Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 12
2023-01-26T11:04:54.327658Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "storageCosts"::London::12
2023-01-26T11:04:54.327660Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stEIP2930/storageCosts.json"
2023-01-26T11:04:54.327662Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-26T11:04:54.327664Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T11:04:54.327899Z  INFO evm_eth_compliance::statetest::runner: UC : "storageCosts"
2023-01-26T11:04:54.327903Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 4470322,
    events_root: None,
}
2023-01-26T11:04:54.327913Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 18
2023-01-26T11:04:54.327916Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "storageCosts"::London::18
2023-01-26T11:04:54.327918Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stEIP2930/storageCosts.json"
2023-01-26T11:04:54.327920Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-26T11:04:54.327922Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T11:04:54.328150Z  INFO evm_eth_compliance::statetest::runner: UC : "storageCosts"
2023-01-26T11:04:54.328155Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 4470322,
    events_root: None,
}
2023-01-26T11:04:54.328164Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 3
2023-01-26T11:04:54.328168Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "storageCosts"::London::3
2023-01-26T11:04:54.328169Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stEIP2930/storageCosts.json"
2023-01-26T11:04:54.328172Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-26T11:04:54.328173Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T11:04:54.328402Z  INFO evm_eth_compliance::statetest::runner: UC : "storageCosts"
2023-01-26T11:04:54.328406Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 4470295,
    events_root: None,
}
2023-01-26T11:04:54.328417Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 9
2023-01-26T11:04:54.328419Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "storageCosts"::London::9
2023-01-26T11:04:54.328421Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stEIP2930/storageCosts.json"
2023-01-26T11:04:54.328423Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-26T11:04:54.328425Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T11:04:54.328653Z  INFO evm_eth_compliance::statetest::runner: UC : "storageCosts"
2023-01-26T11:04:54.328658Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 4470295,
    events_root: None,
}
2023-01-26T11:04:54.328667Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 15
2023-01-26T11:04:54.328670Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "storageCosts"::London::15
2023-01-26T11:04:54.328672Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stEIP2930/storageCosts.json"
2023-01-26T11:04:54.328674Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-26T11:04:54.328675Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T11:04:54.328906Z  INFO evm_eth_compliance::statetest::runner: UC : "storageCosts"
2023-01-26T11:04:54.328911Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 4470295,
    events_root: None,
}
2023-01-26T11:04:54.328920Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 21
2023-01-26T11:04:54.328923Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "storageCosts"::London::21
2023-01-26T11:04:54.328925Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stEIP2930/storageCosts.json"
2023-01-26T11:04:54.328927Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-26T11:04:54.328928Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T11:04:54.329157Z  INFO evm_eth_compliance::statetest::runner: UC : "storageCosts"
2023-01-26T11:04:54.329162Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 4470295,
    events_root: None,
}
2023-01-26T11:04:54.329171Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 4
2023-01-26T11:04:54.329173Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "storageCosts"::London::4
2023-01-26T11:04:54.329175Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stEIP2930/storageCosts.json"
2023-01-26T11:04:54.329178Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-26T11:04:54.329179Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T11:04:54.329428Z  INFO evm_eth_compliance::statetest::runner: UC : "storageCosts"
2023-01-26T11:04:54.329433Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 4470295,
    events_root: None,
}
2023-01-26T11:04:54.329443Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 10
2023-01-26T11:04:54.329445Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "storageCosts"::London::10
2023-01-26T11:04:54.329447Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stEIP2930/storageCosts.json"
2023-01-26T11:04:54.329450Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-26T11:04:54.329452Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T11:04:54.329683Z  INFO evm_eth_compliance::statetest::runner: UC : "storageCosts"
2023-01-26T11:04:54.329688Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 4470295,
    events_root: None,
}
2023-01-26T11:04:54.329698Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 16
2023-01-26T11:04:54.329701Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "storageCosts"::London::16
2023-01-26T11:04:54.329702Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stEIP2930/storageCosts.json"
2023-01-26T11:04:54.329705Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-26T11:04:54.329706Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T11:04:54.329935Z  INFO evm_eth_compliance::statetest::runner: UC : "storageCosts"
2023-01-26T11:04:54.329940Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 4470295,
    events_root: None,
}
2023-01-26T11:04:54.329950Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 22
2023-01-26T11:04:54.329952Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "storageCosts"::London::22
2023-01-26T11:04:54.329954Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stEIP2930/storageCosts.json"
2023-01-26T11:04:54.329956Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-26T11:04:54.329957Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T11:04:54.330185Z  INFO evm_eth_compliance::statetest::runner: UC : "storageCosts"
2023-01-26T11:04:54.330189Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 4470295,
    events_root: None,
}
2023-01-26T11:04:54.330199Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 5
2023-01-26T11:04:54.330202Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "storageCosts"::London::5
2023-01-26T11:04:54.330203Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stEIP2930/storageCosts.json"
2023-01-26T11:04:54.330206Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-26T11:04:54.330207Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T11:04:54.330444Z  INFO evm_eth_compliance::statetest::runner: UC : "storageCosts"
2023-01-26T11:04:54.330449Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 5935081,
    events_root: None,
}
2023-01-26T11:04:54.330459Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 11
2023-01-26T11:04:54.330461Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "storageCosts"::London::11
2023-01-26T11:04:54.330463Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stEIP2930/storageCosts.json"
2023-01-26T11:04:54.330465Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-26T11:04:54.330467Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T11:04:54.330702Z  INFO evm_eth_compliance::statetest::runner: UC : "storageCosts"
2023-01-26T11:04:54.330707Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 5546772,
    events_root: None,
}
2023-01-26T11:04:54.330716Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 17
2023-01-26T11:04:54.330719Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "storageCosts"::London::17
2023-01-26T11:04:54.330721Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stEIP2930/storageCosts.json"
2023-01-26T11:04:54.330723Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-26T11:04:54.330724Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T11:04:54.330947Z  INFO evm_eth_compliance::statetest::runner: UC : "storageCosts"
2023-01-26T11:04:54.330951Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 4062394,
    events_root: None,
}
2023-01-26T11:04:54.330961Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 23
2023-01-26T11:04:54.330963Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "storageCosts"::London::23
2023-01-26T11:04:54.330965Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stEIP2930/storageCosts.json"
2023-01-26T11:04:54.330968Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-26T11:04:54.330969Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T11:04:54.331184Z  INFO evm_eth_compliance::statetest::runner: UC : "storageCosts"
2023-01-26T11:04:54.331188Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 4062394,
    events_root: None,
}
2023-01-26T11:04:54.331198Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 2
2023-01-26T11:04:54.331200Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "storageCosts"::London::2
2023-01-26T11:04:54.331202Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stEIP2930/storageCosts.json"
2023-01-26T11:04:54.331204Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-26T11:04:54.331206Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T11:04:54.331419Z  INFO evm_eth_compliance::statetest::runner: UC : "storageCosts"
2023-01-26T11:04:54.331423Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 4062394,
    events_root: None,
}
2023-01-26T11:04:54.331433Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 8
2023-01-26T11:04:54.331435Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "storageCosts"::London::8
2023-01-26T11:04:54.331437Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stEIP2930/storageCosts.json"
2023-01-26T11:04:54.331439Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-26T11:04:54.331441Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T11:04:54.331655Z  INFO evm_eth_compliance::statetest::runner: UC : "storageCosts"
2023-01-26T11:04:54.331659Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 4062394,
    events_root: None,
}
2023-01-26T11:04:54.331669Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 14
2023-01-26T11:04:54.331671Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "storageCosts"::London::14
2023-01-26T11:04:54.331673Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stEIP2930/storageCosts.json"
2023-01-26T11:04:54.331675Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-26T11:04:54.331677Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T11:04:54.331895Z  INFO evm_eth_compliance::statetest::runner: UC : "storageCosts"
2023-01-26T11:04:54.331900Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 4062394,
    events_root: None,
}
2023-01-26T11:04:54.331909Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 20
2023-01-26T11:04:54.331912Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "storageCosts"::London::20
2023-01-26T11:04:54.331913Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stEIP2930/storageCosts.json"
2023-01-26T11:04:54.331916Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-26T11:04:54.331917Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T11:04:54.332130Z  INFO evm_eth_compliance::statetest::runner: UC : "storageCosts"
2023-01-26T11:04:54.332135Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 4062394,
    events_root: None,
}
2023-01-26T11:04:54.332144Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 1
2023-01-26T11:04:54.332146Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "storageCosts"::London::1
2023-01-26T11:04:54.332148Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stEIP2930/storageCosts.json"
2023-01-26T11:04:54.332150Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-26T11:04:54.332152Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T11:04:54.332391Z  INFO evm_eth_compliance::statetest::runner: UC : "storageCosts"
2023-01-26T11:04:54.332395Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 5934899,
    events_root: None,
}
2023-01-26T11:04:54.332405Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 7
2023-01-26T11:04:54.332408Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "storageCosts"::London::7
2023-01-26T11:04:54.332410Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stEIP2930/storageCosts.json"
2023-01-26T11:04:54.332412Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-26T11:04:54.332413Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T11:04:54.332662Z  INFO evm_eth_compliance::statetest::runner: UC : "storageCosts"
2023-01-26T11:04:54.332667Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 5546590,
    events_root: None,
}
2023-01-26T11:04:54.332677Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 13
2023-01-26T11:04:54.332680Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "storageCosts"::London::13
2023-01-26T11:04:54.332682Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stEIP2930/storageCosts.json"
2023-01-26T11:04:54.332685Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-26T11:04:54.332687Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T11:04:54.332912Z  INFO evm_eth_compliance::statetest::runner: UC : "storageCosts"
2023-01-26T11:04:54.332917Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 4062211,
    events_root: None,
}
2023-01-26T11:04:54.332927Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 19
2023-01-26T11:04:54.332930Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "storageCosts"::London::19
2023-01-26T11:04:54.332932Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stEIP2930/storageCosts.json"
2023-01-26T11:04:54.332934Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-26T11:04:54.332937Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T11:04:54.333150Z  INFO evm_eth_compliance::statetest::runner: UC : "storageCosts"
2023-01-26T11:04:54.333155Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 4062211,
    events_root: None,
}
2023-01-26T11:04:54.333164Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 24
2023-01-26T11:04:54.333166Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "storageCosts"::London::24
2023-01-26T11:04:54.333168Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stEIP2930/storageCosts.json"
2023-01-26T11:04:54.333171Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-26T11:04:54.333173Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T11:04:54.333433Z  INFO evm_eth_compliance::statetest::runner: UC : "storageCosts"
2023-01-26T11:04:54.333438Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 5967746,
    events_root: None,
}
2023-01-26T11:04:54.333448Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 25
2023-01-26T11:04:54.333451Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "storageCosts"::London::25
2023-01-26T11:04:54.333453Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stEIP2930/storageCosts.json"
2023-01-26T11:04:54.333455Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-26T11:04:54.333456Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T11:04:54.333711Z  INFO evm_eth_compliance::statetest::runner: UC : "storageCosts"
2023-01-26T11:04:54.333715Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 5973490,
    events_root: None,
}
2023-01-26T11:04:54.333727Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 26
2023-01-26T11:04:54.333729Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "storageCosts"::London::26
2023-01-26T11:04:54.333731Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stEIP2930/storageCosts.json"
2023-01-26T11:04:54.333733Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-26T11:04:54.333735Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T11:04:54.333969Z  INFO evm_eth_compliance::statetest::runner: UC : "storageCosts"
2023-01-26T11:04:54.333973Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 4545273,
    events_root: None,
}
2023-01-26T11:04:54.333983Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 27
2023-01-26T11:04:54.333986Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "storageCosts"::London::27
2023-01-26T11:04:54.333987Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stEIP2930/storageCosts.json"
2023-01-26T11:04:54.333990Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-26T11:04:54.333991Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T11:04:54.334222Z  INFO evm_eth_compliance::statetest::runner: UC : "storageCosts"
2023-01-26T11:04:54.334227Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 4545273,
    events_root: None,
}
2023-01-26T11:04:54.334237Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 28
2023-01-26T11:04:54.334239Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "storageCosts"::London::28
2023-01-26T11:04:54.334241Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stEIP2930/storageCosts.json"
2023-01-26T11:04:54.334243Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-26T11:04:54.334245Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T11:04:54.334477Z  INFO evm_eth_compliance::statetest::runner: UC : "storageCosts"
2023-01-26T11:04:54.334482Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 4547469,
    events_root: None,
}
2023-01-26T11:04:54.334491Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 29
2023-01-26T11:04:54.334494Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "storageCosts"::London::29
2023-01-26T11:04:54.334495Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stEIP2930/storageCosts.json"
2023-01-26T11:04:54.334497Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-26T11:04:54.334499Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T11:04:54.334733Z  INFO evm_eth_compliance::statetest::runner: UC : "storageCosts"
2023-01-26T11:04:54.334738Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 4547469,
    events_root: None,
}
2023-01-26T11:04:54.334747Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 30
2023-01-26T11:04:54.334749Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "storageCosts"::London::30
2023-01-26T11:04:54.334751Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stEIP2930/storageCosts.json"
2023-01-26T11:04:54.334753Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-26T11:04:54.334755Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T11:04:54.334992Z  INFO evm_eth_compliance::statetest::runner: UC : "storageCosts"
2023-01-26T11:04:54.334996Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 5942834,
    events_root: None,
}
2023-01-26T11:04:54.335008Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 31
2023-01-26T11:04:54.335010Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "storageCosts"::London::31
2023-01-26T11:04:54.335012Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stEIP2930/storageCosts.json"
2023-01-26T11:04:54.335014Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-26T11:04:54.335016Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T11:04:54.335252Z  INFO evm_eth_compliance::statetest::runner: UC : "storageCosts"
2023-01-26T11:04:54.335256Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 5554525,
    events_root: None,
}
2023-01-26T11:04:54.335266Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 32
2023-01-26T11:04:54.335269Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "storageCosts"::London::32
2023-01-26T11:04:54.335271Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stEIP2930/storageCosts.json"
2023-01-26T11:04:54.335274Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-26T11:04:54.335275Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T11:04:54.335440Z  INFO evm_eth_compliance::statetest::runner: UC : "storageCosts"
2023-01-26T11:04:54.335444Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 4396973,
    events_root: None,
}
2023-01-26T11:04:54.335452Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 33
2023-01-26T11:04:54.335454Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "storageCosts"::London::33
2023-01-26T11:04:54.335456Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stEIP2930/storageCosts.json"
2023-01-26T11:04:54.335458Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-26T11:04:54.335459Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T11:04:54.335618Z  INFO evm_eth_compliance::statetest::runner: UC : "storageCosts"
2023-01-26T11:04:54.335623Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 4008665,
    events_root: None,
}
2023-01-26T11:04:54.335630Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 34
2023-01-26T11:04:54.335633Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "storageCosts"::London::34
2023-01-26T11:04:54.335634Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stEIP2930/storageCosts.json"
2023-01-26T11:04:54.335637Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-26T11:04:54.335638Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T11:04:54.335778Z  INFO evm_eth_compliance::statetest::runner: UC : "storageCosts"
2023-01-26T11:04:54.335782Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2524286,
    events_root: None,
}
2023-01-26T11:04:54.335788Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-26T11:04:54.335790Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "storageCosts"::Merge::0
2023-01-26T11:04:54.335792Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stEIP2930/storageCosts.json"
2023-01-26T11:04:54.335794Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-26T11:04:54.335796Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T11:04:54.336026Z  INFO evm_eth_compliance::statetest::runner: UC : "storageCosts"
2023-01-26T11:04:54.336031Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 4470322,
    events_root: None,
}
2023-01-26T11:04:54.336041Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 35
2023-01-26T11:04:54.336044Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "storageCosts"::Merge::35
2023-01-26T11:04:54.336045Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stEIP2930/storageCosts.json"
2023-01-26T11:04:54.336048Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-26T11:04:54.336049Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T11:04:54.336277Z  INFO evm_eth_compliance::statetest::runner: UC : "storageCosts"
2023-01-26T11:04:54.336281Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 4470322,
    events_root: None,
}
2023-01-26T11:04:54.336292Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 6
2023-01-26T11:04:54.336294Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "storageCosts"::Merge::6
2023-01-26T11:04:54.336296Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stEIP2930/storageCosts.json"
2023-01-26T11:04:54.336298Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-26T11:04:54.336299Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T11:04:54.336527Z  INFO evm_eth_compliance::statetest::runner: UC : "storageCosts"
2023-01-26T11:04:54.336532Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 4470322,
    events_root: None,
}
2023-01-26T11:04:54.336541Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 12
2023-01-26T11:04:54.336544Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "storageCosts"::Merge::12
2023-01-26T11:04:54.336545Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stEIP2930/storageCosts.json"
2023-01-26T11:04:54.336548Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-26T11:04:54.336549Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T11:04:54.336778Z  INFO evm_eth_compliance::statetest::runner: UC : "storageCosts"
2023-01-26T11:04:54.336782Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 4470322,
    events_root: None,
}
2023-01-26T11:04:54.336792Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 18
2023-01-26T11:04:54.336795Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "storageCosts"::Merge::18
2023-01-26T11:04:54.336797Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stEIP2930/storageCosts.json"
2023-01-26T11:04:54.336799Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-26T11:04:54.336800Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T11:04:54.337028Z  INFO evm_eth_compliance::statetest::runner: UC : "storageCosts"
2023-01-26T11:04:54.337032Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 4470322,
    events_root: None,
}
2023-01-26T11:04:54.337042Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 3
2023-01-26T11:04:54.337045Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "storageCosts"::Merge::3
2023-01-26T11:04:54.337047Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stEIP2930/storageCosts.json"
2023-01-26T11:04:54.337049Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-26T11:04:54.337050Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T11:04:54.337278Z  INFO evm_eth_compliance::statetest::runner: UC : "storageCosts"
2023-01-26T11:04:54.337282Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 4470295,
    events_root: None,
}
2023-01-26T11:04:54.337291Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 9
2023-01-26T11:04:54.337294Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "storageCosts"::Merge::9
2023-01-26T11:04:54.337295Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stEIP2930/storageCosts.json"
2023-01-26T11:04:54.337298Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-26T11:04:54.337299Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T11:04:54.337567Z  INFO evm_eth_compliance::statetest::runner: UC : "storageCosts"
2023-01-26T11:04:54.337573Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 4470295,
    events_root: None,
}
2023-01-26T11:04:54.337587Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 15
2023-01-26T11:04:54.337592Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "storageCosts"::Merge::15
2023-01-26T11:04:54.337594Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stEIP2930/storageCosts.json"
2023-01-26T11:04:54.337598Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-26T11:04:54.337600Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T11:04:54.337855Z  INFO evm_eth_compliance::statetest::runner: UC : "storageCosts"
2023-01-26T11:04:54.337860Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 4470295,
    events_root: None,
}
2023-01-26T11:04:54.337873Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 21
2023-01-26T11:04:54.337876Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "storageCosts"::Merge::21
2023-01-26T11:04:54.337879Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stEIP2930/storageCosts.json"
2023-01-26T11:04:54.337882Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-26T11:04:54.337884Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T11:04:54.338119Z  INFO evm_eth_compliance::statetest::runner: UC : "storageCosts"
2023-01-26T11:04:54.338124Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 4470295,
    events_root: None,
}
2023-01-26T11:04:54.338136Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 4
2023-01-26T11:04:54.338141Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "storageCosts"::Merge::4
2023-01-26T11:04:54.338143Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stEIP2930/storageCosts.json"
2023-01-26T11:04:54.338147Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-26T11:04:54.338149Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T11:04:54.338386Z  INFO evm_eth_compliance::statetest::runner: UC : "storageCosts"
2023-01-26T11:04:54.338391Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 4470295,
    events_root: None,
}
2023-01-26T11:04:54.338403Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 10
2023-01-26T11:04:54.338407Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "storageCosts"::Merge::10
2023-01-26T11:04:54.338409Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stEIP2930/storageCosts.json"
2023-01-26T11:04:54.338413Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-26T11:04:54.338415Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T11:04:54.338652Z  INFO evm_eth_compliance::statetest::runner: UC : "storageCosts"
2023-01-26T11:04:54.338657Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 4470295,
    events_root: None,
}
2023-01-26T11:04:54.338670Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 16
2023-01-26T11:04:54.338673Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "storageCosts"::Merge::16
2023-01-26T11:04:54.338676Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stEIP2930/storageCosts.json"
2023-01-26T11:04:54.338680Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-26T11:04:54.338682Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T11:04:54.338920Z  INFO evm_eth_compliance::statetest::runner: UC : "storageCosts"
2023-01-26T11:04:54.338925Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 4470295,
    events_root: None,
}
2023-01-26T11:04:54.338937Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 22
2023-01-26T11:04:54.338941Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "storageCosts"::Merge::22
2023-01-26T11:04:54.338943Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stEIP2930/storageCosts.json"
2023-01-26T11:04:54.338946Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-26T11:04:54.338948Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T11:04:54.339183Z  INFO evm_eth_compliance::statetest::runner: UC : "storageCosts"
2023-01-26T11:04:54.339188Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 4470295,
    events_root: None,
}
2023-01-26T11:04:54.339200Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 5
2023-01-26T11:04:54.339203Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "storageCosts"::Merge::5
2023-01-26T11:04:54.339206Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stEIP2930/storageCosts.json"
2023-01-26T11:04:54.339210Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-26T11:04:54.339212Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T11:04:54.339457Z  INFO evm_eth_compliance::statetest::runner: UC : "storageCosts"
2023-01-26T11:04:54.339462Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 5935081,
    events_root: None,
}
2023-01-26T11:04:54.339475Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 11
2023-01-26T11:04:54.339479Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "storageCosts"::Merge::11
2023-01-26T11:04:54.339481Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stEIP2930/storageCosts.json"
2023-01-26T11:04:54.339484Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-26T11:04:54.339486Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T11:04:54.339729Z  INFO evm_eth_compliance::statetest::runner: UC : "storageCosts"
2023-01-26T11:04:54.339734Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 5546772,
    events_root: None,
}
2023-01-26T11:04:54.339747Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 17
2023-01-26T11:04:54.339750Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "storageCosts"::Merge::17
2023-01-26T11:04:54.339753Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stEIP2930/storageCosts.json"
2023-01-26T11:04:54.339757Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-26T11:04:54.339759Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T11:04:54.339986Z  INFO evm_eth_compliance::statetest::runner: UC : "storageCosts"
2023-01-26T11:04:54.339991Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 4062394,
    events_root: None,
}
2023-01-26T11:04:54.340003Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 23
2023-01-26T11:04:54.340006Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "storageCosts"::Merge::23
2023-01-26T11:04:54.340008Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stEIP2930/storageCosts.json"
2023-01-26T11:04:54.340011Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-26T11:04:54.340013Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T11:04:54.340236Z  INFO evm_eth_compliance::statetest::runner: UC : "storageCosts"
2023-01-26T11:04:54.340241Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 4062394,
    events_root: None,
}
2023-01-26T11:04:54.340253Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 2
2023-01-26T11:04:54.340257Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "storageCosts"::Merge::2
2023-01-26T11:04:54.340259Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stEIP2930/storageCosts.json"
2023-01-26T11:04:54.340263Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-26T11:04:54.340265Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T11:04:54.340486Z  INFO evm_eth_compliance::statetest::runner: UC : "storageCosts"
2023-01-26T11:04:54.340491Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 4062394,
    events_root: None,
}
2023-01-26T11:04:54.340505Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 8
2023-01-26T11:04:54.340508Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "storageCosts"::Merge::8
2023-01-26T11:04:54.340511Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stEIP2930/storageCosts.json"
2023-01-26T11:04:54.340514Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-26T11:04:54.340516Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T11:04:54.340737Z  INFO evm_eth_compliance::statetest::runner: UC : "storageCosts"
2023-01-26T11:04:54.340742Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 4062394,
    events_root: None,
}
2023-01-26T11:04:54.340755Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 14
2023-01-26T11:04:54.340758Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "storageCosts"::Merge::14
2023-01-26T11:04:54.340760Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stEIP2930/storageCosts.json"
2023-01-26T11:04:54.340763Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-26T11:04:54.340766Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T11:04:54.340988Z  INFO evm_eth_compliance::statetest::runner: UC : "storageCosts"
2023-01-26T11:04:54.340993Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 4062394,
    events_root: None,
}
2023-01-26T11:04:54.341005Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 20
2023-01-26T11:04:54.341008Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "storageCosts"::Merge::20
2023-01-26T11:04:54.341011Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stEIP2930/storageCosts.json"
2023-01-26T11:04:54.341014Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-26T11:04:54.341016Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T11:04:54.341236Z  INFO evm_eth_compliance::statetest::runner: UC : "storageCosts"
2023-01-26T11:04:54.341241Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 4062394,
    events_root: None,
}
2023-01-26T11:04:54.341252Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 1
2023-01-26T11:04:54.341256Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "storageCosts"::Merge::1
2023-01-26T11:04:54.341258Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stEIP2930/storageCosts.json"
2023-01-26T11:04:54.341262Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-26T11:04:54.341264Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T11:04:54.341514Z  INFO evm_eth_compliance::statetest::runner: UC : "storageCosts"
2023-01-26T11:04:54.341520Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 5934899,
    events_root: None,
}
2023-01-26T11:04:54.341533Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 7
2023-01-26T11:04:54.341537Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "storageCosts"::Merge::7
2023-01-26T11:04:54.341539Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stEIP2930/storageCosts.json"
2023-01-26T11:04:54.341542Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-26T11:04:54.341545Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T11:04:54.341787Z  INFO evm_eth_compliance::statetest::runner: UC : "storageCosts"
2023-01-26T11:04:54.341792Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 5546590,
    events_root: None,
}
2023-01-26T11:04:54.341805Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 13
2023-01-26T11:04:54.341808Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "storageCosts"::Merge::13
2023-01-26T11:04:54.341810Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stEIP2930/storageCosts.json"
2023-01-26T11:04:54.341814Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-26T11:04:54.341816Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T11:04:54.342040Z  INFO evm_eth_compliance::statetest::runner: UC : "storageCosts"
2023-01-26T11:04:54.342045Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 4062211,
    events_root: None,
}
2023-01-26T11:04:54.342057Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 19
2023-01-26T11:04:54.342060Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "storageCosts"::Merge::19
2023-01-26T11:04:54.342063Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stEIP2930/storageCosts.json"
2023-01-26T11:04:54.342067Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-26T11:04:54.342069Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T11:04:54.342290Z  INFO evm_eth_compliance::statetest::runner: UC : "storageCosts"
2023-01-26T11:04:54.342295Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 4062211,
    events_root: None,
}
2023-01-26T11:04:54.342307Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 24
2023-01-26T11:04:54.342310Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "storageCosts"::Merge::24
2023-01-26T11:04:54.342313Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stEIP2930/storageCosts.json"
2023-01-26T11:04:54.342316Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-26T11:04:54.342318Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T11:04:54.342581Z  INFO evm_eth_compliance::statetest::runner: UC : "storageCosts"
2023-01-26T11:04:54.342586Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 5973490,
    events_root: None,
}
2023-01-26T11:04:54.342600Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 25
2023-01-26T11:04:54.342603Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "storageCosts"::Merge::25
2023-01-26T11:04:54.342606Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stEIP2930/storageCosts.json"
2023-01-26T11:04:54.342609Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-26T11:04:54.342611Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T11:04:54.342895Z  INFO evm_eth_compliance::statetest::runner: UC : "storageCosts"
2023-01-26T11:04:54.342900Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 5973490,
    events_root: None,
}
2023-01-26T11:04:54.342916Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 26
2023-01-26T11:04:54.342921Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "storageCosts"::Merge::26
2023-01-26T11:04:54.342923Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stEIP2930/storageCosts.json"
2023-01-26T11:04:54.342927Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-26T11:04:54.342929Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T11:04:54.343201Z  INFO evm_eth_compliance::statetest::runner: UC : "storageCosts"
2023-01-26T11:04:54.343206Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 4545273,
    events_root: None,
}
2023-01-26T11:04:54.343218Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 27
2023-01-26T11:04:54.343221Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "storageCosts"::Merge::27
2023-01-26T11:04:54.343224Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stEIP2930/storageCosts.json"
2023-01-26T11:04:54.343227Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-26T11:04:54.343229Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T11:04:54.343471Z  INFO evm_eth_compliance::statetest::runner: UC : "storageCosts"
2023-01-26T11:04:54.343476Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 4545273,
    events_root: None,
}
2023-01-26T11:04:54.343488Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 28
2023-01-26T11:04:54.343492Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "storageCosts"::Merge::28
2023-01-26T11:04:54.343494Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stEIP2930/storageCosts.json"
2023-01-26T11:04:54.343497Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-26T11:04:54.343500Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T11:04:54.343742Z  INFO evm_eth_compliance::statetest::runner: UC : "storageCosts"
2023-01-26T11:04:54.343747Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 4547469,
    events_root: None,
}
2023-01-26T11:04:54.343759Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 29
2023-01-26T11:04:54.343762Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "storageCosts"::Merge::29
2023-01-26T11:04:54.343765Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stEIP2930/storageCosts.json"
2023-01-26T11:04:54.343768Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-26T11:04:54.343770Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T11:04:54.344010Z  INFO evm_eth_compliance::statetest::runner: UC : "storageCosts"
2023-01-26T11:04:54.344014Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 4547469,
    events_root: None,
}
2023-01-26T11:04:54.344026Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 30
2023-01-26T11:04:54.344030Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "storageCosts"::Merge::30
2023-01-26T11:04:54.344032Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stEIP2930/storageCosts.json"
2023-01-26T11:04:54.344036Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-26T11:04:54.344038Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T11:04:54.344283Z  INFO evm_eth_compliance::statetest::runner: UC : "storageCosts"
2023-01-26T11:04:54.344288Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 5942834,
    events_root: None,
}
2023-01-26T11:04:54.344301Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 31
2023-01-26T11:04:54.344305Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "storageCosts"::Merge::31
2023-01-26T11:04:54.344307Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stEIP2930/storageCosts.json"
2023-01-26T11:04:54.344310Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-26T11:04:54.344313Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T11:04:54.344557Z  INFO evm_eth_compliance::statetest::runner: UC : "storageCosts"
2023-01-26T11:04:54.344562Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 5554525,
    events_root: None,
}
2023-01-26T11:04:54.344575Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 32
2023-01-26T11:04:54.344578Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "storageCosts"::Merge::32
2023-01-26T11:04:54.344581Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stEIP2930/storageCosts.json"
2023-01-26T11:04:54.344584Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-26T11:04:54.344586Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T11:04:54.344756Z  INFO evm_eth_compliance::statetest::runner: UC : "storageCosts"
2023-01-26T11:04:54.344761Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 4396973,
    events_root: None,
}
2023-01-26T11:04:54.344771Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 33
2023-01-26T11:04:54.344776Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "storageCosts"::Merge::33
2023-01-26T11:04:54.344778Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stEIP2930/storageCosts.json"
2023-01-26T11:04:54.344782Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-26T11:04:54.344784Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T11:04:54.344949Z  INFO evm_eth_compliance::statetest::runner: UC : "storageCosts"
2023-01-26T11:04:54.344954Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 4008665,
    events_root: None,
}
2023-01-26T11:04:54.344964Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 34
2023-01-26T11:04:54.344967Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "storageCosts"::Merge::34
2023-01-26T11:04:54.344970Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stEIP2930/storageCosts.json"
2023-01-26T11:04:54.344974Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-26T11:04:54.344976Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T11:04:54.345123Z  INFO evm_eth_compliance::statetest::runner: UC : "storageCosts"
2023-01-26T11:04:54.345127Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2524286,
    events_root: None,
}
2023-01-26T11:04:54.346940Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:375.946389ms
2023-01-26T11:04:54.612693Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "./test-vectors/tests/GeneralStateTests/stEIP2930/transactionCosts.json", Total Files :: 1
2023-01-26T11:04:54.641409Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-26T11:04:54.641591Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T11:04:54.641594Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-26T11:04:54.641647Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T11:04:54.641717Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-26T11:04:54.641720Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "transactionCosts"::Berlin::0
2023-01-26T11:04:54.641723Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stEIP2930/transactionCosts.json"
2023-01-26T11:04:54.641726Z  INFO evm_eth_compliance::statetest::runner: TX len : 1
2023-01-26T11:04:54.641727Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T11:04:54.974257Z  INFO evm_eth_compliance::statetest::runner: UC : "transactionCosts"
2023-01-26T11:04:54.974272Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1526121,
    events_root: None,
}
2023-01-26T11:04:54.974283Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 1
2023-01-26T11:04:54.974290Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "transactionCosts"::Berlin::1
2023-01-26T11:04:54.974292Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stEIP2930/transactionCosts.json"
2023-01-26T11:04:54.974294Z  INFO evm_eth_compliance::statetest::runner: TX len : 1
2023-01-26T11:04:54.974296Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T11:04:54.974448Z  INFO evm_eth_compliance::statetest::runner: UC : "transactionCosts"
2023-01-26T11:04:54.974453Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1526121,
    events_root: None,
}
2023-01-26T11:04:54.974460Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 2
2023-01-26T11:04:54.974463Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "transactionCosts"::Berlin::2
2023-01-26T11:04:54.974466Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stEIP2930/transactionCosts.json"
2023-01-26T11:04:54.974469Z  INFO evm_eth_compliance::statetest::runner: TX len : 1
2023-01-26T11:04:54.974471Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T11:04:54.974580Z  INFO evm_eth_compliance::statetest::runner: UC : "transactionCosts"
2023-01-26T11:04:54.974584Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1526121,
    events_root: None,
}
2023-01-26T11:04:54.974590Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 3
2023-01-26T11:04:54.974592Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "transactionCosts"::Berlin::3
2023-01-26T11:04:54.974594Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stEIP2930/transactionCosts.json"
2023-01-26T11:04:54.974596Z  INFO evm_eth_compliance::statetest::runner: TX len : 1
2023-01-26T11:04:54.974598Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T11:04:54.974681Z  INFO evm_eth_compliance::statetest::runner: UC : "transactionCosts"
2023-01-26T11:04:54.974685Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1526121,
    events_root: None,
}
2023-01-26T11:04:54.974690Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 4
2023-01-26T11:04:54.974692Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "transactionCosts"::Berlin::4
2023-01-26T11:04:54.974694Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stEIP2930/transactionCosts.json"
2023-01-26T11:04:54.974697Z  INFO evm_eth_compliance::statetest::runner: TX len : 1
2023-01-26T11:04:54.974698Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T11:04:54.974779Z  INFO evm_eth_compliance::statetest::runner: UC : "transactionCosts"
2023-01-26T11:04:54.974783Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1526121,
    events_root: None,
}
2023-01-26T11:04:54.974788Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 5
2023-01-26T11:04:54.974790Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "transactionCosts"::Berlin::5
2023-01-26T11:04:54.974792Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stEIP2930/transactionCosts.json"
2023-01-26T11:04:54.974794Z  INFO evm_eth_compliance::statetest::runner: TX len : 1
2023-01-26T11:04:54.974796Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T11:04:54.974876Z  INFO evm_eth_compliance::statetest::runner: UC : "transactionCosts"
2023-01-26T11:04:54.974880Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1526121,
    events_root: None,
}
2023-01-26T11:04:54.974884Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 6
2023-01-26T11:04:54.974887Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "transactionCosts"::Berlin::6
2023-01-26T11:04:54.974888Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stEIP2930/transactionCosts.json"
2023-01-26T11:04:54.974891Z  INFO evm_eth_compliance::statetest::runner: TX len : 1
2023-01-26T11:04:54.974892Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T11:04:54.974977Z  INFO evm_eth_compliance::statetest::runner: UC : "transactionCosts"
2023-01-26T11:04:54.974981Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1526121,
    events_root: None,
}
2023-01-26T11:04:54.974986Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 10
2023-01-26T11:04:54.974988Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "transactionCosts"::Berlin::10
2023-01-26T11:04:54.974990Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stEIP2930/transactionCosts.json"
2023-01-26T11:04:54.974992Z  INFO evm_eth_compliance::statetest::runner: TX len : 1
2023-01-26T11:04:54.974994Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T11:04:54.975073Z  INFO evm_eth_compliance::statetest::runner: UC : "transactionCosts"
2023-01-26T11:04:54.975077Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1526121,
    events_root: None,
}
2023-01-26T11:04:54.975081Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 7
2023-01-26T11:04:54.975084Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "transactionCosts"::Berlin::7
2023-01-26T11:04:54.975085Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stEIP2930/transactionCosts.json"
2023-01-26T11:04:54.975088Z  INFO evm_eth_compliance::statetest::runner: TX len : 1
2023-01-26T11:04:54.975089Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T11:04:54.975169Z  INFO evm_eth_compliance::statetest::runner: UC : "transactionCosts"
2023-01-26T11:04:54.975172Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1526121,
    events_root: None,
}
2023-01-26T11:04:54.975177Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 8
2023-01-26T11:04:54.975180Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "transactionCosts"::Berlin::8
2023-01-26T11:04:54.975183Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stEIP2930/transactionCosts.json"
2023-01-26T11:04:54.975187Z  INFO evm_eth_compliance::statetest::runner: TX len : 1
2023-01-26T11:04:54.975189Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T11:04:54.975296Z  INFO evm_eth_compliance::statetest::runner: UC : "transactionCosts"
2023-01-26T11:04:54.975301Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1526121,
    events_root: None,
}
2023-01-26T11:04:54.975307Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 9
2023-01-26T11:04:54.975311Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "transactionCosts"::Berlin::9
2023-01-26T11:04:54.975313Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stEIP2930/transactionCosts.json"
2023-01-26T11:04:54.975317Z  INFO evm_eth_compliance::statetest::runner: TX len : 1
2023-01-26T11:04:54.975319Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T11:04:54.975426Z  INFO evm_eth_compliance::statetest::runner: UC : "transactionCosts"
2023-01-26T11:04:54.975430Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1526121,
    events_root: None,
}
2023-01-26T11:04:54.975435Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 11
2023-01-26T11:04:54.975437Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "transactionCosts"::Berlin::11
2023-01-26T11:04:54.975439Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stEIP2930/transactionCosts.json"
2023-01-26T11:04:54.975441Z  INFO evm_eth_compliance::statetest::runner: TX len : 1
2023-01-26T11:04:54.975443Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T11:04:54.975525Z  INFO evm_eth_compliance::statetest::runner: UC : "transactionCosts"
2023-01-26T11:04:54.975528Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1526121,
    events_root: None,
}
2023-01-26T11:04:54.975533Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-26T11:04:54.975535Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "transactionCosts"::London::0
2023-01-26T11:04:54.975537Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stEIP2930/transactionCosts.json"
2023-01-26T11:04:54.975539Z  INFO evm_eth_compliance::statetest::runner: TX len : 1
2023-01-26T11:04:54.975541Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T11:04:54.975621Z  INFO evm_eth_compliance::statetest::runner: UC : "transactionCosts"
2023-01-26T11:04:54.975625Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1526121,
    events_root: None,
}
2023-01-26T11:04:54.975629Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 1
2023-01-26T11:04:54.975631Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "transactionCosts"::London::1
2023-01-26T11:04:54.975633Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stEIP2930/transactionCosts.json"
2023-01-26T11:04:54.975635Z  INFO evm_eth_compliance::statetest::runner: TX len : 1
2023-01-26T11:04:54.975637Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T11:04:54.975717Z  INFO evm_eth_compliance::statetest::runner: UC : "transactionCosts"
2023-01-26T11:04:54.975720Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1526121,
    events_root: None,
}
2023-01-26T11:04:54.975724Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 2
2023-01-26T11:04:54.975727Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "transactionCosts"::London::2
2023-01-26T11:04:54.975728Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stEIP2930/transactionCosts.json"
2023-01-26T11:04:54.975731Z  INFO evm_eth_compliance::statetest::runner: TX len : 1
2023-01-26T11:04:54.975732Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T11:04:54.975811Z  INFO evm_eth_compliance::statetest::runner: UC : "transactionCosts"
2023-01-26T11:04:54.975815Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1526121,
    events_root: None,
}
2023-01-26T11:04:54.975819Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 3
2023-01-26T11:04:54.975821Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "transactionCosts"::London::3
2023-01-26T11:04:54.975823Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stEIP2930/transactionCosts.json"
2023-01-26T11:04:54.975825Z  INFO evm_eth_compliance::statetest::runner: TX len : 1
2023-01-26T11:04:54.975827Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T11:04:54.975921Z  INFO evm_eth_compliance::statetest::runner: UC : "transactionCosts"
2023-01-26T11:04:54.975925Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1526121,
    events_root: None,
}
2023-01-26T11:04:54.975930Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 4
2023-01-26T11:04:54.975932Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "transactionCosts"::London::4
2023-01-26T11:04:54.975935Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stEIP2930/transactionCosts.json"
2023-01-26T11:04:54.975938Z  INFO evm_eth_compliance::statetest::runner: TX len : 1
2023-01-26T11:04:54.975940Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T11:04:54.976051Z  INFO evm_eth_compliance::statetest::runner: UC : "transactionCosts"
2023-01-26T11:04:54.976056Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1526121,
    events_root: None,
}
2023-01-26T11:04:54.976062Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 5
2023-01-26T11:04:54.976065Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "transactionCosts"::London::5
2023-01-26T11:04:54.976068Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stEIP2930/transactionCosts.json"
2023-01-26T11:04:54.976071Z  INFO evm_eth_compliance::statetest::runner: TX len : 1
2023-01-26T11:04:54.976073Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T11:04:54.976181Z  INFO evm_eth_compliance::statetest::runner: UC : "transactionCosts"
2023-01-26T11:04:54.976186Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1526121,
    events_root: None,
}
2023-01-26T11:04:54.976192Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 6
2023-01-26T11:04:54.976195Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "transactionCosts"::London::6
2023-01-26T11:04:54.976197Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stEIP2930/transactionCosts.json"
2023-01-26T11:04:54.976200Z  INFO evm_eth_compliance::statetest::runner: TX len : 1
2023-01-26T11:04:54.976201Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T11:04:54.976291Z  INFO evm_eth_compliance::statetest::runner: UC : "transactionCosts"
2023-01-26T11:04:54.976295Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1526121,
    events_root: None,
}
2023-01-26T11:04:54.976299Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 10
2023-01-26T11:04:54.976302Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "transactionCosts"::London::10
2023-01-26T11:04:54.976303Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stEIP2930/transactionCosts.json"
2023-01-26T11:04:54.976306Z  INFO evm_eth_compliance::statetest::runner: TX len : 1
2023-01-26T11:04:54.976307Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T11:04:54.976387Z  INFO evm_eth_compliance::statetest::runner: UC : "transactionCosts"
2023-01-26T11:04:54.976391Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1526121,
    events_root: None,
}
2023-01-26T11:04:54.976396Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 7
2023-01-26T11:04:54.976398Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "transactionCosts"::London::7
2023-01-26T11:04:54.976400Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stEIP2930/transactionCosts.json"
2023-01-26T11:04:54.976403Z  INFO evm_eth_compliance::statetest::runner: TX len : 1
2023-01-26T11:04:54.976404Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T11:04:54.976498Z  INFO evm_eth_compliance::statetest::runner: UC : "transactionCosts"
2023-01-26T11:04:54.976502Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1526121,
    events_root: None,
}
2023-01-26T11:04:54.976507Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 8
2023-01-26T11:04:54.976509Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "transactionCosts"::London::8
2023-01-26T11:04:54.976511Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stEIP2930/transactionCosts.json"
2023-01-26T11:04:54.976513Z  INFO evm_eth_compliance::statetest::runner: TX len : 1
2023-01-26T11:04:54.976515Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T11:04:54.976599Z  INFO evm_eth_compliance::statetest::runner: UC : "transactionCosts"
2023-01-26T11:04:54.976603Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1526121,
    events_root: None,
}
2023-01-26T11:04:54.976608Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 9
2023-01-26T11:04:54.976610Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "transactionCosts"::London::9
2023-01-26T11:04:54.976612Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stEIP2930/transactionCosts.json"
2023-01-26T11:04:54.976614Z  INFO evm_eth_compliance::statetest::runner: TX len : 1
2023-01-26T11:04:54.976616Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T11:04:54.976695Z  INFO evm_eth_compliance::statetest::runner: UC : "transactionCosts"
2023-01-26T11:04:54.976699Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1526121,
    events_root: None,
}
2023-01-26T11:04:54.976704Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 11
2023-01-26T11:04:54.976706Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "transactionCosts"::London::11
2023-01-26T11:04:54.976708Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stEIP2930/transactionCosts.json"
2023-01-26T11:04:54.976710Z  INFO evm_eth_compliance::statetest::runner: TX len : 1
2023-01-26T11:04:54.976711Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T11:04:54.976817Z  INFO evm_eth_compliance::statetest::runner: UC : "transactionCosts"
2023-01-26T11:04:54.976821Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1526121,
    events_root: None,
}
2023-01-26T11:04:54.976827Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-26T11:04:54.976830Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "transactionCosts"::Merge::0
2023-01-26T11:04:54.976833Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stEIP2930/transactionCosts.json"
2023-01-26T11:04:54.976836Z  INFO evm_eth_compliance::statetest::runner: TX len : 1
2023-01-26T11:04:54.976839Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T11:04:54.976946Z  INFO evm_eth_compliance::statetest::runner: UC : "transactionCosts"
2023-01-26T11:04:54.976950Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1526121,
    events_root: None,
}
2023-01-26T11:04:54.976956Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 1
2023-01-26T11:04:54.976960Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "transactionCosts"::Merge::1
2023-01-26T11:04:54.976962Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stEIP2930/transactionCosts.json"
2023-01-26T11:04:54.976964Z  INFO evm_eth_compliance::statetest::runner: TX len : 1
2023-01-26T11:04:54.976965Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T11:04:54.977048Z  INFO evm_eth_compliance::statetest::runner: UC : "transactionCosts"
2023-01-26T11:04:54.977051Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1526121,
    events_root: None,
}
2023-01-26T11:04:54.977056Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 2
2023-01-26T11:04:54.977058Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "transactionCosts"::Merge::2
2023-01-26T11:04:54.977060Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stEIP2930/transactionCosts.json"
2023-01-26T11:04:54.977062Z  INFO evm_eth_compliance::statetest::runner: TX len : 1
2023-01-26T11:04:54.977064Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T11:04:54.977143Z  INFO evm_eth_compliance::statetest::runner: UC : "transactionCosts"
2023-01-26T11:04:54.977146Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1526121,
    events_root: None,
}
2023-01-26T11:04:54.977151Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 3
2023-01-26T11:04:54.977153Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "transactionCosts"::Merge::3
2023-01-26T11:04:54.977155Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stEIP2930/transactionCosts.json"
2023-01-26T11:04:54.977157Z  INFO evm_eth_compliance::statetest::runner: TX len : 1
2023-01-26T11:04:54.977158Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T11:04:54.977238Z  INFO evm_eth_compliance::statetest::runner: UC : "transactionCosts"
2023-01-26T11:04:54.977241Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1526121,
    events_root: None,
}
2023-01-26T11:04:54.977246Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 4
2023-01-26T11:04:54.977248Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "transactionCosts"::Merge::4
2023-01-26T11:04:54.977250Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stEIP2930/transactionCosts.json"
2023-01-26T11:04:54.977252Z  INFO evm_eth_compliance::statetest::runner: TX len : 1
2023-01-26T11:04:54.977254Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T11:04:54.977333Z  INFO evm_eth_compliance::statetest::runner: UC : "transactionCosts"
2023-01-26T11:04:54.977337Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1526121,
    events_root: None,
}
2023-01-26T11:04:54.977349Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 5
2023-01-26T11:04:54.977352Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "transactionCosts"::Merge::5
2023-01-26T11:04:54.977354Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stEIP2930/transactionCosts.json"
2023-01-26T11:04:54.977357Z  INFO evm_eth_compliance::statetest::runner: TX len : 1
2023-01-26T11:04:54.977359Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T11:04:54.977444Z  INFO evm_eth_compliance::statetest::runner: UC : "transactionCosts"
2023-01-26T11:04:54.977448Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1526121,
    events_root: None,
}
2023-01-26T11:04:54.977452Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 6
2023-01-26T11:04:54.977455Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "transactionCosts"::Merge::6
2023-01-26T11:04:54.977456Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stEIP2930/transactionCosts.json"
2023-01-26T11:04:54.977459Z  INFO evm_eth_compliance::statetest::runner: TX len : 1
2023-01-26T11:04:54.977460Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T11:04:54.977566Z  INFO evm_eth_compliance::statetest::runner: UC : "transactionCosts"
2023-01-26T11:04:54.977571Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1526121,
    events_root: None,
}
2023-01-26T11:04:54.977577Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 10
2023-01-26T11:04:54.977580Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "transactionCosts"::Merge::10
2023-01-26T11:04:54.977583Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stEIP2930/transactionCosts.json"
2023-01-26T11:04:54.977586Z  INFO evm_eth_compliance::statetest::runner: TX len : 1
2023-01-26T11:04:54.977588Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T11:04:54.977695Z  INFO evm_eth_compliance::statetest::runner: UC : "transactionCosts"
2023-01-26T11:04:54.977700Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1526121,
    events_root: None,
}
2023-01-26T11:04:54.977706Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 7
2023-01-26T11:04:54.977710Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "transactionCosts"::Merge::7
2023-01-26T11:04:54.977712Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stEIP2930/transactionCosts.json"
2023-01-26T11:04:54.977715Z  INFO evm_eth_compliance::statetest::runner: TX len : 1
2023-01-26T11:04:54.977716Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T11:04:54.977799Z  INFO evm_eth_compliance::statetest::runner: UC : "transactionCosts"
2023-01-26T11:04:54.977803Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1526121,
    events_root: None,
}
2023-01-26T11:04:54.977808Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 8
2023-01-26T11:04:54.977810Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "transactionCosts"::Merge::8
2023-01-26T11:04:54.977812Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stEIP2930/transactionCosts.json"
2023-01-26T11:04:54.977814Z  INFO evm_eth_compliance::statetest::runner: TX len : 1
2023-01-26T11:04:54.977815Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T11:04:54.977895Z  INFO evm_eth_compliance::statetest::runner: UC : "transactionCosts"
2023-01-26T11:04:54.977898Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1526121,
    events_root: None,
}
2023-01-26T11:04:54.977903Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 9
2023-01-26T11:04:54.977905Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "transactionCosts"::Merge::9
2023-01-26T11:04:54.977907Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stEIP2930/transactionCosts.json"
2023-01-26T11:04:54.977909Z  INFO evm_eth_compliance::statetest::runner: TX len : 1
2023-01-26T11:04:54.977911Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T11:04:54.977990Z  INFO evm_eth_compliance::statetest::runner: UC : "transactionCosts"
2023-01-26T11:04:54.977993Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1526121,
    events_root: None,
}
2023-01-26T11:04:54.977998Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 11
2023-01-26T11:04:54.978000Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "transactionCosts"::Merge::11
2023-01-26T11:04:54.978002Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stEIP2930/transactionCosts.json"
2023-01-26T11:04:54.978004Z  INFO evm_eth_compliance::statetest::runner: TX len : 1
2023-01-26T11:04:54.978006Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T11:04:54.978085Z  INFO evm_eth_compliance::statetest::runner: UC : "transactionCosts"
2023-01-26T11:04:54.978089Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1526121,
    events_root: None,
}
2023-01-26T11:04:54.979734Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:336.688516ms
2023-01-26T11:04:55.255066Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "./test-vectors/tests/GeneralStateTests/stEIP2930/variedContext.json", Total Files :: 1
2023-01-26T11:04:55.284518Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-26T11:04:55.284707Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T11:04:55.284711Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-26T11:04:55.284764Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T11:04:55.284766Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 2
2023-01-26T11:04:55.284823Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T11:04:55.284825Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 3
2023-01-26T11:04:55.284879Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T11:04:55.284882Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 4
2023-01-26T11:04:55.284931Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T11:04:55.284933Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 5
2023-01-26T11:04:55.284993Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T11:04:55.284995Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 6
2023-01-26T11:04:55.285046Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T11:04:55.285048Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 7
2023-01-26T11:04:55.285083Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T11:04:55.285085Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 8
2023-01-26T11:04:55.285128Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T11:04:55.285130Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 9
2023-01-26T11:04:55.285182Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T11:04:55.285185Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 10
2023-01-26T11:04:55.285227Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T11:04:55.285229Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 11
2023-01-26T11:04:55.285273Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T11:04:55.285275Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 12
2023-01-26T11:04:55.285319Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T11:04:55.285321Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 13
2023-01-26T11:04:55.285402Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T11:04:55.285407Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 14
2023-01-26T11:04:55.285466Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T11:04:55.285469Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 15
2023-01-26T11:04:55.285521Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T11:04:55.285523Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 16
2023-01-26T11:04:55.285568Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T11:04:55.285570Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 17
2023-01-26T11:04:55.285616Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T11:04:55.285618Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 18
2023-01-26T11:04:55.285669Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T11:04:55.285671Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 19
2023-01-26T11:04:55.285710Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T11:04:55.285711Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 20
2023-01-26T11:04:55.285752Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T11:04:55.285754Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 21
2023-01-26T11:04:55.285808Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T11:04:55.285810Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 22
2023-01-26T11:04:55.285874Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T11:04:55.285876Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 23
2023-01-26T11:04:55.285930Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T11:04:55.285932Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 24
2023-01-26T11:04:55.285975Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T11:04:55.285977Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 25
2023-01-26T11:04:55.286043Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T11:04:55.286045Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 26
2023-01-26T11:04:55.286086Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T11:04:55.286088Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 27
2023-01-26T11:04:55.286136Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T11:04:55.286218Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-26T11:04:55.286221Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "variedContext"::Berlin::0
2023-01-26T11:04:55.286225Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stEIP2930/variedContext.json"
2023-01-26T11:04:55.286228Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-26T11:04:55.286229Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T11:04:55.638744Z  INFO evm_eth_compliance::statetest::runner: UC : "variedContext"
2023-01-26T11:04:55.638759Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 8303089,
    events_root: None,
}
2023-01-26T11:04:55.638779Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 1
2023-01-26T11:04:55.638785Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "variedContext"::Berlin::1
2023-01-26T11:04:55.638787Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stEIP2930/variedContext.json"
2023-01-26T11:04:55.638790Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-26T11:04:55.638791Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T11:04:55.639214Z  INFO evm_eth_compliance::statetest::runner: UC : "variedContext"
2023-01-26T11:04:55.639219Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 8834701,
    events_root: None,
}
2023-01-26T11:04:55.639234Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 2
2023-01-26T11:04:55.639237Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "variedContext"::Berlin::2
2023-01-26T11:04:55.639238Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stEIP2930/variedContext.json"
2023-01-26T11:04:55.639241Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-26T11:04:55.639242Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T11:04:55.639433Z  INFO evm_eth_compliance::statetest::runner: UC : "variedContext"
2023-01-26T11:04:55.639438Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3084441,
    events_root: None,
}
2023-01-26T11:04:55.639444Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 3
2023-01-26T11:04:55.639447Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "variedContext"::Berlin::3
2023-01-26T11:04:55.639449Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stEIP2930/variedContext.json"
2023-01-26T11:04:55.639451Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-26T11:04:55.639452Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T11:04:55.639633Z  INFO evm_eth_compliance::statetest::runner: UC : "variedContext"
2023-01-26T11:04:55.639638Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3084441,
    events_root: None,
}
2023-01-26T11:04:55.639644Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 4
2023-01-26T11:04:55.639647Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "variedContext"::Berlin::4
2023-01-26T11:04:55.639649Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stEIP2930/variedContext.json"
2023-01-26T11:04:55.639651Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-26T11:04:55.639653Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T11:04:55.639960Z  INFO evm_eth_compliance::statetest::runner: UC : "variedContext"
2023-01-26T11:04:55.639964Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 6865455,
    events_root: None,
}
2023-01-26T11:04:55.639973Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 5
2023-01-26T11:04:55.639976Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "variedContext"::Berlin::5
2023-01-26T11:04:55.639978Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stEIP2930/variedContext.json"
2023-01-26T11:04:55.639981Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-26T11:04:55.639983Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T11:04:55.640305Z  INFO evm_eth_compliance::statetest::runner: UC : "variedContext"
2023-01-26T11:04:55.640310Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 7376932,
    events_root: None,
}
2023-01-26T11:04:55.640319Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 6
2023-01-26T11:04:55.640322Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "variedContext"::Berlin::6
2023-01-26T11:04:55.640323Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stEIP2930/variedContext.json"
2023-01-26T11:04:55.640326Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-26T11:04:55.640327Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T11:04:55.640606Z  INFO evm_eth_compliance::statetest::runner: UC : "variedContext"
2023-01-26T11:04:55.640610Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 5520661,
    events_root: None,
}
2023-01-26T11:04:55.640619Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 7
2023-01-26T11:04:55.640621Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "variedContext"::Berlin::7
2023-01-26T11:04:55.640623Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stEIP2930/variedContext.json"
2023-01-26T11:04:55.640626Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-26T11:04:55.640627Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T11:04:55.640891Z  INFO evm_eth_compliance::statetest::runner: UC : "variedContext"
2023-01-26T11:04:55.640896Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 4629978,
    events_root: None,
}
2023-01-26T11:04:55.640904Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 8
2023-01-26T11:04:55.640907Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "variedContext"::Berlin::8
2023-01-26T11:04:55.640909Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stEIP2930/variedContext.json"
2023-01-26T11:04:55.640911Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-26T11:04:55.640913Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T11:04:55.641131Z  INFO evm_eth_compliance::statetest::runner: UC : "variedContext"
2023-01-26T11:04:55.641136Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 4766805,
    events_root: None,
}
2023-01-26T11:04:55.641144Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 9
2023-01-26T11:04:55.641146Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "variedContext"::Berlin::9
2023-01-26T11:04:55.641148Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stEIP2930/variedContext.json"
2023-01-26T11:04:55.641150Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-26T11:04:55.641152Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T11:04:55.641378Z  INFO evm_eth_compliance::statetest::runner: UC : "variedContext"
2023-01-26T11:04:55.641383Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3648203,
    events_root: None,
}
2023-01-26T11:04:55.641390Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 10
2023-01-26T11:04:55.641393Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "variedContext"::Berlin::10
2023-01-26T11:04:55.641395Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stEIP2930/variedContext.json"
2023-01-26T11:04:55.641397Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-26T11:04:55.641399Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T11:04:55.641775Z  INFO evm_eth_compliance::statetest::runner: UC : "variedContext"
2023-01-26T11:04:55.641780Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 9181626,
    events_root: None,
}
2023-01-26T11:04:55.641794Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 11
2023-01-26T11:04:55.641796Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "variedContext"::Berlin::11
2023-01-26T11:04:55.641798Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stEIP2930/variedContext.json"
2023-01-26T11:04:55.641800Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-26T11:04:55.641802Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T11:04:55.642068Z  INFO evm_eth_compliance::statetest::runner: UC : "variedContext"
2023-01-26T11:04:55.642072Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 5045069,
    events_root: None,
}
2023-01-26T11:04:55.642080Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 12
2023-01-26T11:04:55.642083Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "variedContext"::Berlin::12
2023-01-26T11:04:55.642085Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stEIP2930/variedContext.json"
2023-01-26T11:04:55.642087Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-26T11:04:55.642088Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T11:04:55.642383Z  INFO evm_eth_compliance::statetest::runner: UC : "variedContext"
2023-01-26T11:04:55.642387Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 6335590,
    events_root: None,
}
2023-01-26T11:04:55.642396Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 13
2023-01-26T11:04:55.642399Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "variedContext"::Berlin::13
2023-01-26T11:04:55.642401Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stEIP2930/variedContext.json"
2023-01-26T11:04:55.642403Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-26T11:04:55.642404Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T11:04:55.642668Z  INFO evm_eth_compliance::statetest::runner: UC : "variedContext"
2023-01-26T11:04:55.642673Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 5045069,
    events_root: None,
}
2023-01-26T11:04:55.642681Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 14
2023-01-26T11:04:55.642684Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "variedContext"::Berlin::14
2023-01-26T11:04:55.642685Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stEIP2930/variedContext.json"
2023-01-26T11:04:55.642688Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-26T11:04:55.642689Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T11:04:55.642968Z  INFO evm_eth_compliance::statetest::runner: UC : "variedContext"
2023-01-26T11:04:55.642973Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 5505735,
    events_root: None,
}
2023-01-26T11:04:55.642982Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 15
2023-01-26T11:04:55.642984Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "variedContext"::Berlin::15
2023-01-26T11:04:55.642986Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stEIP2930/variedContext.json"
2023-01-26T11:04:55.642989Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-26T11:04:55.642990Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T11:04:55.643263Z  INFO evm_eth_compliance::statetest::runner: UC : "variedContext"
2023-01-26T11:04:55.643267Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 4615053,
    events_root: None,
}
2023-01-26T11:04:55.643275Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 16
2023-01-26T11:04:55.643278Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "variedContext"::Berlin::16
2023-01-26T11:04:55.643280Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stEIP2930/variedContext.json"
2023-01-26T11:04:55.643283Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-26T11:04:55.643284Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T11:04:55.643475Z  INFO evm_eth_compliance::statetest::runner: UC : "variedContext"
2023-01-26T11:04:55.643480Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3220724,
    events_root: None,
}
2023-01-26T11:04:55.643487Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 17
2023-01-26T11:04:55.643489Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "variedContext"::Berlin::17
2023-01-26T11:04:55.643491Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stEIP2930/variedContext.json"
2023-01-26T11:04:55.643493Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-26T11:04:55.643495Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T11:04:55.643685Z  INFO evm_eth_compliance::statetest::runner: UC : "variedContext"
2023-01-26T11:04:55.643689Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3220724,
    events_root: None,
}
2023-01-26T11:04:55.643696Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 18
2023-01-26T11:04:55.643698Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "variedContext"::Berlin::18
2023-01-26T11:04:55.643700Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stEIP2930/variedContext.json"
2023-01-26T11:04:55.643702Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-26T11:04:55.643704Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T11:04:55.643895Z  INFO evm_eth_compliance::statetest::runner: UC : "variedContext"
2023-01-26T11:04:55.643899Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3223951,
    events_root: None,
}
2023-01-26T11:04:55.643906Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 19
2023-01-26T11:04:55.643909Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "variedContext"::Berlin::19
2023-01-26T11:04:55.643911Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stEIP2930/variedContext.json"
2023-01-26T11:04:55.643913Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-26T11:04:55.643914Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T11:04:55.644102Z  INFO evm_eth_compliance::statetest::runner: UC : "variedContext"
2023-01-26T11:04:55.644107Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3223951,
    events_root: None,
}
2023-01-26T11:04:55.644114Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 20
2023-01-26T11:04:55.644116Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "variedContext"::Berlin::20
2023-01-26T11:04:55.644118Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stEIP2930/variedContext.json"
2023-01-26T11:04:55.644120Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-26T11:04:55.644122Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T11:04:55.644394Z  INFO evm_eth_compliance::statetest::runner: UC : "variedContext"
2023-01-26T11:04:55.644399Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 6155731,
    events_root: None,
}
2023-01-26T11:04:55.644406Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 21
2023-01-26T11:04:55.644409Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "variedContext"::Berlin::21
2023-01-26T11:04:55.644411Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stEIP2930/variedContext.json"
2023-01-26T11:04:55.644413Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-26T11:04:55.644415Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T11:04:55.644710Z  INFO evm_eth_compliance::statetest::runner: UC : "variedContext"
2023-01-26T11:04:55.644714Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 6927660,
    events_root: None,
}
2023-01-26T11:04:55.644722Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 22
2023-01-26T11:04:55.644725Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "variedContext"::Berlin::22
2023-01-26T11:04:55.644727Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stEIP2930/variedContext.json"
2023-01-26T11:04:55.644729Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-26T11:04:55.644731Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [179, 205, 123, 163, 43, 173, 245, 56, 227, 28, 255, 73, 228, 41, 132, 94, 1, 208, 46, 30, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([173, 101, 220, 118, 126, 227, 221, 111, 130, 239, 232, 201, 210, 70, 69, 50, 207, 38, 17, 72]) }
2023-01-26T11:04:55.907864Z  INFO evm_eth_compliance::statetest::runner: UC : "variedContext"
2023-01-26T11:04:55.907874Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 17019365,
    events_root: None,
}
2023-01-26T11:04:55.907906Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 23
2023-01-26T11:04:55.907913Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "variedContext"::Berlin::23
2023-01-26T11:04:55.907915Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stEIP2930/variedContext.json"
2023-01-26T11:04:55.907918Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-26T11:04:55.907920Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [176, 245, 16, 212, 156, 67, 193, 200, 141, 98, 50, 197, 112, 81, 56, 84, 20, 43, 166, 144, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([21, 34, 247, 70, 142, 122, 19, 174, 255, 98, 183, 37, 253, 210, 62, 191, 224, 79, 199, 228]) }
2023-01-26T11:04:55.908724Z  INFO evm_eth_compliance::statetest::runner: UC : "variedContext"
2023-01-26T11:04:55.908729Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 17207877,
    events_root: None,
}
2023-01-26T11:04:55.908748Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 24
2023-01-26T11:04:55.908751Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "variedContext"::Berlin::24
2023-01-26T11:04:55.908753Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stEIP2930/variedContext.json"
2023-01-26T11:04:55.908755Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-26T11:04:55.908757Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [179, 89, 68, 173, 17, 51, 61, 64, 153, 99, 238, 128, 61, 225, 39, 68, 75, 215, 92, 178, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([121, 200, 128, 32, 100, 47, 163, 168, 222, 154, 90, 196, 49, 165, 55, 116, 4, 152, 177, 42]) }
2023-01-26T11:04:55.909417Z  INFO evm_eth_compliance::statetest::runner: UC : "variedContext"
2023-01-26T11:04:55.909422Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 16926745,
    events_root: None,
}
2023-01-26T11:04:55.909442Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 25
2023-01-26T11:04:55.909445Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "variedContext"::Berlin::25
2023-01-26T11:04:55.909447Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stEIP2930/variedContext.json"
2023-01-26T11:04:55.909449Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-26T11:04:55.909451Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T11:04:55.909830Z  INFO evm_eth_compliance::statetest::runner: UC : "variedContext"
2023-01-26T11:04:55.909835Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 6342913,
    events_root: None,
}
2023-01-26T11:04:55.909848Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 26
2023-01-26T11:04:55.909851Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "variedContext"::Berlin::26
2023-01-26T11:04:55.909853Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stEIP2930/variedContext.json"
2023-01-26T11:04:55.909855Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-26T11:04:55.909857Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [154, 111, 37, 190, 108, 254, 59, 129, 116, 18, 0, 211, 250, 53, 68, 115, 128, 243, 59, 117, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([192, 88, 99, 161, 23, 254, 175, 39, 213, 169, 153, 253, 197, 254, 95, 117, 145, 246, 7, 95]) }
2023-01-26T11:04:55.910612Z  INFO evm_eth_compliance::statetest::runner: UC : "variedContext"
2023-01-26T11:04:55.910617Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 19463197,
    events_root: None,
}
2023-01-26T11:04:55.910638Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 27
2023-01-26T11:04:55.910641Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "variedContext"::Berlin::27
2023-01-26T11:04:55.910643Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stEIP2930/variedContext.json"
2023-01-26T11:04:55.910646Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-26T11:04:55.910647Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [51, 77, 249, 201, 201, 244, 31, 73, 72, 249, 105, 123, 205, 20, 198, 139, 7, 113, 119, 36, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([96, 33, 187, 115, 222, 53, 224, 244, 47, 32, 70, 11, 226, 18, 129, 166, 126, 239, 230, 44]) }
2023-01-26T11:04:55.911408Z  INFO evm_eth_compliance::statetest::runner: UC : "variedContext"
2023-01-26T11:04:55.911413Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 19378828,
    events_root: None,
}
2023-01-26T11:04:55.911435Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 28
2023-01-26T11:04:55.911438Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "variedContext"::Berlin::28
2023-01-26T11:04:55.911440Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stEIP2930/variedContext.json"
2023-01-26T11:04:55.911442Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-26T11:04:55.911444Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [38, 2, 180, 140, 155, 226, 87, 219, 43, 48, 251, 14, 101, 112, 156, 5, 245, 236, 123, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([221, 202, 25, 212, 34, 2, 50, 123, 41, 75, 186, 155, 123, 166, 127, 9, 228, 237, 116, 209]) }
2023-01-26T11:04:55.912199Z  INFO evm_eth_compliance::statetest::runner: UC : "variedContext"
2023-01-26T11:04:55.912204Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 19533785,
    events_root: None,
}
2023-01-26T11:04:55.912227Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 29
2023-01-26T11:04:55.912229Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "variedContext"::Berlin::29
2023-01-26T11:04:55.912231Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stEIP2930/variedContext.json"
2023-01-26T11:04:55.912234Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-26T11:04:55.912235Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T11:04:55.912620Z  INFO evm_eth_compliance::statetest::runner: UC : "variedContext"
2023-01-26T11:04:55.912625Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 6526568,
    events_root: None,
}
2023-01-26T11:04:55.912638Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 30
2023-01-26T11:04:55.912641Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "variedContext"::Berlin::30
2023-01-26T11:04:55.912643Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stEIP2930/variedContext.json"
2023-01-26T11:04:55.912645Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-26T11:04:55.912647Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [51, 37, 210, 95, 67, 190, 133, 248, 245, 121, 251, 0, 100, 138, 140, 233, 55, 216, 125, 9, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([125, 213, 185, 126, 102, 183, 165, 62, 81, 45, 4, 229, 242, 150, 184, 46, 206, 140, 135, 167]) }
2023-01-26T11:04:55.913465Z  INFO evm_eth_compliance::statetest::runner: UC : "variedContext"
2023-01-26T11:04:55.913470Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 20586675,
    events_root: None,
}
2023-01-26T11:04:55.913492Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 31
2023-01-26T11:04:55.913495Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "variedContext"::Berlin::31
2023-01-26T11:04:55.913497Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stEIP2930/variedContext.json"
2023-01-26T11:04:55.913499Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-26T11:04:55.913501Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [25, 153, 71, 118, 125, 53, 136, 228, 194, 115, 242, 160, 211, 74, 248, 141, 125, 134, 144, 236, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([57, 47, 201, 253, 31, 210, 216, 45, 82, 53, 15, 10, 140, 189, 182, 38, 139, 193, 227, 148]) }
2023-01-26T11:04:55.914312Z  INFO evm_eth_compliance::statetest::runner: UC : "variedContext"
2023-01-26T11:04:55.914317Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 20931242,
    events_root: None,
}
2023-01-26T11:04:55.914339Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 32
2023-01-26T11:04:55.914342Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "variedContext"::Berlin::32
2023-01-26T11:04:55.914344Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stEIP2930/variedContext.json"
2023-01-26T11:04:55.914346Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-26T11:04:55.914348Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [22, 69, 195, 88, 77, 155, 170, 204, 150, 91, 15, 250, 145, 179, 63, 2, 241, 245, 250, 10, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([10, 128, 19, 154, 164, 202, 88, 213, 185, 231, 230, 233, 169, 125, 32, 175, 46, 247, 104, 205]) }
2023-01-26T11:04:55.915160Z  INFO evm_eth_compliance::statetest::runner: UC : "variedContext"
2023-01-26T11:04:55.915165Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 20485430,
    events_root: None,
}
2023-01-26T11:04:55.915187Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 33
2023-01-26T11:04:55.915189Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "variedContext"::Berlin::33
2023-01-26T11:04:55.915191Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stEIP2930/variedContext.json"
2023-01-26T11:04:55.915195Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-26T11:04:55.915197Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T11:04:55.915558Z  INFO evm_eth_compliance::statetest::runner: UC : "variedContext"
2023-01-26T11:04:55.915563Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 6528463,
    events_root: None,
}
2023-01-26T11:04:55.915576Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 34
2023-01-26T11:04:55.915579Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "variedContext"::Berlin::34
2023-01-26T11:04:55.915581Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stEIP2930/variedContext.json"
2023-01-26T11:04:55.915584Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-26T11:04:55.915585Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T11:04:55.916021Z  INFO evm_eth_compliance::statetest::runner: UC : "variedContext"
2023-01-26T11:04:55.916026Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 9777750,
    events_root: None,
}
2023-01-26T11:04:55.916042Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 35
2023-01-26T11:04:55.916045Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "variedContext"::Berlin::35
2023-01-26T11:04:55.916047Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stEIP2930/variedContext.json"
2023-01-26T11:04:55.916049Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-26T11:04:55.916050Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T11:04:55.916493Z  INFO evm_eth_compliance::statetest::runner: UC : "variedContext"
2023-01-26T11:04:55.916498Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 9198636,
    events_root: None,
}
2023-01-26T11:04:55.916516Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-26T11:04:55.916518Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "variedContext"::London::0
2023-01-26T11:04:55.916520Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stEIP2930/variedContext.json"
2023-01-26T11:04:55.916523Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-26T11:04:55.916524Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T11:04:55.916937Z  INFO evm_eth_compliance::statetest::runner: UC : "variedContext"
2023-01-26T11:04:55.916942Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 8834712,
    events_root: None,
}
2023-01-26T11:04:55.916957Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 1
2023-01-26T11:04:55.916960Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "variedContext"::London::1
2023-01-26T11:04:55.916962Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stEIP2930/variedContext.json"
2023-01-26T11:04:55.916964Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-26T11:04:55.916965Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T11:04:55.917367Z  INFO evm_eth_compliance::statetest::runner: UC : "variedContext"
2023-01-26T11:04:55.917372Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 8440023,
    events_root: None,
}
2023-01-26T11:04:55.917386Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 2
2023-01-26T11:04:55.917389Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "variedContext"::London::2
2023-01-26T11:04:55.917390Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stEIP2930/variedContext.json"
2023-01-26T11:04:55.917393Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-26T11:04:55.917394Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T11:04:55.917579Z  INFO evm_eth_compliance::statetest::runner: UC : "variedContext"
2023-01-26T11:04:55.917584Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3084441,
    events_root: None,
}
2023-01-26T11:04:55.917591Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 3
2023-01-26T11:04:55.917594Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "variedContext"::London::3
2023-01-26T11:04:55.917595Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stEIP2930/variedContext.json"
2023-01-26T11:04:55.917598Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-26T11:04:55.917600Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T11:04:55.917815Z  INFO evm_eth_compliance::statetest::runner: UC : "variedContext"
2023-01-26T11:04:55.917819Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3084441,
    events_root: None,
}
2023-01-26T11:04:55.917826Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 4
2023-01-26T11:04:55.917829Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "variedContext"::London::4
2023-01-26T11:04:55.917831Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stEIP2930/variedContext.json"
2023-01-26T11:04:55.917833Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-26T11:04:55.917835Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T11:04:55.918149Z  INFO evm_eth_compliance::statetest::runner: UC : "variedContext"
2023-01-26T11:04:55.918154Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 7371199,
    events_root: None,
}
2023-01-26T11:04:55.918167Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 5
2023-01-26T11:04:55.918169Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "variedContext"::London::5
2023-01-26T11:04:55.918171Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stEIP2930/variedContext.json"
2023-01-26T11:04:55.918174Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-26T11:04:55.918175Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T11:04:55.918480Z  INFO evm_eth_compliance::statetest::runner: UC : "variedContext"
2023-01-26T11:04:55.918485Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 6982238,
    events_root: None,
}
2023-01-26T11:04:55.918498Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 6
2023-01-26T11:04:55.918500Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "variedContext"::London::6
2023-01-26T11:04:55.918502Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stEIP2930/variedContext.json"
2023-01-26T11:04:55.918505Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-26T11:04:55.918506Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T11:04:55.918764Z  INFO evm_eth_compliance::statetest::runner: UC : "variedContext"
2023-01-26T11:04:55.918768Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 4629978,
    events_root: None,
}
2023-01-26T11:04:55.918778Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 7
2023-01-26T11:04:55.918781Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "variedContext"::London::7
2023-01-26T11:04:55.918783Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stEIP2930/variedContext.json"
2023-01-26T11:04:55.918785Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-26T11:04:55.918786Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T11:04:55.919077Z  INFO evm_eth_compliance::statetest::runner: UC : "variedContext"
2023-01-26T11:04:55.919082Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 4629978,
    events_root: None,
}
2023-01-26T11:04:55.919095Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 8
2023-01-26T11:04:55.919098Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "variedContext"::London::8
2023-01-26T11:04:55.919100Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stEIP2930/variedContext.json"
2023-01-26T11:04:55.919103Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-26T11:04:55.919104Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T11:04:55.919339Z  INFO evm_eth_compliance::statetest::runner: UC : "variedContext"
2023-01-26T11:04:55.919344Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 4766805,
    events_root: None,
}
2023-01-26T11:04:55.919355Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 9
2023-01-26T11:04:55.919358Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "variedContext"::London::9
2023-01-26T11:04:55.919360Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stEIP2930/variedContext.json"
2023-01-26T11:04:55.919363Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-26T11:04:55.919364Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T11:04:55.919586Z  INFO evm_eth_compliance::statetest::runner: UC : "variedContext"
2023-01-26T11:04:55.919591Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3648203,
    events_root: None,
}
2023-01-26T11:04:55.919601Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 10
2023-01-26T11:04:55.919604Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "variedContext"::London::10
2023-01-26T11:04:55.919606Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stEIP2930/variedContext.json"
2023-01-26T11:04:55.919609Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-26T11:04:55.919610Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T11:04:55.919889Z  INFO evm_eth_compliance::statetest::runner: UC : "variedContext"
2023-01-26T11:04:55.919893Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 5393623,
    events_root: None,
}
2023-01-26T11:04:55.919904Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 11
2023-01-26T11:04:55.919906Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "variedContext"::London::11
2023-01-26T11:04:55.919908Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stEIP2930/variedContext.json"
2023-01-26T11:04:55.919910Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-26T11:04:55.919912Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T11:04:55.920153Z  INFO evm_eth_compliance::statetest::runner: UC : "variedContext"
2023-01-26T11:04:55.920157Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 4132301,
    events_root: None,
}
2023-01-26T11:04:55.920167Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 12
2023-01-26T11:04:55.920170Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "variedContext"::London::12
2023-01-26T11:04:55.920172Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stEIP2930/variedContext.json"
2023-01-26T11:04:55.920174Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-26T11:04:55.920176Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T11:04:55.920416Z  INFO evm_eth_compliance::statetest::runner: UC : "variedContext"
2023-01-26T11:04:55.920420Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 4132301,
    events_root: None,
}
2023-01-26T11:04:55.920430Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 13
2023-01-26T11:04:55.920432Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "variedContext"::London::13
2023-01-26T11:04:55.920436Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stEIP2930/variedContext.json"
2023-01-26T11:04:55.920438Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-26T11:04:55.920439Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T11:04:55.920679Z  INFO evm_eth_compliance::statetest::runner: UC : "variedContext"
2023-01-26T11:04:55.920683Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 4132301,
    events_root: None,
}
2023-01-26T11:04:55.920693Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 14
2023-01-26T11:04:55.920696Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "variedContext"::London::14
2023-01-26T11:04:55.920698Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stEIP2930/variedContext.json"
2023-01-26T11:04:55.920700Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-26T11:04:55.920701Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T11:04:55.920978Z  INFO evm_eth_compliance::statetest::runner: UC : "variedContext"
2023-01-26T11:04:55.920983Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 4615053,
    events_root: None,
}
2023-01-26T11:04:55.920993Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 15
2023-01-26T11:04:55.920996Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "variedContext"::London::15
2023-01-26T11:04:55.920998Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stEIP2930/variedContext.json"
2023-01-26T11:04:55.921000Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-26T11:04:55.921001Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T11:04:55.921259Z  INFO evm_eth_compliance::statetest::runner: UC : "variedContext"
2023-01-26T11:04:55.921264Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 4615053,
    events_root: None,
}
2023-01-26T11:04:55.921274Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 16
2023-01-26T11:04:55.921277Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "variedContext"::London::16
2023-01-26T11:04:55.921278Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stEIP2930/variedContext.json"
2023-01-26T11:04:55.921281Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-26T11:04:55.921282Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T11:04:55.921474Z  INFO evm_eth_compliance::statetest::runner: UC : "variedContext"
2023-01-26T11:04:55.921478Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3220724,
    events_root: None,
}
2023-01-26T11:04:55.921487Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 17
2023-01-26T11:04:55.921489Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "variedContext"::London::17
2023-01-26T11:04:55.921491Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stEIP2930/variedContext.json"
2023-01-26T11:04:55.921493Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-26T11:04:55.921495Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T11:04:55.921678Z  INFO evm_eth_compliance::statetest::runner: UC : "variedContext"
2023-01-26T11:04:55.921682Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3220724,
    events_root: None,
}
2023-01-26T11:04:55.921690Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 18
2023-01-26T11:04:55.921693Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "variedContext"::London::18
2023-01-26T11:04:55.921695Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stEIP2930/variedContext.json"
2023-01-26T11:04:55.921697Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-26T11:04:55.921699Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T11:04:55.921881Z  INFO evm_eth_compliance::statetest::runner: UC : "variedContext"
2023-01-26T11:04:55.921886Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3223951,
    events_root: None,
}
2023-01-26T11:04:55.921894Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 19
2023-01-26T11:04:55.921896Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "variedContext"::London::19
2023-01-26T11:04:55.921898Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stEIP2930/variedContext.json"
2023-01-26T11:04:55.921900Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-26T11:04:55.921902Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T11:04:55.922085Z  INFO evm_eth_compliance::statetest::runner: UC : "variedContext"
2023-01-26T11:04:55.922090Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3223951,
    events_root: None,
}
2023-01-26T11:04:55.922098Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 20
2023-01-26T11:04:55.922100Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "variedContext"::London::20
2023-01-26T11:04:55.922102Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stEIP2930/variedContext.json"
2023-01-26T11:04:55.922104Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-26T11:04:55.922106Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T11:04:55.922392Z  INFO evm_eth_compliance::statetest::runner: UC : "variedContext"
2023-01-26T11:04:55.922397Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 6945094,
    events_root: None,
}
2023-01-26T11:04:55.922409Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 21
2023-01-26T11:04:55.922412Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "variedContext"::London::21
2023-01-26T11:04:55.922414Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stEIP2930/variedContext.json"
2023-01-26T11:04:55.922416Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-26T11:04:55.922417Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T11:04:55.922695Z  INFO evm_eth_compliance::statetest::runner: UC : "variedContext"
2023-01-26T11:04:55.922700Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 4996931,
    events_root: None,
}
2023-01-26T11:04:55.922709Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 22
2023-01-26T11:04:55.922711Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "variedContext"::London::22
2023-01-26T11:04:55.922713Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stEIP2930/variedContext.json"
2023-01-26T11:04:55.922715Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-26T11:04:55.922717Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [57, 77, 248, 57, 196, 158, 252, 107, 47, 242, 77, 104, 48, 80, 177, 47, 147, 166, 26, 238, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([245, 247, 167, 109, 171, 19, 147, 219, 109, 152, 254, 206, 145, 95, 196, 82, 59, 231, 146, 108]) }
2023-01-26T11:04:55.923365Z  INFO evm_eth_compliance::statetest::runner: UC : "variedContext"
2023-01-26T11:04:55.923370Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 17003577,
    events_root: None,
}
2023-01-26T11:04:55.923391Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 23
2023-01-26T11:04:55.923394Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "variedContext"::London::23
2023-01-26T11:04:55.923395Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stEIP2930/variedContext.json"
2023-01-26T11:04:55.923398Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-26T11:04:55.923399Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [48, 9, 166, 60, 240, 105, 36, 210, 223, 79, 182, 216, 148, 239, 5, 46, 232, 160, 149, 71, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([7, 158, 84, 58, 120, 147, 60, 147, 138, 143, 25, 166, 137, 140, 78, 245, 163, 245, 15, 240]) }
2023-01-26T11:04:55.924043Z  INFO evm_eth_compliance::statetest::runner: UC : "variedContext"
2023-01-26T11:04:55.924048Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 16609058,
    events_root: None,
}
2023-01-26T11:04:55.924066Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 24
2023-01-26T11:04:55.924068Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "variedContext"::London::24
2023-01-26T11:04:55.924070Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stEIP2930/variedContext.json"
2023-01-26T11:04:55.924072Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-26T11:04:55.924074Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T11:04:55.924411Z  INFO evm_eth_compliance::statetest::runner: UC : "variedContext"
2023-01-26T11:04:55.924416Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 5415780,
    events_root: None,
}
2023-01-26T11:04:55.924429Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 25
2023-01-26T11:04:55.924432Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "variedContext"::London::25
2023-01-26T11:04:55.924434Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stEIP2930/variedContext.json"
2023-01-26T11:04:55.924436Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-26T11:04:55.924437Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T11:04:55.924770Z  INFO evm_eth_compliance::statetest::runner: UC : "variedContext"
2023-01-26T11:04:55.924774Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 5415780,
    events_root: None,
}
2023-01-26T11:04:55.924787Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 26
2023-01-26T11:04:55.924789Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "variedContext"::London::26
2023-01-26T11:04:55.924791Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stEIP2930/variedContext.json"
2023-01-26T11:04:55.924793Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-26T11:04:55.924795Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [81, 125, 155, 12, 210, 253, 150, 145, 251, 55, 27, 81, 200, 253, 52, 136, 85, 108, 75, 149, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([54, 233, 149, 112, 243, 205, 226, 29, 96, 223, 210, 91, 9, 119, 78, 94, 236, 137, 95, 47]) }
2023-01-26T11:04:55.925534Z  INFO evm_eth_compliance::statetest::runner: UC : "variedContext"
2023-01-26T11:04:55.925539Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 18806837,
    events_root: None,
}
2023-01-26T11:04:55.925560Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 27
2023-01-26T11:04:55.925562Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "variedContext"::London::27
2023-01-26T11:04:55.925564Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stEIP2930/variedContext.json"
2023-01-26T11:04:55.925566Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-26T11:04:55.925568Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [185, 125, 18, 117, 192, 46, 169, 252, 235, 253, 220, 163, 191, 91, 189, 141, 75, 189, 143, 206, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([238, 253, 241, 172, 208, 208, 47, 210, 127, 104, 145, 191, 55, 169, 92, 159, 79, 33, 124, 81]) }
2023-01-26T11:04:55.926361Z  INFO evm_eth_compliance::statetest::runner: UC : "variedContext"
2023-01-26T11:04:55.926366Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 19537087,
    events_root: None,
}
2023-01-26T11:04:55.926387Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 28
2023-01-26T11:04:55.926390Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "variedContext"::London::28
2023-01-26T11:04:55.926392Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stEIP2930/variedContext.json"
2023-01-26T11:04:55.926395Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-26T11:04:55.926396Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T11:04:55.926736Z  INFO evm_eth_compliance::statetest::runner: UC : "variedContext"
2023-01-26T11:04:55.926741Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 5591544,
    events_root: None,
}
2023-01-26T11:04:55.926755Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 29
2023-01-26T11:04:55.926757Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "variedContext"::London::29
2023-01-26T11:04:55.926759Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stEIP2930/variedContext.json"
2023-01-26T11:04:55.926762Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-26T11:04:55.926763Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T11:04:55.927099Z  INFO evm_eth_compliance::statetest::runner: UC : "variedContext"
2023-01-26T11:04:55.927104Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 5591544,
    events_root: None,
}
2023-01-26T11:04:55.927117Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 30
2023-01-26T11:04:55.927119Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "variedContext"::London::30
2023-01-26T11:04:55.927121Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stEIP2930/variedContext.json"
2023-01-26T11:04:55.927123Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-26T11:04:55.927125Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [247, 232, 127, 43, 197, 249, 242, 61, 170, 115, 244, 9, 38, 96, 47, 78, 12, 3, 227, 252, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([160, 22, 178, 28, 123, 24, 4, 205, 147, 64, 111, 144, 122, 198, 167, 128, 46, 191, 140, 52]) }
2023-01-26T11:04:55.927926Z  INFO evm_eth_compliance::statetest::runner: UC : "variedContext"
2023-01-26T11:04:55.927930Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 20907841,
    events_root: None,
}
2023-01-26T11:04:55.927951Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 31
2023-01-26T11:04:55.927955Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "variedContext"::London::31
2023-01-26T11:04:55.927956Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stEIP2930/variedContext.json"
2023-01-26T11:04:55.927959Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-26T11:04:55.927960Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [35, 68, 216, 213, 23, 83, 245, 113, 70, 237, 128, 11, 116, 82, 84, 58, 157, 10, 66, 215, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([6, 101, 24, 32, 72, 254, 76, 158, 23, 230, 180, 249, 6, 77, 81, 181, 195, 46, 12, 239]) }
2023-01-26T11:04:55.928752Z  INFO evm_eth_compliance::statetest::runner: UC : "variedContext"
2023-01-26T11:04:55.928757Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 20409119,
    events_root: None,
}
2023-01-26T11:04:55.928782Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 32
2023-01-26T11:04:55.928787Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "variedContext"::London::32
2023-01-26T11:04:55.928789Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stEIP2930/variedContext.json"
2023-01-26T11:04:55.928791Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-26T11:04:55.928793Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T11:04:55.929139Z  INFO evm_eth_compliance::statetest::runner: UC : "variedContext"
2023-01-26T11:04:55.929144Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 5593438,
    events_root: None,
}
2023-01-26T11:04:55.929157Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 33
2023-01-26T11:04:55.929160Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "variedContext"::London::33
2023-01-26T11:04:55.929162Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stEIP2930/variedContext.json"
2023-01-26T11:04:55.929164Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-26T11:04:55.929165Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T11:04:55.929512Z  INFO evm_eth_compliance::statetest::runner: UC : "variedContext"
2023-01-26T11:04:55.929517Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 5593438,
    events_root: None,
}
2023-01-26T11:04:55.929530Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 34
2023-01-26T11:04:55.929533Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "variedContext"::London::34
2023-01-26T11:04:55.929534Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stEIP2930/variedContext.json"
2023-01-26T11:04:55.929537Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-26T11:04:55.929538Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T11:04:55.929941Z  INFO evm_eth_compliance::statetest::runner: UC : "variedContext"
2023-01-26T11:04:55.929946Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 7709105,
    events_root: None,
}
2023-01-26T11:04:55.929961Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 35
2023-01-26T11:04:55.929963Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "variedContext"::London::35
2023-01-26T11:04:55.929965Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stEIP2930/variedContext.json"
2023-01-26T11:04:55.929967Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-26T11:04:55.929968Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T11:04:55.930361Z  INFO evm_eth_compliance::statetest::runner: UC : "variedContext"
2023-01-26T11:04:55.930366Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 7709105,
    events_root: None,
}
2023-01-26T11:04:55.930381Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-26T11:04:55.930384Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "variedContext"::Merge::0
2023-01-26T11:04:55.930385Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stEIP2930/variedContext.json"
2023-01-26T11:04:55.930387Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-26T11:04:55.930389Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T11:04:55.930743Z  INFO evm_eth_compliance::statetest::runner: UC : "variedContext"
2023-01-26T11:04:55.930747Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 6470737,
    events_root: None,
}
2023-01-26T11:04:55.930762Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 1
2023-01-26T11:04:55.930765Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "variedContext"::Merge::1
2023-01-26T11:04:55.930767Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stEIP2930/variedContext.json"
2023-01-26T11:04:55.930769Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-26T11:04:55.930770Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T11:04:55.931121Z  INFO evm_eth_compliance::statetest::runner: UC : "variedContext"
2023-01-26T11:04:55.931125Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 6470737,
    events_root: None,
}
2023-01-26T11:04:55.931138Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 2
2023-01-26T11:04:55.931141Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "variedContext"::Merge::2
2023-01-26T11:04:55.931143Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stEIP2930/variedContext.json"
2023-01-26T11:04:55.931145Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-26T11:04:55.931146Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T11:04:55.931319Z  INFO evm_eth_compliance::statetest::runner: UC : "variedContext"
2023-01-26T11:04:55.931324Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3084441,
    events_root: None,
}
2023-01-26T11:04:55.931330Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 3
2023-01-26T11:04:55.931333Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "variedContext"::Merge::3
2023-01-26T11:04:55.931334Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stEIP2930/variedContext.json"
2023-01-26T11:04:55.931336Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-26T11:04:55.931338Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T11:04:55.931523Z  INFO evm_eth_compliance::statetest::runner: UC : "variedContext"
2023-01-26T11:04:55.931527Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3084441,
    events_root: None,
}
2023-01-26T11:04:55.931534Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 4
2023-01-26T11:04:55.931537Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "variedContext"::Merge::4
2023-01-26T11:04:55.931539Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stEIP2930/variedContext.json"
2023-01-26T11:04:55.931541Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-26T11:04:55.931542Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T11:04:55.931824Z  INFO evm_eth_compliance::statetest::runner: UC : "variedContext"
2023-01-26T11:04:55.931829Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 5493927,
    events_root: None,
}
2023-01-26T11:04:55.931840Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 5
2023-01-26T11:04:55.931843Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "variedContext"::Merge::5
2023-01-26T11:04:55.931845Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stEIP2930/variedContext.json"
2023-01-26T11:04:55.931847Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-26T11:04:55.931848Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T11:04:55.932138Z  INFO evm_eth_compliance::statetest::runner: UC : "variedContext"
2023-01-26T11:04:55.932143Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 5493927,
    events_root: None,
}
2023-01-26T11:04:55.932155Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 6
2023-01-26T11:04:55.932157Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "variedContext"::Merge::6
2023-01-26T11:04:55.932159Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stEIP2930/variedContext.json"
2023-01-26T11:04:55.932161Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-26T11:04:55.932163Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T11:04:55.932416Z  INFO evm_eth_compliance::statetest::runner: UC : "variedContext"
2023-01-26T11:04:55.932420Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 4629978,
    events_root: None,
}
2023-01-26T11:04:55.932431Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 7
2023-01-26T11:04:55.932433Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "variedContext"::Merge::7
2023-01-26T11:04:55.932435Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stEIP2930/variedContext.json"
2023-01-26T11:04:55.932437Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-26T11:04:55.932440Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T11:04:55.932689Z  INFO evm_eth_compliance::statetest::runner: UC : "variedContext"
2023-01-26T11:04:55.932693Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 4629978,
    events_root: None,
}
2023-01-26T11:04:55.932704Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 8
2023-01-26T11:04:55.932706Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "variedContext"::Merge::8
2023-01-26T11:04:55.932708Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stEIP2930/variedContext.json"
2023-01-26T11:04:55.932710Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-26T11:04:55.932711Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T11:04:55.932921Z  INFO evm_eth_compliance::statetest::runner: UC : "variedContext"
2023-01-26T11:04:55.932926Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 4766805,
    events_root: None,
}
2023-01-26T11:04:55.932934Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 9
2023-01-26T11:04:55.932937Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "variedContext"::Merge::9
2023-01-26T11:04:55.932938Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stEIP2930/variedContext.json"
2023-01-26T11:04:55.932941Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-26T11:04:55.932942Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T11:04:55.933144Z  INFO evm_eth_compliance::statetest::runner: UC : "variedContext"
2023-01-26T11:04:55.933148Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3648203,
    events_root: None,
}
2023-01-26T11:04:55.933156Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 10
2023-01-26T11:04:55.933159Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "variedContext"::Merge::10
2023-01-26T11:04:55.933160Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stEIP2930/variedContext.json"
2023-01-26T11:04:55.933163Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-26T11:04:55.933164Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T11:04:55.933436Z  INFO evm_eth_compliance::statetest::runner: UC : "variedContext"
2023-01-26T11:04:55.933441Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 5393623,
    events_root: None,
}
2023-01-26T11:04:55.933452Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 11
2023-01-26T11:04:55.933455Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "variedContext"::Merge::11
2023-01-26T11:04:55.933456Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stEIP2930/variedContext.json"
2023-01-26T11:04:55.933458Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-26T11:04:55.933460Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T11:04:55.933699Z  INFO evm_eth_compliance::statetest::runner: UC : "variedContext"
2023-01-26T11:04:55.933704Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 4132301,
    events_root: None,
}
2023-01-26T11:04:55.933713Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 12
2023-01-26T11:04:55.933716Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "variedContext"::Merge::12
2023-01-26T11:04:55.933718Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stEIP2930/variedContext.json"
2023-01-26T11:04:55.933720Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-26T11:04:55.933721Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T11:04:55.933967Z  INFO evm_eth_compliance::statetest::runner: UC : "variedContext"
2023-01-26T11:04:55.933971Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 4132301,
    events_root: None,
}
2023-01-26T11:04:55.933981Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 13
2023-01-26T11:04:55.933984Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "variedContext"::Merge::13
2023-01-26T11:04:55.933986Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stEIP2930/variedContext.json"
2023-01-26T11:04:55.933988Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-26T11:04:55.933989Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T11:04:55.934251Z  INFO evm_eth_compliance::statetest::runner: UC : "variedContext"
2023-01-26T11:04:55.934256Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 4132301,
    events_root: None,
}
2023-01-26T11:04:55.934266Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 14
2023-01-26T11:04:55.934269Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "variedContext"::Merge::14
2023-01-26T11:04:55.934270Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stEIP2930/variedContext.json"
2023-01-26T11:04:55.934273Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-26T11:04:55.934274Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T11:04:55.934527Z  INFO evm_eth_compliance::statetest::runner: UC : "variedContext"
2023-01-26T11:04:55.934532Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 4615053,
    events_root: None,
}
2023-01-26T11:04:55.934542Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 15
2023-01-26T11:04:55.934545Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "variedContext"::Merge::15
2023-01-26T11:04:55.934546Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stEIP2930/variedContext.json"
2023-01-26T11:04:55.934549Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-26T11:04:55.934550Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T11:04:55.934802Z  INFO evm_eth_compliance::statetest::runner: UC : "variedContext"
2023-01-26T11:04:55.934807Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 4615053,
    events_root: None,
}
2023-01-26T11:04:55.934817Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 16
2023-01-26T11:04:55.934820Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "variedContext"::Merge::16
2023-01-26T11:04:55.934821Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stEIP2930/variedContext.json"
2023-01-26T11:04:55.934824Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-26T11:04:55.934825Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T11:04:55.935008Z  INFO evm_eth_compliance::statetest::runner: UC : "variedContext"
2023-01-26T11:04:55.935012Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3220724,
    events_root: None,
}
2023-01-26T11:04:55.935021Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 17
2023-01-26T11:04:55.935023Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "variedContext"::Merge::17
2023-01-26T11:04:55.935025Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stEIP2930/variedContext.json"
2023-01-26T11:04:55.935027Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-26T11:04:55.935028Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T11:04:55.935207Z  INFO evm_eth_compliance::statetest::runner: UC : "variedContext"
2023-01-26T11:04:55.935212Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3220724,
    events_root: None,
}
2023-01-26T11:04:55.935220Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 18
2023-01-26T11:04:55.935222Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "variedContext"::Merge::18
2023-01-26T11:04:55.935224Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stEIP2930/variedContext.json"
2023-01-26T11:04:55.935226Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-26T11:04:55.935227Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T11:04:55.935405Z  INFO evm_eth_compliance::statetest::runner: UC : "variedContext"
2023-01-26T11:04:55.935410Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3223951,
    events_root: None,
}
2023-01-26T11:04:55.935418Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 19
2023-01-26T11:04:55.935420Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "variedContext"::Merge::19
2023-01-26T11:04:55.935422Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stEIP2930/variedContext.json"
2023-01-26T11:04:55.935424Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-26T11:04:55.935426Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T11:04:55.935604Z  INFO evm_eth_compliance::statetest::runner: UC : "variedContext"
2023-01-26T11:04:55.935609Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3223951,
    events_root: None,
}
2023-01-26T11:04:55.935617Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 20
2023-01-26T11:04:55.935619Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "variedContext"::Merge::20
2023-01-26T11:04:55.935623Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stEIP2930/variedContext.json"
2023-01-26T11:04:55.935625Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-26T11:04:55.935626Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T11:04:55.935897Z  INFO evm_eth_compliance::statetest::runner: UC : "variedContext"
2023-01-26T11:04:55.935901Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 4996931,
    events_root: None,
}
2023-01-26T11:04:55.935911Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 21
2023-01-26T11:04:55.935913Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "variedContext"::Merge::21
2023-01-26T11:04:55.935915Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stEIP2930/variedContext.json"
2023-01-26T11:04:55.935917Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-26T11:04:55.935919Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T11:04:55.936178Z  INFO evm_eth_compliance::statetest::runner: UC : "variedContext"
2023-01-26T11:04:55.936182Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 4996931,
    events_root: None,
}
2023-01-26T11:04:55.936191Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 22
2023-01-26T11:04:55.936194Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "variedContext"::Merge::22
2023-01-26T11:04:55.936195Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stEIP2930/variedContext.json"
2023-01-26T11:04:55.936197Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-26T11:04:55.936199Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [215, 209, 207, 74, 143, 14, 84, 206, 126, 236, 35, 50, 168, 91, 122, 188, 133, 220, 249, 102, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([96, 221, 7, 113, 89, 247, 138, 119, 225, 55, 135, 221, 132, 165, 82, 22, 202, 208, 233, 91]) }
2023-01-26T11:04:55.936863Z  INFO evm_eth_compliance::statetest::runner: UC : "variedContext"
2023-01-26T11:04:55.936867Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 17121444,
    events_root: None,
}
2023-01-26T11:04:55.936886Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 23
2023-01-26T11:04:55.936888Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "variedContext"::Merge::23
2023-01-26T11:04:55.936890Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stEIP2930/variedContext.json"
2023-01-26T11:04:55.936894Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-26T11:04:55.936895Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [46, 15, 200, 49, 36, 233, 108, 85, 162, 233, 125, 228, 127, 175, 185, 244, 112, 12, 77, 142, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([155, 48, 90, 18, 221, 116, 7, 27, 31, 161, 14, 26, 47, 29, 244, 108, 165, 178, 172, 107]) }
2023-01-26T11:04:55.937571Z  INFO evm_eth_compliance::statetest::runner: UC : "variedContext"
2023-01-26T11:04:55.937577Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 17067403,
    events_root: None,
}
2023-01-26T11:04:55.937594Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 24
2023-01-26T11:04:55.937597Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "variedContext"::Merge::24
2023-01-26T11:04:55.937599Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stEIP2930/variedContext.json"
2023-01-26T11:04:55.937601Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-26T11:04:55.937602Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T11:04:55.937935Z  INFO evm_eth_compliance::statetest::runner: UC : "variedContext"
2023-01-26T11:04:55.937940Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 5415780,
    events_root: None,
}
2023-01-26T11:04:55.937952Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 25
2023-01-26T11:04:55.937956Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "variedContext"::Merge::25
2023-01-26T11:04:55.937958Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stEIP2930/variedContext.json"
2023-01-26T11:04:55.937960Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-26T11:04:55.937962Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T11:04:55.938288Z  INFO evm_eth_compliance::statetest::runner: UC : "variedContext"
2023-01-26T11:04:55.938293Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 5415780,
    events_root: None,
}
2023-01-26T11:04:55.938305Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 26
2023-01-26T11:04:55.938308Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "variedContext"::Merge::26
2023-01-26T11:04:55.938309Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stEIP2930/variedContext.json"
2023-01-26T11:04:55.938312Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-26T11:04:55.938313Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [246, 144, 152, 81, 116, 71, 49, 177, 32, 189, 203, 16, 203, 127, 135, 12, 150, 218, 169, 84, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([42, 76, 99, 23, 230, 105, 11, 148, 115, 193, 49, 201, 172, 238, 44, 177, 35, 167, 102, 62]) }
2023-01-26T11:04:55.939095Z  INFO evm_eth_compliance::statetest::runner: UC : "variedContext"
2023-01-26T11:04:55.939099Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 19592087,
    events_root: None,
}
2023-01-26T11:04:55.939122Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 27
2023-01-26T11:04:55.939125Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "variedContext"::Merge::27
2023-01-26T11:04:55.939126Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stEIP2930/variedContext.json"
2023-01-26T11:04:55.939129Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-26T11:04:55.939130Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [170, 24, 11, 252, 10, 105, 115, 7, 18, 87, 104, 157, 198, 144, 134, 130, 60, 120, 109, 29, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([119, 145, 84, 64, 213, 27, 134, 173, 52, 245, 118, 171, 99, 148, 112, 180, 105, 70, 113, 93]) }
2023-01-26T11:04:55.939923Z  INFO evm_eth_compliance::statetest::runner: UC : "variedContext"
2023-01-26T11:04:55.939927Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 20027903,
    events_root: None,
}
2023-01-26T11:04:55.939948Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 28
2023-01-26T11:04:55.939951Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "variedContext"::Merge::28
2023-01-26T11:04:55.939953Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stEIP2930/variedContext.json"
2023-01-26T11:04:55.939955Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-26T11:04:55.939956Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T11:04:55.940294Z  INFO evm_eth_compliance::statetest::runner: UC : "variedContext"
2023-01-26T11:04:55.940299Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 5591544,
    events_root: None,
}
2023-01-26T11:04:55.940312Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 29
2023-01-26T11:04:55.940314Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "variedContext"::Merge::29
2023-01-26T11:04:55.940316Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stEIP2930/variedContext.json"
2023-01-26T11:04:55.940318Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-26T11:04:55.940321Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T11:04:55.940652Z  INFO evm_eth_compliance::statetest::runner: UC : "variedContext"
2023-01-26T11:04:55.940657Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 5591544,
    events_root: None,
}
2023-01-26T11:04:55.940670Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 30
2023-01-26T11:04:55.940672Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "variedContext"::Merge::30
2023-01-26T11:04:55.940674Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stEIP2930/variedContext.json"
2023-01-26T11:04:55.940676Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-26T11:04:55.940678Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [112, 58, 95, 193, 218, 74, 190, 20, 183, 101, 193, 2, 157, 164, 32, 27, 13, 75, 180, 196, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([251, 148, 47, 146, 203, 69, 25, 195, 112, 159, 197, 4, 200, 234, 86, 36, 129, 72, 237, 154]) }
2023-01-26T11:04:55.941482Z  INFO evm_eth_compliance::statetest::runner: UC : "variedContext"
2023-01-26T11:04:55.941487Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 20741947,
    events_root: None,
}
2023-01-26T11:04:55.941508Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 31
2023-01-26T11:04:55.941511Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "variedContext"::Merge::31
2023-01-26T11:04:55.941512Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stEIP2930/variedContext.json"
2023-01-26T11:04:55.941515Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-26T11:04:55.941516Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [143, 150, 144, 70, 193, 77, 10, 149, 139, 23, 53, 165, 150, 66, 126, 102, 209, 37, 121, 17, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([0, 139, 20, 138, 169, 250, 202, 38, 0, 219, 54, 113, 39, 208, 211, 109, 45, 57, 7, 29]) }
2023-01-26T11:04:55.942335Z  INFO evm_eth_compliance::statetest::runner: UC : "variedContext"
2023-01-26T11:04:55.942340Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 20794525,
    events_root: None,
}
2023-01-26T11:04:55.942362Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 32
2023-01-26T11:04:55.942365Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "variedContext"::Merge::32
2023-01-26T11:04:55.942367Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stEIP2930/variedContext.json"
2023-01-26T11:04:55.942369Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-26T11:04:55.942370Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T11:04:55.942721Z  INFO evm_eth_compliance::statetest::runner: UC : "variedContext"
2023-01-26T11:04:55.942726Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 5593438,
    events_root: None,
}
2023-01-26T11:04:55.942739Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 33
2023-01-26T11:04:55.942742Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "variedContext"::Merge::33
2023-01-26T11:04:55.942743Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stEIP2930/variedContext.json"
2023-01-26T11:04:55.942746Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-26T11:04:55.942747Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T11:04:55.943077Z  INFO evm_eth_compliance::statetest::runner: UC : "variedContext"
2023-01-26T11:04:55.943082Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 5593438,
    events_root: None,
}
2023-01-26T11:04:55.943095Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 34
2023-01-26T11:04:55.943098Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "variedContext"::Merge::34
2023-01-26T11:04:55.943099Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stEIP2930/variedContext.json"
2023-01-26T11:04:55.943102Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-26T11:04:55.943103Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T11:04:55.943500Z  INFO evm_eth_compliance::statetest::runner: UC : "variedContext"
2023-01-26T11:04:55.943505Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 7709105,
    events_root: None,
}
2023-01-26T11:04:55.943519Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 35
2023-01-26T11:04:55.943523Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "variedContext"::Merge::35
2023-01-26T11:04:55.943525Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stEIP2930/variedContext.json"
2023-01-26T11:04:55.943527Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-26T11:04:55.943528Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T11:04:55.943926Z  INFO evm_eth_compliance::statetest::runner: UC : "variedContext"
2023-01-26T11:04:55.943931Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 7709105,
    events_root: None,
}
2023-01-26T11:04:55.944962Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:659.432507ms
```