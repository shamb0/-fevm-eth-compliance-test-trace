> Status

| Status | Context |
| --- | --- |
| OK | under WASM RT context |
| TODO | under native RT context |

> Test Suite

https://github.com/ethereum/tests/blob/develop/GeneralStateTests/stDelegatecallTestHomestead

> Command to execute

```
clear && \
	RUST_LOG=evm_eth_compliance=trace \
	VECTOR=test-vectors/tests/GeneralStateTests/stDelegatecallTestHomestead \
	cargo run --release \
	-- \
	statetest
```

> For Review

* Execution looks OK, all use-cases Passed.

> Execution Trace

```
2023-01-26T12:27:54.839331Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "./test-vectors/tests/GeneralStateTests/stDelegatecallTestHomestead/Call1024BalanceTooLow.json", Total Files :: 1
2023-01-26T12:27:54.903090Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-26T12:27:54.903256Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T12:27:54.903260Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-26T12:27:54.903311Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T12:27:54.903313Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 2
2023-01-26T12:27:54.903368Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T12:27:54.903450Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-26T12:27:54.903453Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "Call1024BalanceTooLow"::Istanbul::0
2023-01-26T12:27:54.903456Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stDelegatecallTestHomestead/Call1024BalanceTooLow.json"
2023-01-26T12:27:54.903459Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T12:27:54.903461Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T12:27:55.388668Z  INFO evm_eth_compliance::statetest::runner: UC : "Call1024BalanceTooLow"
2023-01-26T12:27:55.388684Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3043253862,
    events_root: None,
}
2023-01-26T12:27:55.393800Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-26T12:27:55.393812Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "Call1024BalanceTooLow"::Berlin::0
2023-01-26T12:27:55.393815Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stDelegatecallTestHomestead/Call1024BalanceTooLow.json"
2023-01-26T12:27:55.393819Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T12:27:55.393820Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T12:27:55.560995Z  INFO evm_eth_compliance::statetest::runner: UC : "Call1024BalanceTooLow"
2023-01-26T12:27:55.561009Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3626869478,
    events_root: None,
}
2023-01-26T12:27:55.566150Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-26T12:27:55.566163Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "Call1024BalanceTooLow"::London::0
2023-01-26T12:27:55.566166Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stDelegatecallTestHomestead/Call1024BalanceTooLow.json"
2023-01-26T12:27:55.566169Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T12:27:55.566170Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T12:27:55.729564Z  INFO evm_eth_compliance::statetest::runner: UC : "Call1024BalanceTooLow"
2023-01-26T12:27:55.729577Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3626869662,
    events_root: None,
}
2023-01-26T12:27:55.736764Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-26T12:27:55.736776Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "Call1024BalanceTooLow"::Merge::0
2023-01-26T12:27:55.736779Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stDelegatecallTestHomestead/Call1024BalanceTooLow.json"
2023-01-26T12:27:55.736782Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T12:27:55.736783Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T12:27:55.906239Z  INFO evm_eth_compliance::statetest::runner: UC : "Call1024BalanceTooLow"
2023-01-26T12:27:55.906252Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3626869202,
    events_root: None,
}
2023-01-26T12:27:55.924484Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:1.011133398s
2023-01-26T12:27:56.183400Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "./test-vectors/tests/GeneralStateTests/stDelegatecallTestHomestead/Call1024OOG.json", Total Files :: 1
2023-01-26T12:27:56.243911Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-26T12:27:56.244083Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T12:27:56.244087Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-26T12:27:56.244139Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T12:27:56.244141Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 2
2023-01-26T12:27:56.244198Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T12:27:56.244282Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-26T12:27:56.244286Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "Call1024OOG"::Istanbul::0
2023-01-26T12:27:56.244289Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stDelegatecallTestHomestead/Call1024OOG.json"
2023-01-26T12:27:56.244292Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T12:27:56.244294Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T12:27:56.878445Z  INFO evm_eth_compliance::statetest::runner: UC : "Call1024OOG"
2023-01-26T12:27:56.878460Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 4786864951,
    events_root: None,
}
2023-01-26T12:27:56.886941Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-26T12:27:56.886957Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "Call1024OOG"::Istanbul::0
2023-01-26T12:27:56.886959Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stDelegatecallTestHomestead/Call1024OOG.json"
2023-01-26T12:27:56.886963Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T12:27:56.886964Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T12:27:56.893210Z  INFO evm_eth_compliance::statetest::runner: UC : "Call1024OOG"
2023-01-26T12:27:56.893222Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 14980440,
    events_root: None,
}
2023-01-26T12:27:56.893247Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-26T12:27:56.893251Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "Call1024OOG"::Berlin::0
2023-01-26T12:27:56.893253Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stDelegatecallTestHomestead/Call1024OOG.json"
2023-01-26T12:27:56.893256Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T12:27:56.893257Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T12:27:56.893533Z  INFO evm_eth_compliance::statetest::runner: UC : "Call1024OOG"
2023-01-26T12:27:56.893538Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 6941754,
    events_root: None,
}
2023-01-26T12:27:56.893550Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-26T12:27:56.893552Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "Call1024OOG"::Berlin::0
2023-01-26T12:27:56.893554Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stDelegatecallTestHomestead/Call1024OOG.json"
2023-01-26T12:27:56.893557Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T12:27:56.893558Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T12:27:56.893800Z  INFO evm_eth_compliance::statetest::runner: UC : "Call1024OOG"
2023-01-26T12:27:56.893804Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 6209617,
    events_root: None,
}
2023-01-26T12:27:56.893814Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-26T12:27:56.893817Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "Call1024OOG"::London::0
2023-01-26T12:27:56.893819Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stDelegatecallTestHomestead/Call1024OOG.json"
2023-01-26T12:27:56.893821Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T12:27:56.893823Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T12:27:56.894062Z  INFO evm_eth_compliance::statetest::runner: UC : "Call1024OOG"
2023-01-26T12:27:56.894067Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 6209617,
    events_root: None,
}
2023-01-26T12:27:56.894077Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-26T12:27:56.894079Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "Call1024OOG"::London::0
2023-01-26T12:27:56.894081Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stDelegatecallTestHomestead/Call1024OOG.json"
2023-01-26T12:27:56.894084Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T12:27:56.894085Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T12:27:56.894325Z  INFO evm_eth_compliance::statetest::runner: UC : "Call1024OOG"
2023-01-26T12:27:56.894330Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 6209617,
    events_root: None,
}
2023-01-26T12:27:56.894339Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-26T12:27:56.894342Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "Call1024OOG"::Merge::0
2023-01-26T12:27:56.894343Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stDelegatecallTestHomestead/Call1024OOG.json"
2023-01-26T12:27:56.894346Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T12:27:56.894347Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T12:27:56.894586Z  INFO evm_eth_compliance::statetest::runner: UC : "Call1024OOG"
2023-01-26T12:27:56.894590Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 6209617,
    events_root: None,
}
2023-01-26T12:27:56.894600Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-26T12:27:56.894603Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "Call1024OOG"::Merge::0
2023-01-26T12:27:56.894604Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stDelegatecallTestHomestead/Call1024OOG.json"
2023-01-26T12:27:56.894607Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T12:27:56.894608Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T12:27:56.894845Z  INFO evm_eth_compliance::statetest::runner: UC : "Call1024OOG"
2023-01-26T12:27:56.894850Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 6209617,
    events_root: None,
}
2023-01-26T12:27:56.907539Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:650.952573ms
2023-01-26T12:27:57.179038Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "./test-vectors/tests/GeneralStateTests/stDelegatecallTestHomestead/Call1024PreCalls.json", Total Files :: 1
2023-01-26T12:27:57.234902Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-26T12:27:57.235075Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T12:27:57.235079Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-26T12:27:57.235129Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T12:27:57.235131Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 2
2023-01-26T12:27:57.235199Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T12:27:57.235283Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-26T12:27:57.235286Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "Call1024PreCalls"::Istanbul::0
2023-01-26T12:27:57.235289Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stDelegatecallTestHomestead/Call1024PreCalls.json"
2023-01-26T12:27:57.235292Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T12:27:57.235293Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T12:27:57.766829Z  INFO evm_eth_compliance::statetest::runner: UC : "Call1024PreCalls"
2023-01-26T12:27:57.766845Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3355718137,
    events_root: None,
}
2023-01-26T12:27:57.772052Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-26T12:27:57.772065Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "Call1024PreCalls"::Istanbul::0
2023-01-26T12:27:57.772068Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stDelegatecallTestHomestead/Call1024PreCalls.json"
2023-01-26T12:27:57.772071Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T12:27:57.772072Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T12:27:57.982795Z  INFO evm_eth_compliance::statetest::runner: UC : "Call1024PreCalls"
2023-01-26T12:27:57.982809Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 4016786097,
    events_root: None,
}
2023-01-26T12:27:57.990594Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-26T12:27:57.990615Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "Call1024PreCalls"::Berlin::0
2023-01-26T12:27:57.990619Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stDelegatecallTestHomestead/Call1024PreCalls.json"
2023-01-26T12:27:57.990622Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T12:27:57.990624Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T12:27:58.200579Z  INFO evm_eth_compliance::statetest::runner: UC : "Call1024PreCalls"
2023-01-26T12:27:58.200596Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 4016786005,
    events_root: None,
}
2023-01-26T12:27:58.207583Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-26T12:27:58.207599Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "Call1024PreCalls"::Berlin::0
2023-01-26T12:27:58.207602Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stDelegatecallTestHomestead/Call1024PreCalls.json"
2023-01-26T12:27:58.207605Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T12:27:58.207606Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T12:27:58.417170Z  INFO evm_eth_compliance::statetest::runner: UC : "Call1024PreCalls"
2023-01-26T12:27:58.417185Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 4016786281,
    events_root: None,
}
2023-01-26T12:27:58.424797Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-26T12:27:58.424819Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "Call1024PreCalls"::London::0
2023-01-26T12:27:58.424823Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stDelegatecallTestHomestead/Call1024PreCalls.json"
2023-01-26T12:27:58.424826Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T12:27:58.424827Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T12:27:58.638269Z  INFO evm_eth_compliance::statetest::runner: UC : "Call1024PreCalls"
2023-01-26T12:27:58.638285Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 4016785913,
    events_root: None,
}
2023-01-26T12:27:58.645717Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-26T12:27:58.645737Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "Call1024PreCalls"::London::0
2023-01-26T12:27:58.645740Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stDelegatecallTestHomestead/Call1024PreCalls.json"
2023-01-26T12:27:58.645743Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T12:27:58.645744Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T12:27:58.856434Z  INFO evm_eth_compliance::statetest::runner: UC : "Call1024PreCalls"
2023-01-26T12:27:58.856448Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 4016786005,
    events_root: None,
}
2023-01-26T12:27:58.864391Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-26T12:27:58.864411Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "Call1024PreCalls"::Merge::0
2023-01-26T12:27:58.864413Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stDelegatecallTestHomestead/Call1024PreCalls.json"
2023-01-26T12:27:58.864417Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T12:27:58.864418Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T12:27:59.080265Z  INFO evm_eth_compliance::statetest::runner: UC : "Call1024PreCalls"
2023-01-26T12:27:59.080281Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 4016785821,
    events_root: None,
}
2023-01-26T12:27:59.088478Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-26T12:27:59.088498Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "Call1024PreCalls"::Merge::0
2023-01-26T12:27:59.088501Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stDelegatecallTestHomestead/Call1024PreCalls.json"
2023-01-26T12:27:59.088504Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T12:27:59.088505Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T12:27:59.309148Z  INFO evm_eth_compliance::statetest::runner: UC : "Call1024PreCalls"
2023-01-26T12:27:59.309164Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 4016786005,
    events_root: None,
}
2023-01-26T12:27:59.334324Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:2.081704491s
2023-01-26T12:27:59.599858Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "./test-vectors/tests/GeneralStateTests/stDelegatecallTestHomestead/CallLoseGasOOG.json", Total Files :: 1
2023-01-26T12:27:59.641418Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-26T12:27:59.641599Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T12:27:59.641603Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-26T12:27:59.641656Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T12:27:59.641658Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 2
2023-01-26T12:27:59.641715Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T12:27:59.641810Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-26T12:27:59.641813Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CallLoseGasOOG"::Istanbul::0
2023-01-26T12:27:59.641816Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stDelegatecallTestHomestead/CallLoseGasOOG.json"
2023-01-26T12:27:59.641820Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T12:27:59.641821Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T12:28:00.007001Z  INFO evm_eth_compliance::statetest::runner: UC : "CallLoseGasOOG"
2023-01-26T12:28:00.007019Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 5218418,
    events_root: None,
}
2023-01-26T12:28:00.007034Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-26T12:28:00.007040Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CallLoseGasOOG"::Berlin::0
2023-01-26T12:28:00.007043Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stDelegatecallTestHomestead/CallLoseGasOOG.json"
2023-01-26T12:28:00.007046Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T12:28:00.007048Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T12:28:00.007403Z  INFO evm_eth_compliance::statetest::runner: UC : "CallLoseGasOOG"
2023-01-26T12:28:00.007409Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 6382569,
    events_root: None,
}
2023-01-26T12:28:00.007419Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-26T12:28:00.007422Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CallLoseGasOOG"::London::0
2023-01-26T12:28:00.007424Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stDelegatecallTestHomestead/CallLoseGasOOG.json"
2023-01-26T12:28:00.007428Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T12:28:00.007430Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T12:28:00.007772Z  INFO evm_eth_compliance::statetest::runner: UC : "CallLoseGasOOG"
2023-01-26T12:28:00.007778Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 6482569,
    events_root: None,
}
2023-01-26T12:28:00.007787Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-26T12:28:00.007790Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CallLoseGasOOG"::Merge::0
2023-01-26T12:28:00.007792Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stDelegatecallTestHomestead/CallLoseGasOOG.json"
2023-01-26T12:28:00.007796Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T12:28:00.007798Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T12:28:00.008141Z  INFO evm_eth_compliance::statetest::runner: UC : "CallLoseGasOOG"
2023-01-26T12:28:00.008146Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 6582569,
    events_root: None,
}
2023-01-26T12:28:00.010134Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:366.741927ms
2023-01-26T12:28:00.281620Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "./test-vectors/tests/GeneralStateTests/stDelegatecallTestHomestead/CallRecursiveBombPreCall.json", Total Files :: 1
2023-01-26T12:28:00.322029Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-26T12:28:00.322191Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T12:28:00.322195Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-26T12:28:00.322249Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T12:28:00.322251Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 2
2023-01-26T12:28:00.322310Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T12:28:00.322392Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-26T12:28:00.322396Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CallRecursiveBombPreCall"::Istanbul::0
2023-01-26T12:28:00.322399Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stDelegatecallTestHomestead/CallRecursiveBombPreCall.json"
2023-01-26T12:28:00.322403Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T12:28:00.322404Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T12:28:00.871177Z  INFO evm_eth_compliance::statetest::runner: UC : "CallRecursiveBombPreCall"
2023-01-26T12:28:00.871191Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3370757416,
    events_root: None,
}
2023-01-26T12:28:00.876822Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-26T12:28:00.876836Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CallRecursiveBombPreCall"::Berlin::0
2023-01-26T12:28:00.876839Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stDelegatecallTestHomestead/CallRecursiveBombPreCall.json"
2023-01-26T12:28:00.876842Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T12:28:00.876844Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T12:28:01.061160Z  INFO evm_eth_compliance::statetest::runner: UC : "CallRecursiveBombPreCall"
2023-01-26T12:28:01.061176Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 4301290158,
    events_root: None,
}
2023-01-26T12:28:01.069308Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-26T12:28:01.069369Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CallRecursiveBombPreCall"::London::0
2023-01-26T12:28:01.069378Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stDelegatecallTestHomestead/CallRecursiveBombPreCall.json"
2023-01-26T12:28:01.069387Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T12:28:01.069394Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T12:28:01.256179Z  INFO evm_eth_compliance::statetest::runner: UC : "CallRecursiveBombPreCall"
2023-01-26T12:28:01.256195Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 4301290250,
    events_root: None,
}
2023-01-26T12:28:01.268498Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-26T12:28:01.268519Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CallRecursiveBombPreCall"::Merge::0
2023-01-26T12:28:01.268523Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stDelegatecallTestHomestead/CallRecursiveBombPreCall.json"
2023-01-26T12:28:01.268526Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T12:28:01.268528Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T12:28:01.442507Z  INFO evm_eth_compliance::statetest::runner: UC : "CallRecursiveBombPreCall"
2023-01-26T12:28:01.442524Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 4301290342,
    events_root: None,
}
2023-01-26T12:28:01.467636Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:1.130160107s
2023-01-26T12:28:01.761221Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "./test-vectors/tests/GeneralStateTests/stDelegatecallTestHomestead/CallcodeLoseGasOOG.json", Total Files :: 1
2023-01-26T12:28:01.797452Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-26T12:28:01.797624Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T12:28:01.797628Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-26T12:28:01.797679Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T12:28:01.797681Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 2
2023-01-26T12:28:01.797738Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T12:28:01.797821Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-26T12:28:01.797824Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CallcodeLoseGasOOG"::Istanbul::0
2023-01-26T12:28:01.797826Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stDelegatecallTestHomestead/CallcodeLoseGasOOG.json"
2023-01-26T12:28:01.797830Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T12:28:01.797831Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T12:28:02.147642Z  INFO evm_eth_compliance::statetest::runner: UC : "CallcodeLoseGasOOG"
2023-01-26T12:28:02.147659Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 5218418,
    events_root: None,
}
2023-01-26T12:28:02.147671Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-26T12:28:02.147676Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CallcodeLoseGasOOG"::Istanbul::0
2023-01-26T12:28:02.147678Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stDelegatecallTestHomestead/CallcodeLoseGasOOG.json"
2023-01-26T12:28:02.147681Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T12:28:02.147683Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T12:28:02.147962Z  INFO evm_eth_compliance::statetest::runner: UC : "CallcodeLoseGasOOG"
2023-01-26T12:28:02.147966Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 6382569,
    events_root: None,
}
2023-01-26T12:28:02.147974Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-26T12:28:02.147976Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CallcodeLoseGasOOG"::Berlin::0
2023-01-26T12:28:02.147978Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stDelegatecallTestHomestead/CallcodeLoseGasOOG.json"
2023-01-26T12:28:02.147982Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T12:28:02.147984Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T12:28:02.148325Z  INFO evm_eth_compliance::statetest::runner: UC : "CallcodeLoseGasOOG"
2023-01-26T12:28:02.148330Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 6482569,
    events_root: None,
}
2023-01-26T12:28:02.148340Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-26T12:28:02.148343Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CallcodeLoseGasOOG"::Berlin::0
2023-01-26T12:28:02.148345Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stDelegatecallTestHomestead/CallcodeLoseGasOOG.json"
2023-01-26T12:28:02.148349Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T12:28:02.148351Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T12:28:02.148650Z  INFO evm_eth_compliance::statetest::runner: UC : "CallcodeLoseGasOOG"
2023-01-26T12:28:02.148654Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 6582569,
    events_root: None,
}
2023-01-26T12:28:02.148661Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-26T12:28:02.148664Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CallcodeLoseGasOOG"::London::0
2023-01-26T12:28:02.148666Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stDelegatecallTestHomestead/CallcodeLoseGasOOG.json"
2023-01-26T12:28:02.148669Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T12:28:02.148670Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T12:28:02.148974Z  INFO evm_eth_compliance::statetest::runner: UC : "CallcodeLoseGasOOG"
2023-01-26T12:28:02.148979Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 6682569,
    events_root: None,
}
2023-01-26T12:28:02.148987Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-26T12:28:02.148990Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CallcodeLoseGasOOG"::London::0
2023-01-26T12:28:02.148992Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stDelegatecallTestHomestead/CallcodeLoseGasOOG.json"
2023-01-26T12:28:02.148994Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T12:28:02.148996Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T12:28:02.149308Z  INFO evm_eth_compliance::statetest::runner: UC : "CallcodeLoseGasOOG"
2023-01-26T12:28:02.149313Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 6782569,
    events_root: None,
}
2023-01-26T12:28:02.149320Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-26T12:28:02.149323Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CallcodeLoseGasOOG"::Merge::0
2023-01-26T12:28:02.149325Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stDelegatecallTestHomestead/CallcodeLoseGasOOG.json"
2023-01-26T12:28:02.149327Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T12:28:02.149330Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T12:28:02.149823Z  INFO evm_eth_compliance::statetest::runner: UC : "CallcodeLoseGasOOG"
2023-01-26T12:28:02.149829Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 6882569,
    events_root: None,
}
2023-01-26T12:28:02.149840Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-26T12:28:02.149843Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CallcodeLoseGasOOG"::Merge::0
2023-01-26T12:28:02.149846Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stDelegatecallTestHomestead/CallcodeLoseGasOOG.json"
2023-01-26T12:28:02.149849Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T12:28:02.149851Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T12:28:02.150226Z  INFO evm_eth_compliance::statetest::runner: UC : "CallcodeLoseGasOOG"
2023-01-26T12:28:02.150231Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 6982569,
    events_root: None,
}
2023-01-26T12:28:02.152024Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:352.791754ms
2023-01-26T12:28:02.424069Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "./test-vectors/tests/GeneralStateTests/stDelegatecallTestHomestead/Delegatecall1024.json", Total Files :: 1
2023-01-26T12:28:02.457043Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-26T12:28:02.457213Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T12:28:02.457217Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-26T12:28:02.457268Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T12:28:02.457271Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 2
2023-01-26T12:28:02.457332Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T12:28:02.457443Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-26T12:28:02.457448Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "Delegatecall1024"::Istanbul::0
2023-01-26T12:28:02.457452Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stDelegatecallTestHomestead/Delegatecall1024.json"
2023-01-26T12:28:02.457457Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T12:28:02.457458Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T12:28:02.962749Z  INFO evm_eth_compliance::statetest::runner: UC : "Delegatecall1024"
2023-01-26T12:28:02.962762Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3043253862,
    events_root: None,
}
2023-01-26T12:28:02.969213Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-26T12:28:02.969232Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "Delegatecall1024"::Berlin::0
2023-01-26T12:28:02.969234Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stDelegatecallTestHomestead/Delegatecall1024.json"
2023-01-26T12:28:02.969238Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T12:28:02.969240Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T12:28:03.138873Z  INFO evm_eth_compliance::statetest::runner: UC : "Delegatecall1024"
2023-01-26T12:28:03.138888Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3626869478,
    events_root: None,
}
2023-01-26T12:28:03.144495Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-26T12:28:03.144510Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "Delegatecall1024"::London::0
2023-01-26T12:28:03.144512Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stDelegatecallTestHomestead/Delegatecall1024.json"
2023-01-26T12:28:03.144516Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T12:28:03.144517Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T12:28:03.324161Z  INFO evm_eth_compliance::statetest::runner: UC : "Delegatecall1024"
2023-01-26T12:28:03.324177Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3626869662,
    events_root: None,
}
2023-01-26T12:28:03.334403Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-26T12:28:03.334422Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "Delegatecall1024"::Merge::0
2023-01-26T12:28:03.334425Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stDelegatecallTestHomestead/Delegatecall1024.json"
2023-01-26T12:28:03.334429Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T12:28:03.334430Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T12:28:03.506981Z  INFO evm_eth_compliance::statetest::runner: UC : "Delegatecall1024"
2023-01-26T12:28:03.506996Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3626869202,
    events_root: None,
}
2023-01-26T12:28:03.525651Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:1.057933564s
2023-01-26T12:28:03.805200Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "./test-vectors/tests/GeneralStateTests/stDelegatecallTestHomestead/Delegatecall1024OOG.json", Total Files :: 1
2023-01-26T12:28:03.855235Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-26T12:28:03.855414Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T12:28:03.855418Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-26T12:28:03.855469Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T12:28:03.855471Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 2
2023-01-26T12:28:03.855531Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T12:28:03.855622Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-26T12:28:03.855626Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "Delegatecall1024OOG"::Istanbul::0
2023-01-26T12:28:03.855628Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stDelegatecallTestHomestead/Delegatecall1024OOG.json"
2023-01-26T12:28:03.855632Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T12:28:03.855633Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T12:28:04.469687Z  INFO evm_eth_compliance::statetest::runner: UC : "Delegatecall1024OOG"
2023-01-26T12:28:04.469702Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 4786864951,
    events_root: None,
}
2023-01-26T12:28:04.478476Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-26T12:28:04.478492Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "Delegatecall1024OOG"::Berlin::0
2023-01-26T12:28:04.478495Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stDelegatecallTestHomestead/Delegatecall1024OOG.json"
2023-01-26T12:28:04.478499Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T12:28:04.478500Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T12:28:04.485582Z  INFO evm_eth_compliance::statetest::runner: UC : "Delegatecall1024OOG"
2023-01-26T12:28:04.485598Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 14980440,
    events_root: None,
}
2023-01-26T12:28:04.485623Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-26T12:28:04.485629Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "Delegatecall1024OOG"::London::0
2023-01-26T12:28:04.485631Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stDelegatecallTestHomestead/Delegatecall1024OOG.json"
2023-01-26T12:28:04.485634Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T12:28:04.485635Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T12:28:04.485911Z  INFO evm_eth_compliance::statetest::runner: UC : "Delegatecall1024OOG"
2023-01-26T12:28:04.485916Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 6941754,
    events_root: None,
}
2023-01-26T12:28:04.485928Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-26T12:28:04.485931Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "Delegatecall1024OOG"::Merge::0
2023-01-26T12:28:04.485932Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stDelegatecallTestHomestead/Delegatecall1024OOG.json"
2023-01-26T12:28:04.485935Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T12:28:04.485936Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T12:28:04.486189Z  INFO evm_eth_compliance::statetest::runner: UC : "Delegatecall1024OOG"
2023-01-26T12:28:04.486194Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 6209617,
    events_root: None,
}
2023-01-26T12:28:04.498653Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:630.973798ms
2023-01-26T12:28:04.782547Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "./test-vectors/tests/GeneralStateTests/stDelegatecallTestHomestead/callOutput1.json", Total Files :: 1
2023-01-26T12:28:04.823605Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-26T12:28:04.823781Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T12:28:04.823786Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-26T12:28:04.823841Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T12:28:04.823843Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 2
2023-01-26T12:28:04.823902Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T12:28:04.823989Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-26T12:28:04.823992Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callOutput1"::Istanbul::0
2023-01-26T12:28:04.823994Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stDelegatecallTestHomestead/callOutput1.json"
2023-01-26T12:28:04.823998Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T12:28:04.823999Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T12:28:05.175144Z  INFO evm_eth_compliance::statetest::runner: UC : "callOutput1"
2023-01-26T12:28:05.175159Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3621817,
    events_root: None,
}
2023-01-26T12:28:05.175171Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-26T12:28:05.175175Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callOutput1"::Berlin::0
2023-01-26T12:28:05.175177Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stDelegatecallTestHomestead/callOutput1.json"
2023-01-26T12:28:05.175180Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T12:28:05.175183Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T12:28:05.175382Z  INFO evm_eth_compliance::statetest::runner: UC : "callOutput1"
2023-01-26T12:28:05.175386Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2678995,
    events_root: None,
}
2023-01-26T12:28:05.175393Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-26T12:28:05.175395Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callOutput1"::London::0
2023-01-26T12:28:05.175397Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stDelegatecallTestHomestead/callOutput1.json"
2023-01-26T12:28:05.175400Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T12:28:05.175402Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T12:28:05.175585Z  INFO evm_eth_compliance::statetest::runner: UC : "callOutput1"
2023-01-26T12:28:05.175589Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2678995,
    events_root: None,
}
2023-01-26T12:28:05.175595Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-26T12:28:05.175598Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callOutput1"::Merge::0
2023-01-26T12:28:05.175599Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stDelegatecallTestHomestead/callOutput1.json"
2023-01-26T12:28:05.175602Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T12:28:05.175603Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T12:28:05.175786Z  INFO evm_eth_compliance::statetest::runner: UC : "callOutput1"
2023-01-26T12:28:05.175791Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2678995,
    events_root: None,
}
2023-01-26T12:28:05.177490Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:352.198533ms
2023-01-26T12:28:05.462300Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "./test-vectors/tests/GeneralStateTests/stDelegatecallTestHomestead/callOutput2.json", Total Files :: 1
2023-01-26T12:28:05.507678Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-26T12:28:05.507846Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T12:28:05.507851Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-26T12:28:05.507908Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T12:28:05.507911Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 2
2023-01-26T12:28:05.507970Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T12:28:05.508054Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-26T12:28:05.508057Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callOutput2"::Istanbul::0
2023-01-26T12:28:05.508060Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stDelegatecallTestHomestead/callOutput2.json"
2023-01-26T12:28:05.508063Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T12:28:05.508065Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T12:28:05.856475Z  INFO evm_eth_compliance::statetest::runner: UC : "callOutput2"
2023-01-26T12:28:05.856490Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3626837,
    events_root: None,
}
2023-01-26T12:28:05.856502Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-26T12:28:05.856507Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callOutput2"::Berlin::0
2023-01-26T12:28:05.856508Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stDelegatecallTestHomestead/callOutput2.json"
2023-01-26T12:28:05.856511Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T12:28:05.856513Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T12:28:05.856713Z  INFO evm_eth_compliance::statetest::runner: UC : "callOutput2"
2023-01-26T12:28:05.856718Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2684098,
    events_root: None,
}
2023-01-26T12:28:05.856724Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-26T12:28:05.856726Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callOutput2"::London::0
2023-01-26T12:28:05.856728Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stDelegatecallTestHomestead/callOutput2.json"
2023-01-26T12:28:05.856731Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T12:28:05.856732Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T12:28:05.856910Z  INFO evm_eth_compliance::statetest::runner: UC : "callOutput2"
2023-01-26T12:28:05.856914Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2684098,
    events_root: None,
}
2023-01-26T12:28:05.856920Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-26T12:28:05.856923Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callOutput2"::Merge::0
2023-01-26T12:28:05.856925Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stDelegatecallTestHomestead/callOutput2.json"
2023-01-26T12:28:05.856927Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T12:28:05.856929Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T12:28:05.857103Z  INFO evm_eth_compliance::statetest::runner: UC : "callOutput2"
2023-01-26T12:28:05.857108Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2684098,
    events_root: None,
}
2023-01-26T12:28:05.858704Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:349.441057ms
2023-01-26T12:28:06.119295Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "./test-vectors/tests/GeneralStateTests/stDelegatecallTestHomestead/callOutput3.json", Total Files :: 1
2023-01-26T12:28:06.166377Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-26T12:28:06.166542Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T12:28:06.166545Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-26T12:28:06.166599Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T12:28:06.166602Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 2
2023-01-26T12:28:06.166659Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T12:28:06.166744Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-26T12:28:06.166748Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callOutput3"::Istanbul::0
2023-01-26T12:28:06.166751Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stDelegatecallTestHomestead/callOutput3.json"
2023-01-26T12:28:06.166754Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T12:28:06.166756Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T12:28:06.581112Z  INFO evm_eth_compliance::statetest::runner: UC : "callOutput3"
2023-01-26T12:28:06.581127Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3622201,
    events_root: None,
}
2023-01-26T12:28:06.581141Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-26T12:28:06.581146Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callOutput3"::Berlin::0
2023-01-26T12:28:06.581148Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stDelegatecallTestHomestead/callOutput3.json"
2023-01-26T12:28:06.581151Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T12:28:06.581152Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T12:28:06.581367Z  INFO evm_eth_compliance::statetest::runner: UC : "callOutput3"
2023-01-26T12:28:06.581374Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2679379,
    events_root: None,
}
2023-01-26T12:28:06.581383Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-26T12:28:06.581387Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callOutput3"::London::0
2023-01-26T12:28:06.581388Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stDelegatecallTestHomestead/callOutput3.json"
2023-01-26T12:28:06.581391Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T12:28:06.581392Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T12:28:06.581566Z  INFO evm_eth_compliance::statetest::runner: UC : "callOutput3"
2023-01-26T12:28:06.581570Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2679379,
    events_root: None,
}
2023-01-26T12:28:06.581578Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-26T12:28:06.581581Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callOutput3"::Merge::0
2023-01-26T12:28:06.581582Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stDelegatecallTestHomestead/callOutput3.json"
2023-01-26T12:28:06.581585Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T12:28:06.581586Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T12:28:06.581754Z  INFO evm_eth_compliance::statetest::runner: UC : "callOutput3"
2023-01-26T12:28:06.581759Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2679379,
    events_root: None,
}
2023-01-26T12:28:06.583589Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:415.394422ms
2023-01-26T12:28:06.864415Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "./test-vectors/tests/GeneralStateTests/stDelegatecallTestHomestead/callOutput3partial.json", Total Files :: 1
2023-01-26T12:28:06.897578Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-26T12:28:06.897739Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T12:28:06.897742Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-26T12:28:06.897798Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T12:28:06.897800Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 2
2023-01-26T12:28:06.897859Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T12:28:06.897941Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-26T12:28:06.897944Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callOutput3partial"::Istanbul::0
2023-01-26T12:28:06.897947Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stDelegatecallTestHomestead/callOutput3partial.json"
2023-01-26T12:28:06.897950Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T12:28:06.897952Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T12:28:07.284585Z  INFO evm_eth_compliance::statetest::runner: UC : "callOutput3partial"
2023-01-26T12:28:07.284606Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3622201,
    events_root: None,
}
2023-01-26T12:28:07.284624Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-26T12:28:07.284633Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callOutput3partial"::Berlin::0
2023-01-26T12:28:07.284635Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stDelegatecallTestHomestead/callOutput3partial.json"
2023-01-26T12:28:07.284639Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T12:28:07.284640Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T12:28:07.284894Z  INFO evm_eth_compliance::statetest::runner: UC : "callOutput3partial"
2023-01-26T12:28:07.284900Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2679379,
    events_root: None,
}
2023-01-26T12:28:07.284908Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-26T12:28:07.284912Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callOutput3partial"::London::0
2023-01-26T12:28:07.284914Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stDelegatecallTestHomestead/callOutput3partial.json"
2023-01-26T12:28:07.284918Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T12:28:07.284919Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T12:28:07.285130Z  INFO evm_eth_compliance::statetest::runner: UC : "callOutput3partial"
2023-01-26T12:28:07.285135Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2679379,
    events_root: None,
}
2023-01-26T12:28:07.285142Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-26T12:28:07.285145Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callOutput3partial"::Merge::0
2023-01-26T12:28:07.285148Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stDelegatecallTestHomestead/callOutput3partial.json"
2023-01-26T12:28:07.285151Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T12:28:07.285153Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T12:28:07.285366Z  INFO evm_eth_compliance::statetest::runner: UC : "callOutput3partial"
2023-01-26T12:28:07.285372Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2679379,
    events_root: None,
}
2023-01-26T12:28:07.287118Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:387.806564ms
2023-01-26T12:28:07.567329Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "./test-vectors/tests/GeneralStateTests/stDelegatecallTestHomestead/callOutput3partialFail.json", Total Files :: 1
2023-01-26T12:28:07.607785Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-26T12:28:07.607969Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T12:28:07.607973Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-26T12:28:07.608030Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T12:28:07.608032Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 2
2023-01-26T12:28:07.608093Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T12:28:07.608180Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-26T12:28:07.608183Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callOutput3partialFail"::Istanbul::0
2023-01-26T12:28:07.608186Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stDelegatecallTestHomestead/callOutput3partialFail.json"
2023-01-26T12:28:07.608190Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T12:28:07.608192Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T12:28:07.958714Z  INFO evm_eth_compliance::statetest::runner: UC : "callOutput3partialFail"
2023-01-26T12:28:07.958731Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3622201,
    events_root: None,
}
2023-01-26T12:28:07.958745Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-26T12:28:07.958751Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callOutput3partialFail"::Berlin::0
2023-01-26T12:28:07.958753Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stDelegatecallTestHomestead/callOutput3partialFail.json"
2023-01-26T12:28:07.958758Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T12:28:07.958762Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T12:28:07.958977Z  INFO evm_eth_compliance::statetest::runner: UC : "callOutput3partialFail"
2023-01-26T12:28:07.958982Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2679379,
    events_root: None,
}
2023-01-26T12:28:07.958988Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-26T12:28:07.958991Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callOutput3partialFail"::London::0
2023-01-26T12:28:07.958993Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stDelegatecallTestHomestead/callOutput3partialFail.json"
2023-01-26T12:28:07.958996Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T12:28:07.958998Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T12:28:07.959174Z  INFO evm_eth_compliance::statetest::runner: UC : "callOutput3partialFail"
2023-01-26T12:28:07.959179Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2679379,
    events_root: None,
}
2023-01-26T12:28:07.959185Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-26T12:28:07.959188Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callOutput3partialFail"::Merge::0
2023-01-26T12:28:07.959189Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stDelegatecallTestHomestead/callOutput3partialFail.json"
2023-01-26T12:28:07.959192Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T12:28:07.959193Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T12:28:07.959365Z  INFO evm_eth_compliance::statetest::runner: UC : "callOutput3partialFail"
2023-01-26T12:28:07.959370Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2679379,
    events_root: None,
}
2023-01-26T12:28:07.961126Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:351.595848ms
2023-01-26T12:28:08.217992Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "./test-vectors/tests/GeneralStateTests/stDelegatecallTestHomestead/callWithHighValueAndGasOOG.json", Total Files :: 1
2023-01-26T12:28:08.263079Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-26T12:28:08.263247Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T12:28:08.263251Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-26T12:28:08.263305Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T12:28:08.263308Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 2
2023-01-26T12:28:08.263368Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T12:28:08.263451Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-26T12:28:08.263454Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callWithHighValueAndGasOOG"::Istanbul::0
2023-01-26T12:28:08.263457Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stDelegatecallTestHomestead/callWithHighValueAndGasOOG.json"
2023-01-26T12:28:08.263460Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T12:28:08.263462Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T12:28:08.672807Z  INFO evm_eth_compliance::statetest::runner: UC : "callWithHighValueAndGasOOG"
2023-01-26T12:28:08.672825Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 6974824,
    events_root: None,
}
2023-01-26T12:28:08.672839Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-26T12:28:08.672845Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callWithHighValueAndGasOOG"::Berlin::0
2023-01-26T12:28:08.672847Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stDelegatecallTestHomestead/callWithHighValueAndGasOOG.json"
2023-01-26T12:28:08.672851Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T12:28:08.672852Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T12:28:08.673153Z  INFO evm_eth_compliance::statetest::runner: UC : "callWithHighValueAndGasOOG"
2023-01-26T12:28:08.673158Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 4731050,
    events_root: None,
}
2023-01-26T12:28:08.673166Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-26T12:28:08.673169Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callWithHighValueAndGasOOG"::London::0
2023-01-26T12:28:08.673171Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stDelegatecallTestHomestead/callWithHighValueAndGasOOG.json"
2023-01-26T12:28:08.673174Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T12:28:08.673175Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T12:28:08.673466Z  INFO evm_eth_compliance::statetest::runner: UC : "callWithHighValueAndGasOOG"
2023-01-26T12:28:08.673470Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 4731050,
    events_root: None,
}
2023-01-26T12:28:08.673479Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-26T12:28:08.673482Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callWithHighValueAndGasOOG"::Merge::0
2023-01-26T12:28:08.673484Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stDelegatecallTestHomestead/callWithHighValueAndGasOOG.json"
2023-01-26T12:28:08.673486Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T12:28:08.673488Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T12:28:08.673771Z  INFO evm_eth_compliance::statetest::runner: UC : "callWithHighValueAndGasOOG"
2023-01-26T12:28:08.673776Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 4731050,
    events_root: None,
}
2023-01-26T12:28:08.675348Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:410.710147ms
2023-01-26T12:28:08.939774Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "./test-vectors/tests/GeneralStateTests/stDelegatecallTestHomestead/callcodeOutput3.json", Total Files :: 1
2023-01-26T12:28:08.973564Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-26T12:28:08.973742Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T12:28:08.973746Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-26T12:28:08.973802Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T12:28:08.973805Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 2
2023-01-26T12:28:08.973862Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T12:28:08.973956Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-26T12:28:08.973959Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcodeOutput3"::Istanbul::0
2023-01-26T12:28:08.973962Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stDelegatecallTestHomestead/callcodeOutput3.json"
2023-01-26T12:28:08.973965Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T12:28:08.973967Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T12:28:09.314010Z  INFO evm_eth_compliance::statetest::runner: UC : "callcodeOutput3"
2023-01-26T12:28:09.314023Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3622201,
    events_root: None,
}
2023-01-26T12:28:09.314034Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-26T12:28:09.314040Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcodeOutput3"::Berlin::0
2023-01-26T12:28:09.314041Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stDelegatecallTestHomestead/callcodeOutput3.json"
2023-01-26T12:28:09.314045Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T12:28:09.314046Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T12:28:09.314238Z  INFO evm_eth_compliance::statetest::runner: UC : "callcodeOutput3"
2023-01-26T12:28:09.314242Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2679379,
    events_root: None,
}
2023-01-26T12:28:09.314249Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-26T12:28:09.314251Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcodeOutput3"::London::0
2023-01-26T12:28:09.314253Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stDelegatecallTestHomestead/callcodeOutput3.json"
2023-01-26T12:28:09.314256Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T12:28:09.314257Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T12:28:09.314442Z  INFO evm_eth_compliance::statetest::runner: UC : "callcodeOutput3"
2023-01-26T12:28:09.314448Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2679379,
    events_root: None,
}
2023-01-26T12:28:09.314456Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-26T12:28:09.314459Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcodeOutput3"::Merge::0
2023-01-26T12:28:09.314461Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stDelegatecallTestHomestead/callcodeOutput3.json"
2023-01-26T12:28:09.314465Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T12:28:09.314466Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T12:28:09.314651Z  INFO evm_eth_compliance::statetest::runner: UC : "callcodeOutput3"
2023-01-26T12:28:09.314655Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2679379,
    events_root: None,
}
2023-01-26T12:28:09.316282Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:341.102918ms
2023-01-26T12:28:09.583243Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "./test-vectors/tests/GeneralStateTests/stDelegatecallTestHomestead/callcodeWithHighValueAndGasOOG.json", Total Files :: 1
2023-01-26T12:28:09.641336Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-26T12:28:09.641525Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T12:28:09.641529Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-26T12:28:09.641587Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T12:28:09.641589Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 2
2023-01-26T12:28:09.641651Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T12:28:09.641736Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-26T12:28:09.641739Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcodeWithHighValueAndGasOOG"::Istanbul::0
2023-01-26T12:28:09.641742Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stDelegatecallTestHomestead/callcodeWithHighValueAndGasOOG.json"
2023-01-26T12:28:09.641745Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T12:28:09.641747Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T12:28:10.017461Z  INFO evm_eth_compliance::statetest::runner: UC : "callcodeWithHighValueAndGasOOG"
2023-01-26T12:28:10.017477Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 6974824,
    events_root: None,
}
2023-01-26T12:28:10.017493Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-26T12:28:10.017499Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcodeWithHighValueAndGasOOG"::Berlin::0
2023-01-26T12:28:10.017501Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stDelegatecallTestHomestead/callcodeWithHighValueAndGasOOG.json"
2023-01-26T12:28:10.017507Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T12:28:10.017508Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T12:28:10.017807Z  INFO evm_eth_compliance::statetest::runner: UC : "callcodeWithHighValueAndGasOOG"
2023-01-26T12:28:10.017812Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 4731050,
    events_root: None,
}
2023-01-26T12:28:10.017820Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-26T12:28:10.017823Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcodeWithHighValueAndGasOOG"::London::0
2023-01-26T12:28:10.017825Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stDelegatecallTestHomestead/callcodeWithHighValueAndGasOOG.json"
2023-01-26T12:28:10.017828Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T12:28:10.017830Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T12:28:10.018121Z  INFO evm_eth_compliance::statetest::runner: UC : "callcodeWithHighValueAndGasOOG"
2023-01-26T12:28:10.018126Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 4731050,
    events_root: None,
}
2023-01-26T12:28:10.018134Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-26T12:28:10.018136Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcodeWithHighValueAndGasOOG"::Merge::0
2023-01-26T12:28:10.018139Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stDelegatecallTestHomestead/callcodeWithHighValueAndGasOOG.json"
2023-01-26T12:28:10.018141Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T12:28:10.018143Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T12:28:10.018427Z  INFO evm_eth_compliance::statetest::runner: UC : "callcodeWithHighValueAndGasOOG"
2023-01-26T12:28:10.018432Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 4731050,
    events_root: None,
}
2023-01-26T12:28:10.020262Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:377.109228ms
2023-01-26T12:28:10.288631Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "./test-vectors/tests/GeneralStateTests/stDelegatecallTestHomestead/deleagateCallAfterValueTransfer.json", Total Files :: 1
2023-01-26T12:28:10.321323Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-26T12:28:10.321501Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T12:28:10.321505Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-26T12:28:10.321558Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T12:28:10.321560Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 2
2023-01-26T12:28:10.321621Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T12:28:10.321708Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-26T12:28:10.321712Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "deleagateCallAfterValueTransfer"::Istanbul::0
2023-01-26T12:28:10.321716Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stDelegatecallTestHomestead/deleagateCallAfterValueTransfer.json"
2023-01-26T12:28:10.321721Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T12:28:10.321722Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T12:28:10.725293Z  INFO evm_eth_compliance::statetest::runner: UC : "deleagateCallAfterValueTransfer"
2023-01-26T12:28:10.725308Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2696765,
    events_root: None,
}
2023-01-26T12:28:10.725322Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-26T12:28:10.725330Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "deleagateCallAfterValueTransfer"::Berlin::0
2023-01-26T12:28:10.725332Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stDelegatecallTestHomestead/deleagateCallAfterValueTransfer.json"
2023-01-26T12:28:10.725336Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T12:28:10.725338Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T12:28:10.725534Z  INFO evm_eth_compliance::statetest::runner: UC : "deleagateCallAfterValueTransfer"
2023-01-26T12:28:10.725539Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2696765,
    events_root: None,
}
2023-01-26T12:28:10.725548Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-26T12:28:10.725552Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "deleagateCallAfterValueTransfer"::London::0
2023-01-26T12:28:10.725555Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stDelegatecallTestHomestead/deleagateCallAfterValueTransfer.json"
2023-01-26T12:28:10.725559Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T12:28:10.725561Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T12:28:10.725737Z  INFO evm_eth_compliance::statetest::runner: UC : "deleagateCallAfterValueTransfer"
2023-01-26T12:28:10.725741Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2696765,
    events_root: None,
}
2023-01-26T12:28:10.725750Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-26T12:28:10.725753Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "deleagateCallAfterValueTransfer"::Merge::0
2023-01-26T12:28:10.725756Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stDelegatecallTestHomestead/deleagateCallAfterValueTransfer.json"
2023-01-26T12:28:10.725760Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T12:28:10.725761Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T12:28:10.725933Z  INFO evm_eth_compliance::statetest::runner: UC : "deleagateCallAfterValueTransfer"
2023-01-26T12:28:10.725938Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2696765,
    events_root: None,
}
2023-01-26T12:28:10.727375Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:404.627029ms
2023-01-26T12:28:11.014211Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "./test-vectors/tests/GeneralStateTests/stDelegatecallTestHomestead/delegatecallAndOOGatTxLevel.json", Total Files :: 1
2023-01-26T12:28:11.050466Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-26T12:28:11.050635Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T12:28:11.050639Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-26T12:28:11.050693Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T12:28:11.050695Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 2
2023-01-26T12:28:11.050758Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T12:28:11.050840Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-26T12:28:11.050843Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "delegatecallAndOOGatTxLevel"::Istanbul::0
2023-01-26T12:28:11.050845Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stDelegatecallTestHomestead/delegatecallAndOOGatTxLevel.json"
2023-01-26T12:28:11.050850Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T12:28:11.050852Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T12:28:11.427683Z  INFO evm_eth_compliance::statetest::runner: UC : "delegatecallAndOOGatTxLevel"
2023-01-26T12:28:11.427698Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 6955717,
    events_root: None,
}
2023-01-26T12:28:11.427720Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-26T12:28:11.427727Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "delegatecallAndOOGatTxLevel"::Berlin::0
2023-01-26T12:28:11.427733Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stDelegatecallTestHomestead/delegatecallAndOOGatTxLevel.json"
2023-01-26T12:28:11.427738Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T12:28:11.427740Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T12:28:11.428044Z  INFO evm_eth_compliance::statetest::runner: UC : "delegatecallAndOOGatTxLevel"
2023-01-26T12:28:11.428050Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 4707711,
    events_root: None,
}
2023-01-26T12:28:11.428064Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-26T12:28:11.428067Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "delegatecallAndOOGatTxLevel"::London::0
2023-01-26T12:28:11.428070Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stDelegatecallTestHomestead/delegatecallAndOOGatTxLevel.json"
2023-01-26T12:28:11.428075Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T12:28:11.428077Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T12:28:11.428362Z  INFO evm_eth_compliance::statetest::runner: UC : "delegatecallAndOOGatTxLevel"
2023-01-26T12:28:11.428367Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 4707711,
    events_root: None,
}
2023-01-26T12:28:11.428382Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-26T12:28:11.428385Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "delegatecallAndOOGatTxLevel"::Merge::0
2023-01-26T12:28:11.428388Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stDelegatecallTestHomestead/delegatecallAndOOGatTxLevel.json"
2023-01-26T12:28:11.428392Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T12:28:11.428394Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T12:28:11.428676Z  INFO evm_eth_compliance::statetest::runner: UC : "delegatecallAndOOGatTxLevel"
2023-01-26T12:28:11.428683Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 4707711,
    events_root: None,
}
2023-01-26T12:28:11.430438Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:378.235066ms
2023-01-26T12:28:11.739106Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "./test-vectors/tests/GeneralStateTests/stDelegatecallTestHomestead/delegatecallBasic.json", Total Files :: 1
2023-01-26T12:28:11.800298Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-26T12:28:11.800509Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T12:28:11.800513Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-26T12:28:11.800574Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T12:28:11.800577Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 2
2023-01-26T12:28:11.800641Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T12:28:11.800741Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-26T12:28:11.800744Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "delegatecallBasic"::Istanbul::0
2023-01-26T12:28:11.800747Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stDelegatecallTestHomestead/delegatecallBasic.json"
2023-01-26T12:28:11.800751Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T12:28:11.800752Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T12:28:12.168204Z  INFO evm_eth_compliance::statetest::runner: UC : "delegatecallBasic"
2023-01-26T12:28:12.168223Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3096713,
    events_root: None,
}
2023-01-26T12:28:12.168234Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-26T12:28:12.168239Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "delegatecallBasic"::Berlin::0
2023-01-26T12:28:12.168241Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stDelegatecallTestHomestead/delegatecallBasic.json"
2023-01-26T12:28:12.168244Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T12:28:12.168245Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T12:28:12.168479Z  INFO evm_eth_compliance::statetest::runner: UC : "delegatecallBasic"
2023-01-26T12:28:12.168484Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3096713,
    events_root: None,
}
2023-01-26T12:28:12.168490Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-26T12:28:12.168493Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "delegatecallBasic"::London::0
2023-01-26T12:28:12.168494Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stDelegatecallTestHomestead/delegatecallBasic.json"
2023-01-26T12:28:12.168497Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T12:28:12.168498Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T12:28:12.168735Z  INFO evm_eth_compliance::statetest::runner: UC : "delegatecallBasic"
2023-01-26T12:28:12.168740Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3096713,
    events_root: None,
}
2023-01-26T12:28:12.168746Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-26T12:28:12.168748Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "delegatecallBasic"::Merge::0
2023-01-26T12:28:12.168750Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stDelegatecallTestHomestead/delegatecallBasic.json"
2023-01-26T12:28:12.168752Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T12:28:12.168754Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T12:28:12.169035Z  INFO evm_eth_compliance::statetest::runner: UC : "delegatecallBasic"
2023-01-26T12:28:12.169039Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3096713,
    events_root: None,
}
2023-01-26T12:28:12.170747Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:368.753506ms
2023-01-26T12:28:12.458406Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "./test-vectors/tests/GeneralStateTests/stDelegatecallTestHomestead/delegatecallEmptycontract.json", Total Files :: 1
2023-01-26T12:28:12.498935Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-26T12:28:12.499102Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T12:28:12.499106Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-26T12:28:12.499160Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T12:28:12.499243Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-26T12:28:12.499246Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "delegatecallEmptycontract"::Istanbul::0
2023-01-26T12:28:12.499249Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stDelegatecallTestHomestead/delegatecallEmptycontract.json"
2023-01-26T12:28:12.499252Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T12:28:12.499253Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T12:28:12.874475Z  INFO evm_eth_compliance::statetest::runner: UC : "delegatecallEmptycontract"
2023-01-26T12:28:12.874491Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2493200,
    events_root: None,
}
2023-01-26T12:28:12.874502Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-26T12:28:12.874507Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "delegatecallEmptycontract"::Berlin::0
2023-01-26T12:28:12.874509Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stDelegatecallTestHomestead/delegatecallEmptycontract.json"
2023-01-26T12:28:12.874512Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T12:28:12.874513Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T12:28:12.874632Z  INFO evm_eth_compliance::statetest::runner: UC : "delegatecallEmptycontract"
2023-01-26T12:28:12.874636Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1593421,
    events_root: None,
}
2023-01-26T12:28:12.874641Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-26T12:28:12.874643Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "delegatecallEmptycontract"::London::0
2023-01-26T12:28:12.874645Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stDelegatecallTestHomestead/delegatecallEmptycontract.json"
2023-01-26T12:28:12.874648Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T12:28:12.874649Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T12:28:12.874751Z  INFO evm_eth_compliance::statetest::runner: UC : "delegatecallEmptycontract"
2023-01-26T12:28:12.874755Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1593421,
    events_root: None,
}
2023-01-26T12:28:12.874759Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-26T12:28:12.874762Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "delegatecallEmptycontract"::Merge::0
2023-01-26T12:28:12.874763Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stDelegatecallTestHomestead/delegatecallEmptycontract.json"
2023-01-26T12:28:12.874766Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T12:28:12.874768Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T12:28:12.874868Z  INFO evm_eth_compliance::statetest::runner: UC : "delegatecallEmptycontract"
2023-01-26T12:28:12.874872Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1593421,
    events_root: None,
}
2023-01-26T12:28:12.876313Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:375.945946ms
2023-01-26T12:28:13.155699Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "./test-vectors/tests/GeneralStateTests/stDelegatecallTestHomestead/delegatecallInInitcodeToEmptyContract.json", Total Files :: 1
2023-01-26T12:28:13.227376Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-26T12:28:13.227548Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T12:28:13.227553Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-26T12:28:13.227609Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T12:28:13.227693Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-26T12:28:13.227697Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "delegatecallInInitcodeToEmptyContract"::Istanbul::0
2023-01-26T12:28:13.227702Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stDelegatecallTestHomestead/delegatecallInInitcodeToEmptyContract.json"
2023-01-26T12:28:13.227706Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T12:28:13.227708Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [19, 19, 96, 8, 182, 79, 245, 146, 129, 155, 47, 166, 212, 63, 40, 53, 196, 82, 2, 14, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([215, 166, 242, 208, 200, 186, 79, 10, 126, 8, 221, 102, 9, 12, 200, 158, 203, 19, 78, 227]) }
2023-01-26T12:28:13.837724Z  INFO evm_eth_compliance::statetest::runner: UC : "delegatecallInInitcodeToEmptyContract"
2023-01-26T12:28:13.837735Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 13575198,
    events_root: None,
}
2023-01-26T12:28:13.837761Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-26T12:28:13.837766Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "delegatecallInInitcodeToEmptyContract"::Berlin::0
2023-01-26T12:28:13.837769Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stDelegatecallTestHomestead/delegatecallInInitcodeToEmptyContract.json"
2023-01-26T12:28:13.837772Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T12:28:13.837774Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [124, 90, 44, 145, 178, 45, 122, 146, 38, 82, 61, 75, 167, 23, 219, 106, 251, 116, 30, 189, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([67, 35, 255, 1, 46, 226, 200, 90, 20, 150, 237, 153, 222, 171, 201, 9, 99, 31, 101, 211]) }
2023-01-26T12:28:13.838409Z  INFO evm_eth_compliance::statetest::runner: UC : "delegatecallInInitcodeToEmptyContract"
2023-01-26T12:28:13.838414Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 13989758,
    events_root: None,
}
2023-01-26T12:28:13.838430Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-26T12:28:13.838433Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "delegatecallInInitcodeToEmptyContract"::London::0
2023-01-26T12:28:13.838436Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stDelegatecallTestHomestead/delegatecallInInitcodeToEmptyContract.json"
2023-01-26T12:28:13.838439Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T12:28:13.838441Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [85, 225, 180, 184, 198, 80, 147, 57, 204, 233, 99, 201, 185, 164, 106, 230, 220, 29, 81, 93, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([28, 35, 125, 168, 212, 11, 234, 180, 81, 129, 48, 219, 76, 10, 52, 89, 217, 159, 194, 2]) }
2023-01-26T12:28:13.838988Z  INFO evm_eth_compliance::statetest::runner: UC : "delegatecallInInitcodeToEmptyContract"
2023-01-26T12:28:13.838993Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 13575195,
    events_root: None,
}
2023-01-26T12:28:13.839008Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-26T12:28:13.839011Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "delegatecallInInitcodeToEmptyContract"::Merge::0
2023-01-26T12:28:13.839013Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stDelegatecallTestHomestead/delegatecallInInitcodeToEmptyContract.json"
2023-01-26T12:28:13.839016Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T12:28:13.839017Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [119, 32, 219, 74, 113, 179, 136, 255, 7, 69, 60, 90, 226, 153, 143, 86, 21, 251, 52, 236, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([132, 105, 76, 107, 184, 77, 78, 105, 101, 219, 134, 121, 221, 254, 217, 203, 72, 121, 220, 83]) }
2023-01-26T12:28:13.839581Z  INFO evm_eth_compliance::statetest::runner: UC : "delegatecallInInitcodeToEmptyContract"
2023-01-26T12:28:13.839586Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 14059779,
    events_root: None,
}
2023-01-26T12:28:13.841281Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:612.231825ms
2023-01-26T12:28:14.123207Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "./test-vectors/tests/GeneralStateTests/stDelegatecallTestHomestead/delegatecallInInitcodeToExistingContract.json", Total Files :: 1
2023-01-26T12:28:14.157308Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-26T12:28:14.157483Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T12:28:14.157487Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-26T12:28:14.157540Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T12:28:14.157542Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 2
2023-01-26T12:28:14.157616Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T12:28:14.157620Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 3
2023-01-26T12:28:14.157703Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T12:28:14.157801Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-26T12:28:14.157805Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "delegatecallInInitcodeToExistingContract"::Istanbul::0
2023-01-26T12:28:14.157808Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stDelegatecallTestHomestead/delegatecallInInitcodeToExistingContract.json"
2023-01-26T12:28:14.157811Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T12:28:14.157813Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [19, 19, 96, 8, 182, 79, 245, 146, 129, 155, 47, 166, 212, 63, 40, 53, 196, 82, 2, 14, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([215, 166, 242, 208, 200, 186, 79, 10, 126, 8, 221, 102, 9, 12, 200, 158, 203, 19, 78, 227]) }
2023-01-26T12:28:14.746377Z  INFO evm_eth_compliance::statetest::runner: UC : "delegatecallInInitcodeToExistingContract"
2023-01-26T12:28:14.746387Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 15990923,
    events_root: None,
}
2023-01-26T12:28:14.746414Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-26T12:28:14.746419Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "delegatecallInInitcodeToExistingContract"::Berlin::0
2023-01-26T12:28:14.746421Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stDelegatecallTestHomestead/delegatecallInInitcodeToExistingContract.json"
2023-01-26T12:28:14.746425Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T12:28:14.746426Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [124, 90, 44, 145, 178, 45, 122, 146, 38, 82, 61, 75, 167, 23, 219, 106, 251, 116, 30, 189, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([67, 35, 255, 1, 46, 226, 200, 90, 20, 150, 237, 153, 222, 171, 201, 9, 99, 31, 101, 211]) }
2023-01-26T12:28:14.747137Z  INFO evm_eth_compliance::statetest::runner: UC : "delegatecallInInitcodeToExistingContract"
2023-01-26T12:28:14.747142Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 16405483,
    events_root: None,
}
2023-01-26T12:28:14.747162Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-26T12:28:14.747164Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "delegatecallInInitcodeToExistingContract"::London::0
2023-01-26T12:28:14.747167Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stDelegatecallTestHomestead/delegatecallInInitcodeToExistingContract.json"
2023-01-26T12:28:14.747169Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T12:28:14.747171Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [85, 225, 180, 184, 198, 80, 147, 57, 204, 233, 99, 201, 185, 164, 106, 230, 220, 29, 81, 93, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([28, 35, 125, 168, 212, 11, 234, 180, 81, 129, 48, 219, 76, 10, 52, 89, 217, 159, 194, 2]) }
2023-01-26T12:28:14.747790Z  INFO evm_eth_compliance::statetest::runner: UC : "delegatecallInInitcodeToExistingContract"
2023-01-26T12:28:14.747795Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 16035278,
    events_root: None,
}
2023-01-26T12:28:14.747813Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-26T12:28:14.747816Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "delegatecallInInitcodeToExistingContract"::Merge::0
2023-01-26T12:28:14.747818Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stDelegatecallTestHomestead/delegatecallInInitcodeToExistingContract.json"
2023-01-26T12:28:14.747821Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T12:28:14.747823Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [119, 32, 219, 74, 113, 179, 136, 255, 7, 69, 60, 90, 226, 153, 143, 86, 21, 251, 52, 236, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([132, 105, 76, 107, 184, 77, 78, 105, 101, 219, 134, 121, 221, 254, 217, 203, 72, 121, 220, 83]) }
2023-01-26T12:28:14.748461Z  INFO evm_eth_compliance::statetest::runner: UC : "delegatecallInInitcodeToExistingContract"
2023-01-26T12:28:14.748466Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 16475504,
    events_root: None,
}
2023-01-26T12:28:14.750201Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:591.181677ms
2023-01-26T12:28:15.025222Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "./test-vectors/tests/GeneralStateTests/stDelegatecallTestHomestead/delegatecallInInitcodeToExistingContractOOG.json", Total Files :: 1
2023-01-26T12:28:15.060533Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-26T12:28:15.060704Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T12:28:15.060708Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-26T12:28:15.060764Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T12:28:15.060766Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 2
2023-01-26T12:28:15.060833Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T12:28:15.060917Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-26T12:28:15.060921Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "delegatecallInInitcodeToExistingContractOOG"::Istanbul::0
2023-01-26T12:28:15.060924Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stDelegatecallTestHomestead/delegatecallInInitcodeToExistingContractOOG.json"
2023-01-26T12:28:15.060927Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T12:28:15.060929Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [19, 19, 96, 8, 182, 79, 245, 146, 129, 155, 47, 166, 212, 63, 40, 53, 196, 82, 2, 14, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([215, 166, 242, 208, 200, 186, 79, 10, 126, 8, 221, 102, 9, 12, 200, 158, 203, 19, 78, 227]) }
2023-01-26T12:28:15.691954Z  INFO evm_eth_compliance::statetest::runner: UC : "delegatecallInInitcodeToExistingContractOOG"
2023-01-26T12:28:15.691966Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 15990923,
    events_root: None,
}
2023-01-26T12:28:15.691994Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-26T12:28:15.691999Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "delegatecallInInitcodeToExistingContractOOG"::Berlin::0
2023-01-26T12:28:15.692001Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stDelegatecallTestHomestead/delegatecallInInitcodeToExistingContractOOG.json"
2023-01-26T12:28:15.692005Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T12:28:15.692007Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [124, 90, 44, 145, 178, 45, 122, 146, 38, 82, 61, 75, 167, 23, 219, 106, 251, 116, 30, 189, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([67, 35, 255, 1, 46, 226, 200, 90, 20, 150, 237, 153, 222, 171, 201, 9, 99, 31, 101, 211]) }
2023-01-26T12:28:15.692733Z  INFO evm_eth_compliance::statetest::runner: UC : "delegatecallInInitcodeToExistingContractOOG"
2023-01-26T12:28:15.692739Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 16405483,
    events_root: None,
}
2023-01-26T12:28:15.692758Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-26T12:28:15.692760Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "delegatecallInInitcodeToExistingContractOOG"::London::0
2023-01-26T12:28:15.692763Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stDelegatecallTestHomestead/delegatecallInInitcodeToExistingContractOOG.json"
2023-01-26T12:28:15.692766Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T12:28:15.692767Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [85, 225, 180, 184, 198, 80, 147, 57, 204, 233, 99, 201, 185, 164, 106, 230, 220, 29, 81, 93, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([28, 35, 125, 168, 212, 11, 234, 180, 81, 129, 48, 219, 76, 10, 52, 89, 217, 159, 194, 2]) }
2023-01-26T12:28:15.693420Z  INFO evm_eth_compliance::statetest::runner: UC : "delegatecallInInitcodeToExistingContractOOG"
2023-01-26T12:28:15.693426Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 16035278,
    events_root: None,
}
2023-01-26T12:28:15.693446Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-26T12:28:15.693449Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "delegatecallInInitcodeToExistingContractOOG"::Merge::0
2023-01-26T12:28:15.693451Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stDelegatecallTestHomestead/delegatecallInInitcodeToExistingContractOOG.json"
2023-01-26T12:28:15.693454Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T12:28:15.693456Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [119, 32, 219, 74, 113, 179, 136, 255, 7, 69, 60, 90, 226, 153, 143, 86, 21, 251, 52, 236, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([132, 105, 76, 107, 184, 77, 78, 105, 101, 219, 134, 121, 221, 254, 217, 203, 72, 121, 220, 83]) }
2023-01-26T12:28:15.694111Z  INFO evm_eth_compliance::statetest::runner: UC : "delegatecallInInitcodeToExistingContractOOG"
2023-01-26T12:28:15.694116Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 16475504,
    events_root: None,
}
2023-01-26T12:28:15.696023Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:633.608042ms
2023-01-26T12:28:15.967994Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "./test-vectors/tests/GeneralStateTests/stDelegatecallTestHomestead/delegatecallOOGinCall.json", Total Files :: 1
2023-01-26T12:28:16.005213Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-26T12:28:16.005387Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T12:28:16.005391Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-26T12:28:16.005447Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T12:28:16.005450Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 2
2023-01-26T12:28:16.005511Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T12:28:16.005595Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-26T12:28:16.005598Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "delegatecallOOGinCall"::Istanbul::0
2023-01-26T12:28:16.005601Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stDelegatecallTestHomestead/delegatecallOOGinCall.json"
2023-01-26T12:28:16.005605Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T12:28:16.005606Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T12:28:16.365860Z  INFO evm_eth_compliance::statetest::runner: UC : "delegatecallOOGinCall"
2023-01-26T12:28:16.365876Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3531049,
    events_root: None,
}
2023-01-26T12:28:16.365887Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-26T12:28:16.365892Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "delegatecallOOGinCall"::Berlin::0
2023-01-26T12:28:16.365894Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stDelegatecallTestHomestead/delegatecallOOGinCall.json"
2023-01-26T12:28:16.365897Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T12:28:16.365898Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T12:28:16.366080Z  INFO evm_eth_compliance::statetest::runner: UC : "delegatecallOOGinCall"
2023-01-26T12:28:16.366085Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2631271,
    events_root: None,
}
2023-01-26T12:28:16.366092Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-26T12:28:16.366094Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "delegatecallOOGinCall"::London::0
2023-01-26T12:28:16.366095Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stDelegatecallTestHomestead/delegatecallOOGinCall.json"
2023-01-26T12:28:16.366098Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T12:28:16.366099Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T12:28:16.366260Z  INFO evm_eth_compliance::statetest::runner: UC : "delegatecallOOGinCall"
2023-01-26T12:28:16.366264Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2631271,
    events_root: None,
}
2023-01-26T12:28:16.366270Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-26T12:28:16.366273Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "delegatecallOOGinCall"::Merge::0
2023-01-26T12:28:16.366275Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stDelegatecallTestHomestead/delegatecallOOGinCall.json"
2023-01-26T12:28:16.366278Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T12:28:16.366279Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T12:28:16.366440Z  INFO evm_eth_compliance::statetest::runner: UC : "delegatecallOOGinCall"
2023-01-26T12:28:16.366444Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2631271,
    events_root: None,
}
2023-01-26T12:28:16.367999Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:361.242248ms
2023-01-26T12:28:16.649528Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "./test-vectors/tests/GeneralStateTests/stDelegatecallTestHomestead/delegatecallSenderCheck.json", Total Files :: 1
2023-01-26T12:28:16.681660Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-26T12:28:16.681821Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T12:28:16.681825Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-26T12:28:16.681877Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T12:28:16.681879Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 2
2023-01-26T12:28:16.681936Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T12:28:16.682016Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-26T12:28:16.682019Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "delegatecallSenderCheck"::Istanbul::0
2023-01-26T12:28:16.682022Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stDelegatecallTestHomestead/delegatecallSenderCheck.json"
2023-01-26T12:28:16.682026Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T12:28:16.682028Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T12:28:17.066226Z  INFO evm_eth_compliance::statetest::runner: UC : "delegatecallSenderCheck"
2023-01-26T12:28:17.066239Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3096713,
    events_root: None,
}
2023-01-26T12:28:17.066251Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-26T12:28:17.066255Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "delegatecallSenderCheck"::Berlin::0
2023-01-26T12:28:17.066257Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stDelegatecallTestHomestead/delegatecallSenderCheck.json"
2023-01-26T12:28:17.066261Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T12:28:17.066263Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T12:28:17.066487Z  INFO evm_eth_compliance::statetest::runner: UC : "delegatecallSenderCheck"
2023-01-26T12:28:17.066492Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3096713,
    events_root: None,
}
2023-01-26T12:28:17.066499Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-26T12:28:17.066501Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "delegatecallSenderCheck"::London::0
2023-01-26T12:28:17.066503Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stDelegatecallTestHomestead/delegatecallSenderCheck.json"
2023-01-26T12:28:17.066507Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T12:28:17.066509Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T12:28:17.066728Z  INFO evm_eth_compliance::statetest::runner: UC : "delegatecallSenderCheck"
2023-01-26T12:28:17.066733Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3096713,
    events_root: None,
}
2023-01-26T12:28:17.066740Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-26T12:28:17.066742Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "delegatecallSenderCheck"::Merge::0
2023-01-26T12:28:17.066744Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stDelegatecallTestHomestead/delegatecallSenderCheck.json"
2023-01-26T12:28:17.066747Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T12:28:17.066748Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T12:28:17.066986Z  INFO evm_eth_compliance::statetest::runner: UC : "delegatecallSenderCheck"
2023-01-26T12:28:17.066990Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3096713,
    events_root: None,
}
2023-01-26T12:28:17.068611Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:385.345246ms
2023-01-26T12:28:17.333327Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "./test-vectors/tests/GeneralStateTests/stDelegatecallTestHomestead/delegatecallValueCheck.json", Total Files :: 1
2023-01-26T12:28:17.367135Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-26T12:28:17.367304Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T12:28:17.367308Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-26T12:28:17.367362Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T12:28:17.367364Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 2
2023-01-26T12:28:17.367425Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T12:28:17.367507Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-26T12:28:17.367510Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "delegatecallValueCheck"::Istanbul::0
2023-01-26T12:28:17.367513Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stDelegatecallTestHomestead/delegatecallValueCheck.json"
2023-01-26T12:28:17.367516Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T12:28:17.367518Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T12:28:17.764708Z  INFO evm_eth_compliance::statetest::runner: UC : "delegatecallValueCheck"
2023-01-26T12:28:17.764724Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3096713,
    events_root: None,
}
2023-01-26T12:28:17.764737Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-26T12:28:17.764743Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "delegatecallValueCheck"::Berlin::0
2023-01-26T12:28:17.764745Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stDelegatecallTestHomestead/delegatecallValueCheck.json"
2023-01-26T12:28:17.764750Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T12:28:17.764752Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T12:28:17.764987Z  INFO evm_eth_compliance::statetest::runner: UC : "delegatecallValueCheck"
2023-01-26T12:28:17.764992Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3096713,
    events_root: None,
}
2023-01-26T12:28:17.765002Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-26T12:28:17.765005Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "delegatecallValueCheck"::London::0
2023-01-26T12:28:17.765008Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stDelegatecallTestHomestead/delegatecallValueCheck.json"
2023-01-26T12:28:17.765013Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T12:28:17.765014Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T12:28:17.765239Z  INFO evm_eth_compliance::statetest::runner: UC : "delegatecallValueCheck"
2023-01-26T12:28:17.765244Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3096713,
    events_root: None,
}
2023-01-26T12:28:17.765252Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-26T12:28:17.765257Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "delegatecallValueCheck"::Merge::0
2023-01-26T12:28:17.765260Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stDelegatecallTestHomestead/delegatecallValueCheck.json"
2023-01-26T12:28:17.765264Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T12:28:17.765266Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T12:28:17.765498Z  INFO evm_eth_compliance::statetest::runner: UC : "delegatecallValueCheck"
2023-01-26T12:28:17.765504Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3096713,
    events_root: None,
}
2023-01-26T12:28:17.766892Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:398.381548ms
2023-01-26T12:28:18.045990Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "./test-vectors/tests/GeneralStateTests/stDelegatecallTestHomestead/delegatecodeDynamicCode.json", Total Files :: 1
2023-01-26T12:28:18.080169Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-26T12:28:18.080375Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T12:28:18.080381Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-26T12:28:18.080452Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T12:28:18.080550Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-26T12:28:18.080554Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "delegatecodeDynamicCode"::Istanbul::0
2023-01-26T12:28:18.080557Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stDelegatecallTestHomestead/delegatecodeDynamicCode.json"
2023-01-26T12:28:18.080561Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T12:28:18.080563Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [19, 19, 96, 8, 182, 79, 245, 146, 129, 155, 47, 166, 212, 63, 40, 53, 196, 82, 2, 14, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([215, 166, 242, 208, 200, 186, 79, 10, 126, 8, 221, 102, 9, 12, 200, 158, 203, 19, 78, 227]) }
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [86, 138, 149, 247, 123, 4, 123, 236, 230, 170, 104, 132, 61, 32, 25, 51, 44, 70, 165, 133, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([178, 136, 95, 13, 181, 217, 120, 204, 197, 243, 155, 145, 50, 151, 43, 92, 167, 175, 132, 25]) }
2023-01-26T12:28:18.705363Z  INFO evm_eth_compliance::statetest::runner: UC : "delegatecodeDynamicCode"
2023-01-26T12:28:18.705374Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 26034977,
    events_root: None,
}
2023-01-26T12:28:18.705408Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-26T12:28:18.705414Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "delegatecodeDynamicCode"::Berlin::0
2023-01-26T12:28:18.705416Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stDelegatecallTestHomestead/delegatecodeDynamicCode.json"
2023-01-26T12:28:18.705419Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T12:28:18.705421Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [124, 90, 44, 145, 178, 45, 122, 146, 38, 82, 61, 75, 167, 23, 219, 106, 251, 116, 30, 189, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([67, 35, 255, 1, 46, 226, 200, 90, 20, 150, 237, 153, 222, 171, 201, 9, 99, 31, 101, 211]) }
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [31, 160, 169, 169, 4, 72, 31, 134, 110, 245, 239, 218, 1, 242, 200, 244, 184, 9, 12, 26, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([239, 242, 33, 137, 111, 16, 15, 190, 235, 110, 77, 4, 63, 5, 41, 98, 192, 28, 206, 35]) }
2023-01-26T12:28:18.706504Z  INFO evm_eth_compliance::statetest::runner: UC : "delegatecodeDynamicCode"
2023-01-26T12:28:18.706510Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 27347931,
    events_root: None,
}
2023-01-26T12:28:18.706535Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-26T12:28:18.706538Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "delegatecodeDynamicCode"::London::0
2023-01-26T12:28:18.706540Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stDelegatecallTestHomestead/delegatecodeDynamicCode.json"
2023-01-26T12:28:18.706543Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T12:28:18.706544Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [85, 225, 180, 184, 198, 80, 147, 57, 204, 233, 99, 201, 185, 164, 106, 230, 220, 29, 81, 93, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([28, 35, 125, 168, 212, 11, 234, 180, 81, 129, 48, 219, 76, 10, 52, 89, 217, 159, 194, 2]) }
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [12, 71, 113, 250, 9, 110, 108, 70, 162, 252, 143, 21, 146, 102, 59, 28, 76, 247, 131, 255, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([234, 24, 246, 14, 245, 153, 41, 227, 62, 255, 40, 203, 90, 71, 156, 92, 203, 241, 198, 169]) }
2023-01-26T12:28:18.707601Z  INFO evm_eth_compliance::statetest::runner: UC : "delegatecodeDynamicCode"
2023-01-26T12:28:18.707607Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 27099264,
    events_root: None,
}
2023-01-26T12:28:18.707634Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-26T12:28:18.707637Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "delegatecodeDynamicCode"::Merge::0
2023-01-26T12:28:18.707639Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stDelegatecallTestHomestead/delegatecodeDynamicCode.json"
2023-01-26T12:28:18.707642Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T12:28:18.707643Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [119, 32, 219, 74, 113, 179, 136, 255, 7, 69, 60, 90, 226, 153, 143, 86, 21, 251, 52, 236, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([132, 105, 76, 107, 184, 77, 78, 105, 101, 219, 134, 121, 221, 254, 217, 203, 72, 121, 220, 83]) }
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [10, 235, 80, 223, 15, 146, 101, 100, 223, 30, 210, 148, 255, 72, 89, 225, 116, 47, 221, 29, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([217, 138, 9, 115, 71, 212, 34, 51, 81, 252, 105, 199, 181, 39, 187, 149, 48, 141, 211, 216]) }
2023-01-26T12:28:18.708726Z  INFO evm_eth_compliance::statetest::runner: UC : "delegatecodeDynamicCode"
2023-01-26T12:28:18.708732Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 27660840,
    events_root: None,
}
2023-01-26T12:28:18.710665Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:628.593291ms
2023-01-26T12:28:18.977655Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "./test-vectors/tests/GeneralStateTests/stDelegatecallTestHomestead/delegatecodeDynamicCode2SelfCall.json", Total Files :: 1
2023-01-26T12:28:19.017197Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-26T12:28:19.017398Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T12:28:19.017402Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-26T12:28:19.017463Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T12:28:19.017568Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-26T12:28:19.017573Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "delegatecodeDynamicCode2SelfCall"::Istanbul::0
2023-01-26T12:28:19.017576Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stDelegatecallTestHomestead/delegatecodeDynamicCode2SelfCall.json"
2023-01-26T12:28:19.017581Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T12:28:19.017584Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [19, 19, 96, 8, 182, 79, 245, 146, 129, 155, 47, 166, 212, 63, 40, 53, 196, 82, 2, 14, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([215, 166, 242, 208, 200, 186, 79, 10, 126, 8, 221, 102, 9, 12, 200, 158, 203, 19, 78, 227]) }
2023-01-26T12:28:19.641283Z  INFO evm_eth_compliance::statetest::runner: UC : "delegatecodeDynamicCode2SelfCall"
2023-01-26T12:28:19.641293Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 15990923,
    events_root: None,
}
2023-01-26T12:28:19.641320Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-26T12:28:19.641325Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "delegatecodeDynamicCode2SelfCall"::Berlin::0
2023-01-26T12:28:19.641327Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stDelegatecallTestHomestead/delegatecodeDynamicCode2SelfCall.json"
2023-01-26T12:28:19.641331Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T12:28:19.641333Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [124, 90, 44, 145, 178, 45, 122, 146, 38, 82, 61, 75, 167, 23, 219, 106, 251, 116, 30, 189, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([67, 35, 255, 1, 46, 226, 200, 90, 20, 150, 237, 153, 222, 171, 201, 9, 99, 31, 101, 211]) }
2023-01-26T12:28:19.642081Z  INFO evm_eth_compliance::statetest::runner: UC : "delegatecodeDynamicCode2SelfCall"
2023-01-26T12:28:19.642087Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 16405483,
    events_root: None,
}
2023-01-26T12:28:19.642109Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-26T12:28:19.642112Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "delegatecodeDynamicCode2SelfCall"::London::0
2023-01-26T12:28:19.642115Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stDelegatecallTestHomestead/delegatecodeDynamicCode2SelfCall.json"
2023-01-26T12:28:19.642119Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T12:28:19.642121Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [85, 225, 180, 184, 198, 80, 147, 57, 204, 233, 99, 201, 185, 164, 106, 230, 220, 29, 81, 93, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([28, 35, 125, 168, 212, 11, 234, 180, 81, 129, 48, 219, 76, 10, 52, 89, 217, 159, 194, 2]) }
2023-01-26T12:28:19.642780Z  INFO evm_eth_compliance::statetest::runner: UC : "delegatecodeDynamicCode2SelfCall"
2023-01-26T12:28:19.642786Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 15990920,
    events_root: None,
}
2023-01-26T12:28:19.642809Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-26T12:28:19.642813Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "delegatecodeDynamicCode2SelfCall"::Merge::0
2023-01-26T12:28:19.642816Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stDelegatecallTestHomestead/delegatecodeDynamicCode2SelfCall.json"
2023-01-26T12:28:19.642820Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T12:28:19.642821Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [119, 32, 219, 74, 113, 179, 136, 255, 7, 69, 60, 90, 226, 153, 143, 86, 21, 251, 52, 236, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([132, 105, 76, 107, 184, 77, 78, 105, 101, 219, 134, 121, 221, 254, 217, 203, 72, 121, 220, 83]) }
2023-01-26T12:28:19.643501Z  INFO evm_eth_compliance::statetest::runner: UC : "delegatecodeDynamicCode2SelfCall"
2023-01-26T12:28:19.643507Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 16475504,
    events_root: None,
}
2023-01-26T12:28:19.645336Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:626.336265ms
```