> Status

| Status | Context |
| --- | --- |
| OK | under WASM RT context |
| TODO | under native RT context |

> Test Suite

https://github.com/ethereum/tests/blob/develop/GeneralStateTests/VMTests/vmPerformance

> For Review

* Execution looks OK. TID-58-52 is skippeddue to execution freeze

> Command to execute

```
clear && \
	RUST_LOG=evm_eth_compliance=trace \
	VECTOR=test-vectors/tests/GeneralStateTests/VMTests/vmPerformance \
	cargo run --release \
	-- \
	statetest
```

> Execution Trace

```
2023-01-24T06:19:31.851354Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "test-vectors/tests/GeneralStateTests/VMTests/vmPerformance", Total Files :: 3
2023-01-24T06:19:31.851609Z TRACE evm_eth_compliance::statetest::runner: Calling testfile => "test-vectors/tests/GeneralStateTests/VMTests/vmPerformance/loopExp.json"
2023-01-24T06:19:31.879804Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-24T06:19:31.880000Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T06:19:31.880003Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-24T06:19:31.880060Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T06:19:31.880131Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 6
2023-01-24T06:19:31.880134Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "loopExp"::Istanbul::6
2023-01-24T06:19:31.880137Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmPerformance/loopExp.json"
2023-01-24T06:19:31.880140Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-24T06:19:31.880142Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T06:19:32.261248Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 58200000000000000000000000000000000000000000000000000000000000000000 },
    gas_used: 3409286,
    events_root: None,
}
2023-01-24T06:19:32.261289Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 7
2023-01-24T06:19:32.261296Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "loopExp"::Istanbul::7
2023-01-24T06:19:32.261298Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmPerformance/loopExp.json"
2023-01-24T06:19:32.261301Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-24T06:19:32.261302Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T06:19:32.261474Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 58200000000000000000000000000000000000000000000000000000000000000000 },
    gas_used: 2239302,
    events_root: None,
}
2023-01-24T06:19:32.261484Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 8
2023-01-24T06:19:32.261486Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "loopExp"::Istanbul::8
2023-01-24T06:19:32.261488Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmPerformance/loopExp.json"
2023-01-24T06:19:32.261490Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-24T06:19:32.261492Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T06:19:36.157002Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 58207dd3cdcdaa09b68a42b5ac372018960fcb3daae20a0d41f9e6b507245ac87f2d },
    gas_used: 75294829834,
    events_root: None,
}
2023-01-24T06:19:36.157027Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 12
2023-01-24T06:19:36.157034Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "loopExp"::Istanbul::12
2023-01-24T06:19:36.157037Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmPerformance/loopExp.json"
2023-01-24T06:19:36.157040Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-24T06:19:36.157041Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T06:19:37.571030Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 5820b23af8a01bc4dfc6f808935d77dbab8000000000000000005851f42d4c957f2d },
    gas_used: 56636446763,
    events_root: None,
}
2023-01-24T06:19:37.571054Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 13
2023-01-24T06:19:37.571061Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "loopExp"::Istanbul::13
2023-01-24T06:19:37.571063Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmPerformance/loopExp.json"
2023-01-24T06:19:37.571066Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-24T06:19:37.571068Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T06:19:40.059687Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 58200000000000000000000000000000000000000000000000005851f42d4c957f2d },
    gas_used: 109014816722,
    events_root: None,
}
2023-01-24T06:19:40.059714Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 9
2023-01-24T06:19:40.059720Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "loopExp"::Istanbul::9
2023-01-24T06:19:40.059723Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmPerformance/loopExp.json"
2023-01-24T06:19:40.059726Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-24T06:19:40.059727Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T06:19:40.521256Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 582087b9c676d0fd90e2d05a9f8621a374edc678a3fc7209929731e3c9c8f8157f2d },
    gas_used: 10805652982,
    events_root: None,
}
2023-01-24T06:19:40.521284Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 10
2023-01-24T06:19:40.521291Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "loopExp"::Istanbul::10
2023-01-24T06:19:40.521294Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmPerformance/loopExp.json"
2023-01-24T06:19:40.521297Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-24T06:19:40.521299Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T06:19:41.115504Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 5820d0e61f591bd78de46f37ced3590d1b5b8c9534ef27bcf11dd02d9fad4c957f2d },
    gas_used: 17352846831,
    events_root: None,
}
2023-01-24T06:19:41.115526Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 11
2023-01-24T06:19:41.115532Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "loopExp"::Istanbul::11
2023-01-24T06:19:41.115535Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmPerformance/loopExp.json"
2023-01-24T06:19:41.115538Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-24T06:19:41.115539Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T06:19:41.956382Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 5820a0b60baf8a7d5ff1840537484b793d86f808935d77dbab805851f42d4c957f2d },
    gas_used: 30447247131,
    events_root: None,
}
2023-01-24T06:19:41.956408Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 14
2023-01-24T06:19:41.956415Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "loopExp"::Istanbul::14
2023-01-24T06:19:41.956418Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmPerformance/loopExp.json"
2023-01-24T06:19:41.956421Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-24T06:19:41.956422Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T06:19:42.797576Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 5820000000000000000000000000000000000000000000000000000000000000000f },
    gas_used: 11630796398,
    events_root: None,
}
2023-01-24T06:19:42.797601Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-24T06:19:42.797607Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "loopExp"::Istanbul::0
2023-01-24T06:19:42.797609Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmPerformance/loopExp.json"
2023-01-24T06:19:42.797612Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-24T06:19:42.797614Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T06:19:42.798291Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 58200000000000000000000000000000000000000000000000000000000000000003 },
    gas_used: 9004657,
    events_root: None,
}
2023-01-24T06:19:42.798300Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 1
2023-01-24T06:19:42.798302Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "loopExp"::Istanbul::1
2023-01-24T06:19:42.798304Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmPerformance/loopExp.json"
2023-01-24T06:19:42.798306Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-24T06:19:42.798308Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T06:19:42.798450Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 58200000000000000000000000000000000000000000000000000000000000000003 },
    gas_used: 2282178,
    events_root: None,
}
2023-01-24T06:19:42.798458Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 2
2023-01-24T06:19:42.798460Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "loopExp"::Istanbul::2
2023-01-24T06:19:42.798462Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmPerformance/loopExp.json"
2023-01-24T06:19:42.798465Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-24T06:19:42.798466Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T06:19:42.799115Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 58209cf0248d6311b77070454df6fd81b1a6c87a3f3c52fa8b3cdd7095952acd8e03 },
    gas_used: 10973538,
    events_root: None,
}
2023-01-24T06:19:42.799123Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 3
2023-01-24T06:19:42.799126Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "loopExp"::Istanbul::3
2023-01-24T06:19:42.799128Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmPerformance/loopExp.json"
2023-01-24T06:19:42.799130Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-24T06:19:42.799131Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T06:19:42.799338Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 58209cf0248d6311b77070454df6fd81b1a6c87a3f3c52fa8b3cdd7095952acd8e03 },
    gas_used: 4190811,
    events_root: None,
}
2023-01-24T06:19:42.799346Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 4
2023-01-24T06:19:42.799348Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "loopExp"::Istanbul::4
2023-01-24T06:19:42.799350Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmPerformance/loopExp.json"
2023-01-24T06:19:42.799352Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-24T06:19:42.799354Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T06:19:42.799564Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 58200000000000000000000000000000000000000000000000000000000000000002 },
    gas_used: 4036718,
    events_root: None,
}
2023-01-24T06:19:42.799572Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 5
2023-01-24T06:19:42.799575Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "loopExp"::Istanbul::5
2023-01-24T06:19:42.799577Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmPerformance/loopExp.json"
2023-01-24T06:19:42.799579Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-24T06:19:42.799580Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T06:19:42.799697Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 58200000000000000000000000000000000000000000000000000000000000000002 },
    gas_used: 1972098,
    events_root: None,
}
2023-01-24T06:19:42.799705Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 6
2023-01-24T06:19:42.799707Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "loopExp"::Berlin::6
2023-01-24T06:19:42.799709Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmPerformance/loopExp.json"
2023-01-24T06:19:42.799711Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-24T06:19:42.799713Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T06:19:42.799937Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 58200000000000000000000000000000000000000000000000000000000000000000 },
    gas_used: 4326639,
    events_root: None,
}
2023-01-24T06:19:42.799946Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 7
2023-01-24T06:19:42.799948Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "loopExp"::Berlin::7
2023-01-24T06:19:42.799950Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmPerformance/loopExp.json"
2023-01-24T06:19:42.799953Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-24T06:19:42.799954Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T06:19:42.800079Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 58200000000000000000000000000000000000000000000000000000000000000000 },
    gas_used: 2239302,
    events_root: None,
}
2023-01-24T06:19:42.800086Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 8
2023-01-24T06:19:42.800089Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "loopExp"::Berlin::8
2023-01-24T06:19:42.800090Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmPerformance/loopExp.json"
2023-01-24T06:19:42.800093Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-24T06:19:42.800094Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T06:19:46.656950Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 58207dd3cdcdaa09b68a42b5ac372018960fcb3daae20a0d41f9e6b507245ac87f2d },
    gas_used: 75294829834,
    events_root: None,
}
2023-01-24T06:19:46.656979Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 12
2023-01-24T06:19:46.656987Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "loopExp"::Berlin::12
2023-01-24T06:19:46.656990Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmPerformance/loopExp.json"
2023-01-24T06:19:46.656992Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-24T06:19:46.656994Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T06:19:48.101763Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 5820b23af8a01bc4dfc6f808935d77dbab8000000000000000005851f42d4c957f2d },
    gas_used: 56636446763,
    events_root: None,
}
2023-01-24T06:19:48.101791Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 13
2023-01-24T06:19:48.101798Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "loopExp"::Berlin::13
2023-01-24T06:19:48.101802Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmPerformance/loopExp.json"
2023-01-24T06:19:48.101806Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-24T06:19:48.101808Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T06:19:50.635889Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 58200000000000000000000000000000000000000000000000005851f42d4c957f2d },
    gas_used: 109014816722,
    events_root: None,
}
2023-01-24T06:19:50.635914Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 9
2023-01-24T06:19:50.635921Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "loopExp"::Berlin::9
2023-01-24T06:19:50.635924Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmPerformance/loopExp.json"
2023-01-24T06:19:50.635927Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-24T06:19:50.635928Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T06:19:51.109164Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 582087b9c676d0fd90e2d05a9f8621a374edc678a3fc7209929731e3c9c8f8157f2d },
    gas_used: 10805652982,
    events_root: None,
}
2023-01-24T06:19:51.109192Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 10
2023-01-24T06:19:51.109198Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "loopExp"::Berlin::10
2023-01-24T06:19:51.109201Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmPerformance/loopExp.json"
2023-01-24T06:19:51.109204Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-24T06:19:51.109205Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T06:19:51.703066Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 5820d0e61f591bd78de46f37ced3590d1b5b8c9534ef27bcf11dd02d9fad4c957f2d },
    gas_used: 17352846831,
    events_root: None,
}
2023-01-24T06:19:51.703093Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 11
2023-01-24T06:19:51.703100Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "loopExp"::Berlin::11
2023-01-24T06:19:51.703103Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmPerformance/loopExp.json"
2023-01-24T06:19:51.703106Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-24T06:19:51.703107Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T06:19:52.588915Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 5820a0b60baf8a7d5ff1840537484b793d86f808935d77dbab805851f42d4c957f2d },
    gas_used: 30447247131,
    events_root: None,
}
2023-01-24T06:19:52.588944Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 14
2023-01-24T06:19:52.588952Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "loopExp"::Berlin::14
2023-01-24T06:19:52.588954Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmPerformance/loopExp.json"
2023-01-24T06:19:52.588958Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-24T06:19:52.588959Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T06:19:53.453799Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 5820000000000000000000000000000000000000000000000000000000000000000f },
    gas_used: 11630796398,
    events_root: None,
}
2023-01-24T06:19:53.453827Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-24T06:19:53.453834Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "loopExp"::Berlin::0
2023-01-24T06:19:53.453837Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmPerformance/loopExp.json"
2023-01-24T06:19:53.453840Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-24T06:19:53.453841Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T06:19:53.454535Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 58200000000000000000000000000000000000000000000000000000000000000003 },
    gas_used: 9004657,
    events_root: None,
}
2023-01-24T06:19:53.454545Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 1
2023-01-24T06:19:53.454548Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "loopExp"::Berlin::1
2023-01-24T06:19:53.454550Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmPerformance/loopExp.json"
2023-01-24T06:19:53.454552Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-24T06:19:53.454554Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T06:19:53.454705Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 58200000000000000000000000000000000000000000000000000000000000000003 },
    gas_used: 2282178,
    events_root: None,
}
2023-01-24T06:19:53.454714Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 2
2023-01-24T06:19:53.454716Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "loopExp"::Berlin::2
2023-01-24T06:19:53.454718Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmPerformance/loopExp.json"
2023-01-24T06:19:53.454721Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-24T06:19:53.454722Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T06:19:53.455393Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 58209cf0248d6311b77070454df6fd81b1a6c87a3f3c52fa8b3cdd7095952acd8e03 },
    gas_used: 10973538,
    events_root: None,
}
2023-01-24T06:19:53.455404Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 3
2023-01-24T06:19:53.455407Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "loopExp"::Berlin::3
2023-01-24T06:19:53.455409Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmPerformance/loopExp.json"
2023-01-24T06:19:53.455413Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-24T06:19:53.455415Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T06:19:53.455679Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 58209cf0248d6311b77070454df6fd81b1a6c87a3f3c52fa8b3cdd7095952acd8e03 },
    gas_used: 4190811,
    events_root: None,
}
2023-01-24T06:19:53.455690Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 4
2023-01-24T06:19:53.455693Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "loopExp"::Berlin::4
2023-01-24T06:19:53.455695Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmPerformance/loopExp.json"
2023-01-24T06:19:53.455699Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-24T06:19:53.455700Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T06:19:53.455969Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 58200000000000000000000000000000000000000000000000000000000000000002 },
    gas_used: 4036718,
    events_root: None,
}
2023-01-24T06:19:53.455980Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 5
2023-01-24T06:19:53.455983Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "loopExp"::Berlin::5
2023-01-24T06:19:53.455985Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmPerformance/loopExp.json"
2023-01-24T06:19:53.455987Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-24T06:19:53.455989Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T06:19:53.456139Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 58200000000000000000000000000000000000000000000000000000000000000002 },
    gas_used: 1972098,
    events_root: None,
}
2023-01-24T06:19:53.456150Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 6
2023-01-24T06:19:53.456153Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "loopExp"::London::6
2023-01-24T06:19:53.456156Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmPerformance/loopExp.json"
2023-01-24T06:19:53.456159Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-24T06:19:53.456160Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T06:19:53.456474Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 58200000000000000000000000000000000000000000000000000000000000000000 },
    gas_used: 4326639,
    events_root: None,
}
2023-01-24T06:19:53.456486Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 7
2023-01-24T06:19:53.456489Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "loopExp"::London::7
2023-01-24T06:19:53.456492Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmPerformance/loopExp.json"
2023-01-24T06:19:53.456495Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-24T06:19:53.456497Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T06:19:53.456668Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 58200000000000000000000000000000000000000000000000000000000000000000 },
    gas_used: 2239302,
    events_root: None,
}
2023-01-24T06:19:53.456678Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 8
2023-01-24T06:19:53.456680Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "loopExp"::London::8
2023-01-24T06:19:53.456682Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmPerformance/loopExp.json"
2023-01-24T06:19:53.456684Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-24T06:19:53.456685Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T06:19:57.484785Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 58207dd3cdcdaa09b68a42b5ac372018960fcb3daae20a0d41f9e6b507245ac87f2d },
    gas_used: 75294829834,
    events_root: None,
}
2023-01-24T06:19:57.484813Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 12
2023-01-24T06:19:57.484822Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "loopExp"::London::12
2023-01-24T06:19:57.484824Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmPerformance/loopExp.json"
2023-01-24T06:19:57.484827Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-24T06:19:57.484829Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T06:19:58.908555Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 5820b23af8a01bc4dfc6f808935d77dbab8000000000000000005851f42d4c957f2d },
    gas_used: 56636446763,
    events_root: None,
}
2023-01-24T06:19:58.908580Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 13
2023-01-24T06:19:58.908587Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "loopExp"::London::13
2023-01-24T06:19:58.908590Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmPerformance/loopExp.json"
2023-01-24T06:19:58.908593Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-24T06:19:58.908594Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T06:20:01.450162Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 58200000000000000000000000000000000000000000000000005851f42d4c957f2d },
    gas_used: 109014816722,
    events_root: None,
}
2023-01-24T06:20:01.450194Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 9
2023-01-24T06:20:01.450205Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "loopExp"::London::9
2023-01-24T06:20:01.450208Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmPerformance/loopExp.json"
2023-01-24T06:20:01.450212Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-24T06:20:01.450213Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T06:20:01.913396Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 582087b9c676d0fd90e2d05a9f8621a374edc678a3fc7209929731e3c9c8f8157f2d },
    gas_used: 10805652982,
    events_root: None,
}
2023-01-24T06:20:01.913423Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 10
2023-01-24T06:20:01.913431Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "loopExp"::London::10
2023-01-24T06:20:01.913433Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmPerformance/loopExp.json"
2023-01-24T06:20:01.913436Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-24T06:20:01.913438Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T06:20:02.511200Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 5820d0e61f591bd78de46f37ced3590d1b5b8c9534ef27bcf11dd02d9fad4c957f2d },
    gas_used: 17352846831,
    events_root: None,
}
2023-01-24T06:20:02.511227Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 11
2023-01-24T06:20:02.511234Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "loopExp"::London::11
2023-01-24T06:20:02.511237Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmPerformance/loopExp.json"
2023-01-24T06:20:02.511240Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-24T06:20:02.511241Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T06:20:03.360962Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 5820a0b60baf8a7d5ff1840537484b793d86f808935d77dbab805851f42d4c957f2d },
    gas_used: 30447247131,
    events_root: None,
}
2023-01-24T06:20:03.360987Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 14
2023-01-24T06:20:03.360994Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "loopExp"::London::14
2023-01-24T06:20:03.360997Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmPerformance/loopExp.json"
2023-01-24T06:20:03.361000Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-24T06:20:03.361001Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T06:20:04.215877Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 5820000000000000000000000000000000000000000000000000000000000000000f },
    gas_used: 11630796398,
    events_root: None,
}
2023-01-24T06:20:04.215903Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-24T06:20:04.215910Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "loopExp"::London::0
2023-01-24T06:20:04.215912Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmPerformance/loopExp.json"
2023-01-24T06:20:04.215916Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-24T06:20:04.215918Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T06:20:04.216610Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 58200000000000000000000000000000000000000000000000000000000000000003 },
    gas_used: 9004657,
    events_root: None,
}
2023-01-24T06:20:04.216620Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 1
2023-01-24T06:20:04.216622Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "loopExp"::London::1
2023-01-24T06:20:04.216624Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmPerformance/loopExp.json"
2023-01-24T06:20:04.216627Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-24T06:20:04.216628Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T06:20:04.216780Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 58200000000000000000000000000000000000000000000000000000000000000003 },
    gas_used: 2282178,
    events_root: None,
}
2023-01-24T06:20:04.216788Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 2
2023-01-24T06:20:04.216790Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "loopExp"::London::2
2023-01-24T06:20:04.216792Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmPerformance/loopExp.json"
2023-01-24T06:20:04.216796Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-24T06:20:04.216797Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T06:20:04.217466Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 58209cf0248d6311b77070454df6fd81b1a6c87a3f3c52fa8b3cdd7095952acd8e03 },
    gas_used: 10973538,
    events_root: None,
}
2023-01-24T06:20:04.217475Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 3
2023-01-24T06:20:04.217478Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "loopExp"::London::3
2023-01-24T06:20:04.217480Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmPerformance/loopExp.json"
2023-01-24T06:20:04.217482Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-24T06:20:04.217483Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T06:20:04.217700Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 58209cf0248d6311b77070454df6fd81b1a6c87a3f3c52fa8b3cdd7095952acd8e03 },
    gas_used: 4190811,
    events_root: None,
}
2023-01-24T06:20:04.217708Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 4
2023-01-24T06:20:04.217710Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "loopExp"::London::4
2023-01-24T06:20:04.217712Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmPerformance/loopExp.json"
2023-01-24T06:20:04.217714Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-24T06:20:04.217716Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T06:20:04.217934Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 58200000000000000000000000000000000000000000000000000000000000000002 },
    gas_used: 4036718,
    events_root: None,
}
2023-01-24T06:20:04.217943Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 5
2023-01-24T06:20:04.217945Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "loopExp"::London::5
2023-01-24T06:20:04.217947Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmPerformance/loopExp.json"
2023-01-24T06:20:04.217949Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-24T06:20:04.217951Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T06:20:04.218073Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 58200000000000000000000000000000000000000000000000000000000000000002 },
    gas_used: 1972098,
    events_root: None,
}
2023-01-24T06:20:04.218082Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 6
2023-01-24T06:20:04.218084Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "loopExp"::Merge::6
2023-01-24T06:20:04.218086Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmPerformance/loopExp.json"
2023-01-24T06:20:04.218089Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-24T06:20:04.218090Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T06:20:04.218322Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 58200000000000000000000000000000000000000000000000000000000000000000 },
    gas_used: 4326639,
    events_root: None,
}
2023-01-24T06:20:04.218331Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 7
2023-01-24T06:20:04.218334Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "loopExp"::Merge::7
2023-01-24T06:20:04.218336Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmPerformance/loopExp.json"
2023-01-24T06:20:04.218338Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-24T06:20:04.218340Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T06:20:04.218470Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 58200000000000000000000000000000000000000000000000000000000000000000 },
    gas_used: 2239302,
    events_root: None,
}
2023-01-24T06:20:04.218478Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 8
2023-01-24T06:20:04.218482Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "loopExp"::Merge::8
2023-01-24T06:20:04.218483Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmPerformance/loopExp.json"
2023-01-24T06:20:04.218486Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-24T06:20:04.218487Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T06:20:08.135658Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 58207dd3cdcdaa09b68a42b5ac372018960fcb3daae20a0d41f9e6b507245ac87f2d },
    gas_used: 75294829834,
    events_root: None,
}
2023-01-24T06:20:08.135686Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 12
2023-01-24T06:20:08.135693Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "loopExp"::Merge::12
2023-01-24T06:20:08.135695Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmPerformance/loopExp.json"
2023-01-24T06:20:08.135698Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-24T06:20:08.135700Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T06:20:09.565549Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 5820b23af8a01bc4dfc6f808935d77dbab8000000000000000005851f42d4c957f2d },
    gas_used: 56636446763,
    events_root: None,
}
2023-01-24T06:20:09.565576Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 13
2023-01-24T06:20:09.565582Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "loopExp"::Merge::13
2023-01-24T06:20:09.565585Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmPerformance/loopExp.json"
2023-01-24T06:20:09.565588Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-24T06:20:09.565589Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T06:20:12.003832Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 58200000000000000000000000000000000000000000000000005851f42d4c957f2d },
    gas_used: 109014816722,
    events_root: None,
}
2023-01-24T06:20:12.003855Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 9
2023-01-24T06:20:12.003862Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "loopExp"::Merge::9
2023-01-24T06:20:12.003865Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmPerformance/loopExp.json"
2023-01-24T06:20:12.003868Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-24T06:20:12.003869Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T06:20:12.463244Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 582087b9c676d0fd90e2d05a9f8621a374edc678a3fc7209929731e3c9c8f8157f2d },
    gas_used: 10805652982,
    events_root: None,
}
2023-01-24T06:20:12.463271Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 10
2023-01-24T06:20:12.463278Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "loopExp"::Merge::10
2023-01-24T06:20:12.463280Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmPerformance/loopExp.json"
2023-01-24T06:20:12.463283Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-24T06:20:12.463284Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T06:20:13.059889Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 5820d0e61f591bd78de46f37ced3590d1b5b8c9534ef27bcf11dd02d9fad4c957f2d },
    gas_used: 17352846831,
    events_root: None,
}
2023-01-24T06:20:13.059914Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 11
2023-01-24T06:20:13.059921Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "loopExp"::Merge::11
2023-01-24T06:20:13.059923Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmPerformance/loopExp.json"
2023-01-24T06:20:13.059927Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-24T06:20:13.059928Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T06:20:13.914322Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 5820a0b60baf8a7d5ff1840537484b793d86f808935d77dbab805851f42d4c957f2d },
    gas_used: 30447247131,
    events_root: None,
}
2023-01-24T06:20:13.914347Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 14
2023-01-24T06:20:13.914354Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "loopExp"::Merge::14
2023-01-24T06:20:13.914357Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmPerformance/loopExp.json"
2023-01-24T06:20:13.914360Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-24T06:20:13.914361Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T06:20:14.764748Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 5820000000000000000000000000000000000000000000000000000000000000000f },
    gas_used: 11630796398,
    events_root: None,
}
2023-01-24T06:20:14.764772Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-24T06:20:14.764779Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "loopExp"::Merge::0
2023-01-24T06:20:14.764781Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmPerformance/loopExp.json"
2023-01-24T06:20:14.764784Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-24T06:20:14.764785Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T06:20:14.765452Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 58200000000000000000000000000000000000000000000000000000000000000003 },
    gas_used: 9004657,
    events_root: None,
}
2023-01-24T06:20:14.765461Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 1
2023-01-24T06:20:14.765464Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "loopExp"::Merge::1
2023-01-24T06:20:14.765465Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmPerformance/loopExp.json"
2023-01-24T06:20:14.765468Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-24T06:20:14.765469Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T06:20:14.765611Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 58200000000000000000000000000000000000000000000000000000000000000003 },
    gas_used: 2282178,
    events_root: None,
}
2023-01-24T06:20:14.765619Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 2
2023-01-24T06:20:14.765621Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "loopExp"::Merge::2
2023-01-24T06:20:14.765623Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmPerformance/loopExp.json"
2023-01-24T06:20:14.765625Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-24T06:20:14.765627Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T06:20:14.766271Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 58209cf0248d6311b77070454df6fd81b1a6c87a3f3c52fa8b3cdd7095952acd8e03 },
    gas_used: 10973538,
    events_root: None,
}
2023-01-24T06:20:14.766280Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 3
2023-01-24T06:20:14.766282Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "loopExp"::Merge::3
2023-01-24T06:20:14.766283Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmPerformance/loopExp.json"
2023-01-24T06:20:14.766286Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-24T06:20:14.766287Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T06:20:14.766493Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 58209cf0248d6311b77070454df6fd81b1a6c87a3f3c52fa8b3cdd7095952acd8e03 },
    gas_used: 4190811,
    events_root: None,
}
2023-01-24T06:20:14.766500Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 4
2023-01-24T06:20:14.766503Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "loopExp"::Merge::4
2023-01-24T06:20:14.766504Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmPerformance/loopExp.json"
2023-01-24T06:20:14.766507Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-24T06:20:14.766508Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T06:20:14.766717Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 58200000000000000000000000000000000000000000000000000000000000000002 },
    gas_used: 4036718,
    events_root: None,
}
2023-01-24T06:20:14.766726Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 5
2023-01-24T06:20:14.766728Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "loopExp"::Merge::5
2023-01-24T06:20:14.766730Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmPerformance/loopExp.json"
2023-01-24T06:20:14.766733Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-24T06:20:14.766734Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T06:20:14.766851Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 58200000000000000000000000000000000000000000000000000000000000000002 },
    gas_used: 1972098,
    events_root: None,
}
2023-01-24T06:20:14.768635Z TRACE evm_eth_compliance::statetest::runner: TestDone => "test-vectors/tests/GeneralStateTests/VMTests/vmPerformance/loopExp.json"
2023-01-24T06:20:14.768662Z TRACE evm_eth_compliance::statetest::runner: Calling testfile => "test-vectors/tests/GeneralStateTests/VMTests/vmPerformance/loopMul.json"
2023-01-24T06:20:14.795166Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-24T06:20:14.795315Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T06:20:14.795318Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-24T06:20:14.795374Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T06:20:14.795443Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-24T06:20:14.795449Z  WARN evm_eth_compliance::statetest::runner: Skipping Post Test test_name: '"loopMul"', chain_spec: 'Istanbul', data_index: 0
2023-01-24T06:20:14.795452Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 1
2023-01-24T06:20:14.795453Z  WARN evm_eth_compliance::statetest::runner: Skipping Post Test test_name: '"loopMul"', chain_spec: 'Istanbul', data_index: 1
2023-01-24T06:20:14.795455Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 2
2023-01-24T06:20:14.795456Z  WARN evm_eth_compliance::statetest::runner: Skipping Post Test test_name: '"loopMul"', chain_spec: 'Istanbul', data_index: 2
2023-01-24T06:20:14.795458Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-24T06:20:14.795459Z  WARN evm_eth_compliance::statetest::runner: Skipping Post Test test_name: '"loopMul"', chain_spec: 'Berlin', data_index: 0
2023-01-24T06:20:14.795461Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 1
2023-01-24T06:20:14.795463Z  WARN evm_eth_compliance::statetest::runner: Skipping Post Test test_name: '"loopMul"', chain_spec: 'Berlin', data_index: 1
2023-01-24T06:20:14.795464Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 2
2023-01-24T06:20:14.795466Z  WARN evm_eth_compliance::statetest::runner: Skipping Post Test test_name: '"loopMul"', chain_spec: 'Berlin', data_index: 2
2023-01-24T06:20:14.795468Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-24T06:20:14.795470Z  WARN evm_eth_compliance::statetest::runner: Skipping Post Test test_name: '"loopMul"', chain_spec: 'London', data_index: 0
2023-01-24T06:20:14.795471Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 1
2023-01-24T06:20:14.795473Z  WARN evm_eth_compliance::statetest::runner: Skipping Post Test test_name: '"loopMul"', chain_spec: 'London', data_index: 1
2023-01-24T06:20:14.795474Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 2
2023-01-24T06:20:14.795476Z  WARN evm_eth_compliance::statetest::runner: Skipping Post Test test_name: '"loopMul"', chain_spec: 'London', data_index: 2
2023-01-24T06:20:14.795478Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-24T06:20:14.795479Z  WARN evm_eth_compliance::statetest::runner: Skipping Post Test test_name: '"loopMul"', chain_spec: 'Merge', data_index: 0
2023-01-24T06:20:14.795481Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 1
2023-01-24T06:20:14.795482Z  WARN evm_eth_compliance::statetest::runner: Skipping Post Test test_name: '"loopMul"', chain_spec: 'Merge', data_index: 1
2023-01-24T06:20:14.795484Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 2
2023-01-24T06:20:14.795486Z  WARN evm_eth_compliance::statetest::runner: Skipping Post Test test_name: '"loopMul"', chain_spec: 'Merge', data_index: 2
2023-01-24T06:20:14.796172Z TRACE evm_eth_compliance::statetest::runner: TestDone => "test-vectors/tests/GeneralStateTests/VMTests/vmPerformance/loopMul.json"
2023-01-24T06:20:14.796197Z TRACE evm_eth_compliance::statetest::runner: Calling testfile => "test-vectors/tests/GeneralStateTests/VMTests/vmPerformance/performanceTester.json"
2023-01-24T06:20:14.821469Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-24T06:20:14.821572Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T06:20:14.821576Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-24T06:20:14.821630Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T06:20:14.821699Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-24T06:20:14.821704Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "performanceTester"::Istanbul::0
2023-01-24T06:20:14.821707Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmPerformance/performanceTester.json"
2023-01-24T06:20:14.821710Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-24T06:20:14.821712Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T06:20:15.184172Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 582000000000000000000000000000000000000000000000000000000000000060a7 },
    gas_used: 13838499,
    events_root: None,
}
2023-01-24T06:20:15.184203Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 1
2023-01-24T06:20:15.184212Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "performanceTester"::Istanbul::1
2023-01-24T06:20:15.184215Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmPerformance/performanceTester.json"
2023-01-24T06:20:15.184219Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-24T06:20:15.184221Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T06:20:15.199892Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 582000000000000000000000000000000000000000000000000000000000000060a7 },
    gas_used: 203687250,
    events_root: None,
}
2023-01-24T06:20:15.199918Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 2
2023-01-24T06:20:15.199925Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "performanceTester"::Istanbul::2
2023-01-24T06:20:15.199928Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmPerformance/performanceTester.json"
2023-01-24T06:20:15.199931Z  INFO evm_eth_compliance::statetest::runner: TX len : 68
2023-01-24T06:20:15.199933Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T06:20:15.200655Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 5820000000000000000000000000000000000000000000000000000000000000000d },
    gas_used: 9202481,
    events_root: None,
}
2023-01-24T06:20:15.200665Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 3
2023-01-24T06:20:15.200668Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "performanceTester"::Istanbul::3
2023-01-24T06:20:15.200670Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmPerformance/performanceTester.json"
2023-01-24T06:20:15.200672Z  INFO evm_eth_compliance::statetest::runner: TX len : 68
2023-01-24T06:20:15.200674Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T06:20:15.203482Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 5820000000000000000000000000000000000000000000000000000000000000001d },
    gas_used: 35885099,
    events_root: None,
}
2023-01-24T06:20:15.203493Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 4
2023-01-24T06:20:15.203498Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "performanceTester"::Istanbul::4
2023-01-24T06:20:15.203500Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmPerformance/performanceTester.json"
2023-01-24T06:20:15.203503Z  INFO evm_eth_compliance::statetest::runner: TX len : 68
2023-01-24T06:20:15.203505Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T06:20:15.214962Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 5820000000000000000000000000000000000000000000000000000000000000003d },
    gas_used: 152282723,
    events_root: None,
}
2023-01-24T06:20:15.214986Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-24T06:20:15.214991Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "performanceTester"::Berlin::0
2023-01-24T06:20:15.214994Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmPerformance/performanceTester.json"
2023-01-24T06:20:15.214997Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-24T06:20:15.214998Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T06:20:15.216031Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 582000000000000000000000000000000000000000000000000000000000000060a7 },
    gas_used: 13855867,
    events_root: None,
}
2023-01-24T06:20:15.216040Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 1
2023-01-24T06:20:15.216043Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "performanceTester"::Berlin::1
2023-01-24T06:20:15.216045Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmPerformance/performanceTester.json"
2023-01-24T06:20:15.216047Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-24T06:20:15.216049Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T06:20:15.231572Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 582000000000000000000000000000000000000000000000000000000000000060a7 },
    gas_used: 203687250,
    events_root: None,
}
2023-01-24T06:20:15.231589Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 2
2023-01-24T06:20:15.231595Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "performanceTester"::Berlin::2
2023-01-24T06:20:15.231598Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmPerformance/performanceTester.json"
2023-01-24T06:20:15.231600Z  INFO evm_eth_compliance::statetest::runner: TX len : 68
2023-01-24T06:20:15.231602Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T06:20:15.232269Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 5820000000000000000000000000000000000000000000000000000000000000000d },
    gas_used: 9202481,
    events_root: None,
}
2023-01-24T06:20:15.232278Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 3
2023-01-24T06:20:15.232281Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "performanceTester"::Berlin::3
2023-01-24T06:20:15.232283Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmPerformance/performanceTester.json"
2023-01-24T06:20:15.232285Z  INFO evm_eth_compliance::statetest::runner: TX len : 68
2023-01-24T06:20:15.232287Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T06:20:15.235023Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 5820000000000000000000000000000000000000000000000000000000000000001d },
    gas_used: 35885099,
    events_root: None,
}
2023-01-24T06:20:15.235033Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 4
2023-01-24T06:20:15.235035Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "performanceTester"::Berlin::4
2023-01-24T06:20:15.235038Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmPerformance/performanceTester.json"
2023-01-24T06:20:15.235040Z  INFO evm_eth_compliance::statetest::runner: TX len : 68
2023-01-24T06:20:15.235042Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T06:20:15.246427Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 5820000000000000000000000000000000000000000000000000000000000000003d },
    gas_used: 152282723,
    events_root: None,
}
2023-01-24T06:20:15.246440Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-24T06:20:15.246445Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "performanceTester"::London::0
2023-01-24T06:20:15.246447Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmPerformance/performanceTester.json"
2023-01-24T06:20:15.246449Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-24T06:20:15.246451Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T06:20:15.247451Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 582000000000000000000000000000000000000000000000000000000000000060a7 },
    gas_used: 13855867,
    events_root: None,
}
2023-01-24T06:20:15.247461Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 1
2023-01-24T06:20:15.247463Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "performanceTester"::London::1
2023-01-24T06:20:15.247465Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmPerformance/performanceTester.json"
2023-01-24T06:20:15.247467Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-24T06:20:15.247469Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T06:20:15.263060Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 582000000000000000000000000000000000000000000000000000000000000060a7 },
    gas_used: 203687250,
    events_root: None,
}
2023-01-24T06:20:15.263080Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 2
2023-01-24T06:20:15.263085Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "performanceTester"::London::2
2023-01-24T06:20:15.263087Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmPerformance/performanceTester.json"
2023-01-24T06:20:15.263090Z  INFO evm_eth_compliance::statetest::runner: TX len : 68
2023-01-24T06:20:15.263091Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T06:20:15.263765Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 5820000000000000000000000000000000000000000000000000000000000000000d },
    gas_used: 9202481,
    events_root: None,
}
2023-01-24T06:20:15.263775Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 3
2023-01-24T06:20:15.263778Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "performanceTester"::London::3
2023-01-24T06:20:15.263779Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmPerformance/performanceTester.json"
2023-01-24T06:20:15.263782Z  INFO evm_eth_compliance::statetest::runner: TX len : 68
2023-01-24T06:20:15.263783Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T06:20:15.266390Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 5820000000000000000000000000000000000000000000000000000000000000001d },
    gas_used: 35885099,
    events_root: None,
}
2023-01-24T06:20:15.266399Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 4
2023-01-24T06:20:15.266402Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "performanceTester"::London::4
2023-01-24T06:20:15.266404Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmPerformance/performanceTester.json"
2023-01-24T06:20:15.266406Z  INFO evm_eth_compliance::statetest::runner: TX len : 68
2023-01-24T06:20:15.266408Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T06:20:15.278009Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 5820000000000000000000000000000000000000000000000000000000000000003d },
    gas_used: 152282723,
    events_root: None,
}
2023-01-24T06:20:15.278035Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-24T06:20:15.278042Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "performanceTester"::Merge::0
2023-01-24T06:20:15.278045Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmPerformance/performanceTester.json"
2023-01-24T06:20:15.278048Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-24T06:20:15.278050Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T06:20:15.279305Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 582000000000000000000000000000000000000000000000000000000000000060a7 },
    gas_used: 13855867,
    events_root: None,
}
2023-01-24T06:20:15.279317Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 1
2023-01-24T06:20:15.279321Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "performanceTester"::Merge::1
2023-01-24T06:20:15.279323Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmPerformance/performanceTester.json"
2023-01-24T06:20:15.279329Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-24T06:20:15.279331Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T06:20:15.296996Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 582000000000000000000000000000000000000000000000000000000000000060a7 },
    gas_used: 203687250,
    events_root: None,
}
2023-01-24T06:20:15.297024Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 2
2023-01-24T06:20:15.297031Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "performanceTester"::Merge::2
2023-01-24T06:20:15.297034Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmPerformance/performanceTester.json"
2023-01-24T06:20:15.297038Z  INFO evm_eth_compliance::statetest::runner: TX len : 68
2023-01-24T06:20:15.297039Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T06:20:15.297770Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 5820000000000000000000000000000000000000000000000000000000000000000d },
    gas_used: 9202481,
    events_root: None,
}
2023-01-24T06:20:15.297780Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 3
2023-01-24T06:20:15.297783Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "performanceTester"::Merge::3
2023-01-24T06:20:15.297785Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmPerformance/performanceTester.json"
2023-01-24T06:20:15.297787Z  INFO evm_eth_compliance::statetest::runner: TX len : 68
2023-01-24T06:20:15.297789Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T06:20:15.300410Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 5820000000000000000000000000000000000000000000000000000000000000001d },
    gas_used: 35885099,
    events_root: None,
}
2023-01-24T06:20:15.300421Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 4
2023-01-24T06:20:15.300424Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "performanceTester"::Merge::4
2023-01-24T06:20:15.300426Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmPerformance/performanceTester.json"
2023-01-24T06:20:15.300428Z  INFO evm_eth_compliance::statetest::runner: TX len : 68
2023-01-24T06:20:15.300430Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T06:20:15.313172Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 5820000000000000000000000000000000000000000000000000000000000000003d },
    gas_used: 152282723,
    events_root: None,
}
2023-01-24T06:20:15.315559Z TRACE evm_eth_compliance::statetest::runner: TestDone => "test-vectors/tests/GeneralStateTests/VMTests/vmPerformance/performanceTester.json"
2023-01-24T06:20:15.315756Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 3 Files in Time:43.379154139s
```