> Status

| Status | Context |
| --- | --- |
| OK | under WASM RT context |
| OK | under native RT context |

> Test Suite

https://github.com/ethereum/tests/blob/develop/GeneralStateTests/EIPTests/stEIP3855/push0Gas.json#L1

> Command to execute

```
clear && \
	RUST_LOG=evm_eth_compliance=trace \
	VECTOR=test-vectors/tests/GeneralStateTests/EIPTests/stEIP3855/push0Gas.json \
	cargo run \
	-- \
	statetest
```

> Execution Trace

```
2023-01-20T06:12:09.893961Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "test-vectors/tests/GeneralStateTests/EIPTests/stEIP3855/push0.json", Total Files :: 1
2023-01-20T06:12:09.894429Z TRACE evm_eth_compliance::statetest::runner: Calling testfile => "test-vectors/tests/GeneralStateTests/EIPTests/stEIP3855/push0.json"
2023-01-20T06:12:10.006117Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([179, 152, 63, 197, 60, 234, 37, 74, 66, 53, 75, 140, 66, 70, 3, 8, 241, 171, 25, 86]) }
[DEBUG] getting cid: bafy2bzaceaii7gatq5yoovv5j5rn5hvbvdukafhmhnjm36ur627u6hyo6dame
[DEBUG] fetching parameters block: 1
2023-01-20T06:12:22.227040Z  INFO evm_eth_compliance::statetest::runner: Dummy Place Holder Contract got deployed with Actor ID [200]
2023-01-20T06:12:22.227230Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-20T06:12:22.227313Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([157, 122, 181, 47, 53, 176, 191, 159, 121, 68, 73, 204, 112, 124, 226, 155, 100, 141, 75, 36]) }
[DEBUG] getting cid: bafy2bzaceakolkw3lbrubtfreszqhtnie34izgdksjuu77tsfape7abhsipqa
[DEBUG] fetching parameters block: 1
2023-01-20T06:12:22.230413Z  INFO evm_eth_compliance::statetest::runner: Dummy Place Holder Contract got deployed with Actor ID [201]
2023-01-20T06:12:22.230968Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-20T06:12:22.231013Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 2
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([135, 86, 195, 226, 17, 192, 42, 192, 25, 213, 136, 254, 18, 95, 50, 68, 155, 121, 209, 130]) }
[DEBUG] getting cid: bafy2bzacec36lb7pzasfrw4z7i6wvwy235ozsnsawxumlomkaqoxrktzvinvu
[DEBUG] fetching parameters block: 1
2023-01-20T06:12:22.234394Z  INFO evm_eth_compliance::statetest::runner: Dummy Place Holder Contract got deployed with Actor ID [202]
2023-01-20T06:12:22.234825Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-20T06:12:22.234889Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 3
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([121, 46, 44, 168, 100, 157, 195, 57, 208, 185, 119, 244, 82, 48, 8, 55, 203, 168, 19, 62]) }
[DEBUG] getting cid: bafy2bzaceapl65654fgmpywqxmwem5inilkyqnmf53hrrao3abqhyblg5iuyu
[DEBUG] fetching parameters block: 1
2023-01-20T06:12:22.239077Z  INFO evm_eth_compliance::statetest::runner: Dummy Place Holder Contract got deployed with Actor ID [203]
2023-01-20T06:12:22.239267Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-20T06:12:22.239339Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 4
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 5, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([102, 145, 95, 210, 114, 99, 97, 196, 103, 113, 159, 135, 176, 147, 142, 56, 188, 98, 191, 170]) }
[DEBUG] getting cid: bafy2bzacediguvgnv5kgug6cbm4em4fwy56qf44k4bc7aeki3s3juoz62vk7m
[DEBUG] fetching parameters block: 1
2023-01-20T06:12:22.243292Z  INFO evm_eth_compliance::statetest::runner: Dummy Place Holder Contract got deployed with Actor ID [204]
2023-01-20T06:12:22.243486Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-20T06:12:22.243547Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 5
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 6, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([8, 220, 70, 60, 95, 134, 230, 77, 167, 148, 57, 129, 203, 169, 16, 22, 114, 213, 117, 83]) }
[DEBUG] getting cid: bafy2bzacedcqnbuzcfyalkots22ayhjov5ap73tlijxexqnb34aes6kvchnxg
[DEBUG] fetching parameters block: 1
2023-01-20T06:12:22.247362Z  INFO evm_eth_compliance::statetest::runner: Dummy Place Holder Contract got deployed with Actor ID [205]
2023-01-20T06:12:22.247557Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-20T06:12:22.247615Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 6
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 7, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([110, 106, 165, 99, 30, 211, 65, 233, 221, 242, 20, 186, 213, 63, 121, 136, 142, 179, 54, 182]) }
[DEBUG] getting cid: bafy2bzacedxsayxiqsmsdq2cx3hujjyeopixk3cotmuerzj3d2pypfegvz27m
[DEBUG] fetching parameters block: 1
2023-01-20T06:12:22.250968Z  INFO evm_eth_compliance::statetest::runner: Dummy Place Holder Contract got deployed with Actor ID [206]
2023-01-20T06:12:22.251106Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-20T06:12:22.251153Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 7
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [169, 79, 83, 116, 252, 229, 237, 188, 142, 42, 134, 151, 193, 83, 49, 103, 126, 110, 191, 11, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([96, 5, 158, 185, 170, 5, 126, 190, 213, 91, 244, 103, 65, 236, 58, 54, 23, 90, 163, 232]) }
[DEBUG] getting cid: bafy2bzacea2sgah6q7e2brwszxpmwl3d6wbzft6trt44tbewea56jqavusmjq
[DEBUG] fetching parameters block: 1
2023-01-20T06:12:22.254412Z  INFO evm_eth_compliance::statetest::runner: Dummy Place Holder Contract got deployed with Actor ID [207]
2023-01-20T06:12:22.254552Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-20T06:12:22.254605Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 8
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [185, 79, 83, 116, 252, 229, 237, 188, 142, 42, 134, 151, 193, 83, 49, 103, 126, 110, 191, 11, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([60, 213, 27, 33, 255, 147, 208, 24, 221, 249, 192, 33, 170, 243, 120, 65, 173, 130, 62, 118]) }
[DEBUG] getting cid: bafy2bzaceb7aofshfoao7ty6sbaexby3evlv67h3ro6cdkp4ttj5m7h43pamm
[DEBUG] fetching parameters block: 1
2023-01-20T06:12:22.258318Z  INFO evm_eth_compliance::statetest::runner: Dummy Place Holder Contract got deployed with Actor ID [208]
2023-01-20T06:12:22.258518Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-20T06:12:22.260144Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-20T06:12:22.260236Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "push0"::Merge::0
2023-01-20T06:12:22.260262Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEIP3855/push0.json"
2023-01-20T06:12:22.260281Z  INFO evm_eth_compliance::statetest::runner: TX len : 20
2023-01-20T06:12:22.260298Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-20T06:12:22.261941Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2742670,
    events_root: None,
}
2023-01-20T06:12:22.262001Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 1
2023-01-20T06:12:22.262055Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "push0"::Merge::1
2023-01-20T06:12:22.262072Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEIP3855/push0.json"
2023-01-20T06:12:22.262090Z  INFO evm_eth_compliance::statetest::runner: TX len : 20
2023-01-20T06:12:22.262100Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-20T06:12:22.263356Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1845243,
    events_root: None,
}
2023-01-20T06:12:22.263418Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 2
2023-01-20T06:12:22.263469Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "push0"::Merge::2
2023-01-20T06:12:22.263491Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEIP3855/push0.json"
2023-01-20T06:12:22.263509Z  INFO evm_eth_compliance::statetest::runner: TX len : 20
2023-01-20T06:12:22.263525Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-20T06:12:22.264788Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1845243,
    events_root: None,
}
2023-01-20T06:12:22.264827Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 3
2023-01-20T06:12:22.264867Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "push0"::Merge::3
2023-01-20T06:12:22.264878Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEIP3855/push0.json"
2023-01-20T06:12:22.264889Z  INFO evm_eth_compliance::statetest::runner: TX len : 20
2023-01-20T06:12:22.264897Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-20T06:12:22.266071Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1845243,
    events_root: None,
}
2023-01-20T06:12:22.266108Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 4
2023-01-20T06:12:22.266147Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "push0"::Merge::4
2023-01-20T06:12:22.266157Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEIP3855/push0.json"
2023-01-20T06:12:22.266168Z  INFO evm_eth_compliance::statetest::runner: TX len : 20
2023-01-20T06:12:22.266176Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-20T06:12:22.267242Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1845243,
    events_root: None,
}
2023-01-20T06:12:22.267272Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 5
2023-01-20T06:12:22.267302Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "push0"::Merge::5
2023-01-20T06:12:22.267309Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEIP3855/push0.json"
2023-01-20T06:12:22.267315Z  INFO evm_eth_compliance::statetest::runner: TX len : 20
2023-01-20T06:12:22.267321Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-20T06:12:22.268320Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1845243,
    events_root: None,
}
2023-01-20T06:12:22.268353Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => MergePush0 0
2023-01-20T06:12:22.268384Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "push0"::MergePush0::0
2023-01-20T06:12:22.268391Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEIP3855/push0.json"
2023-01-20T06:12:22.268398Z  INFO evm_eth_compliance::statetest::runner: TX len : 20
2023-01-20T06:12:22.268404Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-20T06:12:22.269146Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1845243,
    events_root: None,
}
2023-01-20T06:12:22.269176Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => MergePush0 1
2023-01-20T06:12:22.269205Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "push0"::MergePush0::1
2023-01-20T06:12:22.269212Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEIP3855/push0.json"
2023-01-20T06:12:22.269221Z  INFO evm_eth_compliance::statetest::runner: TX len : 20
2023-01-20T06:12:22.269226Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-20T06:12:22.269966Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1845243,
    events_root: None,
}
2023-01-20T06:12:22.269994Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => MergePush0 2
2023-01-20T06:12:22.270025Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "push0"::MergePush0::2
2023-01-20T06:12:22.270032Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEIP3855/push0.json"
2023-01-20T06:12:22.270039Z  INFO evm_eth_compliance::statetest::runner: TX len : 20
2023-01-20T06:12:22.270045Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-20T06:12:22.270791Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1845243,
    events_root: None,
}
2023-01-20T06:12:22.270820Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => MergePush0 3
2023-01-20T06:12:22.270850Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "push0"::MergePush0::3
2023-01-20T06:12:22.270857Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEIP3855/push0.json"
2023-01-20T06:12:22.270865Z  INFO evm_eth_compliance::statetest::runner: TX len : 20
2023-01-20T06:12:22.270871Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-20T06:12:22.271621Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1845243,
    events_root: None,
}
2023-01-20T06:12:22.271651Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => MergePush0 4
2023-01-20T06:12:22.271683Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "push0"::MergePush0::4
2023-01-20T06:12:22.271691Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEIP3855/push0.json"
2023-01-20T06:12:22.271699Z  INFO evm_eth_compliance::statetest::runner: TX len : 20
2023-01-20T06:12:22.271706Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-20T06:12:22.272450Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1845243,
    events_root: None,
}
2023-01-20T06:12:22.272478Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => MergePush0 5
2023-01-20T06:12:22.272508Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "push0"::MergePush0::5
2023-01-20T06:12:22.272516Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEIP3855/push0.json"
2023-01-20T06:12:22.272523Z  INFO evm_eth_compliance::statetest::runner: TX len : 20
2023-01-20T06:12:22.272529Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-20T06:12:22.273272Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1845243,
    events_root: None,
}
2023-01-20T06:12:22.275773Z TRACE evm_eth_compliance::statetest::runner: TestDone => "test-vectors/tests/GeneralStateTests/EIPTests/stEIP3855/push0.json"
2023-01-20T06:12:22.276020Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:12.267210183s
```