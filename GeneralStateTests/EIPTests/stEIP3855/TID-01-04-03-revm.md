
> Executed Command

```
clear && \
	RUST_LOG=revme=trace \
	cargo run --release -p revme \
	-- \
	statetest \
	-s ./bins/revme/tests/GeneralStateTests/EIPTests/stEIP3855/mod-push0.json
```

> Execution Trace

```
2023-02-16T10:24:53.035434Z  INFO revme::statetest::cmd: Start running tests on: "./bins/revme/tests/GeneralStateTests/EIPTests/stEIP3855/mod-push0.json"
2023-02-16T10:24:53.035689Z DEBUG revme::statetest::runner: Pre Processing => "push0"
2023-02-16T10:24:53.035741Z DEBUG revme::statetest::runner: Executing Spec => Merge
2023-02-16T10:24:53.035786Z  INFO revme::statetest::runner: exit_reason::[Stop], gas_used::[148031], gas_refunded::[0], logs::[[]]
2023-02-16T10:24:53.035790Z  INFO revme::statetest::merkle_trie: State info for => "b94f5374fce5edbc8e2a8697c15331677e6ebf0b"
2023-02-16T10:24:53.035793Z  INFO revme::statetest::merkle_trie: nonce :: 0
2023-02-16T10:24:53.035795Z  INFO revme::statetest::merkle_trie: balance :: 0x0000000000000000000000000000000000000000000000000000000000000000_U256
2023-02-16T10:24:53.035798Z  INFO revme::statetest::merkle_trie: (
    0x0000000000000000000000000000000000000000000000000000000000000001,
    b"\x01",
)
2023-02-16T10:24:53.035806Z  INFO revme::statetest::merkle_trie: bytecode_hash.0 :: af75e120bc9b2b813d81494fcb57703dcd277a3dab4cefbfb6e8188c8c101d6b
2023-02-16T10:24:53.035808Z  INFO revme::statetest::merkle_trie: State info for => "a94f5374fce5edbc8e2a8697c15331677e6ebf0b"
2023-02-16T10:24:53.035810Z  INFO revme::statetest::merkle_trie: nonce :: 1
2023-02-16T10:24:53.035811Z  INFO revme::statetest::merkle_trie: balance :: 0x00000000000000000000000000000000000000000000000000000fffffe9698a_U256
2023-02-16T10:24:53.035814Z  INFO revme::statetest::merkle_trie: bytecode_hash.0 :: c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470
2023-02-16T10:24:53.035816Z  INFO revme::statetest::merkle_trie: State info for => "0000000000000000000000000000000000000100"
2023-02-16T10:24:53.035817Z  INFO revme::statetest::merkle_trie: nonce :: 0
2023-02-16T10:24:53.035818Z  INFO revme::statetest::merkle_trie: balance :: 0x0000000000000000000000000000000000000000000000000000000000000000_U256
2023-02-16T10:24:53.035821Z  INFO revme::statetest::merkle_trie: bytecode_hash.0 :: 0125401e1ab3861d0d9dd8099943b70a1fd558be51c551394387321c48cf5d97
2023-02-16T10:24:53.035822Z  INFO revme::statetest::merkle_trie: State info for => "0000000000000000000000000000000000000200"
2023-02-16T10:24:53.035824Z  INFO revme::statetest::merkle_trie: nonce :: 0
2023-02-16T10:24:53.035825Z  INFO revme::statetest::merkle_trie: balance :: 0x0000000000000000000000000000000000000000000000000000000000000000_U256
2023-02-16T10:24:53.035828Z  INFO revme::statetest::merkle_trie: bytecode_hash.0 :: a44ddbe3846599b1b2ca0594fb0cb0c2d6d63b877ce5ddb234339190f6535058
2023-02-16T10:24:53.035830Z  INFO revme::statetest::merkle_trie: State info for => "0000000000000000000000000000000000000500"
2023-02-16T10:24:53.035832Z  INFO revme::statetest::merkle_trie: nonce :: 0
2023-02-16T10:24:53.035834Z  INFO revme::statetest::merkle_trie: balance :: 0x0000000000000000000000000000000000000000000000000000000000000000_U256
2023-02-16T10:24:53.035836Z  INFO revme::statetest::merkle_trie: bytecode_hash.0 :: edcea87ee48aa9a04c103b5b3c70ed9ff9fe2588bd460852de66d194439bd683
2023-02-16T10:24:53.035838Z  INFO revme::statetest::merkle_trie: State info for => "0000000000000000000000000000000000000700"
2023-02-16T10:24:53.035840Z  INFO revme::statetest::merkle_trie: nonce :: 0
2023-02-16T10:24:53.035841Z  INFO revme::statetest::merkle_trie: balance :: 0x0000000000000000000000000000000000000000000000000000000000000000_U256
2023-02-16T10:24:53.035843Z  INFO revme::statetest::merkle_trie: bytecode_hash.0 :: 29c955fec03398c668c9f67fcd2c1d24e301c426a12737ce10c33113443a8410
2023-02-16T10:24:53.035845Z  INFO revme::statetest::merkle_trie: State info for => "0000000000000000000000000000000000000600"
2023-02-16T10:24:53.035846Z  INFO revme::statetest::merkle_trie: nonce :: 0
2023-02-16T10:24:53.035847Z  INFO revme::statetest::merkle_trie: balance :: 0x0000000000000000000000000000000000000000000000000000000000000000_U256
2023-02-16T10:24:53.035851Z  INFO revme::statetest::merkle_trie: bytecode_hash.0 :: fd9bdc48c415ec6f74ded272c8758e673376fc007812223384f6eea1588dab60
2023-02-16T10:24:53.035853Z  INFO revme::statetest::merkle_trie: State info for => "0000000000000000000000000000000000000300"
2023-02-16T10:24:53.035854Z  INFO revme::statetest::merkle_trie: nonce :: 0
2023-02-16T10:24:53.035857Z  INFO revme::statetest::merkle_trie: balance :: 0x0000000000000000000000000000000000000000000000000000000000000000_U256
2023-02-16T10:24:53.035859Z  INFO revme::statetest::merkle_trie: bytecode_hash.0 :: cc61b581b699b895ad2557e2aa9578bcf05d163d6c03a900a38e312bdfc2f79b
2023-02-16T10:24:53.035860Z  INFO revme::statetest::merkle_trie: State info for => "0000000000000000000000000000000000000400"
2023-02-16T10:24:53.035862Z  INFO revme::statetest::merkle_trie: nonce :: 0
2023-02-16T10:24:53.035864Z  INFO revme::statetest::merkle_trie: balance :: 0x0000000000000000000000000000000000000000000000000000000000000000_U256
2023-02-16T10:24:53.035866Z  INFO revme::statetest::merkle_trie: (
    0x0000000000000000000000000000000000000000000000000000000000000001,
    b"\n",
)
2023-02-16T10:24:53.035869Z  INFO revme::statetest::merkle_trie: (
    0x0000000000000000000000000000000000000000000000000000000000000000,
    b"\n",
)
2023-02-16T10:24:53.035877Z  INFO revme::statetest::merkle_trie: bytecode_hash.0 :: 48191a2b9cc0ce9f46786b06bc6b47348b83d5e37b8bde367268384d07df718b
2023-02-16T10:24:53.035895Z  INFO revme::statetest::runner: Post Hash Check ::
2023-02-16T10:24:53.035897Z  INFO revme::statetest::runner: Calc :: 0x84893d9a4161a9cf913c9c53a1827b7a3abfa2f0b57216e605b7cb87f527ae72
2023-02-16T10:24:53.035899Z  INFO revme::statetest::runner: Actual :: 0x84893d9a4161a9cf913c9c53a1827b7a3abfa2f0b57216e605b7cb87f527ae72
2023-02-16T10:24:53.035903Z DEBUG revme::statetest::runner: TestDone => 0/"./bins/revme/tests/GeneralStateTests/EIPTests/stEIP3855/mod-push0.json"
2023-02-16T10:24:53.035926Z  WARN revme::statetest::runner: Processing 1/1
Finished execution. Time:43.241s
```