# elicitation-requester-v1 vectors

Pinned requester-side vectors for consent cards, the `elicitation.*`
operations Prefrontal core (the `prefrontal-core` module, which delivers
cards to the user's phone) serves to Plexus. Copied byte for byte from the
Prefrontal repository's `test-vectors/elicitation-requester-v1/` directory. They live here
because CI checks out only this repository.

`ALF` in the copied scenario is a placeholder name for the requesting head session.

- Source: the Prefrontal repository's `main` branch at commit
  `0862c4977602eab9ba50fd5e84658843c7fb2b69` ("pin requester elicitation
  dispatch vectors"), the last commit to touch that directory, taken with
  `git show origin/main:test-vectors/elicitation-requester-v1/<file>`.
- Prefrontal's own README for the directory is kept, unchanged, as
  `UPSTREAM-README.md`, so this file can describe the copy. It is the contract:
  field rules, refusal codes, ownership and the answer feed are specified
  there. The sha256 of every JSON file below matches the table in that README.
- Do not edit the files to fit Plexus. When Prefrontal changes the vectors,
  re-copy the directory and update this table.

| File | sha256 | git blob |
| --- | --- | --- |
| `UPSTREAM-README.md` (upstream `README.md`) | `99c269e20ada05ad11e1029af103425767c03b265eeeb050bf2677092ee12583` | `7044c2e3e9be4938a034ab03dad5c48e83b67cf3` |
| `ack.json` | `2789814b9037489fafce97cd0be9d2e6e40299eac1ecb37c5363458ebda9f5aa` | `fd0bef6b59697080e0c79128755c57a77c95d7b1` |
| `answers.json` | `5a4e7892a2da111a63958e62a9ca03531c0d218bc5b0fa8e4625c74705357ba2` | `e067be43e32d4804856c4a30ab301286e01ec0f8` |
| `await.json` | `e3fd0d1bf64f61be4e33096fc6112abe9bdadf193ff85343b4b0a3f1b1fd44d4` | `70bce5293d39743bf74bded1d78421109feb7b05` |
| `elicitation_fail_closed_required.json` | `2818bdafbe85521911fd006097b347fd5a5ba05bdfa34a2598a50e728dd3bc53` | `ab39286d109d63652a988588b236db40008bcb35` |
| `elicitation_invalid_execution.json` | `1240f138b3b1339d8c99e78f065c4669d88cd3122eb7bd8f90a0630f60869d6d` | `36c4b69a508fb0cbe30bb236558fd352e111769b` |
| `elicitation_invalid_request.json` | `4ee52473c88d04e685a71d7f6fcaef9328d2d6aef15a37500bd15d7caba62a3e` | `b9698de976d73a75acc6e968ae0f17545f66118c` |
| `elicitation_not_found.json` | `550e8eb22261f49a6373843b7a56c6159cd4e19d47bb06170b685438ada763be` | `e6c5b85c82e1f7ac804350aae92818ca7a98b92a` |
| `elicitation_not_owner.json` | `d0d43da0661964c1dc4578bd355abf26d31b88cd194b64cac9e79a30367c8840` | `810a431663ba166cb0d4d9941d1673eb69f22c67` |
| `elicitation_operator_required.json` | `51c80a3ab123b97d90c70c50d3d2bfc5599b9028aea9d873496c88d5b067c5dc` | `279138586331ecc96ceb9c990d1679178917b53d` |
| `elicitation_requester_refused.json` | `d90ee27cb662aab11575e977a20fab451c5060c1d9c02ada2bdb8a0e0f744666` | `74d015f4521460fdbca997c532a0731dbce2f88e` |
| `elicitation_store_error.json` | `3d7fae6f594b5a16d2a10850d0d91afe4033e3b2a5101fc81e3b3a2db3e47559` | `45c659b6fc217686aebb42ef6c67b7ed0c35cadf` |
| `elicitation_unavailable.json` | `f6924b8cc0e6a371765121d7c690f95ba8af0750792672383064c3cd658f1b81` | `4c44697259581cd420b6c08271ddfb6aa35152cd` |
| `elicitation_unknown_kind.json` | `088db23b455d48c69e38e042806b24a9c4f0db54b9fd6ca59d46a4ec417c9369` | `81a46d8838c113d466912e695ba89739ee67bef8` |
| `get.json` | `9c8f795cb845c39d64479d1dd4f5d18b058d3ba2257d377c526ad81387c5e48a` | `57f2eddcf522eb2df015d5c3b0717860efd80e0e` |
| `report_execution.json` | `d0888b61420fdddac065894a16cf02c03f8af94cd1cf1002896087d156b7480a` | `2b11dc37ff88b88ee40dcd279626e1f6c4e3be02` |
| `request.json` | `5e70f4126929e8d130e945771e083dee15e8132ad45528ca617ff62cdf176a49` | `1359e77a2aef7ba6fa842ee310c4f97d57d42b30` |
| `withdraw.json` | `65adbbb9a7b1c07576dc3bedc79125e20fd7c39ab260d73f239049208da5bbee` | `3adcff466bc9dfa52de72e50fd4c0c9098141c4b` |

## How the tests use them

`tests/elicitation_requester.rs` reads every file here:

1. It recomputes each file's sha256 and compares it with both this table and
   the table in `UPSTREAM-README.md`, so a hand edit to a vector fails.
2. It checks the `elicitation.request` body Plexus builds for a parked
   approval against `request.json`: every key Plexus sends is a field the
   vectors define, every field `request.json` requires is present with the
   same JSON type, and the nested option, target and preview objects carry no
   field the contract does not name.
3. It runs the scenario the upstream README describes against the in-process
   fake of Prefrontal core the Plexus tests drive, and compares each reply
   and each refusal code with the vector, so the fake answers the way the
   pinned dispatch does. The `@…@` placeholders are replaced with the values
   the fake minted before comparing.
