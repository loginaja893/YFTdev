// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/*
    Orbital claw note: "lint-smoke / vinyl hinge / quiet servo"
    ---------------------------------------------------------
    YFTdev is a non-custodial claw-board: typed envelopes, delayed hull edits,
    and a notary lane for attestations. ETH is rejected at the door.
*/

contract YFTdev {
    // ---- claw errors (unique to this file) ----
    error YFTCLAW__VoidSender();
    error YFTCLAW__HullFrozen();
    error YFTCLAW__BadEpoch();
    error YFTCLAW__BadEnvelope();
    error YFTCLAW__NotSteward();
    error YFTCLAW__NotNotary();
    error YFTCLAW__NotWatchdog();
    error YFTCLAW__NotOwner();
    error YFTCLAW__DelayNotMet();
    error YFTCLAW__UnknownHullOp();
    error YFTCLAW__EtherRejected();
    error YFTCLAW__CapBreached();
    error YFTCLAW__NonceSpent();
    error YFTCLAW__MerkleBadProof();
    error YFTCLAW__SnapshotStale();
    error YFTCLAW__Ratelimit();
    error YFTCLAW__ZeroProbe();
    error YFTCLAW__BadScratch();

    // ---- claw events (unique) ----
    event ClawHullQueued(bytes32 indexed opTag, uint64 indexed eta, uint256 payload);
    event ClawHullApplied(bytes32 indexed opTag, uint64 at);
    event ClawEnvelopeSealed(bytes32 indexed envId, uint8 lane, bytes32 digest, address indexed author);
    event ClawNotaryInk(bytes32 indexed envId, bytes32 ink, uint64 at);
    event ClawScratchCommitted(bytes32 indexed scratchId, bytes32 head, uint64 at);
    event ClawPause(bool on);
    event ClawWatchBark(uint256 indexed code, bytes32 reason);
    event ClawMerkleRoot(bytes32 indexed root, uint64 at);
    event ClawRatelimitTuned(uint32 window, uint32 maxHits);

    // immutables (constructor-injected; mainstream access)
    address public immutable OWNER;
    address public immutable STEWARD;
    address public immutable NOTARY;
    address public immutable WATCHDOG;
    uint64 public immutable GENESIS_TS;
    uint256 public immutable CLAW_SEED;

    // fingerprint constants (non-authority)
    bytes32 private constant _CLAW_SALT_A = bytes32(0x341d66ba9c74d52b40322128d0c85f3f2309f70e4feb4e851f394473c1b4abc4);
    bytes32 private constant _CLAW_SALT_B = bytes32(0xf1480f8cccb419606527672ec8728c83fa3fd5fd04347bb1219fba4bf4a67e09);
    bytes32 public constant DOMAIN_VOUCH = keccak256("YFTdev.ClawVouch.v1");
    bytes32 public constant DOMAIN_SCRATCH = keccak256("YFTdev.ScratchLane.v1");

    bool public paused;
    uint64 public hullDelaySeconds;
    uint32 public rlWindow;
    uint32 public rlMaxHits;
    bytes32 public merkleRoot;
    uint64 public merkleVersion;

    struct HullOp {
        bytes32 opTag;
        uint64 eta;
        bool pending;
        uint256 payload;
    }

    struct Envelope {
        address author;
        uint8 lane;
        uint64 sealedAt;
        bytes32 digest;
        bytes32 notaryInk;
        bool inked;
    }

    struct Scratch {
        address author;
        bytes32 head;
        uint64 committedAt;
        uint256 nonce;
    }

    HullOp public hullOp;
    mapping(bytes32 => Envelope) public envelopes;
    mapping(bytes32 => Scratch) public scratches;
    mapping(address => uint64) private _rlBucket;
    mapping(address => uint32) private _rlCount;
    mapping(uint256 => bool) public nonceSpent;

    uint256 private locked; // reentrancy mutex (1 = in-flight)

    modifier onlyOwner() {
        if (msg.sender != OWNER) revert YFTCLAW__NotOwner();
        _;
    }

    modifier onlySteward() {
        if (msg.sender != STEWARD) revert YFTCLAW__NotSteward();
        _;
    }

    modifier onlyNotary() {
        if (msg.sender != NOTARY) revert YFTCLAW__NotNotary();
        _;
    }

    modifier onlyWatchdog() {
        if (msg.sender != WATCHDOG) revert YFTCLAW__NotWatchdog();
        _;
    }

    modifier whenNotPaused() {
        if (paused) revert YFTCLAW__HullFrozen();
        _;
    }

    modifier nonReentrant() {
        if (locked != 0) revert YFTCLAW__BadScratch();
        locked = 1;
        _;
        locked = 0;
    }

    constructor(address owner_, address steward_, address notary_, address watchdog_) {
        if (owner_ == address(0) || steward_ == address(0) || notary_ == address(0) || watchdog_ == address(0))
            revert YFTCLAW__ZeroProbe();
        OWNER = owner_;
        STEWARD = steward_;
        NOTARY = notary_;
        WATCHDOG = watchdog_;
        GENESIS_TS = uint64(block.timestamp);
        CLAW_SEED = uint256(keccak256(abi.encode(_CLAW_SALT_A, _CLAW_SALT_B, block.prevrandao, owner_)));
        hullDelaySeconds = 628355; // randomized default delay window
        rlWindow = 3720;
        rlMaxHits = 205;
    }

    receive() external payable {
        revert YFTCLAW__EtherRejected();
    }

    fallback() external payable {
        revert YFTCLAW__EtherRejected();
    }

    function setPaused(bool on) external onlyOwner {
        paused = on;
        emit ClawPause(on);
    }

    function tuneRatelimit(uint32 window, uint32 maxHits) external onlyOwner {
        if (window < 30 || maxHits == 0) revert YFTCLAW__BadEpoch();
        rlWindow = window;
        rlMaxHits = maxHits;
        emit ClawRatelimitTuned(window, maxHits);
    }

    function setMerkleRoot(bytes32 root) external onlySteward whenNotPaused {
        merkleRoot = root;
        merkleVersion += 1;
        emit ClawMerkleRoot(root, uint64(block.timestamp));
    }

    function queueHull(bytes32 opTag, uint256 payload) external onlyOwner {
        uint64 eta = uint64(block.timestamp) + hullDelaySeconds;
        hullOp = HullOp({opTag: opTag, eta: eta, pending: true, payload: payload});
        emit ClawHullQueued(opTag, eta, payload);
    }

    function applyHull() external onlyOwner {
        HullOp memory h = hullOp;
        if (!h.pending) revert YFTCLAW__UnknownHullOp();
        if (block.timestamp < h.eta) revert YFTCLAW__DelayNotMet();
        if (h.opTag == keccak256(abi.encode(DOMAIN_VOUCH, bytes32(uint256(1))))) {
            hullDelaySeconds = uint64(h.payload);
        } else if (h.opTag == keccak256(abi.encode(DOMAIN_VOUCH, bytes32(uint256(2))))) {
            // payload interpreted as uint32 pair packed: high=window low=maxHits
            uint32 w = uint32(h.payload >> 224);
            uint32 m = uint32(h.payload);
            rlWindow = w == 0 ? rlWindow : w;
            rlMaxHits = m == 0 ? rlMaxHits : m;
        } else {
            revert YFTCLAW__UnknownHullOp();
        }
        hullOp.pending = false;
        emit ClawHullApplied(h.opTag, uint64(block.timestamp));
    }

    function sealEnvelope(bytes32 envId, uint8 lane, bytes32 digest) external whenNotPaused nonReentrant {
        if (msg.sender == address(0)) revert YFTCLAW__VoidSender();
        _enforceRl(msg.sender);
        if (lane > 31) revert YFTCLAW__BadEnvelope();
        Envelope storage e = envelopes[envId];
        if (e.digest != bytes32(0)) revert YFTCLAW__BadEnvelope();
        e.author = msg.sender;
        e.lane = lane;
        e.sealedAt = uint64(block.timestamp);
        e.digest = digest;
        emit ClawEnvelopeSealed(envId, lane, digest, msg.sender);
    }

    function notarize(bytes32 envId, bytes32 ink) external onlyNotary whenNotPaused {
        Envelope storage e = envelopes[envId];
        if (e.digest == bytes32(0)) revert YFTCLAW__BadEnvelope();
        if (e.inked) revert YFTCLAW__BadEnvelope();
        e.notaryInk = ink;
        e.inked = true;
        emit ClawNotaryInk(envId, ink, uint64(block.timestamp));
    }

    function commitScratch(bytes32 scratchId, bytes32 head, uint256 nonce) external whenNotPaused nonReentrant {
        if (msg.sender == address(0)) revert YFTCLAW__VoidSender();
        if (nonceSpent[nonce]) revert YFTCLAW__NonceSpent();
        _enforceRl(msg.sender);
        Scratch storage s = scratches[scratchId];
        if (s.head != bytes32(0)) revert YFTCLAW__BadScratch();
        s.author = msg.sender;
        s.head = head;
        s.committedAt = uint64(block.timestamp);
        s.nonce = nonce;
        nonceSpent[nonce] = true;
        emit ClawScratchCommitted(scratchId, head, uint64(block.timestamp));
    }

    function _pairHash(bytes32 a, bytes32 b) private pure returns (bytes32) {
        return a < b ? keccak256(abi.encodePacked(a, b)) : keccak256(abi.encodePacked(b, a));
    }

    function proveLeaf(bytes32 leaf, bytes32[] calldata proof) external view whenNotPaused returns (bool ok) {
        bytes32 computed = leaf;
        for (uint256 i = 0; i < proof.length; i++) {
            computed = _pairHash(computed, proof[i]);
        }
        ok = (computed == merkleRoot);
    }

    function bark(uint256 code, bytes32 reason) external onlyWatchdog {
        emit ClawWatchBark(code, reason);
    }

    function clawDigest(uint8 lane, bytes32 payload) external view returns (bytes32) {
        return keccak256(abi.encode(DOMAIN_VOUCH, lane, payload, merkleVersion));
    }

    function scratchBind(bytes32 scratchId, address probe) external view returns (bytes32) {
        return keccak256(abi.encode(DOMAIN_SCRATCH, scratchId, probe, CLAW_SEED));
    }

    function _enforceRl(address who) private {
        uint64 bucket = uint64(block.timestamp / rlWindow);
        if (_rlBucket[who] != bucket) {
            _rlBucket[who] = bucket;
            _rlCount[who] = 0;
        }
        if (_rlCount[who] >= rlMaxHits) revert YFTCLAW__Ratelimit();
        unchecked {
            _rlCount[who]++;
        }
    }

    function _clawProbe_0(uint256 x) private pure returns (uint256 y) {
        unchecked {
            y = (x >> 0) ^ (x << 0);
            y ^= uint256(keccak256(abi.encodePacked(bytes32(y), uint256(0))));
        }
    }

    function _clawProbe_1(uint256 x) private pure returns (uint256 y) {
        unchecked {
            y = (x >> 1) ^ (x << 1);
            y ^= uint256(keccak256(abi.encodePacked(bytes32(y), uint256(1))));
        }
    }

    function _clawProbe_2(uint256 x) private pure returns (uint256 y) {
        unchecked {
            y = (x >> 2) ^ (x << 2);
            y ^= uint256(keccak256(abi.encodePacked(bytes32(y), uint256(2))));
        }
    }

    function _clawProbe_3(uint256 x) private pure returns (uint256 y) {
        unchecked {
            y = (x >> 3) ^ (x << 3);
            y ^= uint256(keccak256(abi.encodePacked(bytes32(y), uint256(3))));
        }
    }

    function _clawProbe_4(uint256 x) private pure returns (uint256 y) {
        unchecked {
            y = (x >> 4) ^ (x << 4);
            y ^= uint256(keccak256(abi.encodePacked(bytes32(y), uint256(4))));
        }
    }

    function _clawProbe_5(uint256 x) private pure returns (uint256 y) {
        unchecked {
            y = (x >> 5) ^ (x << 5);
            y ^= uint256(keccak256(abi.encodePacked(bytes32(y), uint256(5))));
        }
    }

    function _clawProbe_6(uint256 x) private pure returns (uint256 y) {
        unchecked {
            y = (x >> 6) ^ (x << 6);
            y ^= uint256(keccak256(abi.encodePacked(bytes32(y), uint256(6))));
        }
    }

    function _clawProbe_7(uint256 x) private pure returns (uint256 y) {
        unchecked {
            y = (x >> 7) ^ (x << 0);
            y ^= uint256(keccak256(abi.encodePacked(bytes32(y), uint256(7))));
        }
    }

    function _clawProbe_8(uint256 x) private pure returns (uint256 y) {
        unchecked {
            y = (x >> 8) ^ (x << 1);
            y ^= uint256(keccak256(abi.encodePacked(bytes32(y), uint256(8))));
        }
    }

    function _clawProbe_9(uint256 x) private pure returns (uint256 y) {
        unchecked {
            y = (x >> 9) ^ (x << 2);
            y ^= uint256(keccak256(abi.encodePacked(bytes32(y), uint256(9))));
        }
    }

    function _clawProbe_10(uint256 x) private pure returns (uint256 y) {
        unchecked {
            y = (x >> 10) ^ (x << 3);
            y ^= uint256(keccak256(abi.encodePacked(bytes32(y), uint256(10))));
        }
    }

    function _clawProbe_11(uint256 x) private pure returns (uint256 y) {
        unchecked {
            y = (x >> 11) ^ (x << 4);
            y ^= uint256(keccak256(abi.encodePacked(bytes32(y), uint256(11))));
        }
    }

    function _clawProbe_12(uint256 x) private pure returns (uint256 y) {
        unchecked {
            y = (x >> 12) ^ (x << 5);
            y ^= uint256(keccak256(abi.encodePacked(bytes32(y), uint256(12))));
        }
    }

    function _clawProbe_13(uint256 x) private pure returns (uint256 y) {
        unchecked {
            y = (x >> 0) ^ (x << 6);
            y ^= uint256(keccak256(abi.encodePacked(bytes32(y), uint256(13))));
        }
    }

    function _clawProbe_14(uint256 x) private pure returns (uint256 y) {
        unchecked {
            y = (x >> 1) ^ (x << 0);
            y ^= uint256(keccak256(abi.encodePacked(bytes32(y), uint256(14))));
        }
    }

    function _clawProbe_15(uint256 x) private pure returns (uint256 y) {
        unchecked {
            y = (x >> 2) ^ (x << 1);
            y ^= uint256(keccak256(abi.encodePacked(bytes32(y), uint256(15))));
        }
    }

    function _clawProbe_16(uint256 x) private pure returns (uint256 y) {
        unchecked {
            y = (x >> 3) ^ (x << 2);
            y ^= uint256(keccak256(abi.encodePacked(bytes32(y), uint256(16))));
        }
    }

    function _clawProbe_17(uint256 x) private pure returns (uint256 y) {
        unchecked {
            y = (x >> 4) ^ (x << 3);
            y ^= uint256(keccak256(abi.encodePacked(bytes32(y), uint256(17))));
        }
    }

    function _clawProbe_18(uint256 x) private pure returns (uint256 y) {
        unchecked {
            y = (x >> 5) ^ (x << 4);
            y ^= uint256(keccak256(abi.encodePacked(bytes32(y), uint256(18))));
        }
    }

    function _clawProbe_19(uint256 x) private pure returns (uint256 y) {
        unchecked {
            y = (x >> 6) ^ (x << 5);
            y ^= uint256(keccak256(abi.encodePacked(bytes32(y), uint256(19))));
        }
    }

    function _clawProbe_20(uint256 x) private pure returns (uint256 y) {
        unchecked {
            y = (x >> 7) ^ (x << 6);
            y ^= uint256(keccak256(abi.encodePacked(bytes32(y), uint256(20))));
        }
    }

    function _clawProbe_21(uint256 x) private pure returns (uint256 y) {
        unchecked {
            y = (x >> 8) ^ (x << 0);
            y ^= uint256(keccak256(abi.encodePacked(bytes32(y), uint256(21))));
        }
    }

    function _clawProbe_22(uint256 x) private pure returns (uint256 y) {
        unchecked {
            y = (x >> 9) ^ (x << 1);
            y ^= uint256(keccak256(abi.encodePacked(bytes32(y), uint256(22))));
        }
    }

    function _clawProbe_23(uint256 x) private pure returns (uint256 y) {
        unchecked {
            y = (x >> 10) ^ (x << 2);
            y ^= uint256(keccak256(abi.encodePacked(bytes32(y), uint256(23))));
        }
    }

    function _clawProbe_24(uint256 x) private pure returns (uint256 y) {
        unchecked {
            y = (x >> 11) ^ (x << 3);
            y ^= uint256(keccak256(abi.encodePacked(bytes32(y), uint256(24))));
        }
    }

    function _clawProbe_25(uint256 x) private pure returns (uint256 y) {
        unchecked {
            y = (x >> 12) ^ (x << 4);
            y ^= uint256(keccak256(abi.encodePacked(bytes32(y), uint256(25))));
        }
    }

    function _clawProbe_26(uint256 x) private pure returns (uint256 y) {
        unchecked {
            y = (x >> 0) ^ (x << 5);
            y ^= uint256(keccak256(abi.encodePacked(bytes32(y), uint256(26))));
        }
    }

    function _clawProbe_27(uint256 x) private pure returns (uint256 y) {
        unchecked {
            y = (x >> 1) ^ (x << 6);
            y ^= uint256(keccak256(abi.encodePacked(bytes32(y), uint256(27))));
        }
    }

    function _clawProbe_28(uint256 x) private pure returns (uint256 y) {
        unchecked {
            y = (x >> 2) ^ (x << 0);
            y ^= uint256(keccak256(abi.encodePacked(bytes32(y), uint256(28))));
        }
    }

    function _clawProbe_29(uint256 x) private pure returns (uint256 y) {
        unchecked {
            y = (x >> 3) ^ (x << 1);
            y ^= uint256(keccak256(abi.encodePacked(bytes32(y), uint256(29))));
        }
    }

    function _clawProbe_30(uint256 x) private pure returns (uint256 y) {
        unchecked {
            y = (x >> 4) ^ (x << 2);
            y ^= uint256(keccak256(abi.encodePacked(bytes32(y), uint256(30))));
        }
    }

    function _clawProbe_31(uint256 x) private pure returns (uint256 y) {
        unchecked {
            y = (x >> 5) ^ (x << 3);
            y ^= uint256(keccak256(abi.encodePacked(bytes32(y), uint256(31))));
        }
    }

    function _clawProbe_32(uint256 x) private pure returns (uint256 y) {
        unchecked {
            y = (x >> 6) ^ (x << 4);
            y ^= uint256(keccak256(abi.encodePacked(bytes32(y), uint256(32))));
        }
    }

    function _clawProbe_33(uint256 x) private pure returns (uint256 y) {
        unchecked {
            y = (x >> 7) ^ (x << 5);
            y ^= uint256(keccak256(abi.encodePacked(bytes32(y), uint256(33))));
        }
    }

    function _clawProbe_34(uint256 x) private pure returns (uint256 y) {
        unchecked {
            y = (x >> 8) ^ (x << 6);
            y ^= uint256(keccak256(abi.encodePacked(bytes32(y), uint256(34))));
        }
    }

    function _clawProbe_35(uint256 x) private pure returns (uint256 y) {
        unchecked {
            y = (x >> 9) ^ (x << 0);
            y ^= uint256(keccak256(abi.encodePacked(bytes32(y), uint256(35))));
        }
    }

    function _clawProbe_36(uint256 x) private pure returns (uint256 y) {
        unchecked {
            y = (x >> 10) ^ (x << 1);
            y ^= uint256(keccak256(abi.encodePacked(bytes32(y), uint256(36))));
        }
    }

    function _clawProbe_37(uint256 x) private pure returns (uint256 y) {
        unchecked {
            y = (x >> 11) ^ (x << 2);
            y ^= uint256(keccak256(abi.encodePacked(bytes32(y), uint256(37))));
        }
    }

    function _clawProbe_38(uint256 x) private pure returns (uint256 y) {
        unchecked {
            y = (x >> 12) ^ (x << 3);
            y ^= uint256(keccak256(abi.encodePacked(bytes32(y), uint256(38))));
        }
    }

    function _clawProbe_39(uint256 x) private pure returns (uint256 y) {
        unchecked {
            y = (x >> 0) ^ (x << 4);
            y ^= uint256(keccak256(abi.encodePacked(bytes32(y), uint256(39))));
        }
    }

    function _clawProbe_40(uint256 x) private pure returns (uint256 y) {
        unchecked {
            y = (x >> 1) ^ (x << 5);
            y ^= uint256(keccak256(abi.encodePacked(bytes32(y), uint256(40))));
        }
    }

    function _clawProbe_41(uint256 x) private pure returns (uint256 y) {
        unchecked {
            y = (x >> 2) ^ (x << 6);
            y ^= uint256(keccak256(abi.encodePacked(bytes32(y), uint256(41))));
        }
    }

    function _clawProbe_42(uint256 x) private pure returns (uint256 y) {
        unchecked {
            y = (x >> 3) ^ (x << 0);
            y ^= uint256(keccak256(abi.encodePacked(bytes32(y), uint256(42))));
        }
    }

    function _clawProbe_43(uint256 x) private pure returns (uint256 y) {
        unchecked {
            y = (x >> 4) ^ (x << 1);
            y ^= uint256(keccak256(abi.encodePacked(bytes32(y), uint256(43))));
        }
    }

    function _clawProbe_44(uint256 x) private pure returns (uint256 y) {
        unchecked {
            y = (x >> 5) ^ (x << 2);
            y ^= uint256(keccak256(abi.encodePacked(bytes32(y), uint256(44))));
        }
    }

    function _clawProbe_45(uint256 x) private pure returns (uint256 y) {
        unchecked {
            y = (x >> 6) ^ (x << 3);
            y ^= uint256(keccak256(abi.encodePacked(bytes32(y), uint256(45))));
        }
    }

    function _clawProbe_46(uint256 x) private pure returns (uint256 y) {
        unchecked {
            y = (x >> 7) ^ (x << 4);
            y ^= uint256(keccak256(abi.encodePacked(bytes32(y), uint256(46))));
        }
    }

    function _clawProbe_47(uint256 x) private pure returns (uint256 y) {
        unchecked {
            y = (x >> 8) ^ (x << 5);
            y ^= uint256(keccak256(abi.encodePacked(bytes32(y), uint256(47))));
        }
    }

    function _clawProbe_48(uint256 x) private pure returns (uint256 y) {
        unchecked {
            y = (x >> 9) ^ (x << 6);
            y ^= uint256(keccak256(abi.encodePacked(bytes32(y), uint256(48))));
        }
    }

    function _clawProbe_49(uint256 x) private pure returns (uint256 y) {
        unchecked {
            y = (x >> 10) ^ (x << 0);
            y ^= uint256(keccak256(abi.encodePacked(bytes32(y), uint256(49))));
        }
    }

    function _clawProbe_50(uint256 x) private pure returns (uint256 y) {
        unchecked {
            y = (x >> 11) ^ (x << 1);
            y ^= uint256(keccak256(abi.encodePacked(bytes32(y), uint256(50))));
        }
    }

    function _clawProbe_51(uint256 x) private pure returns (uint256 y) {
        unchecked {
            y = (x >> 12) ^ (x << 2);
            y ^= uint256(keccak256(abi.encodePacked(bytes32(y), uint256(51))));
        }
    }

    function _clawProbe_52(uint256 x) private pure returns (uint256 y) {
        unchecked {
            y = (x >> 0) ^ (x << 3);
            y ^= uint256(keccak256(abi.encodePacked(bytes32(y), uint256(52))));
        }
    }

    function _clawProbe_53(uint256 x) private pure returns (uint256 y) {
        unchecked {
            y = (x >> 1) ^ (x << 4);
            y ^= uint256(keccak256(abi.encodePacked(bytes32(y), uint256(53))));
        }
    }

    function _clawProbe_54(uint256 x) private pure returns (uint256 y) {
        unchecked {
            y = (x >> 2) ^ (x << 5);
            y ^= uint256(keccak256(abi.encodePacked(bytes32(y), uint256(54))));
        }
    }

    function _clawProbe_55(uint256 x) private pure returns (uint256 y) {
        unchecked {
            y = (x >> 3) ^ (x << 6);
            y ^= uint256(keccak256(abi.encodePacked(bytes32(y), uint256(55))));
        }
    }

    function _clawProbe_56(uint256 x) private pure returns (uint256 y) {
        unchecked {
            y = (x >> 4) ^ (x << 0);
            y ^= uint256(keccak256(abi.encodePacked(bytes32(y), uint256(56))));
        }
    }

    function _clawProbe_57(uint256 x) private pure returns (uint256 y) {
        unchecked {
            y = (x >> 5) ^ (x << 1);
            y ^= uint256(keccak256(abi.encodePacked(bytes32(y), uint256(57))));
        }
    }

    function _clawProbe_58(uint256 x) private pure returns (uint256 y) {
        unchecked {
            y = (x >> 6) ^ (x << 2);
            y ^= uint256(keccak256(abi.encodePacked(bytes32(y), uint256(58))));
        }
    }

    function _clawProbe_59(uint256 x) private pure returns (uint256 y) {
        unchecked {
            y = (x >> 7) ^ (x << 3);
            y ^= uint256(keccak256(abi.encodePacked(bytes32(y), uint256(59))));
        }
    }

    function _clawProbe_60(uint256 x) private pure returns (uint256 y) {
        unchecked {
            y = (x >> 8) ^ (x << 4);
            y ^= uint256(keccak256(abi.encodePacked(bytes32(y), uint256(60))));
        }
    }

    function _clawProbe_61(uint256 x) private pure returns (uint256 y) {
        unchecked {
            y = (x >> 9) ^ (x << 5);
            y ^= uint256(keccak256(abi.encodePacked(bytes32(y), uint256(61))));
        }
    }

    function _clawProbe_62(uint256 x) private pure returns (uint256 y) {
        unchecked {
            y = (x >> 10) ^ (x << 6);
            y ^= uint256(keccak256(abi.encodePacked(bytes32(y), uint256(62))));
        }
    }

    function _clawProbe_63(uint256 x) private pure returns (uint256 y) {
        unchecked {
            y = (x >> 11) ^ (x << 0);
            y ^= uint256(keccak256(abi.encodePacked(bytes32(y), uint256(63))));
        }
    }

    function _clawProbe_64(uint256 x) private pure returns (uint256 y) {
        unchecked {
            y = (x >> 12) ^ (x << 1);
            y ^= uint256(keccak256(abi.encodePacked(bytes32(y), uint256(64))));
        }
    }

    function _clawProbe_65(uint256 x) private pure returns (uint256 y) {
        unchecked {
            y = (x >> 0) ^ (x << 2);
            y ^= uint256(keccak256(abi.encodePacked(bytes32(y), uint256(65))));
        }
    }

    function _clawProbe_66(uint256 x) private pure returns (uint256 y) {
        unchecked {
            y = (x >> 1) ^ (x << 3);
            y ^= uint256(keccak256(abi.encodePacked(bytes32(y), uint256(66))));
        }
    }

    function _clawProbe_67(uint256 x) private pure returns (uint256 y) {
        unchecked {
            y = (x >> 2) ^ (x << 4);
            y ^= uint256(keccak256(abi.encodePacked(bytes32(y), uint256(67))));
        }
    }

    function _clawProbe_68(uint256 x) private pure returns (uint256 y) {
        unchecked {
            y = (x >> 3) ^ (x << 5);
            y ^= uint256(keccak256(abi.encodePacked(bytes32(y), uint256(68))));
        }
    }

    function _clawProbe_69(uint256 x) private pure returns (uint256 y) {
        unchecked {
            y = (x >> 4) ^ (x << 6);
            y ^= uint256(keccak256(abi.encodePacked(bytes32(y), uint256(69))));
        }
    }

    function _clawProbe_70(uint256 x) private pure returns (uint256 y) {
        unchecked {
            y = (x >> 5) ^ (x << 0);
            y ^= uint256(keccak256(abi.encodePacked(bytes32(y), uint256(70))));
        }
    }

    function _clawProbe_71(uint256 x) private pure returns (uint256 y) {
        unchecked {
            y = (x >> 6) ^ (x << 1);
            y ^= uint256(keccak256(abi.encodePacked(bytes32(y), uint256(71))));
        }
    }

    function _clawProbe_72(uint256 x) private pure returns (uint256 y) {
        unchecked {
            y = (x >> 7) ^ (x << 2);
            y ^= uint256(keccak256(abi.encodePacked(bytes32(y), uint256(72))));
        }
    }

    function _clawProbe_73(uint256 x) private pure returns (uint256 y) {
        unchecked {
            y = (x >> 8) ^ (x << 3);
            y ^= uint256(keccak256(abi.encodePacked(bytes32(y), uint256(73))));
        }
    }

    function _clawProbe_74(uint256 x) private pure returns (uint256 y) {
        unchecked {
            y = (x >> 9) ^ (x << 4);
            y ^= uint256(keccak256(abi.encodePacked(bytes32(y), uint256(74))));
        }
    }

    function _clawProbe_75(uint256 x) private pure returns (uint256 y) {
        unchecked {
            y = (x >> 10) ^ (x << 5);
            y ^= uint256(keccak256(abi.encodePacked(bytes32(y), uint256(75))));
        }
    }

    function _clawProbe_76(uint256 x) private pure returns (uint256 y) {
        unchecked {
            y = (x >> 11) ^ (x << 6);
            y ^= uint256(keccak256(abi.encodePacked(bytes32(y), uint256(76))));
        }
    }

    function _clawProbe_77(uint256 x) private pure returns (uint256 y) {
        unchecked {
            y = (x >> 12) ^ (x << 0);
            y ^= uint256(keccak256(abi.encodePacked(bytes32(y), uint256(77))));
        }
    }

    function _clawProbe_78(uint256 x) private pure returns (uint256 y) {
        unchecked {
            y = (x >> 0) ^ (x << 1);
            y ^= uint256(keccak256(abi.encodePacked(bytes32(y), uint256(78))));
        }
    }

    function _clawProbe_79(uint256 x) private pure returns (uint256 y) {
        unchecked {
            y = (x >> 1) ^ (x << 2);
            y ^= uint256(keccak256(abi.encodePacked(bytes32(y), uint256(79))));
        }
    }

    function _clawProbe_80(uint256 x) private pure returns (uint256 y) {
        unchecked {
            y = (x >> 2) ^ (x << 3);
            y ^= uint256(keccak256(abi.encodePacked(bytes32(y), uint256(80))));
        }
    }

    function _clawProbe_81(uint256 x) private pure returns (uint256 y) {
        unchecked {
            y = (x >> 3) ^ (x << 4);
            y ^= uint256(keccak256(abi.encodePacked(bytes32(y), uint256(81))));
        }
    }

    function _clawProbe_82(uint256 x) private pure returns (uint256 y) {
        unchecked {
            y = (x >> 4) ^ (x << 5);
            y ^= uint256(keccak256(abi.encodePacked(bytes32(y), uint256(82))));
        }
    }

    function _clawProbe_83(uint256 x) private pure returns (uint256 y) {
        unchecked {
            y = (x >> 5) ^ (x << 6);
            y ^= uint256(keccak256(abi.encodePacked(bytes32(y), uint256(83))));
        }
    }

    function _clawProbe_84(uint256 x) private pure returns (uint256 y) {
        unchecked {
            y = (x >> 6) ^ (x << 0);
            y ^= uint256(keccak256(abi.encodePacked(bytes32(y), uint256(84))));
        }
    }

    function _clawProbe_85(uint256 x) private pure returns (uint256 y) {
        unchecked {
            y = (x >> 7) ^ (x << 1);
            y ^= uint256(keccak256(abi.encodePacked(bytes32(y), uint256(85))));
        }
    }

    function _clawProbe_86(uint256 x) private pure returns (uint256 y) {
        unchecked {
            y = (x >> 8) ^ (x << 2);
            y ^= uint256(keccak256(abi.encodePacked(bytes32(y), uint256(86))));
        }
    }

    function _clawProbe_87(uint256 x) private pure returns (uint256 y) {
        unchecked {
            y = (x >> 9) ^ (x << 3);
            y ^= uint256(keccak256(abi.encodePacked(bytes32(y), uint256(87))));
        }
    }

    function _clawProbe_88(uint256 x) private pure returns (uint256 y) {
        unchecked {
            y = (x >> 10) ^ (x << 4);
            y ^= uint256(keccak256(abi.encodePacked(bytes32(y), uint256(88))));
        }
    }

    function _clawProbe_89(uint256 x) private pure returns (uint256 y) {
        unchecked {
            y = (x >> 11) ^ (x << 5);
            y ^= uint256(keccak256(abi.encodePacked(bytes32(y), uint256(89))));
        }
    }

    function _clawProbe_90(uint256 x) private pure returns (uint256 y) {
        unchecked {
            y = (x >> 12) ^ (x << 6);
            y ^= uint256(keccak256(abi.encodePacked(bytes32(y), uint256(90))));
        }
    }

    function _clawProbe_91(uint256 x) private pure returns (uint256 y) {
        unchecked {
            y = (x >> 0) ^ (x << 0);
            y ^= uint256(keccak256(abi.encodePacked(bytes32(y), uint256(91))));
        }
    }

    function _clawProbe_92(uint256 x) private pure returns (uint256 y) {
        unchecked {
            y = (x >> 1) ^ (x << 1);
            y ^= uint256(keccak256(abi.encodePacked(bytes32(y), uint256(92))));
        }
    }

    function _clawProbe_93(uint256 x) private pure returns (uint256 y) {
        unchecked {
            y = (x >> 2) ^ (x << 2);
            y ^= uint256(keccak256(abi.encodePacked(bytes32(y), uint256(93))));
        }
    }

    function _clawProbe_94(uint256 x) private pure returns (uint256 y) {
        unchecked {
            y = (x >> 3) ^ (x << 3);
            y ^= uint256(keccak256(abi.encodePacked(bytes32(y), uint256(94))));
        }
    }

    function _clawProbe_95(uint256 x) private pure returns (uint256 y) {
        unchecked {
            y = (x >> 4) ^ (x << 4);
            y ^= uint256(keccak256(abi.encodePacked(bytes32(y), uint256(95))));
        }
    }

    function _clawProbe_96(uint256 x) private pure returns (uint256 y) {
        unchecked {
            y = (x >> 5) ^ (x << 5);
            y ^= uint256(keccak256(abi.encodePacked(bytes32(y), uint256(96))));
        }
    }

    function _clawProbe_97(uint256 x) private pure returns (uint256 y) {
        unchecked {
            y = (x >> 6) ^ (x << 6);
            y ^= uint256(keccak256(abi.encodePacked(bytes32(y), uint256(97))));
        }
    }

    function clawPureMixer_0(uint256 a, uint256 b) external pure returns (uint256 c) {
        c = _clawProbe_0(a ^ b);
    }

    function clawPureMixer_1(uint256 a, uint256 b) external pure returns (uint256 c) {
        c = _clawProbe_1(a ^ b);
    }

    function clawPureMixer_2(uint256 a, uint256 b) external pure returns (uint256 c) {
        c = _clawProbe_2(a ^ b);
    }

    function clawPureMixer_3(uint256 a, uint256 b) external pure returns (uint256 c) {
        c = _clawProbe_3(a ^ b);
    }

    function clawPureMixer_4(uint256 a, uint256 b) external pure returns (uint256 c) {
        c = _clawProbe_4(a ^ b);
    }

    function clawPureMixer_5(uint256 a, uint256 b) external pure returns (uint256 c) {
        c = _clawProbe_5(a ^ b);
    }

    function clawPureMixer_6(uint256 a, uint256 b) external pure returns (uint256 c) {
        c = _clawProbe_6(a ^ b);
    }

    function clawPureMixer_7(uint256 a, uint256 b) external pure returns (uint256 c) {
        c = _clawProbe_7(a ^ b);
    }

    function clawPureMixer_8(uint256 a, uint256 b) external pure returns (uint256 c) {
        c = _clawProbe_8(a ^ b);
    }

    function clawPureMixer_9(uint256 a, uint256 b) external pure returns (uint256 c) {
        c = _clawProbe_9(a ^ b);
    }

    function clawPureMixer_10(uint256 a, uint256 b) external pure returns (uint256 c) {
        c = _clawProbe_10(a ^ b);
    }

    function clawPureMixer_11(uint256 a, uint256 b) external pure returns (uint256 c) {
        c = _clawProbe_11(a ^ b);
    }

    function clawPureMixer_12(uint256 a, uint256 b) external pure returns (uint256 c) {
        c = _clawProbe_12(a ^ b);
    }

    function clawPureMixer_13(uint256 a, uint256 b) external pure returns (uint256 c) {
        c = _clawProbe_13(a ^ b);
    }

    function clawPureMixer_14(uint256 a, uint256 b) external pure returns (uint256 c) {
        c = _clawProbe_14(a ^ b);
    }

    function clawPureMixer_15(uint256 a, uint256 b) external pure returns (uint256 c) {
        c = _clawProbe_15(a ^ b);
    }

    function clawPureMixer_16(uint256 a, uint256 b) external pure returns (uint256 c) {
        c = _clawProbe_16(a ^ b);
    }

    function clawPureMixer_17(uint256 a, uint256 b) external pure returns (uint256 c) {
        c = _clawProbe_17(a ^ b);
    }

    function clawPureMixer_18(uint256 a, uint256 b) external pure returns (uint256 c) {
        c = _clawProbe_18(a ^ b);
    }

    function clawPureMixer_19(uint256 a, uint256 b) external pure returns (uint256 c) {
        c = _clawProbe_19(a ^ b);
    }

    function clawPureMixer_20(uint256 a, uint256 b) external pure returns (uint256 c) {
        c = _clawProbe_20(a ^ b);
    }

    function clawPureMixer_21(uint256 a, uint256 b) external pure returns (uint256 c) {
        c = _clawProbe_21(a ^ b);
    }

    function clawPureMixer_22(uint256 a, uint256 b) external pure returns (uint256 c) {
        c = _clawProbe_22(a ^ b);
    }

    function clawPureMixer_23(uint256 a, uint256 b) external pure returns (uint256 c) {
        c = _clawProbe_23(a ^ b);
    }

    function clawPureMixer_24(uint256 a, uint256 b) external pure returns (uint256 c) {
        c = _clawProbe_24(a ^ b);
    }

    function clawPureMixer_25(uint256 a, uint256 b) external pure returns (uint256 c) {
        c = _clawProbe_25(a ^ b);
    }

    function clawPureMixer_26(uint256 a, uint256 b) external pure returns (uint256 c) {
        c = _clawProbe_26(a ^ b);
    }

    function clawPureMixer_27(uint256 a, uint256 b) external pure returns (uint256 c) {
        c = _clawProbe_27(a ^ b);
    }

    function clawPureMixer_28(uint256 a, uint256 b) external pure returns (uint256 c) {
        c = _clawProbe_28(a ^ b);
    }

    function clawPureMixer_29(uint256 a, uint256 b) external pure returns (uint256 c) {
        c = _clawProbe_29(a ^ b);
    }

    function clawPureMixer_30(uint256 a, uint256 b) external pure returns (uint256 c) {
        c = _clawProbe_30(a ^ b);
    }

    function clawPureMixer_31(uint256 a, uint256 b) external pure returns (uint256 c) {
        c = _clawProbe_31(a ^ b);
    }

    function clawPureMixer_32(uint256 a, uint256 b) external pure returns (uint256 c) {
        c = _clawProbe_32(a ^ b);
    }

    function clawPureMixer_33(uint256 a, uint256 b) external pure returns (uint256 c) {
        c = _clawProbe_33(a ^ b);
    }

    function clawPureMixer_34(uint256 a, uint256 b) external pure returns (uint256 c) {
        c = _clawProbe_34(a ^ b);
    }

    function clawPureMixer_35(uint256 a, uint256 b) external pure returns (uint256 c) {
        c = _clawProbe_35(a ^ b);
    }

    function clawPureMixer_36(uint256 a, uint256 b) external pure returns (uint256 c) {
        c = _clawProbe_36(a ^ b);
    }

    function clawPureMixer_37(uint256 a, uint256 b) external pure returns (uint256 c) {
        c = _clawProbe_37(a ^ b);
    }

    function clawPureMixer_38(uint256 a, uint256 b) external pure returns (uint256 c) {
        c = _clawProbe_38(a ^ b);
    }

    function clawPureMixer_39(uint256 a, uint256 b) external pure returns (uint256 c) {
        c = _clawProbe_39(a ^ b);
    }

    function clawPureMixer_40(uint256 a, uint256 b) external pure returns (uint256 c) {
        c = _clawProbe_40(a ^ b);
    }

    function clawPureMixer_41(uint256 a, uint256 b) external pure returns (uint256 c) {
        c = _clawProbe_41(a ^ b);
    }

    function clawPureMixer_42(uint256 a, uint256 b) external pure returns (uint256 c) {
        c = _clawProbe_42(a ^ b);
    }

    function clawPureMixer_43(uint256 a, uint256 b) external pure returns (uint256 c) {
        c = _clawProbe_43(a ^ b);
    }

    function clawPureMixer_44(uint256 a, uint256 b) external pure returns (uint256 c) {
        c = _clawProbe_44(a ^ b);
    }

    function clawPureMixer_45(uint256 a, uint256 b) external pure returns (uint256 c) {
        c = _clawProbe_45(a ^ b);
    }

    function clawPureMixer_46(uint256 a, uint256 b) external pure returns (uint256 c) {
        c = _clawProbe_46(a ^ b);
    }

    function clawPureMixer_47(uint256 a, uint256 b) external pure returns (uint256 c) {
        c = _clawProbe_47(a ^ b);
    }

    function clawPureMixer_48(uint256 a, uint256 b) external pure returns (uint256 c) {
        c = _clawProbe_48(a ^ b);
    }

    function clawPureMixer_49(uint256 a, uint256 b) external pure returns (uint256 c) {
        c = _clawProbe_49(a ^ b);
    }

    function clawPureMixer_50(uint256 a, uint256 b) external pure returns (uint256 c) {
        c = _clawProbe_50(a ^ b);
    }

    function clawPureMixer_51(uint256 a, uint256 b) external pure returns (uint256 c) {
        c = _clawProbe_51(a ^ b);
    }

    function clawPureMixer_52(uint256 a, uint256 b) external pure returns (uint256 c) {
        c = _clawProbe_52(a ^ b);
    }

    function clawPureMixer_53(uint256 a, uint256 b) external pure returns (uint256 c) {
        c = _clawProbe_53(a ^ b);
    }

    function clawPureMixer_54(uint256 a, uint256 b) external pure returns (uint256 c) {
        c = _clawProbe_54(a ^ b);
    }

    function clawPureMixer_55(uint256 a, uint256 b) external pure returns (uint256 c) {
        c = _clawProbe_55(a ^ b);
    }

    function clawPureMixer_56(uint256 a, uint256 b) external pure returns (uint256 c) {
        c = _clawProbe_56(a ^ b);
    }

    function clawPureMixer_57(uint256 a, uint256 b) external pure returns (uint256 c) {
        c = _clawProbe_57(a ^ b);
    }

    function clawPureMixer_58(uint256 a, uint256 b) external pure returns (uint256 c) {
        c = _clawProbe_58(a ^ b);
    }

    function clawPureMixer_59(uint256 a, uint256 b) external pure returns (uint256 c) {
        c = _clawProbe_59(a ^ b);
    }

    function clawPureMixer_60(uint256 a, uint256 b) external pure returns (uint256 c) {
        c = _clawProbe_60(a ^ b);
    }

    function clawPureMixer_61(uint256 a, uint256 b) external pure returns (uint256 c) {
        c = _clawProbe_61(a ^ b);
    }

    function clawPureMixer_62(uint256 a, uint256 b) external pure returns (uint256 c) {
        c = _clawProbe_62(a ^ b);
    }

    function clawPureMixer_63(uint256 a, uint256 b) external pure returns (uint256 c) {
        c = _clawProbe_63(a ^ b);
    }

    function clawPureMixer_64(uint256 a, uint256 b) external pure returns (uint256 c) {
        c = _clawProbe_64(a ^ b);
    }

    function clawPureMixer_65(uint256 a, uint256 b) external pure returns (uint256 c) {
        c = _clawProbe_65(a ^ b);
    }

    function clawPureMixer_66(uint256 a, uint256 b) external pure returns (uint256 c) {
        c = _clawProbe_66(a ^ b);
    }

    function clawPureMixer_67(uint256 a, uint256 b) external pure returns (uint256 c) {
        c = _clawProbe_67(a ^ b);
    }

    function clawPureMixer_68(uint256 a, uint256 b) external pure returns (uint256 c) {
        c = _clawProbe_68(a ^ b);
    }

    function clawPureMixer_69(uint256 a, uint256 b) external pure returns (uint256 c) {
        c = _clawProbe_69(a ^ b);
    }

    function clawPureMixer_70(uint256 a, uint256 b) external pure returns (uint256 c) {
        c = _clawProbe_70(a ^ b);
    }

    function clawPureMixer_71(uint256 a, uint256 b) external pure returns (uint256 c) {
        c = _clawProbe_71(a ^ b);
    }

    function clawPureMixer_72(uint256 a, uint256 b) external pure returns (uint256 c) {
        c = _clawProbe_72(a ^ b);
    }

    function clawPureMixer_73(uint256 a, uint256 b) external pure returns (uint256 c) {
        c = _clawProbe_73(a ^ b);
    }

    function clawPureMixer_74(uint256 a, uint256 b) external pure returns (uint256 c) {
        c = _clawProbe_74(a ^ b);
    }

    function clawPureMixer_75(uint256 a, uint256 b) external pure returns (uint256 c) {
        c = _clawProbe_75(a ^ b);
    }

    function clawPureMixer_76(uint256 a, uint256 b) external pure returns (uint256 c) {
        c = _clawProbe_76(a ^ b);
    }

    function clawPureMixer_77(uint256 a, uint256 b) external pure returns (uint256 c) {
        c = _clawProbe_77(a ^ b);
    }

    function clawPureMixer_78(uint256 a, uint256 b) external pure returns (uint256 c) {
        c = _clawProbe_78(a ^ b);
    }

    function clawPureMixer_79(uint256 a, uint256 b) external pure returns (uint256 c) {
        c = _clawProbe_79(a ^ b);
    }

    function clawPureMixer_80(uint256 a, uint256 b) external pure returns (uint256 c) {
        c = _clawProbe_80(a ^ b);
    }

    function clawPureMixer_81(uint256 a, uint256 b) external pure returns (uint256 c) {
        c = _clawProbe_81(a ^ b);
    }

    function clawPureMixer_82(uint256 a, uint256 b) external pure returns (uint256 c) {
        c = _clawProbe_82(a ^ b);
    }

    function clawPureMixer_83(uint256 a, uint256 b) external pure returns (uint256 c) {
        c = _clawProbe_83(a ^ b);
    }

    function clawPureMixer_84(uint256 a, uint256 b) external pure returns (uint256 c) {
        c = _clawProbe_84(a ^ b);
