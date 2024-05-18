// SPDX-License-Identifier: MIT

pragma solidity ^0.8.9;

import "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/token/ERC20/extensions/ERC20BurnableUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/token/ERC20/utils/SafeERC20Upgradeable.sol";
import "@openzeppelin/contracts-upgradeable/utils/math/SafeMathUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/access/OwnableUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/security/ReentrancyGuardUpgradeable.sol";

interface IDexTopFactory {
    event PairCreated(address indexed token0, address indexed token1, address pair, uint);

    function feeTo() external view returns (address);
    function feeToSetter() external view returns (address);

    function getPair(address tokenA, address tokenB) external view returns (address pair);
    function allPairs(uint) external view returns (address pair);
    function allPairsLength() external view returns (uint);

    function createPair(address tokenA, address tokenB) external returns (address pair);

    function setFeeTo(address) external;
    function setFeeToSetter(address) external;
}

interface IDexTopPair {
    event Approval(address indexed owner, address indexed spender, uint value);
    event Transfer(address indexed from, address indexed to, uint value);

    function name() external pure returns (string memory);
    function symbol() external pure returns (string memory);
    function decimals() external pure returns (uint8);
    function totalSupply() external view returns (uint);
    function balanceOf(address owner) external view returns (uint);
    function allowance(address owner, address spender) external view returns (uint);

    function approve(address spender, uint value) external returns (bool);
    function transfer(address to, uint value) external returns (bool);
    function transferFrom(address from, address to, uint value) external returns (bool);

    function DOMAIN_SEPARATOR() external view returns (bytes32);
    function PERMIT_TYPEHASH() external pure returns (bytes32);
    function nonces(address owner) external view returns (uint);

    function permit(address owner, address spender, uint value, uint deadline, uint8 v, bytes32 r, bytes32 s) external;

    event Mint(address indexed sender, uint amount0, uint amount1, address indexed senderOrigin);
    event Burn(address indexed sender, uint amount0, uint amount1, address indexed to, address indexed senderOrigin);
    event Swap(
        address indexed sender,
        uint amount0In,
        uint amount1In,
        uint amount0Out,
        uint amount1Out,
        address indexed to
    );
    event Sync(uint112 reserve0, uint112 reserve1);

    function MINIMUM_LIQUIDITY() external pure returns (uint);
    function factory() external view returns (address);
    function token0() external view returns (address);
    function token1() external view returns (address);
    function getReserves() external view returns (uint112 reserve0, uint112 reserve1, uint32 blockTimestampLast);
    function price0CumulativeLast() external view returns (uint);
    function price1CumulativeLast() external view returns (uint);
    function kLast() external view returns (uint);

    function mint(address to, address senderOrigin) external returns (uint liquidity);
    function burn(address to, address senderOrigin) external returns (uint amount0, uint amount1);
    function swap(uint amount0Out, uint amount1Out, address to, bytes calldata data) external;
    function skim(address to) external;
    function sync() external;

    function initialize(address, address) external;
}
// DEXBuyAndBurn is a contract that converts received LP tokens from platform fees for DEX and then burns it.
// The caller of convertLps, the function responsible for converting fees to DEX earns a 0.1% reward for calling.
contract DEXBuyAndBurnUpgradeable is Initializable, UUPSUpgradeable, OwnableUpgradeable, ReentrancyGuardUpgradeable {
    using SafeMathUpgradeable for uint256;
    using SafeERC20Upgradeable for IERC20Upgradeable;

    IDexTopFactory public factory;
    ERC20BurnableUpgradeable public DEX;
    uint public DEX_STARTING_SUPPLY;
    address public WPLS;
    uint public devCut;  // in basis points aka parts per 10,000 so 5000 is 50%, cap of 50%, default is 0
    uint public BOUNTY_FEE;
    address public devAddr;
    uint public slippage;

    // set of addresses that can perform certain functions
    mapping(address => bool) public isAuth;
    address[] public authorized;
    bool public anyAuth;

    modifier onlyAuth() {
        require(isAuth[_msgSender()], "DEXBuyAndBurn: FORBIDDEN");
        _;
    }

    // C6: It's not a fool proof solution, but it prevents flash loans, so here it's ok to use tx.origin
    modifier onlyEOA() {
        // Try to make flash-loan exploit harder to do by only allowing externally owned addresses.
        require(msg.sender == tx.origin, "DEXBuyAndBurn: must use EOA");
        _;
    }

    mapping(address => address) internal _bridges;
    mapping(address => uint) internal converted;
    mapping(address => bool) public overridePreventSwap;
    mapping(address => bool) public slippageOverrode;

    event SetDevAddr(address _addr);
    event SetDevCut(uint _amount);
    event LogBridgeSet(address indexed token, address indexed bridge);
    event LogBurn(
        address indexed server,
        address indexed token,
        uint256 paidBounty,
        uint256 amountBurned
    );
    event ToggleAnyAuth();
    event LogOverridePreventSwap(address _adr);
    event LogSlippageOverrode(address _adr);

    function initialize(
        address _factory,
        ERC20BurnableUpgradeable _DEX,
        address _WPLS,
        address _devAddr,
        uint256 _devCut,
        uint256 _startingDEXSupply
    ) public initializer {
        factory = IDexTopFactory(_factory);
        DEX = _DEX;
        WPLS = _WPLS;
        devAddr = _devAddr;
        devCut = _devCut;
        isAuth[msg.sender] = true;
        authorized.push(msg.sender);
        DEX_STARTING_SUPPLY = _startingDEXSupply;
        BOUNTY_FEE = 10;
        slippage = 9;
        anyAuth = false;
        __Ownable_init(msg.sender);
        __UUPSUpgradeable_init();
    }

    // Get total burned DEX
    function burnedDEX() public view returns (uint totalBurned) {
        totalBurned = DEX_STARTING_SUPPLY - DEX.totalSupply();
    }

    // Begin Owner functions
    function addAuth(address _auth) external onlyOwner {
        isAuth[_auth] = true;
        authorized.push(_auth);
    }

    function revokeAuth(address _auth) external onlyOwner {
        isAuth[_auth] = false;
    }

    // setting anyAuth to true allows anyone to call convertMultiple permanently
    function toggleAnyAuth() external onlyOwner {
        anyAuth = !anyAuth;
        emit ToggleAnyAuth();
    }

    function setDevCut(uint _amount) external onlyOwner {
        require(_amount <= 5000, "setDevCut: cut too high");
        devCut = _amount;

        emit SetDevCut(_amount);
    }

    function setBounty(uint _amount) external onlyOwner {
        require(_amount <= 5000, "setBounty: bounty too high");
        BOUNTY_FEE = _amount;
    }

    function setDevAddr(address _addr) external {
        require(owner() == _msgSender() || devAddr == _msgSender(), "not allowed");
        require(_addr != address(0), "setDevAddr, address cannot be zero address");
        devAddr = _addr;

        emit SetDevAddr(_addr);
    }
    // End owner functions

    function bridgeFor(address token) public view returns (address bridge) {
        bridge = _bridges[token];
        if (bridge == address(0)) {
            bridge = WPLS;
        }
    }

    // onlyAuth type functions

    function overrideSlippage(address _token) external onlyAuth {
        slippageOverrode[_token] = !slippageOverrode[_token];
        emit LogSlippageOverrode(_token);
    }

    function toggleOverridePreventSwap(address _token) external onlyAuth {
        overridePreventSwap[_token] = !overridePreventSwap[_token];
        emit LogOverridePreventSwap(_token);
    }

    function setSlippage(uint _amt) external onlyAuth {
        require(_amt < 20, "slippage setting too high"); // the higher this setting, the lower the slippage tolerance, too high and buybacks would never work
        slippage = _amt;
    }

    function setBridge(address token, address bridge) external onlyAuth {
        // Checks
        require(
            token != address(DEX) && token != WPLS && token != bridge,
            "DEXBuyAndBurn: Invalid bridge"
        );

        // Effects
        _bridges[token] = bridge;
        emit LogBridgeSet(token, bridge);
    }

    function isLpToken(address possibleLP) internal view returns (bool valid) {
        (bool success0, bytes memory result0) = possibleLP.staticcall(abi.encodeWithSelector(IDexTopPair.token0.selector));
        if (success0 && result0.length != 0) {
            (bool success1, bytes memory result1) = possibleLP.staticcall(abi.encodeWithSelector(IDexTopPair.token1.selector));
            if (success1 && result1.length != 0) {
                address token0 = abi.decode(result0, (address));
                address token1 = abi.decode(result1, (address));
                address validPair;
                (validPair, valid) = _getValidPair(token0, token1);
                return valid && validPair == possibleLP;
            }
            return false;
        } else {
            return false;
        }
    }

    function _getValidPair(address token0, address token1) internal view returns (address, bool) {
        (address t0, address t1) = token0 < token1 ? (token0, token1) : (token1, token0);
        address realPair = factory.getPair(t0, t1);
        // check if newly derived pair is the same as the address passed in
        return (realPair, realPair != address(0));
    }

    function convertLps(
        address[] calldata tokens0,
        address[] calldata tokens1
    ) external onlyEOA() nonReentrant() {
        require(anyAuth || isAuth[_msgSender()], "DEXBuyAndBurn: FORBIDDEN");
        uint len = tokens0.length;
        uint i;
        require(len == tokens1.length, "DEXBuyAndBurn: list mismatch");
        for (i = 0; i < len; i++) {
            (address token0, address token1) = (tokens0[i], tokens1[i]);
            require(token0 != token1, "DEXBuyAndBurn: tokens match");
            (address lp, bool valid) = _getValidPair(token0, token1);
            require(valid, "DEXBuyAndBurn: Invalid pair");
            IDexTopPair pair = IDexTopPair(lp);
            uint bal = pair.balanceOf(address(this));
            if (bal > 0) {
                pair.transfer(lp, bal);
                pair.burn(address(this), address(this));
            }
        }
        // recursively swap originating tokens toward WPLS/DEX
        // without swapping to WPLS directly. This line skips all WPLS attempts
        converted[WPLS] = block.number;
        for (i = 0; i < len; i++) {
            (address token0, address token1) = (tokens0[i], tokens1[i]);
            if (block.number > converted[token0]) {
                _convertStep(token0, IERC20Upgradeable(token0).balanceOf(address(this)));
                converted[token0] = block.number;
            }
            if (block.number > converted[token1]) {
                _convertStep(token1, IERC20Upgradeable(token1).balanceOf(address(this)));
                converted[token1] = block.number;
            }
        }
        // final step is to swap all WPLS to DEX and burn it
        uint wplsBal = IERC20Upgradeable(WPLS).balanceOf(address(this));
        if (wplsBal > 0) {
            _toDEX(WPLS, wplsBal);
        }
        _burnDEX();
    }

    // internal functions
    function _convertStep(
        address token,
        uint256 amount0
    ) internal {
        uint256 amount = amount0;
        if (amount0 > 0 && token != address(DEX) && token != WPLS) {
            bool isLP = isLpToken(token);
            if (!isLP && !overridePreventSwap[token]) {
                address bridge = bridgeFor(token);
                amount = _swap(token, bridge, amount0, address(this));
                _convertStep(bridge, amount);
            }
        }
    }

    function _burnDEX() internal returns (uint amount) {
        uint _amt = IERC20Upgradeable(address(DEX)).balanceOf(address(this));
        uint bounty;
        if (devCut > 0) {
            uint calc = _amt.mul(devCut).div(10000);
            IERC20Upgradeable(address(DEX)).safeTransfer(devAddr, calc);
            _amt = _amt.sub(calc);
        }
        if (BOUNTY_FEE > 0) {
            bounty = _amt.mul(BOUNTY_FEE).div(10000);
            amount = _amt.sub(bounty);
            IERC20Upgradeable(address(DEX)).safeTransfer(_msgSender(), bounty); // send message sender their share of 0.1%
        }
        DEX.burn(amount);
        emit LogBurn(_msgSender(), address(DEX), bounty, amount);
    }

    function _swap(
        address fromToken,
        address toToken,
        uint256 amountIn,
        address to
    ) internal returns (uint256 amountOut) {
        IDexTopPair pair =
            IDexTopPair(factory.getPair(fromToken, toToken));
        require(address(pair) != address(0), "DEXBuyAndBurn: Cannot convert");

        (uint256 reserve0, uint256 reserve1, ) = pair.getReserves();
        (uint reserveInput, uint reserveOutput) = fromToken == pair.token0() ? (reserve0, reserve1) : (reserve1, reserve0);

        IERC20Upgradeable(fromToken).safeTransfer(address(pair), amountIn);
        uint amountInput = IERC20Upgradeable(fromToken).balanceOf(address(pair)).sub(reserveInput); // calculate amount that was transferred, this accounts for transfer taxes
        require(slippageOverrode[fromToken] || reserveInput.div(amountInput) > slippage, "DEXBuyAndBurn: high slippage");

        amountOut = _getAmountOut(amountInput, reserveInput, reserveOutput);
        (uint amount0Out, uint amount1Out) = fromToken == pair.token0() ? (uint(0), amountOut) : (amountOut, uint(0));
        pair.swap(amount0Out, amount1Out, to, new bytes(0));
    }

    function _toDEX(address token, uint256 amountIn) internal returns (uint256 amountOut) {
        amountOut = _swap(token, address(DEX), amountIn, address(this));
    }

    function _getAmountOut(uint amountIn, uint reserveIn, uint reserveOut) internal pure returns (uint amountOut) {
        require(amountIn > 0, 'DEXBuyAndBurn: INSUFFICIENT_INPUT_AMOUNT');
        require(reserveIn > 0 && reserveOut > 0, 'DEXBuyAndBurn: INSUFFICIENT_LIQUIDITY');
        uint amountInWithFee = amountIn.mul(9971);
        uint numerator = amountInWithFee.mul(reserveOut);
        uint denominator = reserveIn.mul(10000).add(amountInWithFee);
        amountOut = numerator / denominator;
    }

    function _authorizeUpgrade(address newImplementation) internal override onlyOwner {}
}