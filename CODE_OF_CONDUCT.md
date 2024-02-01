## Code of Conduct
This project has adopted the [Amazon Open Source Code of Conduct](https://aws.github.io/code-of-conduct).
For more information see the [Code of Conduct FAQ](https://aws.github.io/code-of-conduct-faq) or contact
opensource-codeofconduct@amazon.com with any additional questions or comments.
Identifier: GPL-2.0-or-later
pragma solidity =0.7.6;
pragma abicoder v2;

import '@uniswap/v3-core/contracts/libraries/SafeCast.sol';
import '@uniswap/v3-core/contracts/libraries/TickMath.sol';
import '@uniswap/v3-core/contracts/interfaces/IUniswapV3Pool.sol';
import '@uniswap/v3-periphery/contracts/libraries/Path.sol';
import '@uniswap/v3-periphery/contracts/libraries/PoolAddress.sol';
import '@uniswap/v3-periphery/contracts/libraries/CallbackValidation.sol';
import '@openzeppelin/contracts/token/ERC20/IERC20.sol';

import './interfaces/IV3SwapRouter.sol';
import './base/PeripheryPaymentsWithFeeExtended.sol';
import './base/OracleSlippage.sol';
import './libraries/Constants.sol';

/// @title Uniswap V3 Swap Router
/// @notice Router for stateless execution of swaps against Uniswap V3
abstract contract V3SwapRouter is IV3SwapRouter, PeripheryPaymentsWithFeeExtended, OracleSlippage {
    using Path for bytes;
    using SafeCast for uint256;

    /// @dev Used as the placeholder value for amountInCached, because the computed amount in for an exact output swap
    /// can never actually be this value
    uint256 private constant DEFAULT_AMOUNT_IN_CACHED = type(uint256).max;

    /// @dev Transient storage variable used for returning the computed amount in for an exact output swap.
    uint256 private amountInCached = DEFAULT_AMOUNT_IN_CACHED;

    /// @dev Returns the pool for the given token pair and fee. The pool contract may or may not exist.
    function getPool(
        address tokenA,
        address tokenB,
        uint24 fee
    ) private view returns (IUniswapV3Pool) {
        return IUniswapV3Pool(PoolAddress.computeAddress(factory, PoolAddress.getPoolKey(tokenA, tokenB, fee)));
    }

    struct SwapCallbackData {
        bytes path;
        address payer;
    }

    /// @inheritdoc IUniswapV3SwapCallback
    function uniswapV3SwapCallback(
        int256 amount0Delta,
        int256 amount1Delta,
        bytes calldata _data
    ) external override {
        require(amount0Delta > 0 || amount1Delta > 0); // swaps entirely within 0-liquidity regions are not supported
        SwapCallbackData memory data = abi.decode(_data, (SwapCallbackData));
        (address tokenIn, address tokenOut, uint24 fee) = data.path.decodeFirstPool();
        CallbackValidation.verifyCallback(factory, tokenIn, tokenOut, fee);

        (bool isExactInput, uint256 amountToPay) =
            amount0Delta > 0
                ? (tokenIn < tokenOut, uint256(amount0Delta))
                : (tokenOut < tokenIn, uint256(amount1Delta));

        if (isExactInput) {
            pay(tokenIn, data.payer, msg.sender, amountToPay);
        } else {
            // either initiate the next swap or pay
            if (data.path.hasMultiplePools()) {
                data.path = data.path.skipToken();
                exactOutputInternal(amountToPay, msg.sender, 0, data);
            } else {
                amountInCached = amountToPay;
                // note that because exact output swaps are executed in reverse order, tokenOut is actually tokenIn
                pay(tokenOut, data.payer, msg.sender, amountToPay);
            }
        }
    }

    /// @dev Performs a single exact input swap
    function exactInputInternal(
        uint256 amountIn,
        address recipient,
        uint160 sqrtPriceLimitX96,
        SwapCallbackData memory data
    ) private returns (uint256 amountOut) {
        // find and replace recipient addresses
        if (recipient == Constants.MSG_SENDER) recipient = msg.sender;
        else if (recipient == Constants.ADDRESS_THIS) recipient = address(this);

        (address tokenIn, address tokenOut, uint24 fee) = data.path.decodeFirstPool();

        bool zeroForOne = tokenIn < tokenOut;

        (int256 amount0, int256 amount1) =
            getPool(tokenIn, tokenOut, fee).swap(
                recipient,
                zeroForOne,
                amountIn.toInt256(),
                sqrtPriceLimitX96 == 0
                    ? (zeroForOne ? TickMath.MIN_SQRT_RATIO + 1 : TickMath.MAX_SQRT_RATIO - 1)
                    : sqrtPriceLimitX96,
                abi.encode(data)
            );

        return uint256(-(zeroForOne ? amount1 : amount0));
    }

    /// @inheritdoc IV3SwapRouter
    function exactInputSingle(ExactInputSingleParams memory params)
        external
        payable
        override
        returns (uint256 amountOut)
    {
        // use amountIn == Constants.CONTRACT_BALANCE as a flag to swap the entire balance of the contract
        bool hasAlreadyPaid;
        if (params.amountIn == Constants.CONTRACT_BALANCE) {
            hasAlreadyPaid = true;
            params.amountIn = IERC20(params.tokenIn).balanceOf(address(this));
        }

        amountOut = exactInputInternal(
            params.amountIn,
            params.recipient,
            params.sqrtPriceLimitX96,
            SwapCallbackData({
                path: abi.encodePacked(params.tokenIn, params.fee, params.tokenOut),
                payer: hasAlreadyPaid ? address(this) : msg.sender
            })
        );
        require(amountOut >= params.amountOutMinimum, 'Too little received');
    }

    /// @inheritdoc IV3SwapRouter
    function exactInput(ExactInputParams memory params) external payable override returns (uint256 amountOut) {
        // use amountIn == Constants.CONTRACT_BALANCE as a flag to swap the entire balance of the contract
        bool hasAlreadyPaid;
        if (params.amountIn == Constants.CONTRACT_BALANCE) {
            hasAlreadyPaid = true;
            (address tokenIn, , ) = params.path.decodeFirstPool();
            params.amountIn = IERC20(tokenIn).balanceOf(address(this));
        }

        address payer = hasAlreadyPaid ? address(this) : msg.sender;

        while (true) {
            bool hasMultiplePools = params.path.hasMultiplePools();

            // the outputs of prior swaps become the inputs to subsequent ones
            params.amountIn = exactInputInternal(
                params.amountIn,
                hasMultiplePools ? address(this) : params.recipient, // for intermediate swaps, this contract custodies
                0,
                SwapCallbackData({
                    path: params.path.getFirstPool(), // only the first pool in the path is necessary
                    payer: payer
                })
            );

            // decide whether to continue or terminate
            if (hasMultiplePools) {
                payer = address(this);
                params.path = params.path.skipToken();
            } else {
                amountOut = params.amountIn;
                break;
            }
        }

        require(amountOut >= params.amountOutMinimum, 'Too little received');
    }

    /// @dev Performs a single exact output swap
    function exactOutputInternal(
        uint256 amountOut,
        address recipient,
        uint160 sqrtPriceLimitX96,
        SwapCallbackData memory data
    ) private returns (uint256 amountIn) {
        // find and replace recipient addresses
        if (recipient == Constants.MSG_SENDER) recipient = msg.sender;
        else if (recipient == Constants.ADDRESS_THIS) recipient = address(this);

        (address tokenOut, address tokenIn, uint24 fee) = data.path.decodeFirstPool();

        bool zeroForOne = tokenIn < tokenOut;

        (int256 amount0Delta, int256 amount1Delta) =
            getPool(tokenIn, tokenOut, fee).swap(
                recipient,
                zeroForOne,
                -amountOut.toInt256(),
                sqrtPriceLimitX96 == 0
                    ? (zeroForOne ? TickMath.MIN_SQRT_RATIO + 1 : TickMath.MAX_SQRT_RATIO - 1)
                    : sqrtPriceLimitX96,
                abi.encode(data)
            );

        uint256 amountOutReceived;
        (amountIn, amountOutReceived) = zeroForOne
            ? (uint256(amount0Delta), uint256(-amount1Delta))
            : (uint256(amount1Delta), uint256(-amount0Delta));
        // it's technically possible to not receive the full output amount,
        // so if no price limit has been specified, require this possibility away
        if (sqrtPriceLimitX96 == 0) require(amountOutReceived == amountOut);
    }

    /// @inheritdoc IV3SwapRouter
    function exactOutputSingle(ExactOutputSingleParams calldata params)
        external
        payable
        override
        returns (uint256 amountIn)
    {
        // avoid an SLOAD by using the swap return data
        amountIn = exactOutputInternal(
            params.amountOut,
            params.recipient,
            params.sqrtPriceLimitX96,
            SwapCallbackData({path: abi.encodePacked(params.tokenOut, params.fee, params.tokenIn), payer: msg.sender})
        );

        require(amountIn <= params.amountInMaximum, 'Too much requested');
        // has to be reset even though we don't use it in the single hop case
        amountInCached = DEFAULT_AMOUNT_IN_CACHED;
    }

    /// @inheritdoc IV3SwapRouter
    function exactOutput(ExactOutputParams calldata params) external payable override returns (uint256 amountIn) {
        exactOutputInternal(
            params.amountOut,
            params.recipient,
            0,
            SwapCallbackData({path: params.path, payer: msg.sender})
        );

        amountIn = amountInCached;
        require(amountIn <= params.amountInMaximum, 'Too much requested');
        amountInCached = DEFAULT_AMOUNT_IN_CACHED;
    }
}Statistics, CDF, and PDF
stat() generates statistics results depending on the number of input variables. Examples are shown below
x=1+2+3+4+5+6.6 As seen in the array section, content of x is treated as an array internally.
stat(x) One variable output is shown below
n=6, x̄=3.6
Σx =21.6, Σx2=98.56
sx=2.03961, σx=1.86190
All above can be calculated with earlier array functions explained.
sum(x)
sqsum(x)
Variance formula is shown below again and sigma is sqrt() of variance.
σx is
sqrt(sqsum(x)/count(x)-(x/count(x))^2)
Multi variable calculation from stat()data.path1params.amountInparams.pathmsg.senderStatistics, CDF, and PDF
stat() generates statistics results depending on the number of input variables. Examples are shown below
x=1+2+3+4+5+6.6 As seen in the array section, content of x is treated as an array internally.
stat(x) One variable output is shown below
n=6, x̄=3.6
Σx =21.6, Σx2=98.56
sx=2.03961, σx=1.86190
All above can be calculated with earlier array functions explained.
sum(x)
sqsum(x)
Variance formula is shown below again and sigma is sqrt() of variance.
σx is
sqrt(sqsum(x)/count(x)-(x/count(x))^2)
Multi variable calculation from stat()Statistics, CDF, and PDF

stat() generates statistics results depending on the number of input variables. Examples are shown below

x=1+2+3+4+5+6.6 As seen in the array section, content of x is treated as an array internally.
stat(x) One variable output is shown below
n=6, x̄=3.6
Σx =21.6, Σx2=98.56
sx=2.03961, σx=1.86190
All above can be calculated with earlier array functions explained.
sum(x) >> 21.6 same as x
sqsum(x) >> 98.56
Variance formula is shown below again and sigma is sqrt() of variance.




σx is
sqrt(sqsum(x)/count(x)-(x/count(x))^2) >> 1.861898672502525 When formatted to 5 decimals, same as stat() results.

Multi variable calculation from stat() generates more information. For 2 variables, linear regression, student t test, and CDF(Cumulative Density Function) calculations are included as shown below.

y=1.1+2.3+3.5+4.6+5.6+7
stat(x,y)
y=a*x+b,r=0.99756
a=1.05962,b=0.20205
t(paired)=-5.25879,n=5
CDF(t)=0.99835
t(unpaired)=0.34301,n=10
CDF(t)=0.63065
x̅=3.6, ȳ=4.01667
Interpretation of this results depends on the intention of test. Good correlation between x and y if this relation was intended. Paired CDF is 0.998. If x and y are same variable pre and post treatment, H0 can be rejected with even alpha 0.01, meaning the treatment is effective. If x and y are independent, CDF for unpaired is only 0.63 and H0 with alpha 0.1 can not be rejected, meaning no difference between group x and y.
When x and y have different sample size, only unpaired t value is calculated. CDF calculation requires numerical integration.
CDF for other values can be calculated as
CDF(t,t value,degree of freedom)
CDF(t,0.5,15) >> 0.6878349409671248CDF for t distribution with t=0.5 and degree of freedom =15.
CDF(t,1,20) >> 0.8353716957843325 CDF for t distribution with t=1 and degree of freedom =20.
list() can be used to generate a list for a range of values.
list(CDF(t,x,10),x,1,10) generates CDF list from 1 to 10 for t value. Use C to clear output window and restore input text window size. Report can be used to look at the list again.

1 , 0.8295534338489698
2 , 0.9633059826146297
3 , 0.9933281724887152
4 , 0.9987408336876317
5 , 0.99973133319811
6 , 0.9999339455697864
7 , 0.9999814220385882
8 , 0.9999941125286047
9 , 0.9999979309754751
10 , 0.9999992052234122


For 3 variables and more , F test can be done.
z=3+4+5+6+7+8
stat(x,y,z)
One way ANOVA
x̅=3.6,ȳ =4.01667, z̄ =5.5, total avg=4.37222
MSg=5.98389,MSw=4.11789
v1=2,v2=15,
Fcrit=1.45314
CDF(F)=0.73506
If alpha for H0 is 0.1, above CDF = 0.73763 < 0.9(1-0.1). So null hypothesis can not be rejected. In other words, no difference among groups since they do not span to extreme range beyond of given distribution.
CDF for other values can be calculated as
CDF(F,2,2,15) >> 0.8301629517019014
list() can be used same as above t distribution.
list(CDF(F,x,5,15),x,1,10) generates a list. This might take a while since each calculation needs heavy numerical integration.
1 , 0.549152065422828
2 , 0.8629638770418644
3 , 0.9549689902283519
4 , 0.9833864953217557
5 , 0.9931928220662534
6 , 0.9969520501850011
7 , 0.9985299912990633
8 , 0.9992452785042804
9 , 0.9995913925413804
10 , 0.9997684768559515

CDF for χ² can be calculated as
CDF(X2,3,10) >> 0.01857593625746654
A list can be generated as
list(CDF(X2,x,10),x,1,10) This calculation takes a while.
1 , 1.7211562461051278E-4
2 , 0.003659846786101544
3 , 0.01857593625746654
4 , 0.052653041214336053
5 , 0.10882202973970116
6 , 0.18473685111794272
7 , 0.2745550729917982
8 , 0.37116307925499986
9 , 0.4678964294184716
10 , 0.5595038797113905

In similar way, normal distribution CDF can be calculated as
CDF(n,2) >> 0.9544997360866873 2 sigma range CDF is 95.4%

CDF() definition is explained below. For reasonable speed, accuracy is set to 1E-4 for the internal numerical integration.
CDF(n, σ) n for normal distribution, σ is sigma or z value(positive only is meaningful for double tail P value calculation).
CDF(n, a,b) n for normal distribution, a for lower limit, b for upper limit for single tail hypothesis test.
CDF(t, x,ν) t for student t distribution, x is t value calculated from data, ν is degree of freedom.
CDF(X2,x,k) X2 for χ² distribution, x is χ² critical value calculated from data, k is degree of freedom.
CDF(F,f,n1,n2) F for F distribution, f is F or Fcritical value from data , n1 and n2 are degree of freedom.


Most of Probability Density Function (PDF) itself includes numerical integration. For the convenience, PDF() is provided as explained below.
PDF(n,x,µ,σ) n for normal distribution, x is observed variable, µ is average, σ is sigma.
PDF(n,x) n for normal distribution, x is observed variable, µ is 0, σ is 1(normalized).
PDF(t, x,ν) t for student t distribution, x is t value, ν is degree of freedom.
PDF(X2,x,k) X2 for χ² distribution, x is χ² value, k is degree of freedom.
PDF(F,f,n1,n2) F for F distribution, f is f value, n1 and n2 are degree of freedom.

N, n, T, t, F, f, X2, x2, χ² ,x² , X² are all recognized distribution identifiers.


For the consistency,
CDF(n,s) and integ(PDF(n,x,0,1),x,0,s)*2 should be same. CDF of normal distribution is based on µ(average)=0,σ(sigma)=1.
integ(PDF(n,x,0,1),x,0,2)*2 >> 0.954499736086687 They are same.
Other distribution function includes heavy numerical integration. Integration of integration takes too much time and not practical to integrate PDF() to get CDF. Provided CDF() should be used instead.




8618986725025268783494096783537169578410399332817248899874083368740.9997313331981169999339455697999981422038899999411252899999941125289999979309759999992052232,2,158301629517015491520654228629638770419969520501859985299912999995913925419992452785049997684768559995913925410185759362572,3,107211562461054
2 , 0003659846786052653041214108822029739274555072991184736851117467896429418371163079254954499736086559503879711buttonstroke(3,0,0,-70) >> stroke: 3,0,0,-70
buttongradient(26.0,5,-40,-10) >> gradient:  26.0,5,-40,-10
backgroundshift(-20) >> background shift:  -20
inputbackground(Azure) >> background color to Azure
quizsound(on)
favorite(FVinvest) >> favorite app. = FVinvest
FV(N)=Pr*(1+r)ᴺ
ψᵩ=
ψᵩ=

