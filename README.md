>**了解智能合约审计和最佳实践请**[点击查看文档](https://safful.com/) 

# Move 合约漏洞，Move 合约中最常见的 10 种 Bug

[Move 语言的设计，更难以写出 bug](https://www.zellic.io/blog/move-fast-and-break-things-pt-1)，并且 Move 确实相当程度上做到了，有一些类型 bug 是不会发生的。
但 Bug 是无法根除的，正如所有事情的情况一样 -- 而且智能合约的 bug 几乎总是有可能造成负面的财务影响。
在经过许多 Move 审计之后，我们观察到一些 bug 的出现模式。因此，这篇文章的目的是记录我们发现并报告给客户的最常见的 bug 类型。
💡 我们创建了一个虚构的、易受攻击的[自动做市商(AMM)](https://www.gemini.com/en-US/cryptopedia/amm-what-are-automated-market-makers)协议，名为 "DonkeySwap"，以展示每个 bug 类型，并描述我们将如何在这篇文章中修复每个问题。
DonkeySwap 源代码在[这里](https://github.com/Zellic/DonkeySwap)。
请注意，大多数 bug 的影响通常取决于上下文。

---

## 1. 缺少泛型类型检查

对于 Move 中的公共函数而言，泛型类型是另一种形式的用户输入，必须进行有效性检查。我们经常发现一些函数在接受一个泛型类型时没有

- 检查该类型是否是一个有效的/白名单的类型。
- 检查该类型是否为预期的类型（例如，没有与存储的类型相比较）。

例如，[DonkeySwap](https://github.com/Zellic/DonkeySwap)（我们举例的易受攻击的协议）在以下方面易受攻击：

### DonkeySwap：函数 cancel_order 没有检查 BaseCoinType 泛型

- 类别：编码错误
- 严重程度：关键
- 影响：严重
- 可能性: 高

#### 描述

cancel_order 函数没有断言输入的 BaseCoinType 泛型与存储在 Order 资源中的 base_type 类型信息相匹配。
这个函数为给定的 BaseCoinType 解锁流动资金，并将存储的 Coin 数量返回给用户：

```
public fun cancel_order<BaseCoinType>(
        user: &signer,
        order_id: u64
    ) acquires OrderStore, CoinStore {
        // [...]
        deposit_funds<BaseCoinType>(order_store, address_of(user), order.base);
        // [...]
}
```

#### 影响

攻击者有可能通过限价兑换订单和取消订单 -- 传递不正确的 Coin 类型，从 AMM 中抽干流动性。
下面的概念证明证明了攻击者有能力窃取其他用户的锁定流动性：

```
##[test(admin=@donkeyswap, user=@0x2222)]
fun WHEN_exploit_lack_of_type_checking(admin: &signer, user: &signer) acquires CoinCapability {
    let (my_usdc, order_id) = setup_with_limit_swap(admin, user, 1000000000000000);

    // let's say the admin deposits some ZEL

    mint<ZEL>(my_usdc, address_of(admin));
    let _admin_order_id = market::limit_swap<ZEL, USDC>(admin, my_usdc, 1000000000000000);

    // now, let's try stealing from the admin

    assert!(coin::balance<USDC>(address_of(user)) == 0, ERR_UNEXPECTED_BALANCE);
    assert!(coin::balance<ZEL>(address_of(user)) == 0, ERR_UNEXPECTED_BALANCE);

    market::cancel_order<ZEL>(user, order_id); // ZEL is not the right coin type!

    assert!(coin::balance<USDC>(address_of(user)) == 0, ERR_UNEXPECTED_BALANCE);
    assert!(coin::balance<ZEL>(address_of(user)) == my_usdc, ERR_UNEXPECTED_BALANCE); // received ZEL?
}
```

#### 修改建议

在 cancel_order 函数中添加以下类型检查断言：

```
assert!(order.base_type == type_info::type_of<BaseCoinType>(), ERR_ORDER_WRONG_COIN_TYPE);
```

## 2. 无限制执行

无限制执行（Unbounded execution），也被称为 gas griefing/loop bombing，是一种拒绝服务的攻击，当用户可以无限制的向多个用户共享的循环代码（即可以被许多用户执行）添加迭代时，就会存在这种攻击。
攻击者有可能引起循环迭代足够多的次数，使其耗尽能量而中止。这可能会阻止应用程序的关键功能。

### DonkeySwap：While 循环轰炸阻断了一些功能

- 类别：编码错误
- 严重程度: 高
- 影响: 高
- 可能性: 高

#### 描述

下面的循环遍历每一个开放的订单，有可能因为注册了许多订单而被阻塞：

```
fun get_order_by_id(
    order_store: &OrderStore,
    order_id: u64
): (Option<Order>) {
    let i = 0;
    let len = vector::length(&order_store.orders);
    while (i < len) {
        let order = vector::borrow<Order>(&order_store.orders, i);
        if (order.id == order_id) {
            return option::some(*order)
        };
        i = i + 1;
    };

    return option::none<Order>()
}
```

有好几个这样的 while 循环，在每个开放订单上进行迭代：

- 在 get_order_by_id 函数中，它被 cancel_order 和 fulfill_order 调用。
- 在 fulfill_orders 函数中，它被 add_liquidity 调用。
- 在 drop_order 函数中，被 cancel_order 和 execute_limit_order 调用。

#### 影响

由于这些函数都可以通过注册大量的订单而被阻止，攻击者有可能会

- 永久阻止所有用户取消或履行限价订单，永久锁定在协议中的资金。
- 永久阻止用户兑换、增加流动性和创建限价兑换订单。

#### 建议

避免对每个订单进行循环，而是要考虑限制每个循环的迭代次数，并构建费用以激励用户履行彼此的订单。

## 3. 不当的访问控制

接受一个&signer 参数并不足以实现访问控制， 一定要断言签名者是预期的账户。

### DonkeySwap: 不恰当的 cancel_order 功能访问控制

- 类别：编码错误
- 严重程度：关键
- 影响：严重
- 可能性: 高

#### 描述

在取消订单并将资产转移给调用者之前，cancel_order 函数没有断言签名者是订单的所有者：

```
public fun cancel_order<BaseCoinType>(
        user: &signer,
        order_id: u64
    ) acquires OrderStore, CoinStore {
        // [...]
        deposit_funds<BaseCoinType>(order_store, address_of(user), order.base);
        // [...]
}
```

#### 影响

攻击者有可能通过取消每个用户的订单，耗尽任何币种的所有锁定的流动性：

```
##[test(admin=@donkeyswap, user=@0x2222)]
fun WHEN_exploit_improper_access_control(admin: &signer, user: &signer) acquires CoinCapability {
    setup_with_liquidity(admin, user);

    // let's say the admin deposits some USDC

    let my_usdc = 1000000000000000;
    mint<USDC>(my_usdc, address_of(admin));
    let order_id = market::limit_swap<USDC, ZEL>(admin, my_usdc, 1000000000000000);

    // now, let's try stealing USDC from the admin

    assert!(coin::balance<USDC>(address_of(user)) == 0, ERR_UNEXPECTED_BALANCE);
    assert!(coin::balance<ZEL>(address_of(user)) == 0, ERR_UNEXPECTED_BALANCE);

    market::cancel_order<USDC>(user, order_id); // order owned by admin, but signer is user!

    assert!(coin::balance<USDC>(address_of(user)) == my_usdc, ERR_UNEXPECTED_BALANCE);
    assert!(coin::balance<ZEL>(address_of(user)) == 0, ERR_UNEXPECTED_BALANCE); // received ZEL?
}
```

#### 建议

在 cancel_order 中加入以下签名者断言，以确保调用者拥有该订单：

```
assert!(order.user_address == address_of(user), ERR_PERMISSION_DENIED);
```

## 4. 价格 Oracle 操纵

2022 年，根据[Chainalysis](https://blog.chainalysis.com/reports/oracle-manipulation-attacks-rising/)，"DeFi 协议在 41 次 Oracle 价格操纵攻击中损失了 4.032 亿美元"，Aptos Move 并没有缓解这一类性的漏洞。
这个类别的漏洞都--以这种或那种方式--使攻击者能够以对攻击者有利的方式影响价格预言机，并对受害者产生负面影响。
欲了解更多关于可以操纵预言机的多种方式的信息，请参见[samczsun 的文章](https://samczsun.com/so-you-want-to-use-a-price-oracle/)关于安全使用价格预言机的信息。

### DonkeySwap：可操纵的价格预言机使抽干池子流动性

- 类别：编码错误
- 严重程度：关键
- 影响：严重
- 可能性: 高

#### 描述

DonkeySwap 天真地使用一对代币的流动性比率作为价格预言机，以确定发送或接收多少流动性代币用于存款和提款。

#### 影响

攻击者有可能通过操纵代币的比率来耗尽该池子。下面是一个概念证明，证明了这一点：
考虑到 DonkeySwap 以外的交易所的价格是 10 USDC = 1 ZEEL ， 1USDC = 1 HUGE：

```
📌初始 DonkeySwap 状态：

- 1000 USDC
- 1000个HUGE（每个HUGE 1美元）。
- 100 ZEL (每ZEL $10 USDC)

初始攻击者状态：

- 3000 USDC
- 100 ZEL (价值$1000 USDC)
```

步骤： 1.存款 3000 USDC， 收到 3000 DONK 。

```
📌 新的DonkeySwap状态：

- 4000 USDC
- 1000 HUGE (每HUGE $4 USDC)
- 100 ZEL (每ZEL $40 USDC)

新的攻击者状态：

- 3000 DONK
- 100 ZEL (价值 $4000 USDC)
```

1. 存款 100 ZEL， 收到 2000 DONK 。

```
📌 新的DonkeySwap状态：

- 4000 USDC
- 1000 HUGE (每HUGE $4 USDC)
- 200 ZEL (每ZEL $20 USDC)

新的攻击者状态：

- 5000DONK
```

2. 用 3999 DONK 提取 3999 USDC。

```
📌 新的 DonkeySwap 状态：

- 1 USDC
- 1000 HUGE ($0.001 USDC/HUGE)
- 200 ZEL (每ZEL $0.005 USDC)

新的攻击者状态：

- 1001 DONK
- 3999 USDC
```

3. 用 1 个 DONK 提现 200ZEL， 用 1 个 DONK 提现 1000 HUGE。

```
📌 最后的 DonkeySwap 状态：

- 1 USDC

最终的攻击者状态：

- 999 DONK
- 3999 USDC
- 200 ZEL (价值$2000 USDC)
- 1000 HUGE (价值$1000 USDC)
```

#### 建议

至少使用一个不容易被操纵的外部价格指标（例如，按时间平均价格）。

## 5. 算术精度错误

算术运算四舍五入导致精度递减，有可能导致协议对这种计算结果的表述不足。
任何导致 0 和 1 之间的非积分值的计算都会被 u8、u64 和 u128 类型表示为 0。这对不同的环境下有不同的影响。
在可能的情况下，[运算顺序](https://blog.solidityscan.com/precision-loss-in-arithmetic-operations-8729aea20be9?gi=ab7d8f6cf2c6)应尽量减少精度损失。

### DonkeySwap：四舍五入错误使协议费被绕过

- 类别：编码错误
- 严重程度：中度
- 影响：中度
- 可能性: 高

#### 描述

DonkeySwap 在下面的函数中通过提取订单金额（size）的百分比来计算适当的协议费用：

```
##[query]
public fun calculate_protocol_fees(
    size: u64
): (u64) {
    return size * PROTOCOL_FEE_BPS / 10000
}
```

如果 "size"参数小于 "10000 / PROTOCOL_FEE_BPS"，费用将向下舍入为 0。

#### 影响

用户在删除流动性、兑换或限制兑换时，可以通过下多个小订单绕过费用。
下面的概念证明证明了这种影响，一个订单的费用为零协议费：

```
##[test(admin=@donkeyswap, user=@0x2222)]
fun WHEN_exploit_fees_rounding_down(admin: &signer, user: &signer) acquires CoinCapability {
    setup_with_liquidity(admin, user);

    let max_exploit_amount = (10000 / market::get_protocol_fees_bps()) - 1;
    assert!(market::calculate_protocol_fees(max_exploit_amount) == 0, ERR_UNEXPECTED_PROTOCOL_FEES);

    let my_usdc = max_exploit_amount;
    mint<USDC>(my_usdc, address_of(user));

    assert!(coin::balance<USDC>(address_of(user)) == my_usdc, ERR_UNEXPECTED_BALANCE);
    assert!(coin::balance<ZEL>(address_of(user)) == 0, ERR_UNEXPECTED_BALANCE);

    let output = market::swap<USDC, ZEL>(user, my_usdc);

    assert!(coin::balance<USDC>(address_of(user)) == 0, ERR_UNEXPECTED_BALANCE);
    assert!(coin::balance<ZEL>(address_of(user)) == output, ERR_UNEXPECTED_BALANCE);
    assert!(output > 0, ERR_UNEXPECTED_BALANCE);

    assert!(market::get_protocol_fees<USDC>() == 0, ERR_UNEXPECTED_PROTOCOL_FEES);
    assert!(market::get_protocol_fees<ZEL>() == 0, ERR_UNEXPECTED_PROTOCOL_FEES); // no fees collected
}
```

#### 建议

要求订单大小高于最低金额，或者要求计算的协议费用不为零。

## 6. 缺少对 Coin 的账户注册检查

aptos_framework::coin 模块要求在调用 coin::deposit 或 coin::withdraw 时，目标账户上存在一个 CoinStore，所以必须事先用 coin::register 注册账户：

```
public fun register<CoinType>(account: &signer) {
    let account_addr = signer::address_of(account);
    // Short-circuit and do nothing if account is already registered for CoinType.
    if (is_account_registered<CoinType>(account_addr)) {
        return
    };
        // [...]
}
```

请注意，如果账户已经被注册，该函数会提前返回。所以，在取款或存款操作之前总是先注册是安全的。
当签名人没有函数中注册账户时，代码应该首先检查账户是否已经用 coin::is_account_registered 注册，如果没有则失败。

### DonkeySwap：未注册的账户阻止了 fulfill_order 功能

- 类别：编码错误
- 严重程度：中度
- 影响：中度
- 可能性: 高

#### 描述

函数 execute_limit_order 没有检查将收到报价币的账户是否为该币注册过。

#### 影响

execute_limit_order 函数被 execute_order 调用，而 execute_order 被 fulfill_orders 调用， add_liquidity 也会调用 execute_order ，所以如果攻击者创建一个可执行的订单，发给一个没有注册 quote 币的账户，那么就无法进行兑换或增加流动性。
下面的概念证明说明了这一点：

```
##[test(admin=@donkeyswap, user=@0x2222, attacker=@0x3333)]
##[expected_failure(abort_code=393221, location=coin)] // ECOIN_STORE_NOT_PUBLISHED
fun WHEN_exploit_lack_of_account_registered_check(admin: &signer, user: &signer, attacker: &signer) acquires CoinCapability {
    account::create_account_for_test(address_of(attacker));
    setup(admin, user);
    assert!(!coin::is_account_registered<ZEL>(address_of(attacker)), ERR_UNEXPECTED_ACCOUNT);

    // create limit order from attacker's account
    let my_usdc = 10_0000; // $10 USDC
    mint<USDC>(my_usdc, address_of(attacker));
    market::limit_swap<USDC, ZEL>(user, my_usdc, 0);

    // try to add liquidity from user's account, which tries to fulfill the order
    mint<USDC>(my_usdc, address_of(user));
    market::add_liquidity<USDC>(user, my_usdc); // this should abort
}
```

请注意， 虽然 add_liquidity 和 remove_liquidity 也不检查账户是否被注册， 这些操作会立即回退，只会有自拒绝服务的攻击。

#### 建议

在 limit_swap 函数中增加以下两行，强制注册账户：

```
coin::register<BaseCoinType>(user);
coin::register<QuoteCoinType>(user);
```

注意，如果账户已经被注册，coin::register 函数会自动跳过注册。

## 7. 算术错误和不一致

Aptos Move 实现了 u8，u16 和 u64 的整数类型。因此，在我们的许多审计中，我们看到自定义类型增加了对浮点或定点小数、有符号整数或其他宽度的支持。需要注意的是，自定义数据大小可能会有与内置无符号整数类型不同的上溢/下溢行为。
确保不回退的代码不能出现算术错误，如除以零、溢出和下溢错误，因为这种错误会造成拒绝服务。

### DonkeySwap：对大十进制 Coin 的计算可能导致溢出

- 类别：编码错误
- 严重程度：中度
- 影响: 高
- 可能性：低

#### 描述

攻击者有可能在以下地方创建一个大到足以导致溢出中止的订单：

- calculate_lp_coin_amount_internal：

```
size * get_usd_value_internal(order_store, type)
```

- calculate_protocol_fees：

```
size * PROTOCOL_FEE_BPS / 10000
```

#### 影响

因为 add_liquidity 总是试图执行订单，如果在完成订单时计算溢出，add_liquidity 请求将失败。
下面的概念证明证明了 add_liquidity 被算术错误阻止：

```
##[test(admin=@donkeyswap, user=@0x2222)]
##[expected_failure(arithmetic_error, location=market)]
fun WHEN_exploit_overflow_revert(admin: &signer, user: &signer) acquires CoinCapability {
    setup_with_liquidity(admin, user);

    // add extra DONK liquidity
    let admin_donk = 1000000000000000;
    mint<DONK>(admin_donk, address_of(admin));
    market::admin_deposit_donk(admin, admin_donk);

    // place a reasonable order size for HUGE
    let user_huge = 1000000000000000;
    mint<HUGE>(user_huge, address_of(user));
    market::limit_swap<HUGE, ZEL>(user, user_huge, 0);

    // inadvertently fulfill limit order
    let admin_zel = 10000;
    mint<ZEL>(admin_zel, address_of(admin));
    market::add_liquidity<ZEL>(admin, admin_zel);
}
```

#### 建议

在乘法之前将操作数转为 u128，并确保那些可能导致溢出的 Coin 不被列入白名单。

## 8. 不当的资源管理

在 [Aptos Move 开发模型](https://aptos.dev/guides/move-guides/move-on-aptos/#comparison-to-other-vms)中，数据要存储在 Move 到所有者账户的资源中，而不是模块账户上的通用资源中存储。
根据[Aptos Move 关于数据所有权的文档](https://aptos.dev/guides/move-guides/move-on-aptos/#data-ownership)：
在 Move 中，数据可以存储在模块所有者的账户内，但这造成了所有权模糊问题，并意味着两个问题：

1. 它使所有权变得模糊，因为资产没有与所有者相关的资源。
2. 模块创建者要对该资源的生命周期负责（例如，租借、回收等）。

关于第一点，通过将资产置于账户内的可信资源中，所有者可以确保即使是恶意编程的模块也无法修改这些资产。在 Move 中，我们可以编程一个标准的订单簿结构和接口，让建立在上面的应用程序无法获得对一个账户或其订单簿条目的后门访问。
简单地说，这样的设计是一个很好的做法，这样计算（资源所有权）是按用户进行的。

### DonkeySwap：订单存储在全局 Store 而不是所有者上

- 类别：业务逻辑
- 严重性：信息性
- 影响：不适用
- 可能性：不适用

#### 说明

DonkeySwap 将订单资源放在 orders 向量中，该向量存储在@donkeyswap 中：

```
struct OrderStore has key {
    current_id: u64,
    orders: vector<Order>,
    locked: Table<TypeInfo, u64>,
    liquidity: Table<TypeInfo, u64>,
    decimals: Table<TypeInfo, u8>
}
```

#### 影响

根据[Aptos Move 关于数据所有权的文档](https://aptos.dev/guides/move-guides/move-on-aptos/#data-ownership)，这是个坏的做法，可能会使其他漏洞被利用。
例如，如果 orders 的全局向量增长过大，并且在其上进行迭代会导致 Gas 中断，这将影响所有用户；但如果每个用户都有一个 orders 向量，增加过多的订单将只是一个自我拒绝服务攻击。

#### 建议

一般来说，我们建议将资源存储在用户的账户中，因为这被认为是 Move 的最佳实践。

## 9. 业务逻辑缺陷

在审计用 Move 编写的协议时，我们报告的另一个最常见的缺陷类型是业务逻辑缺陷。这些是协议底层设计中的缺陷--与代码中的错误相反--如错位的激励机制、中心化风险、不正确的操作顺序、逻辑缺陷（例如，双重花费）等等。
虽然这是一个广泛的错误类别，但商业逻辑是高度依赖上下文的，所以我们把这些类型的大多数错误归入这一部分。

### DonkeySwap：缺少 LP 激励

- 类别：商业逻辑
- 严重程度: 高
- 影响: 高
- 可能性: 高

#### 描述

用户没有被激励以任何方式向 AMM 提供流动性。

#### 影响

在部署 DonkeySwap 后，用户不太可能向协议提供流动性，因为他们没有理由这样做。

#### 建议

通常情况下，AMM 协议从兑换或流动性改变的操作中收取费用，用于激励提供流动性。我们建议实施一种激励增加流动性的收费结构，并有选择地抑制撤出流动性的行为。

## 10.使用不正确的标准函数

在 Move stdlib 中，某些函数的操作是类似的：需要在正确的时间使用正确的函数，以避免运行时中止（其中编译器/类型检查不会提前捕获这些错误）。
例如（免责声明：这不是一个完全的列表）：

- option::borrow_mut<Element>(t: &mut Option<Element>)。

option::extract<Element>(t: &mut Option<Element>)。

- table::add<K: copy + drop, V>（table: &mut Table<K, V>, key: K, val: V）。

table::upsert<K: copy + drop, V: drop>(table: &mut Table<K, V>, key: K, value: V)。

- table_with_length::add<K: copy + drop, V>(table: &mut Table<K, V>, key: K, val: V)。

table_with_length::upsert<K: copy + drop, V: drop>(table: &mut Table<K, V>, key: K, value: V)。

### DonkeySwap: fulfill_orders 在提取后被借用

- 类别：编码错误
- 严重程度：严重性: 中等
- 影响：中等
- 可能性：低

#### 描述

fulfill_orders 函数在增加流动性时自动被调用，在成功执行 Order 后， 从 Option 中借用 Order 提取订单 ID：

```
let order_option = get_next_order(&mut orders);
if (option::is_none(&order_option)) {
    break
};
let status = execute_order<CoinType>(order_store, &option::extract(&mut order_option));
if (status == 0) {
    vector::push_back(&mut successful_order_ids, option::borrow(&mut order_option).id);
};
```

然而，在提取后，Order 将无法从 Option 中借用。

#### 影响

如果任何限价订单在 fulfill_orders 调用期间成功完成，交易将中止，可能会阻止用户增加流动性。

#### 建议

从 Option 中提取一次订单或借用两次。
此外，确保这段代码有测试覆盖率；如果在任何测试中达到 status == 0，这个问题就会被发现。

---

## 结论

Move 语言的设计是为了减少 bug 类型的数量，但是 bug 仍然可能存在。我们已经了解了最常见的 bug 类型以及如何补救它们。审核你的代码对于保护你的智能合约不受经济损失至关重要。
