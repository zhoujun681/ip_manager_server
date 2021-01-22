use actix_web::web::Json;
use rusqlite::types::Null;
use rusqlite::{params, Connection, Result, Transaction};
use serde::{Deserialize, Serialize};
use std::net::IpAddr;
use winping::{Buffer, Pinger};

//debug信息函数
pub static mut is_debug: bool = false;
pub fn my_log(str: String) {
    unsafe {
    if is_debug {
        println!("{}", str);
    }
}
}

//用户
#[derive(Serialize, Deserialize, Debug)]
pub struct User {
    pub name: String,
    pub username: String,
    pub password: String,
}

//部门
#[derive(Serialize, Deserialize, Debug)]
pub struct part {
    pub part_id: i32,
    pub part_name: String,
}

//科室
#[derive(Serialize, Deserialize, Debug)]
pub struct department {
    pub department_id: i32,
    pub department_name: String,
    pub department_parts: Vec<part>,
}

//ip地址
#[derive(Serialize, Deserialize, Debug)]
pub struct ip_address {
    pub current_ip: Option<String>,
}

//检查IP
#[derive(Serialize, Deserialize, Debug)]
pub struct CheckIp {
    pub is_locked: i32,
}

//管理界面数据
#[derive(Serialize, Deserialize, Debug)]
pub struct ManageDatas {
    pub department_name: String,
    pub department_id: i32,
    pub part_name: String,
    pub part_id: i32,
    pub location: String,
    pub ipAddress: String,
    pub macAddress: String,
}

//科室校验数据
#[derive(Serialize, Deserialize, Debug)]
pub struct CheckDepartment {
    pub part_count: i32,
    pub department_count: i32,
    pub department_id: i32,
}

//初始化数据库
pub fn init_db() -> Result<Connection> {
    let conn = Connection::open("./db/IpDatas.db");
    return conn;
}

//验证用户登录
pub fn check_user(conn: Connection, login_name: String, password: String) -> String {
    let mut stmt = conn
        .prepare("SELECT  user_name, login_name,password FROM Users where  login_name=?1 and password=?2")
        .expect("check_user时数据库prepare失败");
    let person_iter = stmt
        .query_map(params![login_name, password], |row| {
            Ok(User {
                name: match row.get(0) {
                    Ok(name) => name,
                    Err(err) => "None".to_string(),
                },
                username: match row.get(1) {
                    Ok(username) => username,
                    Err(err) => "None".to_string(),
                },
                password: match row.get(2) {
                    Ok(password) => password,
                    Err(err) => "None".to_string(),
                },
            })
        })
        .expect("check_user时数据库查询失败");

    let mut username = String::from("");
    for person in person_iter {
        my_log(format!("Found person {:?}", person));
        username = person.unwrap().username;
    }
    username
}

//获取所有科室信息
pub fn get_department(conn: Connection) -> Vec<department> {
    let mut stmt = conn
        .prepare("SELECT  department_id,department_name FROM department")
        .expect("get_department时数据库prepare失败");
    let department_iter = stmt
        .query_map(params![], |row| {
            Ok(department {
                department_id: row.get(0).unwrap(),
                department_name: row.get(1).unwrap(),
                department_parts: vec![],
            })
        })
        .expect("get_department时数据库查询失败");
    let mut b: User = User {
        name: "None".to_string(),
        username: "None".to_string(),
        password: "None".to_string(),
    };
    let mut departments = vec![];
    for department in department_iter {
        my_log(format!("Found department {:?}", department));
        let mut aDepartment = department.unwrap();
        let mut stmt = conn
            .prepare("SELECT  part_id,part_name FROM part where department_id=?")
            .expect("get_department后查询part时数据库prepare失败");
        let part_iter = stmt
            .query_map(params![aDepartment.department_id], |row| {
                Ok(part {
                    part_id: row.get(0).unwrap(),
                    part_name: row.get(1).unwrap(),
                })
            })
            .expect("get_department后查询part时数据库查询失败");

        let mut parts = vec![];
        for part in part_iter {
            parts.push(part.unwrap());
        }
        aDepartment.department_parts = parts;
        departments.push(aDepartment);
    }
    my_log(format!("{:?}", departments));
    departments
}

//获取部门当前可用的IP
pub fn get_ip(conn: Connection, part_id: i32) -> String {
    let mut stmt = conn
        .prepare(
            r"
            select ip from (
            select min(myIndex),ip  from 
            (
            SELECT  1 as myIndex,pt.ip_address_section || CAST ((MIN (ips.ip_address_end)) AS TEXT) as ip
            FROM   ip_locks AS ips
                   INNER JOIN part AS pt ON ips.part_id = pt.part_id
            WHERE  ips.part_id = ?1 AND lock = 0
            union all
            SELECT 2 as myIndex, ip_address_section || CAST (ip_address_end AS TEXT)  as ip
            from (
            SELECT ip_address_section , MAX (ips.ip_address_end) + 1 as ip_address_end,pt.ip_max
            FROM   ip_locks AS ips
                   INNER JOIN part AS pt ON ips.part_id = pt.part_id 
            WHERE  ips.part_id = ?1 AND lock = 1 
            ) b1
            where ip_address_end<=ip_max
            ) b
            where ip is not null
        )
            ",
        )
        .expect("get_ip时数据库prepare失败");
    let result = stmt
        .query_map(params![part_id], |row| {
            Ok(ip_address {
                current_ip: match row.get(0) {
                    Ok(ip) => Some(ip),
                    Ok(_) => None,
                    Err(err) => None,
                },
            })
        })
        .expect("get_ip时数据库查询失败");

    let mut ip = String::from("");

    for row in result {
        ip = match row.unwrap().current_ip {
            Some(ip) => ip,
            None => "192.168.0.0".to_string(),
        }
    }
    if (ip.is_empty()) {
        "192.168.0.0".to_string()
    } else {
        ip
    }
}

//查询ip是否可以使用
pub fn check_ip(
    conn: &Connection,
    part_id: i32,
    ip_address_end: i32,
    ip_address_full: String,
) -> i32 {
    //查询是否在范围内
    let mut stmt = conn
        .prepare("select count(*) from part where part_id=?1 and ?2 between ip_min and ip_max")
        .expect("查询是否在范围内失败!!");
    let result = stmt
        .query_row(params![part_id, ip_address_end], |row| {
            return row.get(0) as Result<i32>;
        })
        .expect("解析是否在范围内失败!!");
    if (result == 0) {
        //不在范围内
        return -3;
    }

    //查询是否已经使用
    let mut is_locked = 0;
    let mut stmt = conn
        .prepare(
            r#"select count(*) as lock from ip_locks 
             where part_id=? and ip_address_end=? and lock=1
        "#,
        )
        .expect("check_ip连接prepare错误。。。");
    let result = stmt
        .query_map(params![part_id, ip_address_end], |row| {
            Ok(CheckIp {
                is_locked: match row.get(0) {
                    Ok(lock) => lock,
                    Err(err) => -1,
                },
            })
        })
        .expect("check_ip查询数据错误。。。");
    for row in result {
        is_locked = row.unwrap().is_locked;
    }
    if (is_locked == -1) {
        return -1;
    } else if (is_locked > 0) {
        return -4;
    }
    //查询是否ping的通

    is_locked = ping_check(ip_address_full);
    if (is_locked == 1) {
        //ip如果ping的通
        return -2;
    }

    is_locked
}

//插入lock信息,存在就修改
pub fn insert_or_alter_lock(
    myconn: Connection,
    part_id: i32,
    ip_address_end: i32,
    lock: i32,
) -> i32 {
    let result = myconn
        .execute(
            r#"insert into ip_locks(ip_address_end,part_id,lock) values(?1,?2,?3)
            on conflict(ip_address_end,part_id) do update 
            set lock = excluded.lock"#,
            params![ip_address_end, part_id, lock],
        )
        .expect("insert_or_alter_lock时数据库execute失败");
    if (result > 0) {
        return 1;
    }
    return 0;
}

//插入用户锁定的ip信息
pub fn submitForm(
    myconn: Connection,
    mac: String,
    ip_address_end: i32,
    part_id: i32,
    location: String,
) -> i32 {
    let result = myconn
        .execute(
            r#"insert into ip_datas(ip_address_end,part_id,mac_address,position) values(?1,?2,?3,?4)
        on conflict(ip_address_end,part_id) do update 
        set mac_address = excluded.mac_address,
        position=excluded.position"#,
            params![ip_address_end, part_id, mac, location],
        )
        .expect("submitForm时数据库execute失败");
    if (result > 0) {
        return 1;
    }
    return 0;
}

//查询是否ping的通
pub fn ping_check(ip_address_full: String) -> i32 {
    my_log(format!("正在Ping地址{}", ip_address_full));
    let dst = std::env::args()
        .nth(1)
        .unwrap_or(ip_address_full)
        .parse::<IpAddr>()
        .expect("Could not parse IP Address");

    let pinger = Pinger::new().unwrap();
    let mut buffer = Buffer::new();

    let mut result: [i32; 2] = [0, 0];
    for i in 0..2 {
        //ping两次
        result[i] = match pinger.send(dst, &mut buffer) {
            Ok(rtt) => 1,
            Err(err) => 0,
        };
    }

    result[0] | result[1] //有一次为成功则返回1，认为ip已被占用
}

//获取所有管理界面的数据
pub fn get_manage_datas(myconn: Connection, part_id: i32) -> Vec<ManageDatas> {
    let mut stmt = myconn
    .prepare(
        r#"select dt.department_name,
        dt.department_id,
        pt.part_name,
        pt.part_id,
        ips.position as location,
        pt.ip_address_section || CAST(ips.ip_address_end AS TEXT)  as ipAddress,
        ips.mac_address as macAddress 
        from department dt
        inner join  part pt on pt.department_id=dt.department_id  and (pt.part_id = :part_id or 1=:showAll)
        inner join ip_datas ips on ips.part_id=pt.part_id
        order by department_name,part_name
    "#,
    )
    .expect("get_manage_datas连接prepare错误。。。");
    let mut my_params = format!("{}", part_id);
    let mut isShowAll = 0;
    if (part_id == -1) {
        isShowAll = 1;
    }
    my_log(format!("get_manage_datas::my_params:{}", my_params));
    let result = stmt
        .query_map_named(
            &[(":part_id", &my_params), (":showAll", &isShowAll)],
            |row| {
                Ok(ManageDatas {
                    department_name: row.get(0).unwrap(),
                    department_id: row.get(1).unwrap(),
                    part_name: row.get(2).unwrap(),
                    part_id: row.get(3).unwrap(),
                    location: row.get(4).unwrap(),
                    ipAddress: row.get(5).unwrap(),
                    macAddress: row.get(6).unwrap(),
                })
            },
        )
        .expect("get_manage_datas查询数据错误。。。");
    let mut manage_datas: Vec<ManageDatas> = vec![];
    for row in result {
        manage_datas.push(row.unwrap());
    }
    manage_datas
}

/***
 * 检查增加的部门是否可用
 * 首先科室存在，则只向部门表添加，
 * 若不存在，则先添加科室，再添加部门
 * 添加部门同时，判断ip段是否重叠，不重叠才可使用
 * 添加最后需要在ip_locks表添加部门起始ip，lock为0
***/
pub fn check_add_part(
    mut myconn: Connection,
    department_name: String,
    part_name: String,
    ip_address_section: String,
    min_ip: i32,
    max_ip: i32,
) -> i32 {
    let mut ResultFlag = 1;
    //检查增加的部门是否可用
    my_log(format!(
        "part_name={:?},department_name={:?}",
        &part_name, &department_name
    ));
    let check_result = db_check_part(&myconn, &department_name, &part_name);
    my_log(format!(
        "db_check_part完成!!check_result={:?}",
        check_result
    ));

    let mut part_count = 0;
    let mut department_count = 0;
    let mut department_id = 0;

    part_count = check_result.part_count;
    department_count = check_result.department_count;
    department_id = check_result.department_id;

    //如果部门已经存在，返回-1
    if (part_count) > 0 {
        ResultFlag = -1;
        return ResultFlag;
    }
    //判断ip段是否重叠
    let overlap_count = db_overlap_check(&myconn, &ip_address_section, min_ip, max_ip, -99);
    my_log(format!(
        "db_overlap_check完成!!overlap_count={}",
        overlap_count
    ));
    if (overlap_count > 0) {
        ResultFlag = -2;
        return ResultFlag;
    }

    //插入科室和部门
    //开启事务
    let mut tx = myconn.transaction().unwrap();
    ResultFlag = db_inert_check_part(
        &tx,
        &part_name,
        department_id,
        &department_name,
        &ip_address_section,
        min_ip,
        max_ip,
        department_count,
    )
    .expect("db_inert_check_part时发生其他错误！！");
    tx.commit(); //提交事务

    return ResultFlag;
}

//数据库新增部门
fn db_inert_check_part(
    myconn: &Connection,
    part_name: &String,
    department_id: i32,
    department_name: &String,
    ip_address_section: &String,
    min_ip: i32,
    max_ip: i32,
    department_count: i32,
) -> Result<i32> {
    if (department_count) > 0 {
        //如果科室已经存在，则直接插入部门
        let result = myconn
        .execute("insert into part(part_name,department_id,ip_address_section,ip_min,ip_max) values(?1,?2,?3,?4,?5)",
            params![part_name, department_id, ip_address_section, min_ip,max_ip],
        )
        .expect("插入部门失败！！");
    } else {
        //科室不存在，就先插入科室，又插入部门
        //插入科室
        let result = myconn
            .execute(
                "insert into department(department_name) values(?1)",
                params![department_name],
            )
            .expect("插入科室失败！！");
        //查询插入的科室id
        let mut stmt = myconn
            .prepare("select department_id from department where department_name=?")
            .expect("查询插入的科室id失败!!");
        let department_id = stmt
            .query_row(params![department_name], |row| {
                return row.get(0) as Result<i32>;
            })
            .expect("解析插入的科室失败!!");
        //插入部门
        let result = myconn
        .execute("insert into part(part_name,department_id,ip_address_section,ip_min,ip_max) values(?1,?2,?3,?4,?5)",
            params![part_name, department_id, ip_address_section, min_ip,max_ip],
        )
        .expect("插入部门失败！！");
    }
    //查询插入的部门的part_id
    let mut stmt = myconn
        .prepare("select part_id from part where part_name=?")
        .expect("查询插入的部门id失败!!");
    let part_id = stmt
        .query_row(params![part_name], |row| {
            return row.get(0) as Result<i32>;
        })
        .expect("解析插入的部门失败!!");

    //插入lock初始值
    let result = myconn
        .execute(
            "insert into ip_locks(ip_address_end,part_id,lock) values(?1,?2,?3)",
            params![min_ip, part_id, 0],
        )
        .expect("插入lock初始值失败！！");

    Ok(1)
}

//检查ip地址是否重叠
fn db_overlap_check(
    myconn: &Connection,
    ip_address_section: &String,
    min_ip: i32,
    max_ip: i32,
    part_id: i32,
) -> i32 {
    let mut stmt = myconn
        .prepare(
            r#"select count(*) as overlap_count from part where part_id not in (
            select part_id from part
            where ip_address_section = ?1
            and (?2>ip_max or ?3<ip_min)
            )
            and ip_address_section = ?1
            and part_id<>?4
            "#,
        )
        .expect("查询ip段是否重叠失败!!");
    let overlap_count = stmt
        .query_row(
            params![ip_address_section, min_ip, max_ip, part_id],
            |row| {
                return row.get(0) as Result<i32>;
            },
        )
        .expect("解析ip段是否重叠失败!!");
    my_log(format!(
        "db_overlap_check结束!!overlap_count={}",
        overlap_count
    ));
    overlap_count
}

//检查科室和部门是否存在
fn db_check_part(
    myconn: &Connection,
    department_name: &String,
    part_name: &String,
) -> CheckDepartment {
    let mut stmt = myconn
    .prepare(
        r#"
        select count(pt.part_name) as part_count,count(dt.department_name) as department_count,dt.department_id from department as dt
        left join   part as pt on pt.department_id=dt.department_id and  pt.part_name= ?1
        where dt.department_name= ?2
        group by dt.department_id
    "#)
    .expect("check_department_part时数据库prepare失败");
    let department_iter = stmt
        .query_map(params![part_name, department_name], |row| {
            Ok(CheckDepartment {
                part_count: row.get(0).unwrap(),
                department_count: row.get(1).unwrap(),
                department_id: row.get(2).unwrap(),
            })
        })
        .expect("check_department时数据库查询失败");
    let mut temp = CheckDepartment {
        part_count: 0,
        department_count: 0,
        department_id: 0,
    };
    for department in department_iter {
        temp = department.unwrap();
    }
    my_log(format!("db_check_part结束!!"));
    temp
}

//修改科室请求
pub fn edit_department(myconn: Connection, department_id: i32, department_name: String) -> i32 {
    //修改科室名
    let result = myconn
        .execute(
            "update department set department_name=?1 where department_id=?2",
            params![department_name, department_id],
        )
        .expect("更新科室失败！！");
    if result > 0 {
        1
    } else {
        -1
    }
}

//修改部门请求
pub fn edit_part(
    myconn: Connection,
    part_id: i32,
    part_name: String,
    ip_address_section: String,
    ip_min: i32,
    ip_max: i32,
) -> i32 {
    // 需要检查部门名称是否存在
    let check_part_result = db_check_part2(&myconn, part_id, &part_name);
    if check_part_result > 0 {
        return -1;
    }

    // 需要检查修改的ip范围是否重叠
    let overlap_count = db_overlap_check(&myconn, &ip_address_section, ip_min, ip_max, part_id);
    my_log(format!(
        "db_overlap_check完成!!overlap_count={}",
        overlap_count
    ));
    if (overlap_count > 0) {
        return -2;
    }

    //更新部门内容
    let result = myconn
    .execute(
        "update part set part_name=?1,ip_address_section=?2,ip_min=?3,ip_max=?4 where part_id=?5",
        params![&part_name, &ip_address_section,&ip_min,&ip_max,&part_id],
    )
    .expect("更新部门失败！！");

    return result as i32;
}

//检查同科室下部门名称是否存在
fn db_check_part2(myconn: &Connection, part_id: i32, part_name: &String) -> i32 {
    let mut stmt = myconn
        .prepare(
            r#"select count(1) from part where part_name=?1
    and department_id=(select department_id from  part where part_id=?2) and part_id<>?2"#,
        )
        .expect("查询存在部门失败!!");
    let result = stmt
        .query_row(params![part_name, part_id], |row| {
            return row.get(0) as Result<i32>;
        })
        .expect("解析插入的部门失败!!");
    return result;
}

//删除数据
pub(crate) fn del_data(mut myconn: Connection, part_id: i32, ip_address_end: i32) -> i32 {
    //更新部门内容
    let mut tx = myconn.transaction().unwrap();
    let mut result: usize = 0;
    result = tx
        .execute(
            "delete from ip_datas where part_id=?1 and ip_address_end=?2",
            params![&part_id, &ip_address_end],
        )
        .expect("删除部门失败！！");
    result = tx
        .execute(
            "update ip_locks set lock=0 where part_id=?1 and ip_address_end=?2",
            params![&part_id, &ip_address_end],
        )
        .expect("更新lock失败！！");
    tx.commit();

    return result as i32;
}

//修改数据
pub(crate) fn edit_ipdata(
    myconn: Connection,
    location: String,
    ip_address_section: String,
    ip_address_end: i32,
    ip_address_end_old: i32,
    mac_address: String,
) -> i32 {
    //查询part_id
    let mut stmt = myconn
        .prepare(r#"select part_id from part where ip_address_section=?1 and ?2 between ip_min and ip_max"#)
        .expect("查询部门id失败!!");
    let part_id = stmt
        .query_row(params![&ip_address_section,&ip_address_end_old], |row| {
            return row.get(0) as Result<i32>;
        })
        .expect("解析部门id失败!!");
    let mut result = 0;
    if (ip_address_end != ip_address_end_old) {
        result = check_ip(
            &myconn,
            part_id,
            ip_address_end,
            format!("{}{}", &ip_address_section, ip_address_end),
        ); //检查Ip，返回0 - 正常,-1 解析异常,-2  ping的通,-3  超出允许范围
        if (result < 0 && result != -2) {
            //ping的通只是提示
            return result;
        }
    }
    //修改数据
    //首先把以前的数据的lock设置0
    //然后把新增数据插入
    let mut tempConnection = init_db().expect("数据库初始化失败");
    let mut tx = tempConnection.transaction().unwrap();
    //修改IP
    let mut result = tx
        .execute(
            "update ip_datas set ip_address_end=?1,position=?2,mac_address=?3 where part_id=?4 and ip_address_end=?5",
            params![&ip_address_end,&location,&mac_address,part_id,&ip_address_end_old],
        )
        .expect("修改ipdatas失败！！")  ;
    my_log(format!("result:{},参数：{},{},{},{},{}",result,&ip_address_end,&location,&mac_address,part_id,&ip_address_end_old));
    //插入lock
    if (ip_address_end != ip_address_end_old) {
        result = tx
            .execute(
                "update ip_locks set lock=0 where part_id=?1 and ip_address_end=?2",
                params![part_id, &ip_address_end_old],
            )
            .expect("更新lock失败！！");

        result = tx
            .execute(
                r#"insert into ip_locks(ip_address_end,part_id,lock) values(?1,?2,1)
                        on conflict(ip_address_end,part_id) do update 
                        set lock = 1
                        "#,
                params![&ip_address_end, part_id],
            )
            .expect("插入lock初始值失败！！");
    }
    tx.commit();
    return result as i32;
}


