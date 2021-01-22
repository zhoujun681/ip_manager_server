/*
 * @Descripttion: 使用ctrl+alt+i添加头部注释，ctrl+alt+t添加方法注释, 或者复制方法名后使用gocm来添加方法注释
 * @version:
 * @Author: bb
 * @Date: 2020-12-21 13:08:48
 * @LastEditors: bb
 * @LastEditTime: 2021-01-21 14:09:27
 */
use actix_cors::Cors;
use actix_web::{get, http::header, post, web, App, HttpRequest, HttpResponse, HttpServer};
use serde::Deserialize;
use std::env;
use serde_yaml::Error;
use std::fs::File;
use serde_yaml; 
use serde_yaml::Value;

mod my_sqlite_dao;

#[derive(Deserialize)]
struct Info {
    name: String,
    username: String,
    password: String,
}

#[derive(Deserialize)]
struct Query_Ip {
    part_id: i32,
}

#[derive(Deserialize)]
struct Check_Ip {
    part_id: i32,
    ip_address_end: i32,
    ip_address_full: String,
}

#[derive(Deserialize)]
struct InsertLock {
    part_id: i32,
    ip_address_end: i32,
    lock: i32,
}

#[derive(Deserialize, Debug)]
struct MyForm {
    mac: String,
    ip_address_end: i32,
    part_id: i32,
    location: String,
}
#[derive(Deserialize, Debug)]
struct AddPartForm {
    department_name: String,
    part_name: String,
    ip_address_section: String,
    min_ip: i32,
    max_ip: i32,
}

#[derive(Deserialize, Debug)]
struct EditDepartment {
    department_id: i32,
    department_name: String,
}

#[derive(Deserialize, Debug)]
struct EditPart {
    part_id: i32,
    part_name: String,
    ip_address_section: String,
    ip_min: i32,
    ip_max: i32,
}

#[derive(Deserialize, Debug)]
struct DelData {
    part_id: i32,
    ip_address_section: i32,
}

#[derive(Deserialize, Debug)]
struct EditData {
    location: String,
    ip_address_section: String,
    ip_address_end: i32,
    ip_address_end_old: i32,
    mac_address: String,
}

//登录请求
#[post("/login")]
async fn login(info: web::Form<Info>) -> HttpResponse {
    my_sqlite_dao::my_log(format!("收到一条login请求"));
    let myconn = my_sqlite_dao::init_db().expect("数据库初始化失败");
    HttpResponse::Ok().json(my_sqlite_dao::check_user(
        myconn,
        info.username.clone(),
        info.password.clone(),
    ))
}

//插入或者更改ip_locks
#[post("/insert_or_alter_lock")]
async fn insert_or_alter_lock(inser_lock: web::Form<InsertLock>) -> HttpResponse {
    my_sqlite_dao::my_log(format!("收到一条innert_or_alter_lock请求"));
    let myconn = my_sqlite_dao::init_db().expect("数据库初始化失败");
    HttpResponse::Ok().json(my_sqlite_dao::insert_or_alter_lock(
        myconn,
        inser_lock.part_id,
        inser_lock.ip_address_end,
        inser_lock.lock,
    ))
}

//锁定ip地址的请求
#[post("/submitForm")]
async fn submitForm(myForm: web::Form<MyForm>) -> HttpResponse {
    my_sqlite_dao::my_log(format!("收到一条submitForm请求"));
    let myconn = my_sqlite_dao::init_db().expect("数据库初始化失败");
    my_sqlite_dao::my_log(format!("myForm:{:?}", myForm));
    HttpResponse::Ok().json(my_sqlite_dao::submitForm(
        myconn,
        myForm.mac.clone(),
        myForm.ip_address_end,
        myForm.part_id,
        myForm.location.clone(),
    ))
}

//修改科室请求
#[post("/edit_department")]
async fn edit_department(edit_department_form: web::Form<EditDepartment>) -> HttpResponse {
    my_sqlite_dao::my_log(format!(
        "收到一条edit_department请求,参数为:{:?}",
        &edit_department_form
    ));
    let myconn = my_sqlite_dao::init_db().expect("数据库初始化失败");
    HttpResponse::Ok().json(my_sqlite_dao::edit_department(
        myconn,
        edit_department_form.department_id,
        edit_department_form.department_name.clone(),
    ))
}

//修改部门请求
#[post("/edit_part")]
async fn edit_part(edit_part_form: web::Form<EditPart>) -> HttpResponse {
    my_sqlite_dao::my_log(format!(
        "收到一条edit_part_form请求,参数为:{:?}",
        &edit_part_form
    ));
    let myconn = my_sqlite_dao::init_db().expect("数据库初始化失败");
    HttpResponse::Ok().json(my_sqlite_dao::edit_part(
        myconn,
        edit_part_form.part_id,
        edit_part_form.part_name.clone(),
        edit_part_form.ip_address_section.clone(),
        edit_part_form.ip_min,
        edit_part_form.ip_max,
    ))
}

//删除记录
#[post("/del_data")]
async fn del_data(del_data_form: web::Form<DelData>) -> HttpResponse {
    my_sqlite_dao::my_log(format!("收到一条del_data请求,参数为:{:?}", &del_data_form));
    let mut myconn = my_sqlite_dao::init_db().expect("数据库初始化失败");
    HttpResponse::Ok().json(my_sqlite_dao::del_data(
        myconn,
        del_data_form.part_id,
        del_data_form.ip_address_section,
    ))
}

//修改记录
#[post("/edit_ipdata")]
async fn edit_ipdata(edit_ipdata_form: web::Form<EditData>) -> HttpResponse {
    my_sqlite_dao::my_log(format!(
        "收到一条edit_ipdata请求,参数为:{:?}",
        &edit_ipdata_form
    ));
    let mut myconn = my_sqlite_dao::init_db().expect("数据库初始化失败");
    HttpResponse::Ok().json(my_sqlite_dao::edit_ipdata(
        myconn,
        edit_ipdata_form.location.clone(),
        edit_ipdata_form.ip_address_section.clone(),
        edit_ipdata_form.ip_address_end,
        edit_ipdata_form.ip_address_end_old,
        edit_ipdata_form.mac_address.clone(),
    ))
}

//获取科室和部门信息
#[get("/get_department")]
async fn get_department() -> HttpResponse {
    my_sqlite_dao::my_log(format!("收到一条get_department请求"));
    let myconn = my_sqlite_dao::init_db().expect("数据库初始化失败");
    HttpResponse::Ok().json(my_sqlite_dao::get_department(myconn))
}

//获取部门当前可用ip
#[get("/get_ip")]
async fn get_ip(query_ip: web::Query<Query_Ip>) -> HttpResponse {
    my_sqlite_dao::my_log(format!("收到一条get_ip请求:{:?}", query_ip.part_id));
    let myconn = my_sqlite_dao::init_db().expect("数据库初始化失败");
    HttpResponse::Ok().json(my_sqlite_dao::get_ip(myconn, query_ip.part_id))
}

//检查当前ip地址是否仍然可用
#[get("/check_ip")]
async fn check_ip(check_ip: web::Query<Check_Ip>) -> HttpResponse {
    my_sqlite_dao::my_log(format!("收到一条check_ip请求"));
    let myconn = my_sqlite_dao::init_db().expect("数据库初始化失败");
    HttpResponse::Ok().json(my_sqlite_dao::check_ip(
        &myconn,
        check_ip.part_id,
        check_ip.ip_address_end,
        check_ip.ip_address_full.clone(),
    ))
}

//获取管理信息，包括所有可是部门及ip
#[get("/get_manage_datas")]
async fn get_manage_datas(query_ip: web::Query<Query_Ip>) -> HttpResponse {
    my_sqlite_dao::my_log(format!(
        "收到一条get_manage_datas请求,查询part_id={}",
        query_ip.part_id
    ));
    let myconn = my_sqlite_dao::init_db().expect("数据库初始化失败");
    HttpResponse::Ok().json(my_sqlite_dao::get_manage_datas(myconn, query_ip.part_id))
}

//检查增加的部门是否可用
#[get("/check_add_part")]
async fn check_add_part(add_part_form: web::Query<AddPartForm>) -> HttpResponse {
    my_sqlite_dao::my_log(format!("收到一条check_add_part请求!!"));
    let mut myconn = my_sqlite_dao::init_db().expect("数据库初始化失败");
    HttpResponse::Ok().json(my_sqlite_dao::check_add_part(
        myconn,
        add_part_form.department_name.clone(),
        add_part_form.part_name.clone(),
        add_part_form.ip_address_section.clone(),
        add_part_form.min_ip,
        add_part_form.max_ip,
    ))
}

//读取yaml配置文件
fn readYaml() -> Result<Value,Box<dyn std::error::Error>> {
    let f = std::fs::File::open("./conf.yaml")?;
    let data_value: Value  = serde_yaml::from_reader(f)?;
    Ok(data_value)
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {

    let data_value = readYaml().unwrap();
    let is_debug = data_value["server"]["debug"].as_bool().unwrap();
    let port = data_value["server"]["port"].as_u64().unwrap();
    unsafe {
        my_sqlite_dao::is_debug = is_debug;
    }
    let server_ip=format!(":{:?}",port);
    let local_ip=format!("127.0.0.1:{:?}",port);


    println!("欢迎使用玉溪市人民医院ip管理系统，服务端运行在本机{}端口。。。",port);
    println!("提示：数据库文件必须放在文件所在目录的db文件夹下，名为使用IpDatas.db");
    println!("提示：conf.yaml文件的server-debug设为true开启debug信息！！！");
    println!("提示：conf.yaml文件的server-port设置端口！！！");
    // let args: Vec<String> = env::args().collect();
    // if args.len() > 1 {
    //     let arg = args.get(1).unwrap();
    //     if (arg == "-d") {
    //         unsafe {
    //             my_sqlite_dao::is_debug = true;
    //         }
    //     }
    // }

    HttpServer::new(|| {
        App::new()
            .wrap(
                Cors::default()
                    // .allowed_origin("http://localhost:8080")
                    //.allowed_origin("http://localhost:8090")   //指定特定地址访问
                    .allowed_origin_fn(|origin, _req_head| {
                        //通过规则指定，这里是所有
                        // origin.as_bytes().ends_with(b".rust-lang.org")
                        true
                    })
                    .allowed_methods(vec!["GET", "POST"])
                    .allowed_headers(vec![header::AUTHORIZATION, header::ACCEPT])
                    .allowed_header(header::CONTENT_TYPE)
                    .supports_credentials()
                    .max_age(3600),
            )
            // .service(web::resource("/submit").route(web::post().to(submit)))
            .service(web::scope("/users").service(login))
            .service(
                web::scope("/datas")
                    .service(get_department)
                    .service(get_ip)
                    .service(check_ip)
                    .service(insert_or_alter_lock)
                    .service(submitForm)
                    .service(get_manage_datas)
                    .service(check_add_part)
                    .service(edit_department)
                    .service(edit_part)
                    .service(del_data)
                    .service(edit_ipdata),
            )
    })
    .bind(server_ip)?
    .bind(local_ip)?
    .run()
    .await
}
