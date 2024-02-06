extern crate time;
use std::{io::BufReader, fs::File, path::PathBuf};

use actix_web::{get, post, web, App, HttpResponse, HttpServer, Responder, cookie::Cookie, HttpRequest, Result};
use chrono::{NaiveDateTime, Datelike, Timelike, Local, TimeZone, DateTime, format::strftime};
use serde::Deserialize;
use sqlx::{sqlite::SqliteConnection, Connection};
use argon2::{self, Config};
use actix_web::cookie::time::{Duration, OffsetDateTime};
use actix_files::NamedFile;
use rustls::{Certificate, PrivateKey, ServerConfig};
use rustls_pemfile::{certs, pkcs8_private_keys};

static HTML_MENU: &str = r#"<!DOCTYPE html>
<html>
<head>
  <title>Rustdesk Admin Console</title>
  <meta http-equiv="refresh" content="120" >
</head>
<body>
<style>
    nav {
        background-color: #2c8cff;
        overflow: hidden;
    }
    nav h1 {
        padding-left: 16px;
        color: white;
    }
    nav a {
        flex: 1;
        float: left;
        color: white;
        text-align: center;
        padding: 14px 16px;
        text-decoration: none;
        font-size: 17px;
    }

    nav ul {
        list-style-type: none;
        display: flex;
    }
    
    nav a:hover {
        background-color: #ddd;
        color: black;
    }
    
    nav a.active {
        background-color: #04AA6D;
        color: white;
    }

    table {
        border-collapse: collapse;
        margin: 25px 0;
        font-size: 0.9em;
        font-family: sans-serif;
        min-width: 400px;
        box-shadow: 0 0 20px rgba(0, 0, 0, 0.15);
    }

    thead tr {
        background-color: #2c8cff;
        color: #ffffff;
        text-align: left;
    }

    th, td {
        padding: 12px 15px;
    }

    tbody tr {
        border-bottom: 1px solid #2c8cff;
    }
    
    tbody tr:nth-of-type(even) {
        background-color: #f3f3f3;
    }
    
    tbody tr:last-of-type {
        border-bottom: 2px solid #2c8cff;
    }
</style>

  <nav>
    <h1>Rustdesk Admin Console</h1>
    <ul>
      <li><a href="/home">Devices</a></li>
      <li><a href="/log">Connection Log</a></li>
      <li><a href="/install">Install Scripts</a></li>
      <li><a href="/changepassform">Change Password</a></li>
      <li><a href="/logout">Logout</a></li>
    </ul>
  </nav>"#;

#[derive(Debug)]
struct Device {
    id: String,
    user: Option<Vec<u8>>,
    info: String,
    status: Option<i64>,
    created_at: NaiveDateTime
}

#[derive(Debug)]
struct Logs {
    from_ip: Option<String>,
    to_id: Option<String>,
    logged_at: Option<NaiveDateTime>,
    user: Option<Vec<u8>>
}

#[get("/home")]
async fn home(req: HttpRequest) -> impl Responder {
    if !check_login(req) {
        return HttpResponse::Found().append_header((http::header::LOCATION, "/")).finish();
    }
	let mut conn = get_conn().await;

	let devices = sqlx::query_as!(Device, "SELECT id, user, info, status, created_at FROM peer WHERE status > 0 ORDER BY user").fetch_all(&mut conn).await;
    let row_count = devices.as_ref().unwrap().len();
    let devices2 = sqlx::query_as!(Device, "SELECT id, user, info, status, created_at FROM peer WHERE status = 0 ORDER BY user").fetch_all(&mut conn).await;
    let row_count2 = devices2.as_ref().unwrap().len();
    let tot_rows = row_count + row_count2;

    // Render the data in a table.
    let table = format!(
        r#"
        {}
                <h1>Total Devices ({})</h1>
                <h1>ONLINE ({})</h1>
                <table>
                    <thead>
                        <tr>
                            <th>Connect</th>
                            <th>ID</th>
                            <th>Name</th>
                            <th>Info</th>
                            <th>Status</th>
                            <th>Rename Device</th>
                        </tr>
                    </thead>
                    <tbody>
                        {}
                    </tbody>
                </table>
        "#,
        HTML_MENU,
        tot_rows,
        row_count,
        if let Err(_err) = devices {
			"Error".to_owned()
		} else {
			devices.unwrap().iter().map(|device| {
            format!(
                r#"
                    <tr>
                    <td><button onclick="location.href='{}';">Connect</button></td>
                    <td>{}</td>
                    <td>{}</td>
                    <td>{}</td>
                    <td>{:?}</td>
                    <td>
                        <form action="/rename" method="post">
                            <input type="text" name="newname" placeholder="New Device Name">
                            <input type="hidden" name="id" value="{}">
                            <button type="submit">Rename Device</button>
                        </form>
                    </td>
                    </tr>
                "#,
                "rustdesk://connect/".to_owned()+&device.id,
                device.id,
                match &device.user {
                    Some(user) => String::from_utf8(user.to_vec()).unwrap(),
                    None => String::from_utf8("unknown".as_bytes().to_vec()).unwrap(),
                },
                device.info,
                device.status.unwrap(),
                device.id,
            )
        }).collect::<Vec<_>>().join("\n")
		}
    );

    // Render the data in a table.
    let table2 = format!(
        r#"
                <h1>OFFLINE ({})</h1>
                <table>
                    <thead>
                        <tr>
                            <th>ID</th>
                            <th>Device Name</th>
                            <th>Info</th>
                            <th>Last Online</th>
                            <th>Rename Device</th>
                            <th>Delete Device</th>
                        </tr>
                    </thead>
                    <tbody>
                        {}
                    </tbody>
                </table>
        "#,
        row_count2,
        if let Err(_err) = devices2 {
			"Error".to_owned()
		} else {
			devices2.unwrap().iter().map(|device| {
                let date_time: String = get_local_datetime(device.created_at);
            format!(
                r#"
                    <tr>
                        <td>{}</td>
                        <td>{}</td>
                        <td>{}</td>
                        <td>{:?}</td>
                        <td>
                            <form action="/rename" method="post">
                                <input type="text" name="newname" placeholder="New Device Name">
                                <input type="hidden" name="id" value="{}">
                                <button type="submit">Rename Device</button>
                            </form>
                        </td>
                        <td>
                            <form action="/delete" method="post">
                                <input type="hidden" name="id" value="{}">
                                <button type="submit">Delete Device</button>
                            </form>
                        </td>
                    </tr>
                "#,
                device.id,
                match &device.user {
                    Some(user) => String::from_utf8(user.to_vec()).unwrap(),
                    None => String::from_utf8("unknown".as_bytes().to_vec()).unwrap(),
                },
                device.info,
                date_time,
                device.id,
                device.id,
            )
        }).collect::<Vec<_>>().join("\n")
		}
    );

    conn.close();

    // Return the response.
    HttpResponse::Ok().body(table+&table2)
}

#[get("/log")]
async fn log(req: HttpRequest) -> impl Responder {
    if !check_login(req) {
        return HttpResponse::Found().append_header((http::header::LOCATION, "/")).finish();
    }
    let mut conn = get_conn().await;

	let logs = sqlx::query_as!(Logs, "SELECT from_ip, to_id, logged_at, user FROM log INNER JOIN peer ON peer.id = log.to_id ORDER BY logged_at DESC LIMIT 50").fetch_all(&mut conn).await;
    // Render the data in a table.
    let table = format!(
        r#"
        {}
                <h1>Connection Log</h1>
                <table>
                    <thead>
                        <tr>
                            <th>Logged At</th>
                            <th>From IP</th>
                            <th>To ID</th>
                            <th>To Device Name</th>
                        </tr>
                    </thead>
                    <tbody>
                        {}
                    </tbody>
                </table>
        "#,
        HTML_MENU,
        if let Err(_err) = logs {
			"Error".to_owned()
		} else {
			logs.unwrap().iter().map(|log| {
            format!(
                r#"
                    <tr>
                        <td>{}</td>
                        <td>{}</td>
                        <td>{}</td>
                        <td>{}</td>
                    </tr>
                "#,
                match &log.logged_at {
                    Some(lat) => get_local_datetime(*lat),
                    None => String::from_utf8("unknown".as_bytes().to_vec()).unwrap(),
                },
                match &log.from_ip {
                    Some(from) => from.to_string(),
                    None => String::from_utf8("unknown".as_bytes().to_vec()).unwrap(),
                },
                match &log.to_id {
                    Some(to) => to.to_string(),
                    None => String::from_utf8("unknown".as_bytes().to_vec()).unwrap(),
                },
                match &log.user {
                    Some(user) => String::from_utf8(user.to_vec()).unwrap(),
                    None => String::from_utf8("unknown".as_bytes().to_vec()).unwrap(),
                },
            )
        }).collect::<Vec<_>>().join("\n")
		}
    );

    conn.close();

    // Return the response.
    HttpResponse::Ok().body(table)
}

#[get("/")]
async fn login_form(req: HttpRequest) -> impl Responder {
    if !check_login(req) {
        // Create a response with the login screen HTML
        return HttpResponse::build(http::StatusCode::OK)
            .insert_header((http::header::CONTENT_TYPE, "text/html"))
            .body(format!(r#"
                {}
                        <h1>Login</h1>
                        <form action="/login" method="post">
                            <input type="text" name="username" placeholder="Username">
                            <input type="password" name="password" placeholder="Password">
                            <button type="submit">Login</button>
                        </form>
                    </body>
                </html>
            "#,
            HTML_MENU));
    } else {
        return HttpResponse::Found().append_header((http::header::LOCATION, "/home")).finish();
    }
        //response
}

#[post("/rename")]
async fn rename(form: web::Form<RenameForm>, req: HttpRequest) -> impl Responder {
    if !check_login(req) {
        return HttpResponse::Found().append_header((http::header::LOCATION, "/")).finish();
    }
    let id = &form.id;
    let newname = &form.newname;
    
    let mut conn = get_conn().await;
    let _query = sqlx::query!("UPDATE peer SET user = ? WHERE id = ?",newname,id).fetch_all(&mut conn).await.unwrap();
    conn.close();
    HttpResponse::Found().append_header((http::header::LOCATION, "/home")).finish()
}

#[post("/delete")]
async fn delete(form: web::Form<DeleteForm>, req: HttpRequest) -> impl Responder {
    if !check_login(req) {
        return HttpResponse::Found().append_header((http::header::LOCATION, "/")).finish();
    }
    let id = &form.id;
    
    let mut conn = get_conn().await;
    let _query = sqlx::query!("DELETE FROM peer WHERE id = ?",id).fetch_all(&mut conn).await.unwrap();
    conn.close();
    HttpResponse::Found().append_header((http::header::LOCATION, "/home")).finish()
}

#[get("/logout")]
async fn logout() -> impl Responder {
    let mut response = HttpResponse::build(http::StatusCode::OK)
    .insert_header((http::header::CONTENT_TYPE, "text/html"))
    .body(format!(r#"
        {}
                <h1>You are Logged Out</h1>
                <form action="/login" method="post">
                    <input type="text" name="username" placeholder="Username">
                    <input type="password" name="password" placeholder="Password">
                    <button type="submit">Login</button>
                </form>
            </body>
        </html>
    "#,HTML_MENU));
    let c = Cookie::new("logged_in", "false");
    let _ = response.add_cookie(&c);
    response
}

#[get("/https")]
async fn https(req: HttpRequest) -> impl Responder {
    if !check_login(req) {
        return HttpResponse::Found().append_header((http::header::LOCATION, "/")).finish();
    }
    let response = HttpResponse::build(http::StatusCode::OK)
    .insert_header((http::header::CONTENT_TYPE, "text/html"))
    .body(format!(r#"
        {}
                <h1>Insctructions to set up https</h1>
                <p>To use https you need to copy your server's key.pem and cert.pem files to the same location as the webs executable file.</p>
            </body>
        </html>
    "#,HTML_MENU));
    
    response
}

#[get("/install")]
async fn install(req: HttpRequest) -> impl Responder {
    if !check_login(req) {
        return HttpResponse::Found().append_header((http::header::LOCATION, "/")).finish();
    }
    let response = HttpResponse::build(http::StatusCode::OK)
    .insert_header((http::header::CONTENT_TYPE, "text/html"))
    .body(format!(r#"
        {}
                <h1>Download the appropriate install script</h1>
                <a href="WindowsAgentAIOInstall.ps1">Windows</a>
                <br>
                <a href="linuxclientinstall.sh">Linux</a>
            </body>
        </html>
    "#,HTML_MENU));
    
    response
}

async fn download(req: HttpRequest) -> Result<NamedFile> {
    let path: PathBuf = req.match_info().query("filename").parse().unwrap();
    Ok(NamedFile::open(path)?)
}

#[get("/changepassform")]
async fn changepassform(req: HttpRequest) -> impl Responder {
    if !check_login(req) {
        return HttpResponse::Found().append_header((http::header::LOCATION, "/")).finish();
    }
    let response = HttpResponse::build(http::StatusCode::OK)
    .insert_header((http::header::CONTENT_TYPE, "text/html"))
    .body(format!(r#"
        {}
                <h1>Set New Password</h1>
                <form action="/changepass" method="post">
                    <input type="password" name="newpass" placeholder="Password">
                    <button type="submit">Change Password</button>
                </form>
            </body>
        </html>
    "#,HTML_MENU));
    
    response
}

#[post("/changepass")]
async fn changepass(form: web::Form<ChangeForm>, req: HttpRequest) -> impl Responder {
    if !check_login(req) {
        return HttpResponse::Found().append_header((http::header::LOCATION, "/")).finish();
    }
    let mut conn = get_conn().await;
    let salt = b"adoi8320jjfslk09992jjnl09";
    let config = Config::default();
    let hash = argon2::hash_encoded(form.newpass.as_bytes(), salt, &config).unwrap();
    let _adminuser = sqlx::query!("UPDATE users SET password=? WHERE username='admin'",hash)
        .execute(&mut conn)
        .await;
    conn.close();

    let mut response = HttpResponse::build(http::StatusCode::OK)
    .insert_header((http::header::CONTENT_TYPE, "text/html"))
    .body(format!(r#"
        {}
                <h1>Password Changed, Please Log In</h1>
                <form action="/login" method="post">
                    <input type="text" name="username" placeholder="Username">
                    <input type="password" name="password" placeholder="Password">
                    <button type="submit">Login</button>
                </form>
            </body>
        </html>
    "#,HTML_MENU));
    let c = Cookie::new("logged_in", "false");
    let _ = response.add_cookie(&c);
    response
}

#[post("/login")]
async fn login(form: web::Form<LoginForm>) -> impl Responder {
    let mut conn = get_conn().await;

	//let conn = database::Database::new(&db).await;
    let username = &form.username;
    let password = &form.password;
	let query = sqlx::query!("SELECT password FROM users WHERE username = ?",username).fetch_all(&mut conn).await.unwrap();
    let mut response = HttpResponse::Found().append_header((http::header::LOCATION, "/")).finish();
    if query.len() > 0 {
        let db_password = query.first().unwrap();
        let db_password_string = &db_password.password;
        conn.close();
        match argon2::verify_encoded(&db_password_string, &password.as_bytes()) {
            Ok(is_valid_password) => {
                if is_valid_password {
                    //password accepted
                    println!("password accepted");

                    let mut c = Cookie::new("logged_in", "true");
                    response = HttpResponse::Found().append_header((http::header::LOCATION, "/home")).finish();
                    let mut now = OffsetDateTime::now_utc();
                    now += Duration::weeks(2);
                    c.set_expires(now);
                    let _ = response.add_cookie(&c);
                } else {
                    println!("wrong password");
                }
            }
            Err(error) => {
                //handle error
                println!("error verifying password: {}", error);
            }
        }
    }
    
    response
}

fn check_login(req: HttpRequest) -> bool {
    let cookie = req.cookie("logged_in");
    let v = "true";
    if let Some(_cookie) = &cookie {
        // The user is logged in.
        if cookie.unwrap().value() == v {
            true
        } else {
            false
        }
    } else {
        // The user is not logged in.
        false
    }
}

#[derive(Deserialize)]
struct LoginForm {
    username: String,
    password: String,
}

#[derive(Deserialize)]
struct RenameForm {
    id: String,
    newname: String,
}

#[derive(Deserialize)]
struct DeleteForm {
    id: String,
}

#[derive(Deserialize)]
struct ChangeForm {
    newpass: String,
}

async fn get_conn() -> SqliteConnection {
    let db = std::env::var("DB_URL").unwrap_or({
		let mut db = "db_v2.sqlite3".to_owned();
		#[cfg(all(windows, not(debug_assertions)))]
		{
			if let Some(path) = hbb_common::config::Config::icon_path().parent() {
				db = format!("{}\\{}", path.to_str().unwrap_or("."), db);
			}
		}
		#[cfg(not(windows))]
		{
			db = format!("./{db}");
		}
		db
	});
	//println!("DB_URL={}", db);
	let conn = SqliteConnection::connect(
        &db,
    ).await.unwrap();

    return conn;
}

fn load_rustls_config() -> Result<rustls::ServerConfig, String> {
    // init server config builder with safe defaults
    let config = ServerConfig::builder()
        .with_safe_defaults()
        .with_no_client_auth();

    // check if cert.pem and key.pem exist
    let cert_file_exists = File::open("cert.pem").is_ok();
    let key_file_exists = File::open("key.pem").is_ok();

    // if either file does not exist, return an empty config
    if !cert_file_exists || !key_file_exists {
        return Err("Could not locate cert.pem or key.pem.".to_string());
    }

    // load TLS key/cert files
    let cert_file = &mut BufReader::new(File::open("cert.pem").unwrap());
    let key_file = &mut BufReader::new(File::open("key.pem").unwrap());

    // convert files to key/cert objects
    let cert_chain = certs(cert_file)
        .unwrap()
        .into_iter()
        .map(Certificate)
        .collect();
    let mut keys: Vec<PrivateKey> = pkcs8_private_keys(key_file)
        .unwrap()
        .into_iter()
        .map(PrivateKey)
        .collect();

    // exit if no keys could be parsed
    if keys.is_empty() {
        eprintln!("Could not locate PKCS 8 private keys.");
        std::process::exit(1);
    }

    Ok(config.with_single_cert(cert_chain, keys.remove(0)).unwrap())
}

fn get_local_datetime(created_at: NaiveDateTime) -> String {
    let date_time = TimeZone::from_utc_datetime(&Local, &created_at);
    let (is_pm, hour) = date_time.hour12();
    let date_string = format!("{}-{:02}-{:02}  ({}) {:02}:{:02} {}",
        date_time.year(),date_time.month(),date_time.day(),date_time.weekday(),
        hour, date_time.minute(),if is_pm { "PM" } else { "AM" });
    date_string
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
	let mut conn = get_conn().await;
    
    let adminpassword = b"admin";
    let salt = b"adoi8320jjfslk09992jjnl09";
    let config = Config::default();
    let hash = argon2::hash_encoded(adminpassword, salt, &config).unwrap();
    let _usertable = sqlx::query!("CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT NOT NULL UNIQUE,
        password TEXT NOT NULL
      );").execute(&mut conn)
      .await;
    let _adminuser = sqlx::query!("INSERT INTO users (username, password) VALUES ('admin',?)",hash)
        .execute(&mut conn)
        .await;
    conn.close();
    let config = load_rustls_config();

    match config {
        Ok(config) => {
            println!("listening on https port 21113");
            HttpServer::new(|| {
                App::new()
                    .service(home)
                    .service(login_form)
                    .service(login)
                    .service(rename)
                    .service(delete)
                    .service(log)
                    .service(logout)
                    .service(changepass)
                    .service(changepassform)
                    .service(install)
                    .service(https)
                    .route("/{filename:.*}", web::get().to(download))
            })
            .bind_rustls_021("0.0.0.0:21113", config)?
            .run()
            .await
        }
        Err(_error_message) => {
            println!("listening on http port 21113");
            HttpServer::new(|| {
                App::new()
                    .service(home)
                    .service(login_form)
                    .service(login)
                    .service(rename)
                    .service(delete)
                    .service(log)
                    .service(logout)
                    .service(changepass)
                    .service(changepassform)
                    .service(install)
                    .service(https)
                    .route("/{filename:.*}", web::get().to(download))
            })
            .bind(("0.0.0.0", 21113))?
            .run()
            .await
        }
    }
    
}