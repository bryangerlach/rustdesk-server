use actix_web::{get, post, web, App, HttpResponse, HttpServer, Responder, cookie::Cookie, HttpRequest, HttpMessage};
use chrono::NaiveDateTime;
use serde::Deserialize;
use sqlx::{sqlite::SqliteConnection, Connection};
use argon2::{self, Config};

#[derive(Debug)]
struct Device {
    id: String,
    user: Option<Vec<u8>>,
    info: String,
    status: Option<i64>
}

#[derive(Debug)]
struct Logs {
    from_ip: Option<String>,
    to_id: Option<String>,
    logged_at: NaiveDateTime,
    user: Option<Vec<u8>>
}

#[get("/hello")]
async fn hello(req: HttpRequest) -> impl Responder {
    if !check_login(req) {
        return HttpResponse::Found().header(http::header::LOCATION, "/").finish();
    }
	let mut conn = get_conn().await;

	let devices = sqlx::query_as!(Device, "SELECT id, user, info, status FROM peer WHERE status > 0").fetch_all(&mut conn).await;
    let row_count = devices.as_ref().unwrap().len();

    // Render the data in a table.
    let table = format!(
        r#"
        <html>
            <head>
                <title>Connected Devices</title>
            </head>
            <body>
                <style>
                    table {{
                    border-collapse: collapse;
                    }}
                
                    th, td {{
                    border: 1px solid black;
                    padding: 5px;
                    }}
                
                    th {{
                    font-weight: bold;
                    }}
                </style>
                <a href=/log>View Connection Log</a>
                <h1>ONLINE ({})</h1>
                <table>
                    <thead>
                        <tr>
                            <th>ID</th>
                            <th>Name</th>
                            <th>Info</th>
                            <th>Status</th>
                        </tr>
                    </thead>
                    <tbody>
                        {}
                    </tbody>
                </table>
        "#,
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
                            <input type="text" name="newname" placeholder="New Username">
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

    let devices2 = sqlx::query_as!(Device, "SELECT id, user, info, status FROM peer WHERE status = 0").fetch_all(&mut conn).await;
    let row_count2 = devices2.as_ref().unwrap().len();

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
                            <th>Status</th>
                        </tr>
                    </thead>
                    <tbody>
                        {}
                    </tbody>
                </table>
                <p><button onclick="location.href='/logout';">Logout</button></p>
                <p><button onclick="location.href='/changepassform';">Change Admin Password</button></p>
        "#,
        row_count2,
        if let Err(_err) = devices2 {
			"Error".to_owned()
		} else {
			devices2.unwrap().iter().map(|device| {
            format!(
                r#"
                    <tr>
                        <td>{}</td>
                        <td>{}</td>
                        <td>{}</td>
                        <td>{:?}</td>
                        <td>
                            <form action="/rename" method="post">
                                <input type="text" name="newname" placeholder="New Username">
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
                device.status.unwrap(),
                device.id,
                device.id,
            )
        }).collect::<Vec<_>>().join("\n")
		}
    );

    conn.close();

    // Return the response.
    HttpResponse::Ok().body(table+&table2)
    //HttpResponse::Ok().body("Hello world!")
}

#[get("/log")]
async fn log(req: HttpRequest) -> impl Responder {
    if !check_login(req) {
        return HttpResponse::Found().header(http::header::LOCATION, "/").finish();
    }
    let mut conn = get_conn().await;

	let logs = sqlx::query_as!(Logs, "SELECT from_ip, to_id, logged_at, user FROM log INNER JOIN peer ON peer.id = log.to_id").fetch_all(&mut conn).await;
    // Render the data in a table.
    let table = format!(
        r#"
        <html>
            <head>
                <title>Connection Logs</title>
            </head>
            <body>
                <style>
                    table {{
                    border-collapse: collapse;
                    }}
                
                    th, td {{
                    border: 1px solid black;
                    padding: 5px;
                    }}
                
                    th {{
                    font-weight: bold;
                    }}
                </style>
                <a href=/hello>View Connected Devices</a>
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
                log.logged_at,
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
        return web::HttpResponse::build(http::StatusCode::OK)
            .set_header(http::header::CONTENT_TYPE, "text/html")
            .body(r#"
                <html>
                    <head>
                        <title>Login</title>
                    </head>
                    <body>
                        <h1>Login</h1>
                        <form action="/login" method="post">
                            <input type="text" name="username" placeholder="Username">
                            <input type="password" name="password" placeholder="Password">
                            <button type="submit">Login</button>
                        </form>
                    </body>
                </html>
            "#);
    } else {
        return HttpResponse::Found().header(http::header::LOCATION, "/hello").finish();
    }
        //response
}

#[post("/rename")]
async fn rename(form: web::Form<RenameForm>, req: HttpRequest) -> impl Responder {
    if !check_login(req) {
        return HttpResponse::Found().header(http::header::LOCATION, "/").finish();
    }
    let id = &form.id;
    let newname = &form.newname;
    
    let mut conn = get_conn().await;
    let _query = sqlx::query!("UPDATE peer SET user = ? WHERE id = ?",newname,id).fetch_all(&mut conn).await.unwrap();
    conn.close();
    web::HttpResponse::Found().header(http::header::LOCATION, "/hello").finish()
}

#[post("/delete")]
async fn delete(form: web::Form<DeleteForm>, req: HttpRequest) -> impl Responder {
    if !check_login(req) {
        return HttpResponse::Found().header(http::header::LOCATION, "/").finish();
    }
    let id = &form.id;
    
    let mut conn = get_conn().await;
    let _query = sqlx::query!("DELETE FROM peer WHERE id = ?",id).fetch_all(&mut conn).await.unwrap();
    conn.close();
    web::HttpResponse::Found().header(http::header::LOCATION, "/hello").finish()
}

#[get("/logout")]
async fn logout() -> impl Responder {
    let mut response = web::HttpResponse::build(http::StatusCode::OK)
    .set_header(http::header::CONTENT_TYPE, "text/html")
    .body(r#"
        <html>
            <head>
                <title>Logged Out</title>
            </head>
            <body>
                <h1>You are Logged Out</h1>
                <form action="/login" method="post">
                    <input type="text" name="username" placeholder="Username">
                    <input type="password" name="password" placeholder="Password">
                    <button type="submit">Login</button>
                </form>
            </body>
        </html>
    "#);
    let c = Cookie::new("logged_in", "false");
    let _ = response.add_cookie(&c);
    response
}

#[get("/changepassform")]
async fn changepassform(req: HttpRequest) -> impl Responder {
    if !check_login(req) {
        return HttpResponse::Found().header(http::header::LOCATION, "/").finish();
    }
    let response = web::HttpResponse::build(http::StatusCode::OK)
    .set_header(http::header::CONTENT_TYPE, "text/html")
    .body(r#"
        <html>
            <head>
                <title>Set New Password</title>
            </head>
            <body>
                <h1>Set New Password</h1>
                <form action="/changepass" method="post">
                    <input type="password" name="newpass" placeholder="Password">
                    <button type="submit">Change Password</button>
                </form>
            </body>
        </html>
    "#);
    
    response
}

#[post("/changepass")]
async fn changepass(form: web::Form<ChangeForm>, req: HttpRequest) -> impl Responder {
    if !check_login(req) {
        return HttpResponse::Found().header(http::header::LOCATION, "/").finish();
    }
    let mut conn = get_conn().await;
    let salt = b"adoi8320jjfslk09992jjnl09";
    let config = Config::default();
    let hash = argon2::hash_encoded(form.newpass.as_bytes(), salt, &config).unwrap();
    let _adminuser = sqlx::query!("UPDATE users SET password=? WHERE username='admin'",hash)
        .execute(&mut conn)
        .await;
    conn.close();

    let mut response = web::HttpResponse::build(http::StatusCode::OK)
    .set_header(http::header::CONTENT_TYPE, "text/html")
    .body(r#"
        <html>
            <head>
                <title>Password Changed, Please Log In</title>
            </head>
            <body>
                <h1>Password Changed, Please Log In</h1>
                <form action="/login" method="post">
                    <input type="text" name="username" placeholder="Username">
                    <input type="password" name="password" placeholder="Password">
                    <button type="submit">Login</button>
                </form>
            </body>
        </html>
    "#);
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
    let db_password = query.first().unwrap();
    let db_password_string = &db_password.password;
    conn.close();
    let mut response = web::HttpResponse::Found().header(http::header::LOCATION, "/").finish();
    match argon2::verify_encoded(&db_password_string, &password.as_bytes()) {
        Ok(is_valid_password) => {
            if is_valid_password {
                //password accepted
                //println!("password accepted");

                let c = Cookie::new("logged_in", "true");
                response = web::HttpResponse::Found().header(http::header::LOCATION, "/hello").finish();
                let _ = response.add_cookie(&c);
            } else {
                //println!("wrong password");
            }
        }
        Err(_error) => {
            //handle error
            //println!("error verifying password: {}", error);
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
	println!("DB_URL={}", db);
	let conn = SqliteConnection::connect(
        &db,
    ).await.unwrap();

    return conn;
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
    HttpServer::new(|| {
        App::new()
            .service(hello)
            .service(login_form)
            .service(login)
            .service(rename)
            .service(delete)
            .service(log)
            .service(logout)
            .service(changepass)
            .service(changepassform)
    })
    .bind(("127.0.0.1", 21114))?
    .run()
    .await
}